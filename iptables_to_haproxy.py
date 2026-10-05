#!/usr/bin/env python3
"""
iptables_to_haproxy.py

Convert an iptables rules list (e.g. the free IP2Location "visitor blocker"
country list, or any similar firewall list) into HAProxy-ready IP list
files that you can use with an ACL file:   acl <name> src -f <file>

INPUT  -- a text file with one iptables rule per line:

    iptables  -A INPUT -s 5.52.0.0/16   -j ACCEPT
    ip6tables -A INPUT -s 2001:db8::/32 -j ACCEPT
    iptables  -A INPUT -s 1.2.3.0/24    -j DROP

  '#' comment lines and blank lines are ignored. Flags may be in any
  order; -s/--source, -d/--destination, -j/--jump and -A/-I are understood.

OUTPUT -- written next to the input file (override with --outdir):

    haproxy-allow.lst   networks from ACCEPT rules      -> whitelist
    haproxy-block.lst   networks from DROP/REJECT rules -> blocklist
    haproxy-snippet.cfg ready-to-paste haproxy.cfg snippet

  Each .lst file holds one IPv4/IPv6 address or CIDR network per line,
  de-duplicated, sorted, and by default merged into the smallest
  equivalent set of networks (merging never changes which IPs match;
  use --no-merge to keep entries 1:1).

WIRING IT UP (inside the frontend in haproxy.cfg, mode http):

    # blocklist -- deny the listed networks:
    acl country_block src -f /etc/haproxy/haproxy-block.lst
    http-request deny if country_block

    # whitelist -- deny everything NOT listed:
    acl country_allow src -f /etc/haproxy/haproxy-allow.lst
    http-request deny if !country_allow

  Then validate and apply (seamless reload, no dropped connections):

    sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy

NOTES
  * The .lst files contain just the networks by default, so they stay
    portable for any other tool that may consume them. HAProxy 1.6+ safely
    ignores '#' comment lines in -f files (verified against the 1.6/1.8/2.x
    source), so pass --comments to embed a small provenance header if you
    want one.
  * Re-run this script whenever you refresh the list (IP2Location asks for
    a monthly update), copy the new .lst to the server, reload HAProxy.
  * Make sure HAProxy can read the file, e.g.:
        sudo chown root:haproxy /etc/haproxy/haproxy-allow.lst
        sudo chmod 640 /etc/haproxy/haproxy-allow.lst
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple, cast

ACCEPT_TARGETS = ("ACCEPT",)
BLOCK_TARGETS = ("DROP", "REJECT")


class Rule(NamedTuple):
    """The parts of an iptables/ip6tables rule we care about."""

    src: str | None
    dst: str | None
    target: str | None


class Options(NamedTuple):
    """Parsed command-line options."""

    input: str
    outdir: str | None
    comments: bool
    no_merge: bool
    ipv4_only: bool


class WrittenFile(NamedTuple):
    """A generated list file and how many entries it holds."""

    kind: str
    path: Path
    entries: int


def parse_rule(line: str) -> Rule | None:
    """Split an iptables/ip6tables line into its interesting parts."""
    toks = line.split()
    if not toks or toks[0] not in ("iptables", "ip6tables"):
        return None
    src: str | None = None
    dst: str | None = None
    target: str | None = None
    i = 1
    while i < len(toks):
        tok = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if tok in ("-A", "-I") and nxt is not None:
            i += 2
        elif tok in ("-s", "--source") and nxt is not None:
            src = nxt
            i += 2
        elif tok in ("-d", "--destination") and nxt is not None:
            dst = nxt
            i += 2
        elif tok in ("-j", "--jump") and nxt is not None:
            target = nxt
            i += 2
        else:
            i += 1
    return Rule(src=src, dst=dst, target=target)


def sort_key(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int, int]:
    return (net.version, int(net.network_address), net.prefixlen)


def merge(nets: set[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Collapse networks into the smallest equivalent set (union-preserving)."""
    result: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for n in nets:
        if isinstance(n, ipaddress.IPv4Network):
            v4.append(n)
        else:
            v6.append(n)
    result.extend(ipaddress.collapse_addresses(v4))
    result.extend(ipaddress.collapse_addresses(v6))
    return sorted(result, key=sort_key)


def write_lst(path: Path,
              nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
              header: list[str] | None = None) -> None:
    """Write one network per line, preceded by optional '#' header lines."""
    lines = [f"# {h}\n" for h in header or []]
    lines.extend(f"{net}\n" for net in nets)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)


def parse_options(argv: Sequence[str] | None) -> Options:
    ap = argparse.ArgumentParser(
        description="Convert an iptables list (ACCEPT/DROP rules) into HAProxy '-f' list files usable with 'acl <name> src -f <file>'.")
    _ = ap.add_argument("input", nargs="?", default="firewall.txt",
                        help="iptables list file (default: firewall.txt)")
    _ = ap.add_argument("--outdir", default=None,
                        help="directory for the generated files (default: next to the input)")
    _ = ap.add_argument("--comments", action="store_true",
                        help="write a small '#' provenance header into the .lst files (HAProxy 1.6+ ignores '#' lines in -f files)")
    _ = ap.add_argument("--no-merge", action="store_true",
                        help="do not merge networks into the minimal equivalent set")
    _ = ap.add_argument("--ipv4-only", action="store_true",
                        help="ignore IPv6 (ip6tables) entries")
    ns = ap.parse_args(argv)
    return Options(
        input=cast("str", ns.input),
        outdir=cast("str | None", ns.outdir),
        comments=cast("bool", ns.comments),
        no_merge=cast("bool", ns.no_merge),
        ipv4_only=cast("bool", ns.ipv4_only),
    )


def main(argv: Sequence[str] | None = None) -> int:
    opts = parse_options(argv)

    src_path = Path(opts.input)
    if not src_path.is_file():
        print(f"error: input file not found: {src_path}", file=sys.stderr)
        return 1
    outdir = Path(opts.outdir) if opts.outdir else src_path.parent
    outdir.mkdir(parents=True, exist_ok=True)

    allow: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    block: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    skips: list[tuple[int, str, str]] = []
    filtered_v6 = 0
    total_rules = 0

    text = src_path.read_text(encoding="utf-8-sig", errors="replace")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rule = parse_rule(line)
        if rule is None:
            skips.append((lineno, "not an iptables rule", line))
            continue
        if rule.target is None:
            skips.append((lineno, "no -j/--jump target", line))
            continue
        target = rule.target.upper()
        if target not in ACCEPT_TARGETS and target not in BLOCK_TARGETS:
            skips.append((lineno, f"unsupported target '{rule.target}'", line))
            continue
        if rule.src is None:
            skips.append((lineno, "rule has no -s/--source", line))
            continue
        if rule.dst is not None:
            skips.append((lineno, "rule matches -d destination (not client source); skipped", line))
            continue
        try:
            net = ipaddress.ip_network(rule.src, strict=False)
        except ValueError as exc:
            skips.append((lineno, f"bad network '{rule.src}': {exc}", line))
            continue
        if opts.ipv4_only and net.version == 6:
            filtered_v6 += 1
            continue
        total_rules += 1
        (allow if target in ACCEPT_TARGETS else block).add(net)

    if not allow and not block:
        print(f"error: no usable rules found in {src_path}", file=sys.stderr)
        for lineno, why, line in skips[:20]:
            print(f"  line {lineno}: {why} -- {line}", file=sys.stderr)
        return 1

    overlap = allow & block
    if overlap:
        print(f"warning: {len(overlap)} network(s) appear in BOTH accept and block rules",
              file=sys.stderr)

    print(f"Parsed {total_rules} usable rules from {src_path} ({len(allow)} ACCEPT, {len(block)} DROP/REJECT)")
    if filtered_v6:
        print(f"  filtered out {filtered_v6} IPv6 rule(s) (--ipv4-only)")
    if skips:
        print(f"  skipped {len(skips)} line(s):")
        for skip in skips[:10]:
            print(f"    line {skip[0]}: {skip[1]}")
        if len(skips) > 10:
            print(f"    ... and {len(skips) - 10} more")

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    written: list[WrittenFile] = []
    for kind, nets, fname in (("allow", allow, "haproxy-allow.lst"),
                              ("block", block, "haproxy-block.lst")):
        if not nets:
            continue
        final = sorted(nets, key=sort_key) if opts.no_merge else merge(nets)
        header: list[str] | None = None
        if opts.comments:
            header = [
                f"HAProxy {kind} list generated from {src_path.name} (iptables_to_haproxy.py)",
                f"{len(final)} networks -- {stamp}",
            ]
        path = outdir / fname
        write_lst(path, final, header)
        written.append(WrittenFile(kind=kind, path=path, entries=len(final)))
        if len(final) != len(nets):
            print(f"  {fname}: {len(nets)} unique networks merged into {len(final)} (identical match set)")

    for w in written:
        print(f"Wrote {w.path}  ({w.entries} entries)")

    # ------------------------------------------------------------------ snippet
    snip: list[str] = [
        "# ----------------------------------------------------------------",
        f"# HAProxy snippet generated from: {src_path.name}",
        "# Copy the .lst file(s) next to haproxy.cfg on the server, e.g.:",
    ]
    for w in written:
        snip.extend((
            f"#   sudo cp {w.path.name} /etc/haproxy/",
            f"#   sudo chown root:haproxy /etc/haproxy/{w.path.name}",
            f"#   sudo chmod 640 /etc/haproxy/{w.path.name}",
        ))
    snip.append("# Then put these lines INSIDE the frontend that serves the site:")
    for w in written:
        snip.append("")
        if w.kind == "allow":
            snip.extend((
                "# -- whitelist: deny everything EXCEPT the listed networks --",
                "acl country_allow src -f /etc/haproxy/haproxy-allow.lst",
                "http-request deny if !country_allow",
                "# (to DENY these networks instead, drop the '!': use 'http-request deny if country_allow')",
            ))
        else:
            snip.extend((
                "# -- blocklist: deny the listed networks --",
                "acl country_block src -f /etc/haproxy/haproxy-block.lst",
                "http-request deny if country_block",
            ))
    snip.extend([
        "",
        "# For a 'mode tcp' frontend use 'tcp-request connection reject'",
        "# instead of 'http-request deny'.",
        "#",
        "# Validate + apply (seamless reload, no dropped connections):",
        "#   sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy",
        "# ----------------------------------------------------------------",
    ])

    snippet_path = outdir / "haproxy-snippet.cfg"
    with open(snippet_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(f"{s}\n" for s in snip)

    print()
    print("\n".join(snip))
    print()
    print(f"Wrote {snippet_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
