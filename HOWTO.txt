IPTABLES -> HAPROXY
===========================================

Files
  firewall.txt                 source list (iptables rules, e.g. an IP2Location country list)
  iptables_to_haproxy.py       converter (writes the two files below)
  haproxy-allow.lst            generated: networks to allow (referenced by HAProxy)
  haproxy-snippet.cfg          ready-to-paste haproxy.cfg lines
  test_iptables_to_haproxy.py  QA suite (~15 s, offline) - must pass before deploying

Generate / refresh the list
  1. save the new list over firewall.txt
  2. python iptables_to_haproxy.py firewall.txt
  3. scp haproxy-allow.lst to the server:  /etc/haproxy/
  4. sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy

HAProxy config (inside the frontend that serves the site, mode http)
  acl country_allow src -f /etc/haproxy/haproxy-allow.lst
  http-request deny if !country_allow
  # to DENY these networks instead (blocklist), drop the "!":
  #   http-request deny if country_allow
  # mode tcp frontend: use "tcp-request connection reject" instead

Server file permissions (once)
  sudo chown root:haproxy /etc/haproxy/haproxy-allow.lst
  sudo chmod 640 /etc/haproxy/haproxy-allow.lst

Converter options (all optional)
  --comments    add a small #-header to the generated .lst
  --no-merge    don't merge networks (dedupe only)
  --ipv4-only   skip ip6tables entries
  --outdir DIR  write the output files to DIR instead of this folder
  (DROP/REJECT rules, if any, go to haproxy-block.lst automatically.)

Notes
  - iptables ACCEPT rules become an allow-list (whitelist). Refresh monthly.
  - The reload is seamless; if "haproxy -c" fails, the reload aborts and the
    old config keeps running.
  - Full details: docstring at the top of iptables_to_haproxy.py.
