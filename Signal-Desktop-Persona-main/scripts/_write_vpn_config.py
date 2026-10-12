#!/usr/bin/env python3
"""Rewrite the client config to talk to a VM's own TLS proxy over the VPN.

Split out of personas-remote-setup.sh because embedding Python inside a shell
heredoc inside another heredoc is how quoting bugs are born.
"""
import json
import os
import sys

cfg_path = sys.argv[1]
host = os.environ["HOSTNAME_ARG"]
ca = os.environ["CA_PEM"]

with open(cfg_path) as f:
    cfg = json.load(f)

base = f"https://{host}:8443"
cfg["serverUrl"] = base
cfg["storageUrl"] = base
# All three CDN slots: the test server stands in for every CDN.
cfg["cdn"] = {"0": base, "2": base, "3": base}
# Required here, unlike the public-proxy path: the VM presents its OWN self-signed
# certificate, and Node's `ca` option REPLACES the trust store rather than adding to
# it, so this must be exactly that CA.
cfg["certificateAuthority"] = ca

with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

print(f"  serverUrl / storageUrl / cdn -> {base}")
print(f"  certificateAuthority <- the VM's CA ({len(ca)} chars)")
