#!/usr/bin/env bash
# Adapt a quic-interop-runner checkout to a host whose kernel has no IPv6
# (/proc/sys/net/ipv6 missing), e.g. a Firecracker sandbox or a minimal CI VM.
#
#   quic/interop/no-ipv6/patch-runner.sh [RUNNER_DIR]
#
# What it does, all idempotent:
#   1. Strips the IPv6 subnets, addresses and host aliases from docker-compose.yml
#      (Docker refuses to create a dual-stack bridge without kernel IPv6).
#   2. Drops the `memlock` ulimits, which an unprivileged sandbox can't raise.
#   3. Turns off bridge netfilter. With br_netfilter on, frames bridged between
#      the client and the sim traverse iptables, and Docker 28+'s raw-table rule
#      ("drop traffic to a container IP arriving on another bridge") drops every
#      client packet routed through the sim.
#   4. Builds v6shim.so and preloads it into the server and client containers,
#      so endpoints that bind "[::]:443" or "[::]:0" run on an AF_INET socket
#      instead of dying with EAFNOSUPPORT.
#
# Testcases that need real IPv6 (ipv6, connectionmigration's v6 path) can't pass
# on such a host; treat their results as environment failures.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
RUNNER_DIR="${1:-${RUNNER_DIR:-$REPO_ROOT/../quic-interop-runner}}"
SHIM_DIR="$RUNNER_DIR/.v6shim"
COMPOSE="$RUNNER_DIR/docker-compose.yml"

[ -f "$COMPOSE" ] || { echo "no docker-compose.yml in $RUNNER_DIR" >&2; exit 1; }

mkdir -p "$SHIM_DIR"
gcc -O2 -fPIC -shared -Wall -fno-stack-protector -U_FORTIFY_SOURCE \
    -o "$SHIM_DIR/v6shim.so" "$SCRIPT_DIR/v6shim.c"

[ -f "$COMPOSE.orig" ] || cp "$COMPOSE" "$COMPOSE.orig"

python3 - "$COMPOSE.orig" "$COMPOSE" "$SHIM_DIR" <<'EOF'
import re, sys
src, dst, shim = sys.argv[1:]
s = open(src).read()
s = re.sub(r'\n\s+ipv6_address: [^\n]+', '', s)
s = re.sub(r'\n\s+- "[a-z0-9]+:fd00:[^\n]+"', '', s)
s = re.sub(r'\n\s+- subnet: fd00:[^\n]+', '', s)
s = s.replace('enable_ipv6: true', 'enable_ipv6: false')
s = re.sub(r'\n\s+ulimits:\n\s+memlock: \d+', '', s)
# Preload the shim into both endpoints: either side can be a peer's image
# (our JVM endpoint runs fine under it too).
for role in ('server', 'client'):
    m = re.search(r'\n  %s:\n(?:    .*\n|\n)*?(?=\n  \w)' % role, s)
    block = m.group(0)
    block = block.replace('      - ROLE=%s\n' % role, '      - ROLE=%s\n      - LD_PRELOAD=/v6shim/v6shim.so\n      - ASAN_OPTIONS=verify_asan_link_order=0\n' % role, 1)
    block = block.replace('      - $CERTS:/certs:ro\n', '      - $CERTS:/certs:ro\n      - %s:/v6shim:ro\n' % shim, 1)
    s = s.replace(m.group(0), block)
open(dst, 'w').write(s)
EOF

if [ -w /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    echo 0 > /proc/sys/net/bridge/bridge-nf-call-iptables
    [ -w /proc/sys/net/bridge/bridge-nf-call-ip6tables ] && echo 0 > /proc/sys/net/bridge/bridge-nf-call-ip6tables
fi

echo "patched $COMPOSE (original kept as docker-compose.yml.orig); shim at $SHIM_DIR/v6shim.so"
