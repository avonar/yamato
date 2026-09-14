#!/usr/bin/env bash
set -euo pipefail
if [[ $(uname -s) != Linux || $EUID != 0 ]]; then
  echo 'Run as root on Linux; this test creates isolated network namespaces.' >&2
  exit 1
fi
for tool in ip iptables ip6tables python3 ping; do command -v "$tool" >/dev/null; done
binary=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "${1:-./bin/tunnel-lab-linux-amd64}")
transport=${2:-webrtc}
case "$transport" in sip|webrtc|reality) ;; *) echo 'transport must be sip, webrtc or reality' >&2; exit 1 ;; esac
[[ -x "$binary" ]]
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d /tmp/tunnel-lab-netns.XXXXXX)
prefix="tlab-$$"
client="$prefix-c"; server="$prefix-s"; wan="$prefix-w"
cleanup() {
  set +e
  for ns in "$client" "$server" "$wan"; do
    for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -TERM "$pid" 2>/dev/null; done
  done
  sleep 1
  for ns in "$client" "$server" "$wan"; do
    for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -KILL "$pid" 2>/dev/null; done
    ip netns del "$ns" 2>/dev/null
  done
  echo "Logs/configs: $work"
}
trap cleanup EXIT INT TERM
for ns in "$client" "$server" "$wan"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
# Create links inside their namespaces, without temporary host interfaces.
ip -n "$client" link add underlay type veth peer name clientside netns "$server"
ip -n "$server" link add egress type veth peer name serverside netns "$wan"
ip -n "$client" addr add 192.0.2.2/24 dev underlay
ip -n "$server" addr add 192.0.2.1/24 dev clientside
ip -n "$server" addr add 198.18.0.1/24 dev egress
ip -n "$wan" addr add 198.18.0.2/24 dev serverside
ip -n "$server" addr add fdc0:2::1/64 dev egress nodad
ip -n "$wan" addr add fdc0:2::2/64 dev serverside nodad
ip -n "$wan" addr add 203.0.113.10/32 dev lo
ip -n "$wan" addr add 2001:db8::10/128 dev lo nodad
ip -n "$client" link set underlay up
ip -n "$server" link set clientside up
ip -n "$server" link set egress up
ip -n "$wan" link set serverside up
ip -n "$server" route add default via 198.18.0.2
ip -n "$server" -6 route add default via fdc0:2::2
init_args=(-out "$work/config" -server 192.0.2.1:28443 -transport "$transport")
if [[ "$transport" == reality ]]; then init_args+=(-target 127.0.0.1:28444 -sni localhost); fi
"$binary" init "${init_args[@]}"
python3 - "$work/config" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
c = json.loads((p/'client.json').read_text())
c['tun'] = 'tlab0'
c['network']['auto'] = False
(p/'client.json').write_text(json.dumps(c))
s = json.loads((p/'server.json').read_text())
s['network']['egress'] = 'egress'
(p/'server.json').write_text(json.dumps(s))
PY
if [[ "$transport" == reality ]]; then
  command -v openssl >/dev/null
  ip netns exec "$server" openssl s_server -accept 127.0.0.1:28444 \
    -cert "$work/config/cert.pem" -key "$work/config/server-key.pem" \
    -tls1_3 -groups X25519 -alpn h2,http/1.1 -quiet >"$work/target.log" 2>&1 &
fi
ip netns exec "$wan" python3 "$script_dir/netns-fixture.py" >"$work/fixture.log" 2>&1 &
ip netns exec "$server" "$binary" -config "$work/config/server.json" >"$work/server.log" 2>&1 &
ip netns exec "$client" "$binary" -config "$work/config/client.json" >"$work/client.log" 2>&1 &
ready=false
for _ in {1..60}; do
  if ip -n "$client" link show tlab0 >/dev/null 2>&1 && ip -n "$server" addr show tlab0 2>/dev/null | grep -q '10.77.0.1'; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != true ]]; then cat "$work/server.log" "$work/client.log" >&2; exit 1; fi
ip -n "$client" addr add 10.77.0.2/30 dev tlab0
ip -n "$client" addr add fd77::2/126 dev tlab0 nodad
ip -n "$client" link set tlab0 mtu 1280 up
ip -n "$client" route add default dev tlab0
ip -n "$client" -6 route add default dev tlab0
sleep 2
ip netns exec "$client" ping -c 2 -W 3 203.0.113.10
ip netns exec "$client" ping -6 -c 2 -W 3 2001:db8::10
ip netns exec "$client" python3 "$script_dir/netns-fixture.py" --check
echo "PASS: $transport, IPv4/IPv6, ICMP, TCP checksum, UDP, DNS, server default gateway and NAT"
