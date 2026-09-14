#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary="$root/bin/tunnel-lab"
[[ -x "$binary" ]]
work=$(mktemp -d "${TMPDIR:-/tmp}/tunnel-lab-smoke.XXXXXX")
pid=''
cleanup() { if [[ -n "$pid" ]]; then kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; echo "Smoke logs: $work"; }
trap cleanup EXIT
for mode in sip sips vp8 h264; do
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
  args=(-out "$work/$mode" -server "127.0.0.1:$port")
  case "$mode" in
    sip) args+=(-transport sip) ;;
    sips) args+=(-transport sip -sip-tls) ;;
    vp8|h264) args+=(-transport webrtc -codec "$mode") ;;
  esac
  "$binary" init "${args[@]}"
  "$binary" -config "$work/$mode/server.json" -mode echo >"$work/$mode-server.log" 2>&1 &
  pid=$!
  ok=false
  for _ in {1..10}; do
    if "$binary" -config "$work/$mode/client.json" -mode probe -count 100 -size 1280 >"$work/$mode-client.log" 2>&1; then ok=true; break; fi
    sleep 0.2
  done
  if [[ "$ok" != true ]]; then cat "$work/$mode-server.log" "$work/$mode-client.log" >&2; exit 1; fi
  echo "$mode"
  cat "$work/$mode-client.log"
  kill -TERM "$pid"
  wait "$pid"
  pid=''
done
