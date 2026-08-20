#!/usr/bin/env bash
# meshlink TUN end-to-end demo (Faz 4 / G6 canlı doğrulama)
#
# Opens two TUN interfaces (two agents on one host), forces the ICMP traffic
# through the encrypted tunnel with host routes, and pings the far overlay
# address. Requires root for /dev/utunN / /dev/net/tun and route setup.
#
# Traffic flow:
#   ping host -> utun9 (agent a) -> [Noise E2E] -> agent b -> utun10 -> kernel
#   kernel ICMP reply -> utun10 (agent b) -> [Noise E2E] -> agent a -> utun9
#
# The kernel only answers the echo because utun10 owns 10.62.0.2; without the
# two /32 host routes the kernel would shortcut everything locally and the
# tunnel would never be exercised.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"

log()  { printf '\033[1;36m[tun-demo]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[tun-demo FAIL]\033[0m %s\n' "$*"; exit 1; }
pass() { printf '\033[1;32m[tun-demo PASS]\033[0m %s\n' "$*"; }

# Re-exec under sudo so the whole demo (recognized devices + routes) is a
# single privileged transaction, carrying caller overrides through env.
if [ "$(id -u)" -ne 0 ]; then
  printf '\033[1;36m[tun-demo]\033[0m re-execing as root (sudo)...\n'
  # sudo(8) drops the environment by default; hand the overrides we care
  # about explicitly (empty values fall back to defaults in the root process).
  exec sudo env \
    TUN_A="${TUN_A:-}"    TUN_B="${TUN_B:-}" \
    IP_A="${IP_A:-}"      IP_B="${IP_B:-}" \
    PEER_A="${PEER_A:-}"  PEER_B="${PEER_B:-}" \
    "$0" "$@"
fi

# The scratch dir is created only after the exec so the unprivileged copy of
# this script never leaks a temp dir behind.
TMP="$(mktemp -d)"
KEYA="$TMP/key.a"
KEYB="$TMP/key.b"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

# pick_utun prints the lowest utun index that is not currently in use and not
# already handed out by this script. Excludes are passed as additional args.
pick_utun() {
  local used skip i
  used="$(ifconfig -a 2>/dev/null | grep -oE '^utun[0-9]+' | sed 's/utun//' | tr '\n' ' ')"
  used="$used $*"
  for i in $(seq 0 63); do
    case " $used " in
      *" $i "*) ;;
      *) echo "$i"; return 0 ;;
    esac
  done
  return 1
}

OS="$(uname -s)"
case "$OS" in
  Darwin)
    if [ -z "${TUN_A:-}" ]; then
      A_IDX="$(pick_utun)" || fail "no free utun index for agent A"
      TUN_A="utun$A_IDX"
    fi
    if [ -z "${TUN_B:-}" ]; then
      B_IDX="$(pick_utun "${TUN_A#utun}")" || fail "no second free utun index for agent B"
      TUN_B="utun$B_IDX"
    fi
    ;;
  Linux)
    TUN_A="${TUN_A:-meshlink_a}"
    TUN_B="${TUN_B:-meshlink_b}"
    ;;
  *)
    fail "unsupported OS for TUN demo: $OS"
    ;;
esac
IP_A="${IP_A:-10.61.0.1}"
IP_B="${IP_B:-10.62.0.2}"
PEER_B="${PEER_B:-$IP_B}"
PEER_A="${PEER_A:-$IP_A}"
log "using $TUN_A / $TUN_B on $OS ($IP_A / $IP_B)"

# build
if [ ! -x "$BIN/coordinator" ] || [ ! -x "$BIN/agent" ]; then
  (cd "$ROOT" && make build) || fail "build failed"
fi

launch() { # launch <name> <binary> [args...]
  local name="$1"; shift
  "$@" >"$TMP/$name.log" 2>&1 &
  PIDS+=($!)
}

log "starting coordinator..."
launch coordinator "$BIN/coordinator" -ctrl 127.0.0.1:19200 -stun 127.0.0.1:19201 -keyfile "$TMP/coord.key"

COORD_PUB=""
for _ in $(seq 1 50); do
  if [ -f "$TMP/coordinator.log" ]; then
    COORD_PUB="$(grep -oE 'control public key .*: [0-9a-f]{64}' "$TMP/coordinator.log" | tail -1 | grep -oE '[0-9a-f]{64}')"
    if [ -n "$COORD_PUB" ]; then break; fi
  fi
  sleep 0.1
done
[ -n "$COORD_PUB" ] || fail "could not read coordinator control public key"

log "starting agent a ($TUN_A / $IP_A -> peer b=$PEER_B)..."
launch agenta "$BIN/agent" up --name a --keyfile "$KEYA" --data 127.0.0.1:19501 \
       --coordinator 127.0.0.1:19200 --coord-pubkey "$COORD_PUB" \
       --stun 127.0.0.1:19201 --relay "" \
       --tun "$TUN_A" --tun-ip "$IP_A" --tun-peer "b=$PEER_B"

log "starting agent b ($TUN_B / $IP_B -> peer a=$PEER_A)..."
launch agentb "$BIN/agent" up --name b --keyfile "$KEYB" --data 127.0.0.1:19502 \
       --coordinator 127.0.0.1:19200 --coord-pubkey "$COORD_PUB" \
       --stun 127.0.0.1:19201 --relay "" \
       --tun "$TUN_B" --tun-ip "$IP_B" --tun-peer "a=$PEER_A"

wait_for_dev() { # wait_for_dev <dev>
  local dev="$1" i
  case "$OS" in
    Darwin) for i in $(seq 1 50); do ifconfig "$dev" >/dev/null 2>&1 && return 0; sleep 0.1; done ;;
    Linux)  for i in $(seq 1 50); do ip link show "$dev" >/dev/null 2>&1 && return 0; sleep 0.1; done ;;
  esac
  return 1
}

log "configuring interfaces + host routes..."
case "$OS" in
  Darwin)
    wait_for_dev "$TUN_A" || fail "agent a never opened $TUN_A"
    wait_for_dev "$TUN_B" || fail "agent b never opened $TUN_B"
    ifconfig "$TUN_A" inet "$IP_A"/24 up
    ifconfig "$TUN_B" inet "$IP_B"/24 up
    route add -host "$PEER_B" -interface "$TUN_A" 2>"$TMP/route-a.err" || true
    route add -host "$PEER_A" -interface "$TUN_B" 2>>"$TMP/route-b.err" || true
    log "routes:"; netstat -rn | grep -E "$PEER_B|$PEER_A" || true
    ;;
  Linux)
    wait_for_dev "$TUN_A" || fail "agent a never opened $TUN_A"
    wait_for_dev "$TUN_B" || fail "agent b never opened $TUN_B"
    ip addr add "$IP_A"/24 dev "$TUN_A"
    ip link set "$TUN_A" up
    ip addr add "$IP_B"/24 dev "$TUN_B"
    ip link set "$TUN_B" up
    ip route add "$PEER_B"/32 dev "$TUN_A" 2>"$TMP/route-a.err" || true
    ip route add "$PEER_A"/32 dev "$TUN_B" 2>>"$TMP/route-b.err" || true
    log "routes:"; ip route show | grep -E "$PEER_B|$PEER_A" || true
    ;;
esac

# Give the sessions a moment to fully establish (registration + handshake).
sleep 2
log "pinging $PEER_B through the tunnel (expect no loss)..."
PING_OUT="$TMP/ping.log"
set +e
ping -c 3 -i 1 "$PEER_B" 2>&1 | tee "$PING_OUT"
RC="${PIPESTATUS[0]}"

if [ "$RC" -eq 0 ] && grep -qE '0(\.[0]+)?% packet loss' "$PING_OUT"; then
  log "agent a tunnel counters (PktsIn/PktsRouted/PktsDropped) live in tun.Router;"
  log "see docs/TUN.md for the route layer."
  for f in "$TMP"/agenta.log "$TMP"/agentb.log; do
    echo "== $f"; tail -3 "$f"; done
  pass "ICMP roundtrip through the encrypted tunnel succeeded"
else
  log "--- operator logs ---"
  for f in "$TMP"/*.log; do
    if [ -f "$f" ]; then echo "== $f"; tail -8 "$f"; fi
  done
  fail "tunnel ping failed; check $TMP logs"
fi

exit 0