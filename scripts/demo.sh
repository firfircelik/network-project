#!/usr/bin/env bash
# meshlink end-to-end demo
#
# Phase 1: full-cone NATs  -> direct P2P hole punching must succeed (path=direct)
# Phase 2: symmetric NATs  -> classic hole punching must fail, relay fallback
#                             must keep the tunnel alive (path=relay)
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
TMP="$(mktemp -d)"
KEYA="$TMP/key.a"
KEYB="$TMP/key.b"
PIDS=()

log()  { printf '\033[1;36m[demo]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[demo FAIL]\033[0m %s\n' "$*"; exit 1; }
pass() { printf '\033[1;32m[demo PASS]\033[0m %s\n' "$*"; }

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

# build
if [ ! -x "$BIN/coordinator" ] || [ ! -x "$BIN/relay" ] || [ ! -x "$BIN/natbox" ] || [ ! -x "$BIN/agent" ]; then
  (cd "$ROOT" && make build) || fail "build failed"
fi

launch() { # launch <phase> <name> <binary> [args...]
  local phase="$1" name="$2"; shift 2
  "$@" >"$TMP/$phase.$name.log" 2>&1 &
  PIDS+=($!)
}

stop_all() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  PIDS=()
}

run_phase() {
  local phase="$1" behavior="$2" expect_path="$3"
  log "phase $phase: behavior=$behavior, expecting path=$expect_path"

  launch "$phase" coordinator "$BIN/coordinator" -ctrl 127.0.0.1:19200 -stun 127.0.0.1:19201 -keyfile "$TMP/coord.$phase.key"
  launch "$phase" relay       "$BIN/relay" -addr 127.0.0.1:19205
  launch "$phase" nat1        "$BIN/natbox" -name nat1 -behavior "$behavior" -public 127.0.0.1:19301 -door 127.0.0.1:19401 -host 127.0.0.1:19501
  launch "$phase" nat2        "$BIN/natbox" -name nat2 -behavior "$behavior" -public 127.0.0.1:19302 -door 127.0.0.1:19402 -host 127.0.0.1:19502
  sleep 0.5

  # G3: agents must pin the coordinator's control-plane public key, which the
  # coordinator prints on startup.
  COORD_PUB=""
  for _ in $(seq 1 50); do
    if [ -f "$TMP/$phase.coordinator.log" ]; then
      COORD_PUB="$(grep -oE 'control public key .*: [0-9a-f]{64}' "$TMP/$phase.coordinator.log" | tail -1 | grep -oE '[0-9a-f]{64}')"
      if [ -n "$COORD_PUB" ]; then break; fi
    fi
    sleep 0.1
  done
  [ -n "$COORD_PUB" ] || fail "could not read coordinator control public key"

  launch "$phase" agenta "$BIN/agent" up --name a --keyfile "$KEYA" --data 127.0.0.1:19501 --nat 127.0.0.1:19401 \
         --coordinator 127.0.0.1:19200 --coord-pubkey "$COORD_PUB" \
         --stun 127.0.0.1:19201 --relay 127.0.0.1:19205
  sleep 2

  log "running ping from b to a..."
  "$BIN/agent" ping --name b --keyfile "$KEYB" --data 127.0.0.1:19502 --nat 127.0.0.1:19402 \
         --coordinator 127.0.0.1:19200 --coord-pubkey "$COORD_PUB" \
         --stun 127.0.0.1:19201 --relay 127.0.0.1:19205 \
         --peer a --count 3 --interval 1s 2>&1 | tee "$TMP/ping.$phase.log"
  if grep -q "avg_rtt" "$TMP/ping.$phase.log" && grep -q "path=$expect_path" "$TMP/ping.$phase.log"; then
    pass "phase $phase: ping succeeded over path=$expect_path"
  else
    log "--- operator logs ---"
    for f in "$TMP"/$phase.*.log; do
      if [ -f "$f" ]; then echo "== $f"; tail -6 "$f"; fi
    done
    fail "phase $phase: expected path=$expect_path but ping failed"
  fi
  stop_all
  sleep 0.5
}

# Phase 1: full-cone NATs, hole punching should give a direct path.
run_phase 1 fullcone direct

# Phase 2: symmetric NATs; hole punching fails, the relay path must take over.
run_phase 2 symmetric relay

log "all phases passed 🎉"
exit 0