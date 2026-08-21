#!/usr/bin/env bash
# meshlink LAN demo — "iki cihaz birbirini görür mü?" sorusunun anında cevabı
#
# VPS gerekmez: koordinatör + relay bu makinede çalışır; agent'lar gerçek LAN/
# Wi-Fi arayüzüne bağlanır ve gerçek paketler üzerinden path=direct doğrulanır.
#
# Tek makine modu (varsayılan): agent a bir daemon olarak çalışır, ping işlemi
# agent b rolünde LAN üzerinden a'ya ping atar -> path=direct.
#
# İki cihaz modu: betiğin basacağı komutları ikinci cihaza kopyala (aynı Wi-Fi/
# LAN), sonra aynı betiği sadece cihaz B'de de doğrulayabilirsin; eğer LAN_IP
# ve limanlar iki makinede de erişilebilirse path=direct görürsün.
#
# Ortam değişkenleri (üzerine yazılabilir):
#   LAN_IP    bu makinenin LAN adresi (otomatik algılanır)
#   A_DATA    agent a'nın veri soketi (varsayılan 0.0.0.0:19501)
#   B_DATA    ping işleminin veri soketi (varsayılan 0.0.0.0:19502)
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
TMP="$(mktemp -d)"
KEYA="$TMP/key.a"
KEYB="$TMP/key.b"
PIDS=()

log()  { printf '\033[1;36m[lan-demo]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[lan-demo FAIL]\033[0m %s\n' "$*"; exit 1; }
pass() { printf '\033[1;32m[lan-demo PASS]\033[0m %s\n' "$*"; }

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

# Detect LAN IP
detect_lan_ip() {
  case "$(uname -s)" in
    Darwin)
      ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true
      ;;
    Linux)
      hostname -I 2>/dev/null | awk '{print $1}'
      ;;
    *)
      return 1
      ;;
  esac
}
LAN_IP="${LAN_IP:-$(detect_lan_ip)}"
case "${LAN_IP:-}" in
  *.*.*.*) ;;
  *) fail "could not detect a LAN IPv4 address; set LAN_IP (e.g. LAN_IP=192.168.1.40 ./scripts/lan-demo.sh)" ;;
esac
A_DATA="${A_DATA:-0.0.0.0:19501}"
B_DATA="${B_DATA:-0.0.0.0:19502}"

log "LAN IP: $LAN_IP (override with LAN_IP=...)"
log "agent a data: $A_DATA · agent b data: $B_DATA"

# build
if [ ! -x "$BIN/coordinator" ] || [ ! -x "$BIN/relay" ] || [ ! -x "$BIN/agent" ]; then
  (cd "$ROOT" && make build) || fail "build failed"
fi

launch() { # launch <name> <binary> [args...]
  local name="$1"; shift
  "$@" >"$TMP/$name.log" 2>&1 &
  PIDS+=($!)
}

log "starting coordinator + relay on 0.0.0.0 ..."
launch coordinator "$BIN/coordinator" -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile "$TMP/coord.key"
launch relay       "$BIN/relay" -addr 0.0.0.0:19205
sleep 0.3

COORD_PUB=""
for _ in $(seq 1 50); do
  if [ -f "$TMP/coordinator.log" ]; then
    COORD_PUB="$(grep -oE 'control public key .*: [0-9a-f]{64}' "$TMP/coordinator.log" | tail -1 | grep -oE '[0-9a-f]{64}')"
    if [ -n "$COORD_PUB" ]; then break; fi
  fi
  sleep 0.1
done
[ -n "$COORD_PUB" ] || fail "could not read coordinator control public key"

log "starting agent a (daemon)..."
launch agenta "$BIN/agent" up --name a --keyfile "$KEYA" --data "$A_DATA" \
       --coordinator "$LAN_IP:19200" --coord-pubkey "$COORD_PUB" \
       --stun "$LAN_IP:19201" --relay "$LAN_IP:19205"
sleep 1.5

# status: makinece okunabilir anlık görüntü (yeni 'status' alt komutu).
# Ayrı bir kimlik (probe) kullanır, böylece daemon 'a'nın kaydına dokunmaz.
"$BIN/agent" status --name probe --keyfile "$TMP/key.probe" --data 0.0.0.0:19511 \
       --coordinator "$LAN_IP:19200" --coord-pubkey "$COORD_PUB" \
       --stun "$LAN_IP:19201" --relay "$LAN_IP:19205" 2>&1 | tee "$TMP/status.log"

log "running ping from b to a over the LAN..."
"$BIN/agent" ping --name b --keyfile "$KEYB" --data "$B_DATA" \
       --coordinator "$LAN_IP:19200" --coord-pubkey "$COORD_PUB" \
       --stun "$LAN_IP:19201" --relay "$LAN_IP:19205" \
       --peer a --count 3 --interval 1s 2>&1 | tee "$TMP/ping.log"
if grep -q "avg_rtt" "$TMP/ping.log" && grep -q "path=direct" "$TMP/ping.log"; then
  pass "LAN ping succeeded over path=direct (no NAT, no VPS)"
else
  log "--- operator logs ---"
  for f in "$TMP"/agenta.log "$TMP"/relay.log; do
    if [ -f "$f" ]; then echo "== $f"; tail -6 "$f"; fi
  done
  fail "expected path=direct over the LAN but ping failed"
fi

cat <<EOF

────────────────────────────────────────────────────────────────
 TİP İKİ CİHAZ — paylaş bu komutları (aynı Wi-Fi/LAN):
────────────────────────────────────────────────────────────────

 # Bu makinede (cihaz A, daemon):
 bin/agent up --name a --keyfile key.a --data "$A_DATA" \\
   --coordinator "$LAN_IP:19200" --coord-pubkey "$COORD_PUB" \\
   --stun "$LAN_IP:19201" --relay "$LAN_IP:19205"

 # İkinci cihazda (cihaz B, tek seferlik ping):
 bin/agent ping --name b --keyfile key.b --data "$B_DATA" \\
   --coordinator "$LAN_IP:19200" --coord-pubkey "$COORD_PUB" \\
   --stun "$LAN_IP:19201" --relay "$LAN_IP:19205" \\
   --peer a --count 3 --interval 1s

 # Canlı gösterge (cihaz B):
 bin/agent tui --name b --keyfile key.b --data "$B_DATA" \\
   --coordinator "$LAN_IP:19200" --coord-pubkey "$COORD_PUB" \\
   --stun "$LAN_IP:19201" --relay "$LAN_IP:19205"
────────────────────────────────────────────────────────────────
EOF

exit 0