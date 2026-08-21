#!/usr/bin/env bash
# meshlink — terminalde canlı çalıştırma scripti
#
# HOST (tam stack kurulur + canlı TUI açılır):
#   ./scripts/run-mesh.sh
#     coordinator + relay + agent a başlatır, sonra canlı TUI'yi (b perspektifi)
#     açar. Çıktıda İKİNCİ cihaz için hazır client komutu basılır.
#
# CLIENT (ikinci cihaz, HOST makineye bağlanır):
#   HOST=<host-lan-ip> COORD_PUB=<hex> ./scripts/run-mesh.sh
#     sadece agent b'yi başlatır ve canlı TUI'yi açar.
#
# Çıkmak için TUI içinde q veya Ctrl+C -> arkadaki servisler otomatik kapanır.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
TMP="$(mktemp -d)"
KEYA="$TMP/key.a"; KEYB="$TMP/key.b"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

launch(){ local name=$1; shift; "$@" >"$TMP/$name.log" 2>&1 & PIDS+=($!); }

detect_lan_ip(){
  case "$(uname -s)" in
    Darwin) ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true ;;
    Linux)  hostname -I 2>/dev/null | awk '{print $1}' ;;
  esac
}

[ -x "$BIN/coordinator" ] && [ -x "$BIN/relay" ] && [ -x "$BIN/agent" ] || \
  (cd "$ROOT" && make build) || { echo "build failed"; exit 1; }

if [ -z "${HOST:-}" ]; then
  # ===================== HOST MODU =====================
  LAN_IP="${LAN_IP:-$(detect_lan_ip)}"
  case "$LAN_IP" in *.*.*.*) ;; *) echo "LAN IP algılanamadı; LAN_IP=192.168.x.x ver"; exit 1;; esac
  echo "▶ HOST modu · LAN_IP=$LAN_IP"

  launch coordinator "$BIN/coordinator" -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile "$TMP/coord.key"
  launch relay       "$BIN/relay" -addr 0.0.0.0:19205
  sleep 0.4
  COORD_PUB="$(grep -oE 'control public key .*: [0-9a-f]{64}' "$TMP/coordinator.log" | tail -1 | grep -oE '[0-9a-f]{64}')"
  [ -n "$COORD_PUB" ] || { echo "coord pubkey okunamadı:"; cat "$TMP/coordinator.log"; exit 1; }

  launch agenta "$BIN/agent" up --name a --keyfile "$KEYA" --data 0.0.0.0:19501 \
        --coordinator "$LAN_IP:19200" --coord-pubkey "$COORD_PUB" \
        --stun "$LAN_IP:19201" --relay "$LAN_IP:19205"
  sleep 1.5

  cat <<EOF

────────────────── İKİNCİ CİHAZ (client) İÇİN KOPYALA ──────────────────
  HOST=$LAN_IP COORD_PUB=$COORD_PUB ./scripts/run-mesh.sh

  # (istersen kalıcı daemon + ayrı bir terminalde TUI):
  bin/agent up --name b --keyfile key.b --data 0.0.0.0:19502 \\
    --coordinator $LAN_IP:19200 --coord-pubkey $COORD_PUB \\
    --stun $LAN_IP:19201 --relay $LAN_IP:19205
  bin/agent tui --name b --keyfile key.b --data 0.0.0.0:19502 \\
    --coordinator $LAN_IP:19200 --coord-pubkey $COORD_PUB \\
    --stun $LAN_IP:19201 --relay $LAN_IP:19205
────────────────────────────────────────────────────────────────────────
EOF
  echo "▶ Canlı TUI açılıyor (b perspektifi). Çıkmak için q / Ctrl+C"
  "$BIN/agent" tui --name b --keyfile "$KEYB" --data 0.0.0.0:19502 \
        --coordinator "$LAN_IP:19200" --coord-pubkey "$COORD_PUB" \
        --stun "$LAN_IP:19201" --relay "$LAN_IP:19205"
else
  # ===================== CLIENT MODU =====================
  [ -n "${COORD_PUB:-}" ] || { echo "COORD_PUB=<hex> gerekli (HOST makinenin coord.log'ından)"; exit 1; }
  echo "▶ CLIENT modu · HOST=$HOST"
  echo "▶ Canlı TUI açılıyor (b perspektifi, HOST=$HOST). Çıkmak için q / Ctrl+C"
  "$BIN/agent" tui --name b --keyfile "$KEYB" --data 0.0.0.0:19502 \
        --coordinator "$HOST:19200" --coord-pubkey "$COORD_PUB" \
        --stun "$HOST:19201" --relay "$HOST:19205"
fi
