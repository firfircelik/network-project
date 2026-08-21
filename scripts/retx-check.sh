#!/usr/bin/env bash
# meshlink wire-level loss/timing checker
#
# Proves a transfer is loss-free on the wire by capturing it N times and
# counting TCP retransmission-analysis events with tshark. This measures the
# "netpoll result" directly instead of inferring it from file hashes: even when
# the bytes arrive intact (a.bin == b.bin), the capture tells us whether the
# kernel/TCP stack had to retransmit, reorder, or drop anything along the way.
#
# Two modes:
#   capture+analyze (default)  run RETX_TRANSFER RETX_RUNS times, capturing on
#                              RETX_IFACE each time, and analyze every capture.
#   --analyze <dir|glob>       analyze existing pcap(s) only (no transfer).
#
# Capture engine: tshark if present, else tcpdump. Analysis needs tshark; if
# it is missing the captures are still written and can be analyzed afterwards
# on a machine where tshark exists (e.g. the VM itself, or `brew install
# wireshark`).
#
# Environment (overridable):
#   RETX_IFACE          interface to capture on (required in capture mode)
#   RETX_RUNS           how many times to run the transfer (default 10)
#   RETX_TRANSFER       command to run in each iteration (eval'd; quote it!)
#                       e.g. 'curl -sfS -o /dev/null https://10.0.0.5/a.bin'
#   RETX_CAP_FILTER     capture (BPF) filter (default "tcp"; narrow it to the
#                       transfer: e.g. "tcp and host 10.0.0.5 and port 443")
#   RETX_CAP_ENGINE     force capture engine: "tshark" or "tcpdump" (default:
#                       tshark if present, else tcpdump)
#   RETX_OUT            directory to keep captures in (default: temp dir,
#                       deleted on exit)
#   RETX_VERBOSE        print per-packet retransmission detail (default 0)
#
# Real (non-loopback) interfaces need root: pass the variables through sudo,
# e.g.  sudo env RETX_IFACE=en0 RETX_TRANSFER='curl -sfS -o /dev/null
# https://host/a.bin' scripts/retx-check.sh
#
# Exit status: 0 when not a single packet showed retransmission/reordering/
# loss indicators across all runs, 1 when they did, when the capture failed,
# or on usage errors.
set -u

log()  { printf '\033[1;36m[retx]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[retx warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[retx FAIL]\033[0m %s\n' "$*"; exit 1; }
pass() { printf '\033[1;32m[retx PASS]\033[0m %s\n' "$*"; }

usage() {
  cat <<'EOF'
usage: scripts/retx-check.sh [--analyze <dir|glob>] [--capture-only] [--help]

  capture+analyze (default)
    RETX_IFACE=<iface> RETX_TRANSFER='<transfer command>' [RETX_RUNS=10] \
      scripts/retx-check.sh

  --analyze <dir|glob>   analyze existing pcap(s) (no transfer, no capture)
  --capture-only         capture only; skip analysis (analysis needs tshark)
  --help                 this message
EOF
}

MODE=capture
ANALYZE_TARGET=""
CAPTURE_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --analyze)  MODE=analyze; ANALYZE_TARGET="${2:-}"; [ -n "$ANALYZE_TARGET" ] || fail "--analyze needs a directory or glob"; shift 2 ;;
    --capture-only) CAPTURE_ONLY=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown option: $1 (see --help)" ;;
  esac
done

# --------------------------------------------------------------------------
# tool discovery
# --------------------------------------------------------------------------
TSHARK="$(command -v tshark 2>/dev/null || true)"
TCPDUMP="$(command -v tcpdump 2>/dev/null || true)"
CAP_ENGINE=""
if [ -n "${RETX_CAP_ENGINE:-}" ]; then
  case "$RETX_CAP_ENGINE" in
    tshark)  [ -n "$TSHARK" ]  || fail "RETX_CAP_ENGINE=tshark but tshark not found"; CAP_ENGINE=tshark ;;
    tcpdump) [ -n "$TCPDUMP" ] || fail "RETX_CAP_ENGINE=tcpdump but tcpdump not found"; CAP_ENGINE=tcpdump ;;
    *) fail "RETX_CAP_ENGINE must be 'tshark' or 'tcpdump' (got '$RETX_CAP_ENGINE')" ;;
  esac
elif [ -n "$TSHARK" ]; then
  CAP_ENGINE=tshark
elif [ -n "$TCPDUMP" ]; then
  CAP_ENGINE=tcpdump
fi

if [ "$MODE" = "analyze" ] || [ "$CAPTURE_ONLY" -eq 0 ]; then
  [ -n "$TSHARK" ] || fail "analysis requires tshark (brew install wireshark); can't continue in mode=$MODE"
fi
if [ "$MODE" = "capture" ] && [ -z "$CAP_ENGINE" ]; then
  fail "no capture engine found (need tshark or tcpdump)"
fi

# --------------------------------------------------------------------------
# single-pass tshark analysis of one capture
# fields: frame.number frame.len frame.time_epoch tcp.stream
#         tcp.analysis.retransmission | fast | spurious | duplicate_ack
#         | out-of-order | lost_segment | ack_rtt
# --------------------------------------------------------------------------
ANALYZE_FLDS=(
  -e frame.number -e frame.len -e frame.time_epoch -e tcp.stream
  -e tcp.analysis.retransmission -e tcp.analysis.fast_retransmission
  -e tcp.analysis.spurious_retransmission -e tcp.analysis.duplicate_ack
  -e tcp.analysis.out_of_order -e tcp.analysis.lost_segment -e tcp.analysis.ack_rtt
)

# prints a single tab-separated line:
#   frames bytes secs retx fast spur dupack ooo lost rttmin_ms rttavg_ms rttmax_ms streams_retx
analyze_pcap() {
  local pcap="$1" out
  out="$("$TSHARK" -r "$pcap" -T fields "${ANALYZE_FLDS[@]}" 2>/dev/null | awk -F'\t' '
    {
      n++; b = b + $2;
      if (min_t == "") { min_t = $3 }; max_t = $3;
      if ($5 != "") { retx++; if (!seen[$4]++) rstream = rstream "," $4 }
      if ($6 != "") fast++;
      if ($7 != "") spur++;
      if ($8 != "") dupack++;
      if ($9 != "") ooo++;
      if ($10 != "") lost++;
      if ($11 != "") { rn++; rs = rs + $11; if (rmin == "" || $11 < rmin) rmin = $11; if ($11 > rmax) rmax = $11 }
    }
    END {
      rmin = (rn ? sprintf("%.3f", rmin*1000) : "");
      ravg = (rn ? sprintf("%.3f", rs/rn*1000) : "");
      rmax = (rn ? sprintf("%.3f", rmax*1000) : "");
      rstream = (rstream != "" ? substr(rstream, 2) : "");
      printf "%d\t%d\t%.3f\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n",
        n, b, (max_t - min_t), retx, fast, spur, dupack, ooo, lost, rmin, ravg, rmax, rstream
    }' 2>/dev/null)"
  IFS=$'\t' read -r t_frames t_bytes t_secs t_retx t_fast t_spur t_dupack t_ooo t_lost t_rttmin t_rttavg t_rttmax t_streams <<<"$out"
}

print_header() {
  printf '%-4s %7s %6s %8s  %4s %4s %4s %4s %4s %4s  %4s\n' \
    run wall cap MB retx fast spur dup ooo lost rtt_ms
}

print_row() { # run wall cap mb retx fast spur dup ooo lost rtt
  printf '%-4s %7.1f %6.2f %8.2f  %4s %4s %4s %4s %4s %4s  %4s\n' "$@"
}

mb() { awk -v b="$1" 'BEGIN{printf "%.2f", b/1048576}'; }

# precise wall clock: python3 if available, GNU date, else integer seconds
now() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(repr(time.time()))'
  elif date +%s.%N >/dev/null 2>&1; then
    date +%s.%N
  else
    date +%s
  fi
}

# --------------------------------------------------------------------------
# mode: analyze existing captures
# --------------------------------------------------------------------------
if [ "$MODE" = "analyze" ]; then
  PCAPS=()
  if [ -d "$ANALYZE_TARGET" ]; then
    while IFS= read -r f; do PCAPS+=("$f"); done < <(find "$ANALYZE_TARGET" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) | sort)
  else
    # shellcheck disable=SC2012,SC2086  # glob target is intentional; ls gives stable ordering
    while IFS= read -r f; do PCAPS+=("$f"); done < <(ls -1 $ANALYZE_TARGET 2>/dev/null | sort)
  fi
  [ "${#PCAPS[@]}" -gt 0 ] || fail "no pcap files found in/at '$ANALYZE_TARGET'"

  echo "Analyzing ${#PCAPS[@]} capture(s) with $("$TSHARK" --version | head -1)..."
  print_header
  tot_retx=0; tot_fast=0; tot_spur=0; tot_dup=0; tot_ooo=0; tot_lost=0; tot_frames=0
  for p in "${PCAPS[@]}"; do
    analyze_pcap "$p"
    printf -v mbs "%s" "$(mb "$t_bytes")"
    print_row "$(basename "$p")" 0 "$t_secs" "$mbs" "$t_retx" "$t_fast" "$t_spur" "$t_dupack" "$t_ooo" "$t_lost" "${t_rttavg:+${t_rttavg}ms}"
    tot_retx=$((tot_retx+t_retx)); tot_fast=$((tot_fast+t_fast)); tot_spur=$((tot_spur+t_spur))
    tot_dup=$((tot_dup+t_dupack)); tot_ooo=$((tot_ooo+t_ooo)); tot_lost=$((tot_lost+t_lost))
    tot_frames=$((tot_frames+t_frames))
    if [ "${RETX_VERBOSE:-0}" = "1" ]; then
      echo "  rtt(min/avg/max): ${t_rttmin:-n/a}/${t_rttavg:-n/a}/${t_rttmax:-n/a} ms · retx streams: ${t_streams:-none}"
      "$TSHARK" -r "$p" -Y 'tcp.analysis.retransmission' -T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.dstport -e tcp.analysis.retransmission 2>/dev/null | sed 's/^/    /'
    fi
  done
  echo "---"
  echo "totals: frames=$tot_frames retx=$tot_retx fast=$tot_fast spur=$tot_spur dupAck=$tot_dup ooo=$tot_ooo lost=$tot_lost"
  if [ $((tot_retx+tot_dup+tot_ooo+tot_lost)) -eq 0 ]; then
    pass "clean: zero retransmission/reordering/loss indicators across all captures"
    exit 0
  fi
  warn "at least one capture shows TCP loss indicators — check the rows above"
  exit 1
fi

# --------------------------------------------------------------------------
# mode: capture (+ analyze unless --capture-only)
# --------------------------------------------------------------------------
RUNS="${RETX_RUNS:-10}"
IFACE="${RETX_IFACE:-}"
CAP_FILTER="${RETX_CAP_FILTER:-tcp}"
TRANSFER="${RETX_TRANSFER:-}"

[ -n "$IFACE" ]        || fail "RETX_IFACE is required (interface to capture on)"
[ -n "$TRANSFER" ]     || fail "RETX_TRANSFER is required (e.g. 'curl -sfS -o /dev/null https://host/a.bin')"
case "$RUNS" in *[!0-9]*|"") fail "RETX_RUNS must be a number (got '$RUNS')" ;; esac
[ "$RUNS" -ge 1 ]      || fail "RETX_RUNS must be >= 1"

OUT_DIR="${RETX_OUT:-$(mktemp -d)}"
mkdir -p "$OUT_DIR"
if [ -z "${RETX_OUT:-}" ]; then
  trap 'rm -rf "$OUT_DIR"' EXIT
fi

[ "$(id -u)" -eq 0 ] || warn "packet capture usually needs root; use sudo if the capture picks up nothing"
log "interface=$IFACE runs=$RUNS filter='$CAP_FILTER'"
log "transfer: $TRANSFER"
log "captures will be written to $OUT_DIR"

if [ -n "$TSHARK" ] && [ "$CAPTURE_ONLY" -eq 0 ]; then
  [ "$CAP_ENGINE" = "tshark" ] || log "using tcpdump for capture (analysis still via tshark)"
else
  warn "--capture-only: no analysis will be done; re-analyze later with:"
  warn "  scripts/retx-check.sh --analyze '$OUT_DIR'"
fi

tot_retx=0; tot_fast=0; tot_spur=0; tot_dup=0; tot_ooo=0; tot_lost=0; tot_frames=0; tot_wall=0; tot_bytes=0
tot_cap=0
FAILED_RUNS=0

if [ "$CAPTURE_ONLY" -eq 1 ]; then
  log "capture-only mode: writing $RUNS capture(s) to $OUT_DIR (analyze later with --analyze)"
else
  print_header
fi

for i in $(seq 1 "$RUNS"); do
  cap="$OUT_DIR/run-$i.pcapng"
  # start capture
  if [ "$CAP_ENGINE" = "tshark" ]; then
    "$TSHARK" -l -i "$IFACE" -f "$CAP_FILTER" -w "$cap" >/dev/null 2>&1 & CAP_PID=$!
  else
    "$TCPDUMP" -i "$IFACE" -w "$cap" "$CAP_FILTER" >/dev/null 2>&1 & CAP_PID=$!
  fi
  sleep 0.5
  kill -0 "$CAP_PID" 2>/dev/null || fail "capture engine failed to start (permissions? interface '$IFACE'?)"

  # run the transfer (subshell so an `exit` inside RETX_TRANSFER can't kill the harness)
  w0="$(now)"
  ( eval "$TRANSFER" ) 2>"$OUT_DIR/run-$i.transfer.err"
  rc=$?
  w1="$(now)"
  wall="$(awk -v a="$w0" -v b="$w1" 'BEGIN{printf "%.3f", b-a}')"

  # stop capture (SIGINT -> graceful finalize)
  kill -INT "$CAP_PID" 2>/dev/null
  wait "$CAP_PID" 2>/dev/null

  [ "$rc" -eq 0 ] || { warn "run $i: transfer exited with status $rc (stderr below)"; FAILED_RUNS=$((FAILED_RUNS+1)); }
  [ "$rc" -ne 0 ] && sed 's/^/    /' "$OUT_DIR/run-$i.transfer.err" 2>/dev/null

  if [ "$CAPTURE_ONLY" -eq 0 ]; then
    analyze_pcap "$cap"
    printf -v mbs "%s" "$(mb "$t_bytes")"
    rtavg="${t_rttavg:+${t_rttavg}ms}"; rtavg="${rtavg:-n/a}"
    print_row "$i" "$wall" "$t_secs" "$mbs" "$t_retx" "$t_fast" "$t_spur" "$t_dupack" "$t_ooo" "$t_lost" "$rtavg"
    tot_retx=$((tot_retx+t_retx)); tot_fast=$((tot_fast+t_fast)); tot_spur=$((tot_spur+t_spur))
    tot_dup=$((tot_dup+t_dupack)); tot_ooo=$((tot_ooo+t_ooo)); tot_lost=$((tot_lost+t_lost))
    tot_frames=$((tot_frames+t_frames)); tot_bytes=$((tot_bytes+t_bytes))
    tot_cap="$(awk -v a="$tot_cap" -v v="$t_secs" 'BEGIN{printf "%.3f", a+v}')"
    tot_wall="$(awk -v a="$tot_wall" -v v="$wall" 'BEGIN{printf "%.3f", a+v}')"
    if [ "${RETX_VERBOSE:-0}" = "1" ]; then
      echo "  run $i rtt(min/avg/max): ${t_rttmin:-n/a}/${t_rttavg:-n/a}/${t_rttmax:-n/a} ms · retx streams: ${t_streams:-none}"
      "$TSHARK" -r "$cap" -Y 'tcp.analysis.retransmission' -T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.dstport -e tcp.analysis.retransmission 2>/dev/null | sed 's/^/    /'
    fi
  else
    echo "run $i  capture written: $cap (transfer wall time ${wall}s)"
  fi
done

if [ "$CAPTURE_ONLY" -eq 0 ] && [ "$RUNS" -gt 0 ]; then
  if [ "$FAILED_RUNS" -gt 0 ]; then
    warn "transfer failed in $FAILED_RUNS of $RUNS run(s); a failed transfer must not be read as 'clean'"
    exit 1
  fi
  avg_wall="$(awk -v s="$tot_wall" -v n="$RUNS" 'BEGIN{printf "%.2f", s/n}')"
  avg_cap="$(awk -v s="$tot_cap" -v n="$RUNS" 'BEGIN{printf "%.2f", s/n}')"
  avg_mb="$(awk -v b="$tot_bytes" -v n="$RUNS" 'BEGIN{printf "%.2f", b/1048576/n}')"
  echo "---"
  echo "totals (n=$RUNS): frames=$tot_frames retx=$tot_retx fast=$tot_fast spur=$tot_spur dupAck=$tot_dup ooo=$tot_ooo lost=$tot_lost"
  echo "avgs: wall=${avg_wall}s cap=${avg_cap}s xfer=${avg_mb} MB"
  if [ $((tot_retx+tot_dup+tot_ooo+tot_lost)) -eq 0 ]; then
    pass "clean across all $RUNS runs: zero retransmission/reordering/loss indicators (netpoll result measured, not inferred)"
    exit 0
  fi
  warn "at least one run shows TCP loss indicators — inspect the rows and the capture files in $OUT_DIR"
  exit 1
fi

if [ "$FAILED_RUNS" -gt 0 ]; then
  warn "transfer failed in $FAILED_RUNS of $RUNS run(s); captures are still in $OUT_DIR"
  exit 1
fi

exit 0