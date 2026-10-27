#!/usr/bin/env bash
#
# CredGuard overhead benchmark. Run as root from anywhere.
#
# Measures:
#   - average IMDS request time with the agent OFF vs in MONITOR mode
#   - per-call cost of each eBPF hook (kernel bpf_stats: run_time_ns / run_cnt)
#   - agent memory (RSS) and CPU while under load
#
# Usage: sudo bash scripts/bench.sh [requests]   (default 200)
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
N="${1:-200}"
RUN=/tmp/credguard-bench; mkdir -p "$RUN"
URL="http://169.254.169.254/latest/meta-data/instance-id"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
cleanup(){
  sysctl -q -w kernel.bpf_stats_enabled=0 2>/dev/null
  for p in cg imds app; do [ -f "$RUN/$p.pid" ] && kill "$(cat "$RUN/$p.pid")" 2>/dev/null; done
  ip addr del 169.254.169.254/32 dev lo 2>/dev/null
  rm -f "$RUN"/*.pid
}
trap cleanup EXIT

avg_ms(){   # time N sequential requests, print average in ms
  local t0 t1
  t0=$(date +%s%N)
  for _ in $(seq 1 "$N"); do curl -s -o /dev/null "$URL"; done
  t1=$(date +%s%N)
  awk "BEGIN{printf \"%.3f\", ($t1-$t0)/$N/1e6}"
}

ip addr add 169.254.169.254/32 dev lo 2>/dev/null
python3 "$HERE/lab/mock_imds.py" >"$RUN/imds.log" 2>&1 & echo $! >"$RUN/imds.pid"
python3 "$HERE/lab/ssrf_app.py"  >"$RUN/app.log"  2>&1 & echo $! >"$RUN/app.pid"
sleep 1.2

echo "requests per run       : $N"
echo "IMDS avg, agent OFF    : $(avg_ms) ms"

sysctl -q -w kernel.bpf_stats_enabled=1
stdbuf -oL "$HERE/build/credguard" >"$RUN/cg.log" 2>"$RUN/cg.err" & echo $! >"$RUN/cg.pid"
sleep 1.5
echo "IMDS avg, agent MONITOR: $(avg_ms) ms"

# non-IMDS traffic exercises the hook's early-exit path
for _ in $(seq 1 "$N"); do curl -s -o /dev/null http://127.0.0.1:8080/; done
echo "alerts logged          : $(wc -l <"$RUN/cg.log")"

bpftool prog show 2>/dev/null | grep -E 'cg_tcp_sendmsg|cg_connect4' | awk '{
  for (i = 1; i <= NF; i++) {
    if ($i == "name") n = $(i+1)
    if ($i == "run_time_ns") t = $(i+1)
    if ($i == "run_cnt") c = $(i+1)
  }
  if (c > 0) printf "hook %-15s: %.0f ns/call over %d calls\n", n, t/c, c
}'
COLUMNS=200 ps -o rss=,pcpu= -p "$(cat "$RUN/cg.pid")" 2>/dev/null | awk '{printf "agent memory / CPU     : %.1f MB RSS, %s%% CPU\n", $1/1024, $2}'
