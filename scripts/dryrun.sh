#!/usr/bin/env bash
#
# Timed rehearsal of the two-terminal live demo (DEMO.md, Option B).
#
# It plays both terminals for you: Terminal 1 (lab + agent) runs in the
# background writing alerts to a log; Terminal 2 (attacker) fires each step.
# After every step it prints what Terminal 1 would show, the wall-clock time
# of the step, and the measured detection/response latency.
#
# Use it to learn the pacing before you present. Run as root.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
RUN=/tmp/credguard-lab; mkdir -p "$RUN"
CG_LOG="$RUN/cg.log"

c(){ printf '\033[1;36m%s\033[0m\n' "$*"; }     # cyan heading
g(){ printf '\033[1;32m%s\033[0m\n' "$*"; }     # green T1 output
y(){ printf '\033[0;33m%s\033[0m\n' "$*"; }     # yellow timing
hr(){ printf '%s\n' "------------------------------------------------------------"; }

cleanup(){
  for p in cg imds app; do [ -f "$RUN/$p.pid" ] && kill "$(cat "$RUN/$p.pid")" 2>/dev/null; done
  ip addr del 169.254.169.254/32 dev lo 2>/dev/null
  rm -f "$RUN"/*.pid /usr/bin/aws 2>/dev/null
}
trap cleanup EXIT
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

# wait until a new line appears in the agent log; echo elapsed seconds
wait_for_alert(){
  local before="$1" t0 t1
  t0=$(date +%s.%N)
  for _ in $(seq 1 200); do        # up to ~2s
    [ "$(wc -l <"$CG_LOG")" -gt "$before" ] && break
    sleep 0.01
  done
  t1=$(date +%s.%N)
  awk "BEGIN{printf \"%.3f\", $t1-$t0}"
}

start_agent(){   # $1 = extra flags (e.g. --enforce)
  : >"$CG_LOG"
  stdbuf -oL "$HERE/build/credguard" $1 >"$CG_LOG" 2>"$RUN/cg.err" & echo $! >"$RUN/cg.pid"
  sleep 1.5
}

STEP0=$(date +%s)

c "### TERMINAL 1 — bring up the lab and the agent (monitor mode)"
ip addr add 169.254.169.254/32 dev lo 2>/dev/null
python3 "$HERE/lab/mock_imds.py" >"$RUN/imds.log" 2>&1 & echo $! >"$RUN/imds.pid"
python3 "$HERE/lab/ssrf_app.py"  >"$RUN/app.log"  2>&1 & echo $! >"$RUN/app.pid"
sleep 1
start_agent ""
g "[credguard] running in MONITOR mode. watching 169.254.169.254."
y "T1 ready at +$(( $(date +%s) - STEP0 ))s"
hr

c "### TERMINAL 2 — step 1: harmless lookup through the SSRF bug"
y ">>> bash lab/attack.sh benign"
B=$(wc -l <"$CG_LOG"); S=$(date +%s)
bash "$HERE/lab/attack.sh" benign >/dev/null 2>&1
LAT=$(wait_for_alert "$B")
g "T1 shows:"; tail -n +$((B+1)) "$CG_LOG" | sed 's/^/   /'
y "step time ~$(( $(date +%s) - S ))s   |   detection latency ${LAT}s   |   expect: ALERT / low"
hr

c "### TERMINAL 2 — step 2: the Capital One move — steal IAM credentials"
y ">>> bash lab/attack.sh steal"
B=$(wc -l <"$CG_LOG"); S=$(date +%s)
bash "$HERE/lab/attack.sh" steal >/dev/null 2>&1
LAT=$(wait_for_alert "$B")
g "T1 shows:"; tail -n +$((B+1)) "$CG_LOG" | sed 's/^/   /'
y "step time ~$(( $(date +%s) - S ))s   |   detection latency ${LAT}s   |   expect: ALERT / critical"
hr

c "### TERMINAL 1 — switch the agent to ENFORCE (Ctrl-C, restart with --enforce)"
kill "$(cat "$RUN/cg.pid")" 2>/dev/null; sleep 0.5
start_agent "--enforce"
g "[credguard] running in ENFORCE mode."
hr

c "### TERMINAL 2 — step 3: run the theft again — now blocked"
y ">>> bash lab/attack.sh steal"
B=$(wc -l <"$CG_LOG"); S=$(date +%s)
OUT=$(bash "$HERE/lab/attack.sh" steal 2>&1)
LAT=$(wait_for_alert "$B")
printf '   attacker sees: %s\n' "$(echo "$OUT" | tail -1)"
g "T1 shows:"; tail -n +$((B+1)) "$CG_LOG" | sed 's/^/   /'
y "step time ~$(( $(date +%s) - S ))s   |   block latency ${LAT}s   |   expect: BLOCKED / critical"
hr

c "### TERMINAL 2 — step 4: an allowlisted tool (aws) still works"
[ -e /usr/bin/aws ] || cp -f "$(command -v curl)" /usr/bin/aws
y ">>> aws (allowlisted) reads instance-id"
B=$(wc -l <"$CG_LOG"); S=$(date +%s)
printf '   attacker sees: '; /usr/bin/aws -s -m 3 http://169.254.169.254/latest/meta-data/instance-id; echo
wait_for_alert "$B" >/dev/null
g "T1 shows:"; tail -n +$((B+1)) "$CG_LOG" | sed 's/^/   /'
y "expect: ALLOW / info — the legitimate call succeeds"
hr

c "### Rehearsal complete"
y "total elapsed: $(( $(date +%s) - STEP0 ))s   (a live run with narration is ~4-6 min)"
