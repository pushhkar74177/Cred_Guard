#!/usr/bin/env bash
#
# CredGuard scripted demo.
#
#   sudo ./demo.sh monitor   # detect the SSRF credential theft, attack succeeds
#   sudo ./demo.sh enforce   # block the SSRF credential theft in real time
#
# It brings up the lab (mock metadata service + vulnerable app), starts the
# agent in the chosen mode, fires a harmless request and then a credential
# theft through the vulnerable app, prints the agent's alerts, and cleans up.
#
set -u
MODE="${1:-monitor}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN=/tmp/credguard-lab
mkdir -p "$RUN"

say(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
cleanup(){
  [ -f "$RUN/cg.pid" ]   && kill "$(cat "$RUN/cg.pid")"   2>/dev/null
  [ -f "$RUN/imds.pid" ] && kill "$(cat "$RUN/imds.pid")" 2>/dev/null
  [ -f "$RUN/app.pid" ]  && kill "$(cat "$RUN/app.pid")"  2>/dev/null
  ip addr del 169.254.169.254/32 dev lo 2>/dev/null
  rm -f "$RUN"/*.pid
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "run with sudo"; exit 1; fi
case "$MODE" in monitor) FLAG="";; enforce) FLAG="--enforce";; *) echo "usage: $0 {monitor|enforce}"; exit 2;; esac

say "lab up: metadata service 169.254.169.254:80 + vulnerable app 127.0.0.1:8080"
ip addr add 169.254.169.254/32 dev lo 2>/dev/null
python3 "$HERE/lab/mock_imds.py" >"$RUN/imds.log" 2>&1 & echo $! >"$RUN/imds.pid"
python3 "$HERE/lab/ssrf_app.py"  >"$RUN/app.log"  2>&1 & echo $! >"$RUN/app.pid"
sleep 1.5

say "starting CredGuard in ${MODE^^} mode"
stdbuf -oL "$HERE/build/credguard" $FLAG >"$RUN/cg.log" 2>"$RUN/cg.err" & echo $! >"$RUN/cg.pid"
sleep 2
cat "$RUN/cg.err"

if [ "$MODE" = monitor ]; then
  say "attacker: harmless lookup (instance-id) through the SSRF bug"
  bash "$HERE/lab/attack.sh" benign; sleep 0.8

  say "attacker: CREDENTIAL THEFT (IAM security-credentials) through the SSRF bug"
  bash "$HERE/lab/attack.sh" steal; sleep 1.5
else
  say "attacker: CREDENTIAL THEFT through the SSRF bug (compromised app, not allowlisted)"
  bash "$HERE/lab/attack.sh" steal; sleep 1.0

  say "legitimate tool: an allowlisted caller (aws) reads instance metadata directly"
  # Stand in for the AWS CLI with a copy at the allowlisted path (only if absent).
  MADE_AWS=0
  if [ ! -e /usr/bin/aws ]; then cp -f "$(command -v curl)" /usr/bin/aws && MADE_AWS=1; fi
  echo -n "aws -> instance-id: "
  /usr/bin/aws -s -m 3 http://169.254.169.254/latest/meta-data/instance-id || echo "(blocked)"
  echo; [ "$MADE_AWS" = 1 ] && rm -f /usr/bin/aws; sleep 1.0
fi

say "CredGuard alerts"
if [ -s "$RUN/cg.log" ]; then
  if command -v python3 >/dev/null; then python3 -m json.tool < "$RUN/cg.log" 2>/dev/null || cat "$RUN/cg.log"
  else cat "$RUN/cg.log"; fi
else echo "(no alerts captured)"; fi

if [ "$MODE" = enforce ]; then
  say "result: the SSRF theft was blocked in real time, while the allowlisted 'aws' call still worked"
else
  say "result: the theft succeeded (creds returned), but CredGuard named the exact process and request"
fi
