#!/usr/bin/env bash
# Bring the lab up: bind the metadata IP to loopback, start the mock IMDS and
# the vulnerable app. Run as root.  Tear down with stop_lab.sh.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN=/tmp/credguard-lab
mkdir -p "$RUN"

# 169.254.169.254 must be a local address so the mock IMDS can bind to it.
ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true

echo "[lab] starting mock metadata service (169.254.169.254:80)"
python3 "$HERE/mock_imds.py" >"$RUN/imds.log" 2>&1 &
echo $! > "$RUN/imds.pid"

echo "[lab] starting vulnerable app (127.0.0.1:8080)"
python3 "$HERE/ssrf_app.py" >"$RUN/app.log" 2>&1 &
echo $! > "$RUN/app.pid"

sleep 1
echo "[lab] up. logs in $RUN/  (imds.log, app.log)"
