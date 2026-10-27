#!/usr/bin/env bash
# Tear the lab down.
set -u
RUN=/tmp/credguard-lab
for p in imds app; do
  if [ -f "$RUN/$p.pid" ]; then
    kill "$(cat "$RUN/$p.pid")" 2>/dev/null || true
    rm -f "$RUN/$p.pid"
  fi
done
ip addr del 169.254.169.254/32 dev lo 2>/dev/null || true
echo "[lab] stopped."
