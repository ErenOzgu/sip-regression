#!/usr/bin/env bash
# Runs a command and, if it fails, repeats the tail of its output as a GitHub
# Actions annotation, so the reason shows on the run summary without opening
# the raw log.
#
#   hack/annotate.sh python3 -m sipreg
set -uo pipefail

log="$(mktemp)"
"$@" >"$log" 2>&1
status=$?
cat "$log"
if [ "$status" -ne 0 ]; then
  message="$(tail -n 60 "$log" | tr -d '\r' | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')"
  echo "::error title=${1##*/} failed::${message:0:3800}"
fi
exit "$status"
