#!/usr/bin/env bash
set -Eeuo pipefail

readonly WS='/Users/user/.coldstore/archive'
readonly PRIMARY="$WS/queue_hostb_cold_verified_20260829.tsv"
readonly ROOTS="$WS/vault_v2_roots.tsv"
readonly LOG="$WS/vault_v2_supervisor.log"
readonly MIGRATION_HOLD="$WS/FUNCTION_V2_MIGRATION_HOLD"

if [[ -e "$MIGRATION_HOLD" ]]; then
  printf '%s\tREFUSE_FUNCTION_V2_MIGRATION_HOLD hold=%s\n' \
    "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$MIGRATION_HOLD" | tee -a "$LOG"
  exit 75
fi

pending_count() {
  awk -F '\t' 'NR==FNR {state[$3]=$6; next}
    !/^#/ && NF>=3 && state[$1]!="ROOT_CLOUD_CONFIRMED" {n++} END {print n+0}' "$ROOTS" "$PRIMARY"
}

last_report=0
while true; do
  pending="$(pending_count)"
  if [[ "$pending" == 0 ]]; then
    printf '%s\tEXPANSION_START primary_pending=0\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" | tee -a "$LOG"
    exec "$WS/run_vault_v2_manifest_hostb.sh"
  fi
  now="$(date +%s)"
  if (( now - last_report >= 1800 )); then
    printf '%s\tEXPANSION_WAIT primary_pending=%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$pending" | tee -a "$LOG"
    last_report="$now"
  fi
  sleep 60
done
