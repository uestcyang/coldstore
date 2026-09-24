#!/usr/bin/env bash
set -Eeuo pipefail

readonly WS='/Users/user/.coldstore/archive'
readonly QUEUE="$WS/queue_hostb_manifest_expansion_20260829.tsv"
readonly LOG="$WS/vault_v2.log"
readonly ROOT_LEDGER="$WS/vault_v2_roots.tsv"
readonly SOURCES="$WS/vault_v2_sources.tsv"
readonly REMOTE='user@host-b'
readonly REMOTE_META='/home/user/.coldstore/archive'
readonly MIGRATION_HOLD="$WS/FUNCTION_V2_MIGRATION_HOLD"

now_iso() { date '+%Y-%m-%dT%H:%M:%S%z'; }
log() { printf '%s\t%s\n' "$(now_iso)" "$*" | tee -a "$LOG"; }

if [[ -e "$MIGRATION_HOLD" ]]; then
  log "REFUSE_FUNCTION_V2_MIGRATION_HOLD hold=$MIGRATION_HOLD"
  exit 75
fi

test -s "$QUEUE"
# scp can recreate this directory without its execute bit.  A directory that
# is readable but not searchable makes every manifest look present while all
# opens fail with EACCES, so normalize and verify it before consuming queue.
ssh -n "$REMOTE" "install -d -m 700 '$REMOTE_META/manifests' && test -x '$REMOTE_META/manifests'"
while IFS=$'\t' read -r label base manifest_name manifest_sha search_name search_sha expected_files expected_bytes description <&3; do
  [[ -z "${label:-}" || "${label:0:1}" == '#' ]] && continue
  root_id="manifest://hostb/$label"
  if awk -F '\t' -v r="$root_id" '$2==r{state=$6} END{exit state!="ROOT_CLOUD_CONFIRMED"}' "$ROOT_LEDGER"; then
    log "SKIP_ROOT_CONFIRMED label=$label root=$root_id"
    continue
  fi
  ssh -n "$REMOTE" "python3 '$REMOTE_META/vault_v2_manifest.py' verify --base '$base' --files0 '$REMOTE_META/manifests/$manifest_name' --manifest-sha256 '$manifest_sha' --search '$REMOTE_META/manifests/$search_name' --search-sha256 '$search_sha' --expected-files '$expected_files' --expected-bytes '$expected_bytes'"
  if ! awk -F '\t' -v x="$label" '$4==x{ok=1} END{exit !ok}' "$SOURCES"; then
    printf '%s\thostb\t%s\t%s\t%s\t%s\n' "$(now_iso)" "$base" "$label" "$expected_bytes" "$description" >> "$SOURCES"
  fi
  "$WS/vault_v2_sync.py" >/dev/null
  log "MANIFEST_ROOT_START label=$label files=$expected_files expected_source_bytes=$expected_bytes base=$base"
  ssh -n "$REMOTE" "bash -o pipefail -c \"gzip -dc -- '$REMOTE_META/manifests/$manifest_name' | sudo -n tar --null --verbatim-files-from --numeric-owner --acls --xattrs --sparse --pax-option=delete=atime,delete=ctime -C '$base' -T - -cf -\"" \
    | "$WS/vault_v2_stream.py" --label "$label" --root "$root_id" \
    | tee -a "$LOG"
  printf '%s\t%s\t%s\t%s\thostb\tROOT_CLOUD_CONFIRMED\n' "$(now_iso)" "$root_id" "$label" "$expected_bytes" >> "$ROOT_LEDGER"
  "$WS/vault_v2_versions.py" commit --asset "$label" --root "$root_id"
  "$WS/vault_v2_sync.py" >/dev/null
  log "ROOT_CLOUD_CONFIRMED machine=hostb label=$label manifest=true source_retained=true"
done 3< "$QUEUE"

log 'VAULT_V2_MANIFEST_EXPANSION_PASS source_retained=true encrypted=true opaque_names=true'
