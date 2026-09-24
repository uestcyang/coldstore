# Threat model

## Protected
- plaintext asset content (GPG AES-256 symmetric, key never in repo)
- passphrase / credentials / account identifiers
- local private paths and runtime ledgers (git-ignored, excluded from release)

## Not protected (by design — say so, do not over-claim)
- object size and count
- upload timing and coarse access pattern
- cloud directory shape (`v2/<bucket>/<random-id>.blob`)
- provider account-level metadata

Blobs are **content-encrypted, opaque objects**. Do not describe the cold tier as
"zero-semantic": the provider still sees traffic shape. Restore integrity relies on the
snapshot manifest and full re-hash, not on the provider.

## Eviction trust boundary
Eviction follows the `trust-the-cloud` contract: a source is deleted after cloud confirmation of
the current head plus local snapshot/re-hash/safety gates, **without** an immediate download-back
test. Consequently, provider-side corruption or loss that happens after confirmation may remain
undetected until a later restore, unless another independent copy or verification mechanism
catches it earlier. Mitigations available in this code: periodic `cloud_asset_restore.py` runs
(recorded, not mandatory), strict cloud audits (`vault_v2_audit.py`, `verify-batch
--require-cloud`), and three-copy replication of catalog + manifests so a lost tree is always
describable. None of these makes the cold tier a backup.
