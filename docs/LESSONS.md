# LESSONS — incidents that became gates

Every non-obvious check in this code has an incident behind it. These are the ones worth knowing before you
"simplify" something.

## 1. "Cloud says present" is not the same as "cloud-confirmed head"
An earlier executor deleted source as soon as the cloud reported a shard present. A later restore
test failed on a shard that was present but truncated. The fix was not a mandatory download-back
before every delete (that was tried, then retired as the `trust-the-cloud` operator policy: it
serialised every eviction through the control host's desktop client). The current contract is:
cloud-confirmed *head* (ledger/catalog, sizes match) + strict cloud audit fresh + live source still
equal to the archive-time snapshot + full local re-hash against the per-version manifest + no open
handles → delete. On the last real run this meant tens of thousands of files re-hashed in seconds
before deletion — cheap insurance. Restore tests still exist and are recorded when run; they are
evidence, not a gate. Residual risk is explicit: provider-side corruption after confirmation is only
caught by a later restore or by the replicated three-copy metadata making the loss describable.

## 2. Read-only engines look stone cold
Liveness is `find -newermt`, i.e. modification time. Model weights are read by every job and
written by none, so they were evicted, then faulted back (~20 GB of weights) through the control host on the
next job, which filled that host to zero free bytes. Fix: `READ_ONLY_ENGINE_PATHS` auto-pin, but
only when a local copy exists (`auto_pin_applies(path, local_present)`), otherwise a cloud-only
entry would be pinned forever.

## 3. Two functions, two clocks
`pressure_waiting()` promised "evictable after the 3-day grace"; `eviction_candidates()` used a
15-day cold line. An asset past grace was neither a candidate nor "waiting" and was invisible for
18 h while the disk sat over the high-water mark. Same clock now, plus a test.

## 4. One refused candidate stalled the whole loop
The pressure loop raised on the first candidate the executor refused (a 114 KB legacy asset outside
`ALLOWED_PREFIXES`), so nothing behind it was ever tried. Now: deterministic refusals go to a
block ledger and the loop continues; `ws page eviction-blocks` / `evict-unblock` manage them.

## 5. A tier can vanish mid-transaction
An external enclosure reset mid-write; the journal aborted and the filesystem went read-only.
The lesson encoded here is not about USB — it is that *any* tier can vanish mid-transaction, so
the ledger records `CLOUD_CONFIRMED` only from an independent read-back, never from the write path.

## 6. Contract-pinned evidence roots
Two directories that are written once and then read by a live contract (a review-receipt root and
a resume-state root) were evicted as "cold" and two pipelines went `CONTROL_INVALID`. Liveness by
mtime cannot see "someone depends on this". Fix: a declarative, append-only pin file
(`contract_pinned_paths.json`) that contract owners can extend without editing shared code.

## 7. Secrets in code paths (this snapshot)
The original code held the passphrase *path* (never the passphrase) and one account-specific
directory hash for the desktop client. Both are now env/glob-resolved. Rule for contributors:
if a string is only true on one machine, it belongs in `config/`, not in `.py`.
