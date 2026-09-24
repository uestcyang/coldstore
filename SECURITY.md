# Security

This repository contains **mechanism code only**. It must never contain:

- credentials, passphrases, OAuth/cloud tokens, cookies, private keys;
- runtime ledgers, catalogs, event logs, sqlite/tsv/jsonl state, encrypted recovery bundles;
- production configuration (`config/*.local.json`, `.secrets/`, `*.env`) — all git-ignored;
- real usernames, home paths, LAN/VPN addresses, ssh targets, account-local directory ids.

`tools/public_privacy_scan.py` is a fail-closed gate for the above and runs on every release
candidate from a clean clone (see `docs/privacy.md`). Do not paste real cloud paths, task ids
or tokens into issues.

**Threat model in one line:** encrypted blobs protect *content*; they do not hide object size,
count, upload timing or directory shape from the cloud provider. Key management is yours.

Report a suspected leak by opening an issue titled `security:` with no reproduction payload;
maintainers will reach out for details out-of-band.
