# 内容加密冷仓 v2 恢复说明

百度云端只保存 `v2/<两位分桶>/<64位随机ID>.blob`，不保存原文件名、目录名、格式或明文清单。

恢复资料三份：Mac 工作区、hostb `/home/user/.coldstore/archive/`、iCloud `coldstore-recovery/`。主密钥不上传百度。

恢复某个源目录：

0. 不知道 asset_id 时，先运行 `./cloud_asset_find.py '文件名或用途关键词'`。memory-service 只负责召回“资产在云端”的语义锚，本目录是路径、状态和哈希的权威源。
1. 运行 `./cloud_asset_restore.py <asset_id> --plan`，得到必须从百度客户端下载的全部密文 blob 路径。
2. 下载到同一目录后运行 `./cloud_asset_restore.py <asset_id> --blob-dir <下载目录> --output <受控恢复目录>`；工具会逐片 fail-closed 校验并恢复。

底层人工恢复原理：

1. 在 `vault_v2_ledger.tsv` 按 `root` 找齐各 part，按 part 升序下载对应 blob。
2. 密文先校验 `encrypted_sha256` 与 `encrypted_size`。
3. 用 `gpg --batch --pinentry-mode loopback --passphrase-file vault-v2-master.key --decrypt <blob> > <part>.plain` 解密。
4. 明文片校验 `plain_sha256` 与 `plain_size`。
5. 按 part 顺序拼接后送入 `tar -xf -`。

缺失审计：运行 `vault_v2_audit.py --strict`。报告会把缺失 blob 反查为原始根目录、标签、part、明文与密文 SHA；百度云端看不到这些描述。
