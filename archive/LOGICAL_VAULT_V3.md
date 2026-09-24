# Logical Vault v3

## 锁定原则

冷热盘的“页”是业务完整性单位，不是固定字节块。固定 1GB 只属于旧 v2
传输实现，不能成为检索、恢复、淘汰或计费单位。

| 数据类别 | 逻辑页 | 内容对象 |
|---|---|---|
| 工作数据 | 通过一致性门的完整工作区快照 | 快照内每个自然文件；目录、权限、软链写入 manifest |
| 工具资产 | 单个精确版本、平台、构建的可恢复 tool capsule | 原始包或脚本封装的自然文件 |
| 模型、数据集、视频等 | 一个不可变 artifact 或其官方 shard 集 | 原生文件/shard，不再二次固定切块 |
| 数据库、活日志、环境、系统服务 | `isolated` / `pinned` | 不进入冷热淘汰器 |

语义检索命中 `capability`，解析到一个或多个 tool capsule；真正搬运的是
capsule manifest 引用的内容对象。相同 SHA-256 的内容全局只上传一次。

## 身份与云路径

- 明文对象身份：`SHA-256 + 实际字节数`。
- 云端对象：`v3/objects/<2>/<keyed-HMAC>.blob`，不泄露包名、路径或格式。
- 加密：沿用现役 AES-256 GPG 主密钥。
- 上传前：从源端流式读取，同时验证实际字节数和明文 SHA-256；不在 Mac
  落明文副本。
- 下载后：密文大小和 SHA-256、GPG 验证、明文大小和 SHA-256 四门全过，
  才原子发布恢复目录。

对象可以是 2 KiB、630,999,412B 或 1,317,495,451B；控制器不存在固定
1GB 分片常量。

上传器可以设置一个临时 staging 窗口来并发喂给百度客户端。窗口只是磁盘
背压上限，不写进 manifest、不改变对象边界，也不是恢复单位；进程重启后仍按
每个自然对象的独立密文大小、SHA-256 和云状态续跑。

## 工作区一致性与所有权

`workspace_snapshot` 注册必须附带通过的一致性证明。manifest 保存自然文件、
空目录、权限位和软链目标。父工作区与子工作区不能同时声明同一目录树；当前
控制器对嵌套所有权直接 fail-closed，后续只有显式 child-unit 引用可以解除。

## 状态机

```text
unit:   REGISTERED → PARTIAL_CLOUD → CLOUD_CONFIRMED → RESTORE_VERIFIED
object: REGISTERED → UPLOADING → CLOUD_CONFIRMED
                         └──────→ FAILED（可从源重新验真后重试）
batch:  REGISTERED → PARTIAL_CLOUD → CLOUD_CONFIRMED → AUDIT_PASS
```

归档状态与页温度正交：

```text
temperature: HOT(有租约) → WARM → COLD
                     PINNED / ISOLATED 不参与自动降温
```

`touch` 记录真实逻辑访问并默认续 8 小时 HOT 租约；`temperature-plan` 按
最近访问计算 HOT/WARM/COLD；`eviction-candidates` 只有在 unit 云确认、批次
全量云索引审计 PASS、租约过期且源对象仍被哈希验证时才列出。该命令只输出
候选，`deletion_authorized=false`，不会因“上云了”就删源。

旧 v2 与 v3 是旁路关系。v3 的真实百度原生恢复和严格审计未通过前：

- 不删除任何旧 v2 云对象；
- 不删除 hostb/Mac 源文件；
- 不把旧页标成可淘汰；
- v3 失败时仍可用 v2 恢复。

## 单一入口

```bash
./logical_vault_v3.py init
./logical_vault_v3.py register-function-batch \
  --batch-id batch-0002 --mapping /path/batch-0002.jsonl \
  --source-root /home/user/asset-pool-v3/batch-0002
./logical_vault_v3.py plan-upload --batch batch-0002
./logical_vault_v3.py upload --unit UNIT_ID --limit 1
./logical_vault_v3.py restore --unit UNIT_ID --download --output-root /tmp/restore
./logical_vault_v3.py verify-batch --batch batch-0002 --require-cloud
./logical_vault_v3.py strict-audit --require-cloud
./logical_vault_v3.py status --batch batch-0002
./logical_vault_v3.py touch --unit UNIT_ID --lease-hours 8 --reason "agent recall"
./logical_vault_v3.py temperature-plan --hot-days 3 --cold-days 15 --apply
./logical_vault_v3.py eviction-candidates --limit 100
```

权威控制面是 `logical_vault_v3.sqlite3`；`logical_vault_v3_events.jsonl` 只由
已提交的 SQLite 事件原子导出。同步脚本用 SQLite backup API 生成一致快照，
再分别加密写入 iCloud、复制到 hostb，不能裸复制活数据库。

## 验收门

批次完成必须同时满足：映射聚合值一致、全部 unit manifest 哈希一致、全部
内容对象 `CLOUD_CONFIRMED`、SQLite `quick_check=ok`、外键检查为空、至少一个
真实 tool capsule 通过“百度原生下载→密文验真→解密→明文验真→单页发布”。
只有再加旧 v2 回退链可用，才允许另行审批清理旧云对象。
