# EasyTier 运行边界与接入决策

> 状态：首发部署约定。本文描述当前 NetworkCore Windows 隧道方案的运行边界，不替代 POP 的路由、ACL 和密钥管理规范。

## 1. 结论

- EasyTier RPC 需要在运行 NetworkCore 的本机可用，但不需要向公网或整个集群开放。
- Windows 原生 EasyTier 客户端和 Linux POP 使用本机回环 RPC；控制面不直接扫描或管理公网 RPC。
- 首发使用同一受控版本的官方 `easytier-core` 和 `easytier-cli`。受控 fork 可以使用，但必须满足本文的兼容性与验收要求。
- iOS 及其他不安装 EasyTier 的终端通过标准 VPN 接入 Linux POP；它们不是 EasyTier mesh 成员，路由和访问策略由 POP 执行。

## 2. 为什么当前 Windows 客户端需要 RPC

Windows Runtime 启动或管理本机 `easytier-core` 后，会调用同机 `easytier-cli` 查询 peer 和路由状态。第四阶段的就绪判定将使用结构化的 `--output json peer` 结果，确认签名配置中的目标 POP peer ID 已作为远端 peer 出现。

这要求 EasyTier core 的 RPC portal 对本机 CLI 可达。它不要求控制面连接远端 POP 的 RPC，也不要求把 RPC 端口发布到 Internet。部署时应显式配置回环地址；上游 CLI 的默认目标是 `127.0.0.1:15888`，但实际端口以受控配置为准。

## 3. 节点角色

| 角色 | 是否运行 EasyTier | RPC 暴露范围 | 主要职责 |
| --- | --- | --- | --- |
| Linux POP / 网关 | 是 | 回环；如确需远程运维，只允许独立管理网 | 接入现有 mesh、路由策略、ACL、出口和标准 VPN 终结 |
| Windows NetworkCore 客户端 | 是 | 回环 | 本机隧道、签名 POP 选择、就绪检查和受控路由 |
| iOS 或标准 VPN 用户 | 否 | 无 | 通过 WireGuard、IKEv2 或其他标准 VPN 接入 POP |
| 控制面 | 否 | 无直接 RPC 访问 | 签名配置下发、审计和状态汇总 |

## 4. 内核与 CLI 准入

官方 `easytier-core` 与配套 `easytier-cli` 是首发基线。为了加入既有 EasyTier 集群，替代内核必须实现兼容的 EasyTier 数据面、认证和本地控制语义；WireGuard、sing-box 或任意其他 overlay 内核不能仅靠配置直接替代它。

受控 fork 只有同时满足以下条件才可进入发布物：

1. Core 与 CLI 作为同一受控版本发布，并记录版本、SHA-256 和来源。
2. CLI 对指定实例能提供稳定的 JSON peer 结果，至少含 `id` 和 `cost` 字段。
3. 本机 RPC 的实例选择、错误语义和权限边界经过 Windows 与 Linux 集成验收。
4. 签名 profile 中的 EasyTier peer ID 与 CLI 返回的远端 peer ID 完全一致时，客户端才允许声明就绪。
5. 新版本先通过隔离测试 POP 验证，再进入生产 artifact allowlist。

## 5. 安全边界

- 不把 RPC 当作公网管理 API；防火墙默认拒绝来自非回环地址的访问。
- 不在文档、日志、工单或 CI 输出中记录集群密钥、RPC 凭据、完整拓扑或生产私钥。
- Windows 客户端必须固定并校验 `easytier-core` 与 `easytier-cli` 的受信任文件哈希，不能按 PATH 自动发现可执行文件。
- POP peer ID 是签名配置的一部分；出现本地 `cost: Local` 不能证明目标 POP 已连接。

## 6. 发布验收

每个受控版本至少保留以下证据：

1. Core 和 CLI 的版本、SHA-256、签名来源和批准日期。
2. 脱敏后的 JSON peer 结果：一条本机 `Local` 记录和一条目标 POP 远端记录。
3. 正确 peer ID 的启动成功记录，以及签名有效但 peer ID 错误时的失败关闭记录。
4. 路由、旁路规则和持久化状态的启动、停止、恢复验证。
5. 对应提交 SHA 与 GitHub Actions 成功运行记录。

## 7. 后续演进

如果未来把 EasyTier core 直接嵌入 NetworkCore，可以移除外部 CLI/RPC 查询路径；这需要新的 engine adapter、等价的身份与就绪证明，以及独立的跨平台验收。该改造不属于当前 Windows 隧道阶段。
