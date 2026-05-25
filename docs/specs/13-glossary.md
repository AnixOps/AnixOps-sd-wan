# 13. 术语表

> 状态：草案锁定  
> 规则：术语含义以本表为准；如需新增术语，先补表再改正文。

| 术语 | 含义 |
|---|---|
| Agent | 常驻客户端进程，负责网络能力、策略执行与状态上报 |
| Control Plane | 控制面，负责身份、策略、证书、编排与观测 |
| Client Gateway | 客户端网关/接入端 |
| China Transport Layer | 中国边界传输层，负责入口协议接入与转发 |
| Edge POP | 海外边界节点，负责接收、鉴权、限速与入口调度 |
| Overseas Core | 海外 SD-WAN Core，负责 Overlay、路由与多出口 |
| Egress | 出口节点/出口层 |
| Overlay | 叠加网络层，这里特指 WireGuard Mesh |
| Transport Layer | 传输层，负责中国到海外边界的接入协议 |
| Native WireGuard | 原生 WireGuard 传输/隧道方式 |
| Hysteria2 | 基于 QUIC 的高性能传输方式 |
| REALITY | 具有 TLS 外观伪装能力的传输方式 |
| TUIC | 首版支持的可选传输协议 |
| FRR | Free Range Routing，用于动态路由 |
| BGP | Border Gateway Protocol，用于路由传播与选路 |
| QoS | 线路质量策略或限制特征 |
| DPI | 深度包检测 |
| GFW | 中国边界网络环境中的封锁风险抽象表述 |
| LAN | 局域网接入侧 |
| DHCP | 动态主机配置协议 |
| DNS | 域名解析服务 |
| Fyne | Go 语言桌面 UI 框架 |
| WFP | Windows Filtering Platform |
| Network Extension | macOS 的网络扩展能力 |
| nftables | Linux 防火墙与包过滤框架 |
| iproute2 | Linux 路由与链路管理工具集 |
| Multi-tenant | 多租户隔离能力 |
| Egress Pool | 可插拔的出口节点集合 |
| Policy Routing | 按规则进行路由分流 |
| Telemetry | 状态、指标、诊断信息上报 |

