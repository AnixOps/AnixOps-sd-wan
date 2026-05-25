# AGENT.md

> 状态：草案锁定，代码实现阶段已启动  
> 说明：本文件是本仓库的总入口与执行约束。正式版出来前，已确认内容不得被直接改写；新增、变更或争议点必须先进入 `docs/specs/12-open-questions.md`。

## 目标
- 本仓库用于标准化一套 Go 语言跨平台 SD-WAN 平台的正式文档。
- 最终形态由客户端 Agent、桌面 UI、中国边界入口层、海外边界层、海外 SD-WAN Core 和多出口层组成。
- 目标场景包括企业跨境、海外加速、多云互联、专线融合、多运营商、多地区出口，以及 AI/国际业务网络。

## 范围
- 覆盖需求、架构、协议、客户端、控制面、桌面 UI、运维、安全、Go 工程标准、测试标准、术语、决策记录与未决清单。
- 当前阶段开始交付 Go 代码实现；实现代码必须遵守本文件、已确认决策和配套规范。
- 原始规划已归档为 `docs/specs/00-original-plan.md`，根目录 `plan.md` 不再作为工作文件。

## 不可变约束
- 实现语言：Go。
- 客户端优先支持 Linux、Windows、macOS。
- 客户端形态：常驻 Agent + 桌面 UI。
- 桌面 UI：Go + Fyne，禁止 HTML 套壳、WebView 套壳作为主桌面方案。
- 控制层：自研，不以 Netmaker 或 flexiWAN 作为首版控制层依赖。
- 海外 Core：纯 WireGuard。
- 动态路由：FRR + BGP。
- 多租户平台。
- 监控与日志可上报海外控制面。
- 传输层与 Overlay 必须分离。
- 正式版前采用草案锁定机制，所有未决项只进入未决清单，不直接改正文。

## 文档索引
- `docs/specs/00-original-plan.md`：原始规划归档，保持 verbatim。
- `docs/specs/01-requirements.md`：产品需求与范围定义。
- `docs/specs/02-architecture.md`：分层架构与职责边界。
- `docs/specs/03-protocols.md`：入口协议、传输模式与切换原则。
- `docs/specs/04-client-agent.md`：客户端 Agent、跨平台能力与本地职责。
- `docs/specs/05-control-plane.md`：自研控制面、租户、策略与分发。
- `docs/specs/06-desktop-ui.md`：桌面 UI 交互与信息架构。
- `docs/specs/07-operations.md`：部署、运行、变更与维护规范。
- `docs/specs/08-security.md`：身份、加密、审计与安全边界。
- `docs/specs/09-go-engineering-standards.md`：Go 工程结构与编码标准。
- `docs/specs/10-testing-standards.md`：测试矩阵、验收与回归标准。
- `docs/specs/11-decision-record.md`：已确认决策记录。
- `docs/specs/12-open-questions.md`：所有未决项与待确认细节。
- `docs/specs/13-glossary.md`：术语表。

## 工作规则
- 任何实现、重构或扩展都必须先检查本文件和配套规范。
- 若发现冲突，以本文件和已确认决策记录为准。
- 若发现未决项，不得擅自补充为事实，必须写入未决清单。
