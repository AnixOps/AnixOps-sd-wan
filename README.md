# AnixOps SD-WAN

> 状态：草案锁定

这是一个 Go 语言跨平台 SD-WAN 平台的正式文档仓库。

当前仓库承载规范、架构、决策记录、未决清单和首版 Go 代码实现。

## 当前入口
- [AGENT.md](./AGENT.md)
- [原始规划归档](./docs/specs/00-original-plan.md)
- [需求定义](./docs/specs/01-requirements.md)
- [架构定义](./docs/specs/02-architecture.md)
- [协议定义](./docs/specs/03-protocols.md)
- [客户端 Agent](./docs/specs/04-client-agent.md)
- [控制面](./docs/specs/05-control-plane.md)
- [桌面 UI](./docs/specs/06-desktop-ui.md)
- [运维规范](./docs/specs/07-operations.md)
- [安全规范](./docs/specs/08-security.md)
- [Go 工程标准](./docs/specs/09-go-engineering-standards.md)
- [测试标准](./docs/specs/10-testing-standards.md)
- [决策记录](./docs/specs/11-decision-record.md)
- [未决清单](./docs/specs/12-open-questions.md)
- [术语表](./docs/specs/13-glossary.md)

## 代码入口
- `cmd/anix-agent`：客户端 Agent 入口。
- `cmd/anix-control`：控制面服务入口。
- `cmd/anix-ui`：桌面 UI 入口；Fyne 实现通过 `-tags fyne` 构建。

## 验证入口
- `scripts/ci-gate.sh`：运行 `go test ./...`、`go vet ./...`、`go build -buildvcs=false ./cmd/...`，并覆盖 Linux、Windows、macOS 的 amd64/arm64 交叉构建。

## 发布与使用
- [1.0.0 使用教程](./docs/releases/1.0.0.md)
- [香港节点接入手册](./docs/guides/operator-hk-node.md)
- [用户接入手册](./docs/guides/user-access.md)

## 现状
- 原始规划已归档到 `docs/specs/00-original-plan.md`，根目录 `plan.md` 已删除。
- 正式版发布前，已确认文档内容保持冻结；新增实现细节仍需进入未决清单或决策记录。
