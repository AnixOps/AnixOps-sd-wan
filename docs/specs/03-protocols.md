# 03. 协议定义

> 状态：草案锁定  
> 规则：协议选择、入口分类与切换规则在正式版前冻结；未决项进 `12-open-questions.md`。

## 1. 首版协议矩阵
### 1.1 Native WireGuard
- 用途：专线、可信线路、海外 Core Overlay。
- 角色：国内直连入口、海外 Core 节点互联、部分稳定链路优先路径。

### 1.2 Hysteria2
- 用途：公网跨境主入口。
- 特征：QUIC、高性能、抗 QoS、移动网络友好。

### 1.3 REALITY
- 用途：国际优化入口与备用入口。
- 特征：TLS 外观、抗 DPI、伪装能力强。

### 1.4 TUIC
- 用途：首版支持的可选入口协议。
- 角色：作为协议矩阵的一部分保留，不锁死为默认入口。

### 1.5 WireGuard over REALITY
- 用途：海外非大陆专线节点的外层接入。
- 角色：作为 WireGuard Overlay 的外层承载，适用于普通海外节点、海外边界节点和海外出口节点的公网接入。
- 约束：外层负责跨境接入，内层仍然以 WireGuard 承载 Overlay 职责。

## 2. 入口档位定义
- 国内直连入口：Native WireGuard。
- 国际优化入口：REALITY。
- 国际普通入口：Hysteria2。
- 大陆专线直连海外节点：Native WireGuard。
- 海外非大陆专线节点接入：WireGuard over REALITY。
- 上述档位可以在策略层切换，但不得破坏协议职责边界。

## 3. 选择规则
- 检测到 IEPL、MPLS、云专线、企业专网时，优先选择 Native WireGuard。
- 检测到公网、QoS、GFW 风险时，优先选择 Hysteria2 或 REALITY。
- 检测到大陆专线可直达海外节点时，优先选择 Native WireGuard。
- 海外普通节点、海外边界节点、海外出口节点在无大陆专线可用时，默认采用 WireGuard over REALITY。
- 移动网络场景优先选择 QUIC 路径。
- 高 QoS 或高 DPI 风险场景优先选择 REALITY。

## 4. 链路探测信号
- RTT
- 丢包
- 抖动
- QoS 特征
- UDP 可用性
- 协议握手成功率

## 5. 切换原则
- 协议切换由客户端 Agent 自动发起。
- 切换必须保留最小中断窗口。
- 切换结果必须回传控制面用于调度。
- 切换失败必须进入回退路径。

## 6. 安全与身份
- 证书由自建 CA 体系签发。
- 证书生命周期受控制面统一管理。
- 入口协议与 Overlay 认证边界分离。

## 7. 组合规则
- 传输层只负责到达海外边界。
- 大陆专线可直达的海外节点可直接使用 WireGuard。
- 海外边界统一转入 WireGuard Core。
- 海外非大陆专线节点的外层接入可以采用 WireGuard over REALITY。
- 海外 Core 内部不再叠加 Hysteria2、REALITY 或 TUIC。
