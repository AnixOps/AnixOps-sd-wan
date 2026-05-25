# 多入口多出口 SD-WAN 项目规划（中国 → 海外）

## 一、项目目标

做一套：

```text
软件化
多入口
多出口
抗 GFW
智能选路
全球 SD-WAN
```

的网络系统。

最终形态：

```text
客户端 Linux 网关
+
海外 SD-WAN Core
+
多区域出口
+
智能调度
```

适用于：

* 企业跨境
* 海外加速
* 多云互联
* 专线融合
* 多运营商
* 多地区出口
* AI/国际业务网络

---

# 二、整体架构（核心）

整个系统拆成：

# 四层架构

```text
[客户端接入层]
        ↓
[抗封锁传输层]
        ↓
[海外边界层]
        ↓
[海外 SD-WAN Core]
        ↓
[多出口层]
```

---

# 三、架构详细说明

---

# 1. 客户端接入层（Linux 网关）

部署位置：

```text
客户机房
企业出口
软路由
旁路由
Mini PC
x86
```

作用：

```text
LAN 接入
DHCP
DNS
透明代理
策略路由
链路探测
自动切换
配置下发
日志
监控
```

---

## 推荐技术栈

```text
Ubuntu/Debian
+ nftables
+ iproute2
+ sing-box
+ local agent
```

---

## 客户端核心能力

### 1. 多传输协议

支持：

```text
Native WireGuard
Hysteria2
REALITY
TUIC
```

---

### 2. 自动链路探测

客户端自动判断：

```text
是否专线
是否公网
是否 QoS
是否 UDP 限速
```

---

### 3. 自动选择传输方式

策略：

```text
专线
  → Native WireGuard

公网跨境
  → Hysteria2 / REALITY

移动网络
  → QUIC 优先

高 QoS 环境
  → REALITY
```

---

### 4. 本地策略路由

支持：

```text
AI流量
视频流量
下载流量
企业流量
游戏流量
```

分别走不同出口。

---

# 四、抗封锁传输层（中国 → 海外）

这是：

# 中国边界层

核心目标：

```text
绕过 GFW
抗 QoS
隐藏 WireGuard
稳定接入
```

---

# 推荐方案

---

## 方案 A（推荐）

# Hysteria2

优点：

```text
QUIC
高性能
抗 QoS
移动网络友好
```

适合作为主入口。

---

## 方案 B

# REALITY

优点：

```text
TLS伪装极强
HTTPS外观
抗 DPI
```

适合作为备用入口。

---

# 推荐结构

```text
客户端
   ↓
Hysteria2 / REALITY
   ↓
海外边界节点
```

---

# 五、海外边界层（Edge POP）

作用：

```text
接收中国流量
鉴权
限速
入口调度
接入 SD-WAN Core
```

---

## 推荐部署区域

```text
香港
日本
新加坡
美国西海岸
德国
```

---

## 边界节点职责

### 接收：

```text
REALITY
Hysteria2
TUIC
```

---

### 转入：

```text
WireGuard SD-WAN Core
```

---

# 六、海外 SD-WAN Core（核心）

这是：

# 真正的核心网络

作用：

```text
节点互联
动态选路
故障切换
多出口
智能路由
```

---

# 推荐核心技术

---

## Overlay

# WireGuard Mesh

原因：

```text
性能最高
CPU占用低
稳定
生态成熟
```

---

## 动态路由

# FRR + BGP

实现：

```text
动态选路
ECMP
故障切换
多出口
```

---

## SD-WAN 控制层

推荐：

# Netmaker

原因：

```text
管理简单
支持 WireGuard
支持 Egress Gateway
适合 Overlay
```

---

# 七、多出口层（Egress）

出口节点：

```text
香港
日本
新加坡
美国
欧洲
```

---

# 出口策略

---

## AI 流量

```text
OpenAI
Anthropic
Google AI
→ 日本/美国
```

---

## 视频流量

```text
YouTube
Netflix
→ 新加坡
```

---

## 企业业务

```text
AWS/GCP/Azure
→ 最近区域
```

---

## 国内回源

```text
香港
```

---

# 八、专线融合（重点）

系统必须支持：

# 专线自动识别

---

## 如果检测到：

```text
IEPL
MPLS
云专线
企业专网
```

则：

# 直接 Native WireGuard

---

## 如果检测到：

```text
公网
QoS
GFW
```

则：

# Hysteria2 / REALITY

---

# 九、智能调度系统（核心能力）

客户端 Agent：

持续检测：

```text
RTT
丢包
抖动
QoS
UDP可用性
```

---

# 自动选择：

```text
最佳入口
最佳出口
最佳传输协议
```

---

# 十、推荐网络拓扑

```text
                     ┌─────────────┐
                     │ Controller  │
                     └──────┬──────┘
                            │
==================================================
            Overseas WireGuard SD-WAN Core
==================================================

      HK Core ───── JP Core ───── SG Core
         │             │              │
         │             │              │
       US Core ───── EU Core ───── Other POP

==================================================
                 Edge POP Layer
==================================================

       HK Edge     JP Edge      SG Edge

==================================================
             China Access Layer
==================================================

        Hysteria2 / REALITY

==================================================
                Client Gateway
==================================================

          Linux SD-WAN Agent
```

---

# 十一、推荐技术栈（最终）

---

## 客户端

```text
Linux
+ sing-box
+ nftables
+ iproute2
+ local controller agent
```

---

## 抗墙层

```text
Hysteria2
REALITY
TUIC
```

---

## Overlay

```text
WireGuard
```

---

## SD-WAN

```text
Netmaker
```

或者：

```text
flexiWAN
```

---

## 路由

```text
FRR
BGP
```

---

## 控制器

```text
Go/Rust
+ PostgreSQL
+ Redis
+ gRPC
```

---

# 十二、推荐开发阶段

---

# 第一阶段（MVP）

目标：

```text
打通中国 → 海外
```

实现：

```text
Linux 网关
+ Hysteria2
+ 单出口
```

---

# 第二阶段

目标：

```text
海外 Overlay
```

实现：

```text
WireGuard Mesh
+ Netmaker
```

---

# 第三阶段

目标：

```text
多出口
智能路由
```

实现：

```text
FRR/BGP
策略路由
```

---

# 第四阶段

目标：

```text
企业级控制器
```

实现：

```text
统一管理
配置下发
监控
计费
多租户
```

---

# 十三、核心设计原则（非常重要）

---

# 原则 1

不要：

```text
全网抗墙
```

只需要：

```text
中国边界抗墙
```

---

# 原则 2

海外核心：

```text
必须纯 WireGuard
```

不要：

```text
海外内部继续套 REALITY
```

---

# 原则 3

传输层与 Overlay 分离

```text
Transport Layer
≠
SD-WAN Core
```

---

# 原则 4

客户端必须：

```text
多协议自动切换
```

---

# 十四、最终产品形态

最终你做出来的：

其实是：

# 企业级跨境 SD-WAN 平台

具备：

```text
多入口
多出口
抗 GFW
智能选路
全球 Overlay
专线融合
自动切换
```

已经接近：

```text
Cloudflare Magic WAN
Tailscale Enterprise
Cato Networks
Aryaka
```

这种方向。
