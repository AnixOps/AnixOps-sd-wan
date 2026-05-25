# 网络管理员手册

这份手册面向网络管理员和平台运维，覆盖租户、节点、角色、配置、上线与回滚。  
当前仓库里的管理员流程只保留这一份，不再拆成香港节点专用手册。

## 1. 你要先明白的角色

- `overseas-edge`：海外边界节点，负责接收接入流量、鉴权、限速和入口调度。
- `core`：海外 Core 节点，负责 WireGuard Overlay、动态路由和节点互联。
- `egress`：出口节点，负责把业务流量送到不同区域或不同出口。

香港、新加坡、日本、美国西海岸、德国等海外节点，都按普通海外节点纳入控制面。  
香港节点不单独作为中国侧专用边界。

## 2. 什么时候用什么链路

- 大陆专线可直达海外节点时：直接用 **Native WireGuard**。
- 非大陆专线的海外节点：外层用 **WireGuard over REALITY**。
- 海外 Core 内部：仍然只用 **WireGuard Overlay**。

这意味着，管理员在部署节点时，先判断链路类型，再决定节点角色和外层接入方式。

## 3. 角色与流量

如果你问“让它真正承载流量怎么做”，答案是：

1. 先在控制面把节点注册成正确角色。
2. 再把该节点部署成对应的数据面角色。
3. 让控制面持续给它下发配置和心跳目标。

`anix-node` 负责登记、同步和心跳，不直接承载用户流量。  
真正承载流量的是节点上部署的数据面角色：

- `overseas-edge`
- `core`
- `egress`

## 4. 管理员是否需要手动指定角色

**第一次上线时，需要。**

原因很简单：控制面必须知道这台机器是 `overseas-edge`、`core` 还是 `egress`，否则无法正确下发配置和路由策略。

但这不代表你每次都要人工改：

- 角色一旦定了，后续主要由控制面分发配置
- 设备上线、心跳、策略版本和证书都可以自动同步
- 你只需要在首次接入和角色变更时明确一次

## 5. 控制面最小启动

```sh
mkdir -p /var/lib/anixops
./anix-control \
  --addr 0.0.0.0:8080 \
  --store-file /var/lib/anixops/control-store.json \
  --session-file /var/lib/anixops/sessions.json \
  --config-signing-key-file /var/lib/anixops/config-signing-key.pem \
  --password-users-file /etc/anixops/password-users.json
```

如果你还要启用 CA、CRL 发布或 OIDC，再按需加上：

- `--ca-cert` / `--ca-key`
- `--crl-publish-dir`
- `--oidc-config-file`

## 6. 登录控制面

```sh
curl -sS http://127.0.0.1:8080/v1/login \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "tenant-a",
    "subject_id": "admin-a",
    "password": "password",
    "ttl_hours": 8
  }'
```

把返回里的 `token` 保存下来：

```sh
export TOKEN='<session-token>'
export TENANT='tenant-a'
```

## 7. 创建租户

```sh
curl -X POST http://127.0.0.1:8080/v1/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "tenant-a",
    "name": "Tenant A"
  }'
```

## 8. 注册节点

### 8.1 海外边界节点

```sh
curl -X POST http://127.0.0.1:8080/v1/tenants/$TENANT/nodes \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "hk-edge-1",
    "role": "overseas-edge",
    "region": "hk",
    "endpoint": "hk-edge-1.example.com:443",
    "healthy": true
  }'
```

### 8.2 海外 Core 节点

```sh
curl -X POST http://127.0.0.1:8080/v1/tenants/$TENANT/nodes \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "core-jp-1",
    "role": "core",
    "region": "jp",
    "endpoint": "core-jp-1.example.com:51820",
    "healthy": true
  }'
```

### 8.3 出口节点

```sh
curl -X POST http://127.0.0.1:8080/v1/tenants/$TENANT/nodes \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "egress-us-1",
    "role": "egress",
    "region": "us-west",
    "endpoint": "egress-us-1.example.com:443",
    "healthy": true
  }'
```

## 9. 下发节点配置

节点配置的 `target_id` 必须和节点 ID 一致。

### 9.1 非大陆专线海外节点

```sh
curl -X POST http://127.0.0.1:8080/v1/tenants/$TENANT/configs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "cfg-hk-edge-1",
    "target_id": "hk-edge-1",
    "version": "v1",
    "values": {
      "endpoint": "hk-edge-1.example.com:443",
      "region": "hk",
      "healthy": "true",
      "transport": "reality"
    }
  }'
```

### 9.2 大陆专线直达海外节点

```sh
curl -X POST http://127.0.0.1:8080/v1/tenants/$TENANT/configs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "cfg-core-jp-1",
    "target_id": "core-jp-1",
    "version": "v1",
    "values": {
      "endpoint": "core-jp-1.example.com:51820",
      "region": "jp",
      "healthy": "true",
      "transport": "wireguard"
    }
  }'
```

`values` 里最常用的是：

- `endpoint`
- `region`
- `healthy`
- `transport`

## 10. 启动节点同步

先跑一次同步，确认控制面和节点连通：

```sh
./anix-node \
  --sync-once \
  --control-url http://127.0.0.1:8080 \
  --tenant-id tenant-a \
  --node-id hk-edge-1 \
  --role overseas-edge \
  --region hk \
  --endpoint hk-edge-1.example.com:443 \
  --healthy=true
```

如果是大陆专线直达海外节点，就把 `--role` 改成对应角色，并把控制面下发的 `transport` 设为 `wireguard`。

## 11. 检查是否真正上线

```sh
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/v1/tenants/$TENANT/inventory

curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8080/v1/tenants/$TENANT/audit?limit=20"
```

你应该看到：

- 节点出现在 inventory
- 有 `node.heartbeat` 审计
- 有 `config.upsert` 审计

## 12. 什么时候算“真正承载流量”

不是 `anix-node` 跑起来就算。  
要算真正承载流量，至少要满足：

- 节点角色已在控制面注册
- 节点已经收到正确配置
- 节点上对应的数据面角色已部署
- 探测和心跳都正常
- 对外接入链路按规则选择：
  - 大陆专线直达：WireGuard
  - 非大陆专线：WireGuard over REALITY

## 13. 四台服务器示范案例

假设你现在有四台服务器：

1. `cn-leased-1`，大陆专线服务器，出口是大陆 IP，直达香港 IP
2. `cn-plain-1`，普通大陆服务器
3. `hk-plain-1`，香港普通服务器
4. `jp-plain-1`，日本服务器

推荐分配如下：

### 13.1 `cn-leased-1`

- 角色：`china-entry`
- 外层接入：**Native WireGuard**
- 用途：大陆侧直接进海外的入口

这是你的大陆专线入口机。  
它不走 REALITY，直接用 WireGuard 去连海外节点。

### 13.2 `cn-plain-1`

- 角色：**不建议直接放进海外流量路径**
- 用途：控制面登录、运维跳板、Agent 测试机或普通用户接入机

这台机器是普通大陆服务器，默认不要把它硬塞成海外流量节点。  
如果你要让它接入海外流量路径，应该先确认它的出口链路能否接受对应的传输方式，再决定是否作为用户侧 Agent 接入端使用。

### 13.3 `hk-plain-1`

- 角色：`overseas-edge`
- 外层接入：**WireGuard over REALITY**
- 用途：海外边界入口节点

这是普通香港海外节点，适合做海外边界入口。  
如果它不是大陆专线直达，就按 WireGuard over REALITY 接入。

### 13.4 `jp-plain-1`

- 角色：`core`
- 外层接入：**WireGuard over REALITY** 或 **WireGuard**，取决于它是否走大陆专线
- 用途：海外 Core 节点

这台日本服务器适合做海外 Core 节点，负责 WireGuard Overlay 和动态路由。  
如果它本身是普通公网线路，就用 WireGuard over REALITY 先接入海外；如果它是大陆专线可直达的海外节点，就可以直接 WireGuard。

## 14. 这个四机案例里，谁真正承载流量

- `cn-leased-1`：承载大陆到海外的入口流量
- `hk-plain-1`：承载海外边界入口流量
- `jp-plain-1`：承载海外 Core Overlay 流量
- `cn-plain-1`：默认不放进海外流量路径，更多是运维或用户接入端

如果你后续还要单独加 `egress` 节点，建议再加一台海外出口机，或者把现有海外节点按容量再拆分一台出来。  
在正式生产里，`core` 和 `egress` 最好不要长期混在一台容量紧张的机器上。
