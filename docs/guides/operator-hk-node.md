# 香港节点接入手册

这份手册面向网络管理员，目标是把一台香港机器接入 SD-WAN，作为 `overseas-edge`、`core` 或 `egress` 节点使用。

推荐选择：

- `overseas-edge`：香港边界入口节点
- `egress`：香港出口节点
- `core`：香港参与海外 WireGuard Core

## 1. 先起控制面

控制面负责租户、节点、配置、证书和审计。最小启动示例：

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

## 2. 登录控制面

如果你启用了密码登录，先换一个管理员会话 token：

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

从返回里取 `token`，后续请求都带上：

```sh
export TOKEN='<session-token>'
export TENANT='tenant-a'
```

## 3. 创建租户

如果租户还不存在，先建租户：

```sh
curl -X POST http://127.0.0.1:8080/v1/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "tenant-a",
    "name": "Tenant A"
  }'
```

## 4. 注册香港节点

假设这台香港机器准备作为海外边界节点：

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

如果你要它作为出口节点，把 `role` 改成 `egress`。  
如果你要它参与海外 Core，把 `role` 改成 `core`。

## 5. 下发这个节点的配置

节点配置的 `target_id` 要和节点 ID 对上。

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
      "healthy": "true"
    }
  }'
```

这里的 `values` 是节点服务读取的本地配置字段：

- `endpoint`
- `region`
- `healthy`

## 6. 在香港机器上启动节点同步进程

最小验证可以先跑一次同步：

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

如果输出里返回了节点快照，说明控制面连通、配置读取和心跳推送都通了。

要长期运行，就去掉 `--sync-once`：

```sh
./anix-node \
  --control-url http://127.0.0.1:8080 \
  --tenant-id tenant-a \
  --node-id hk-edge-1 \
  --role overseas-edge \
  --region hk \
  --endpoint hk-edge-1.example.com:443 \
  --healthy=true
```

## 7. 检查节点是否上线

```sh
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/v1/tenants/$TENANT/inventory

curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8080/v1/tenants/$TENANT/audit?limit=20"
```

你应该能看到：

- `nodes` 里出现香港节点
- `node.heartbeat` 审计记录
- `config.upsert` 审计记录

## 8. 让它真正承载流量

`anix-node` 负责的是节点登记、同步和心跳，不是用户流量本身。  
真正承载流量的是这个香港机器上部署的数据面角色：

- `overseas-edge`
- `core`
- `egress`

具体怎么把这台机变成哪个角色，要看你部署的是哪一层服务。这个仓库里对应的数据面能力已经拆到 `internal/edge`、`internal/core` 和 `internal/linuxgw`，并由远端运行时门禁验证过。

