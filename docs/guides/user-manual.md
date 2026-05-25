# 用户手册

这份手册面向普通用户或设备管理员，目标是把一台电脑接入 SD-WAN。

## 1. 安装客户端

你需要两样东西：

- `anix-agent`
- `anix-ui`

Linux 服务器或网关场景只需要 `anix-agent`。  
桌面用户建议一起装 `anix-ui`。

## 2. 启动 Agent

```sh
mkdir -p ~/.anixops
./anix-agent \
  --control-url http://127.0.0.1:8080 \
  --tenant-id tenant-a \
  --device-id laptop-01 \
  --cache-file ~/.anixops/agent-cache.json \
  --telemetry-queue-file ~/.anixops/telemetry.json \
  --local-api-addr 127.0.0.1:18080
```

如果你已经拿到了控制面签发的配置签名公钥，再加上：

```sh
--config-signing-public-key <base64-ed25519-public-key>
```

## 3. 看本机状态

```sh
curl http://127.0.0.1:18080/healthz
curl http://127.0.0.1:18080/v1/snapshot
curl http://127.0.0.1:18080/v1/telemetry
curl http://127.0.0.1:18080/v1/config
```

如果控制面下发了配置，你会看到：

- `config_version`
- 当前 `transport`
- 链路、遥测和运行状态

## 4. 打开桌面 UI

```sh
./anix-ui --agent-url http://127.0.0.1:18080
```

UI 里常用的页面是：

- `Settings`：查看和提交本机配置
- `Protocol switching`：切换传输协议
- `Diagnostics`：运行自检
- 系统托盘菜单：显示窗口、自检、开机自启

## 5. 用户怎么接入

用户不直接操作海外节点，而是通过 Agent 接入控制面下发的配置。

典型流程是：

1. 管理员在控制面里创建你的设备。
2. 管理员给你的设备下发配置，里面指定使用哪种传输和哪个节点。
3. 你的 `anix-agent` 定期和控制面同步。
4. 你的业务流量由本机 Agent 接管，然后转入平台选择的节点路径。

如果你只是要先验证本机联通，可以先跑一次同步：

```sh
./anix-agent \
  --sync-once \
  --control-url http://127.0.0.1:8080 \
  --tenant-id tenant-a \
  --device-id laptop-01 \
  --config-signing-public-key <base64-ed25519-public-key> \
  --cache-file ~/.anixops/agent-cache.json \
  --telemetry-queue-file ~/.anixops/telemetry.json
```

## 6. 最常见检查项

- 能不能看到当前 `config_version`
- 能不能看到当前 `transport`
- `Diagnostics` 自检是不是通过
- `v1/snapshot` 和 `v1/telemetry` 有没有返回内容

## 7. 如果改了配置但没生效

先确认三件事：

- 设备 ID 是否和控制面里登记的一致
- 配置的 `target_id` 是否和你的设备 ID 一致
- Agent 是否还在和控制面同步

如果你是桌面用户，也可以直接在 `anix-ui` 的 `Settings` 页面重新应用配置。

