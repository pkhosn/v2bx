# V2bX 面板全节点对接文档

本篇文档用于把一个 V2bX 实例一次性对接面板中的全部节点（`vmess`/`vless`/`shadowsocks`/`trojan`/`tuic`/`anytls`/`hysteria2`）。

## 1) 安装 V2bX

```bash
wget -N https://raw.githubusercontent.com/pkhosn/V2bX-script/master/install.sh && bash install.sh
```

## 2) 准备证书目录

```bash
mkdir -p /etc/V2bX/certs
```

## 3) 写入主配置

编辑 `/etc/V2bX/config.json`：

- `ApiHost` 填面板地址（例如 `http://your-panel-domain`）
- `ApiKey` 填面板 `SERVER_TOKEN`
- `Nodes` 里为每个节点填写 `NodeType + NodeID`
- `Cores` 建议同时启用 `xray`、`sing`、`hysteria2`

示例（单实例对接全部常见协议）：

```json
{
  "Log": { "Level": "info", "Output": "" },
  "Cores": [
    {
      "Type": "xray",
      "Log": { "Level": "error", "ErrorPath": "/etc/V2bX/error.log" },
      "OutboundConfigPath": "/etc/V2bX/custom_outbound.json",
      "RouteConfigPath": "/etc/V2bX/route.json"
    },
    {
      "Type": "sing",
      "Log": { "Level": "error", "Timestamp": true },
      "NTP": { "Enable": false, "Server": "time.apple.com", "ServerPort": 0 },
      "OriginalPath": "/etc/V2bX/sing_origin.json"
    },
    {
      "Type": "hysteria2",
      "Log": { "Level": "error" }
    }
  ],
  "Nodes": [
    {
      "Core": "xray",
      "ApiHost": "http://your-panel-domain",
      "ApiKey": "your_server_token",
      "NodeID": 1,
      "NodeType": "vmess",
      "Timeout": 30,
      "ListenIP": "0.0.0.0",
      "SendIP": "0.0.0.0",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "EnableProxyProtocol": false,
      "EnableUot": true,
      "EnableTFO": true,
      "DNSType": "UseIPv4"
    },
    {
      "Core": "xray",
      "ApiHost": "http://your-panel-domain",
      "ApiKey": "your_server_token",
      "NodeID": 1,
      "NodeType": "vless",
      "Timeout": 30,
      "ListenIP": "0.0.0.0",
      "SendIP": "0.0.0.0",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "EnableProxyProtocol": false,
      "EnableUot": true,
      "EnableTFO": true,
      "DNSType": "UseIPv4"
    },
    {
      "Core": "xray",
      "ApiHost": "http://your-panel-domain",
      "ApiKey": "your_server_token",
      "NodeID": 1,
      "NodeType": "shadowsocks",
      "Timeout": 30,
      "ListenIP": "0.0.0.0",
      "SendIP": "0.0.0.0",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "EnableProxyProtocol": false,
      "EnableUot": true,
      "EnableTFO": true,
      "DNSType": "UseIPv4"
    },
    {
      "Core": "xray",
      "ApiHost": "http://your-panel-domain",
      "ApiKey": "your_server_token",
      "NodeID": 3,
      "NodeType": "trojan",
      "Timeout": 30,
      "ListenIP": "0.0.0.0",
      "SendIP": "0.0.0.0",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "EnableProxyProtocol": false,
      "EnableUot": true,
      "EnableTFO": true,
      "DNSType": "UseIPv4",
      "CertConfig": {
        "CertMode": "self",
        "RejectUnknownSni": false,
        "CertDomain": "trojan.example.com",
        "CertFile": "/etc/V2bX/certs/trojan.example.com.crt",
        "KeyFile": "/etc/V2bX/certs/trojan.example.com.key"
      }
    },
    {
      "Core": "sing",
      "ApiHost": "http://your-panel-domain",
      "ApiKey": "your_server_token",
      "NodeID": 1,
      "NodeType": "tuic",
      "Timeout": 30,
      "ListenIP": "::",
      "SendIP": "0.0.0.0",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "TCPFastOpen": false,
      "SniffEnabled": true,
      "CertConfig": {
        "CertMode": "self",
        "RejectUnknownSni": false,
        "CertDomain": "tuic.example.com",
        "CertFile": "/etc/V2bX/certs/tuic.example.com.crt",
        "KeyFile": "/etc/V2bX/certs/tuic.example.com.key"
      }
    },
    {
      "Core": "sing",
      "ApiHost": "http://your-panel-domain",
      "ApiKey": "your_server_token",
      "NodeID": 1,
      "NodeType": "anytls",
      "Timeout": 30,
      "ListenIP": "::",
      "SendIP": "0.0.0.0",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "TCPFastOpen": false,
      "SniffEnabled": true,
      "CertConfig": {
        "CertMode": "self",
        "RejectUnknownSni": false,
        "CertDomain": "anytls.example.com",
        "CertFile": "/etc/V2bX/certs/anytls.example.com.crt",
        "KeyFile": "/etc/V2bX/certs/anytls.example.com.key"
      }
    },
    {
      "Core": "hysteria2",
      "ApiHost": "http://your-panel-domain",
      "ApiKey": "your_server_token",
      "NodeID": 1,
      "NodeType": "hysteria2",
      "Hysteria2ConfigPath": "/etc/V2bX/hy2config.yaml",
      "Timeout": 30,
      "ListenIP": "",
      "SendIP": "0.0.0.0",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "CertConfig": {
        "CertMode": "self",
        "RejectUnknownSni": false,
        "CertDomain": "hy2.example.com",
        "CertFile": "/etc/V2bX/certs/hy2.example.com.crt",
        "KeyFile": "/etc/V2bX/certs/hy2.example.com.key"
      }
    }
  ]
}
```

## 4) 生成 self 证书（可选）

若 `CertMode` 选择 `self`，先生成证书：

```bash
for d in trojan.example.com tuic.example.com anytls.example.com hy2.example.com; do
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "/etc/V2bX/certs/${d}.key" \
    -out "/etc/V2bX/certs/${d}.crt" \
    -days 3650 -subj "/CN=${d}"
done
```

## 5) 启动并验证

```bash
systemctl restart V2bX
systemctl status V2bX --no-pager
journalctl -u V2bX -f
```

验证点：

- 日志出现 `Added ... users` 和 `Nodes started`
- 各节点端口正常监听（如 `10050/10400/10000/10001/10300/10500/443(udp)`）
- `UniProxy/user` 接口对每个 `node_type + node_id` 返回 `200`
