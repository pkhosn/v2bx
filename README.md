# V2bX

[![](https://img.shields.io/badge/TgChat-UnOfficialV2Board%E4%BA%A4%E6%B5%81%E7%BE%A4-green)](https://t.me/unofficialV2board)
[![](https://img.shields.io/badge/TgChat-YuzukiProjects%E4%BA%A4%E6%B5%81%E7%BE%A4-blue)](https://t.me/YuzukiProjects)

A V2board node server based on multi core, modified from XrayR.  
一个基于多种内核的V2board节点服务端，修改自XrayR，支持V2ay,Trojan,Shadowsocks协议。

**注意： 本项目需要搭配[修改版V2board](https://github.com/pkhosn/v2board)**

## 特点

* 永久开源且免费。
* 支持Vmess/Vless, Trojan， Shadowsocks, Hysteria1/2多种协议。
* 支持Vless和XTLS等新特性。
* 支持单实例对接多节点，无需重复启动。
* 支持限制在线IP。
* 支持限制Tcp连接数。
* 支持节点端口级别、用户级别限速。
* 配置简单明了。
* 修改配置自动重启实例。
* 支持多种内核，易扩展。
* 支持条件编译，可仅编译需要的内核。

## 功能介绍

| 功能        | v2ray | trojan | shadowsocks | hysteria1/2 |
|-----------|-------|--------|-------------|----------|
| 自动申请tls证书 | √     | √      | √           | √        |
| 自动续签tls证书 | √     | √      | √           | √        |
| 在线人数统计    | √     | √      | √           | √        |
| 审计规则      | √     | √      | √           | √         |
| 自定义DNS    | √     | √      | √           | √        |
| 在线IP数限制   | √     | √      | √           | √        |
| 连接数限制     | √     | √      | √           | √         |
| 跨节点IP数限制  |√      |√       |√            |√          |
| 按照用户限速    | √     | √      | √           | √         |
| 动态限速(未测试) | √     | √      | √           | √         |

## TODO

- [ ] 重新实现动态限速
- [ ] 完善使用文档

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/pkhosn/V2bX-script/master/install.sh && bash install.sh
```

### 手动安装

[手动安装教程](https://v2bx.v-50.me/v2bx/v2bx-xia-zai-he-an-zhuang/install/manual)

### 面板全节点对接（pkhosn/v2bx）

以下流程用于把一个 V2bX 实例一次性对接面板中的全部节点（vmess/vless/shadowsocks/trojan/tuic/anytls/hysteria2）。

1. 安装 V2bX：

```bash
wget -N https://raw.githubusercontent.com/pkhosn/V2bX-script/master/install.sh && bash install.sh
```

2. 准备证书目录（推荐每个 TLS 节点域名单独证书）：

```bash
mkdir -p /etc/V2bX/certs
```

3. 写入 `/etc/V2bX/config.json`：
- `ApiHost` 填面板地址（如 `http://your-panel-domain`）
- `ApiKey` 填面板 `SERVER_TOKEN`
- `Nodes` 中为每个节点填写 `NodeType + NodeID`
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

4. 若使用 `self` 证书模式，先生成证书文件：

```bash
for d in trojan.example.com tuic.example.com anytls.example.com hy2.example.com; do
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "/etc/V2bX/certs/${d}.key" \
    -out "/etc/V2bX/certs/${d}.crt" \
    -days 3650 -subj "/CN=${d}"
done
```

5. 启动并检查：

```bash
systemctl restart V2bX
systemctl status V2bX --no-pager
journalctl -u V2bX -f
```

6. 验证面板联通：
- 日志出现 `Added ... users`、`Nodes started`
- 各节点端口正常监听（如 `10050/10400/10000/10001/10300/10500/443(udp)`）
- `UniProxy/user` 接口对每个 `node_type + node_id` 返回 `200`

## 构建
``` bash
# 通过-tags选项指定要编译的内核， 可选 xray， sing, hysteria2
GOEXPERIMENT=jsonv2 go build -v -o build_assets/V2bX -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" -trimpath -ldflags "-X 'github.com/pkhosn/v2bx/cmd.version=$version' -s -w -buildid="
```

## 配置文件及详细使用教程

[详细使用教程](https://v2bx.v-50.me/)

## 免责声明

* 此项目用于本人自用，因此本人不能保证向后兼容性。
* 由于本人能力有限，不能保证所有功能的可用性，如果出现问题请在Issues反馈。
* 本人不对任何人使用本项目造成的任何后果承担责任。
* 本人比较多变，因此本项目可能会随想法或思路的变动随性更改项目结构或大规模重构代码，若不能接受请勿使用。

## 赞助

[赞助链接](https://v-50.me/)

## Thanks

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)
* [XrayR](https://github.com/XrayR/XrayR)
* [sing-box](https://github.com/SagerNet/sing-box)

## Stars 增长记录

[![Stargazers over time](https://starchart.cc/pkhosn/V2bX.svg)](https://starchart.cc/pkhosn/V2bX)
