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

## 推荐协议配置（中国网络环境，2026-04）

以下为兼顾长期可维护性、稳定性与抗干扰能力的推荐顺序（建议主备并行部署）：

1. 主力：`VLESS + REALITY + XHTTP`（TCP 系）
2. 主备：`VLESS + WS + TLS + Cloudflare（橙云）+ ECH`
3. 兼容备份：`Trojan + WS + TLS + Cloudflare（橙云）+ ECH`
4. 速度备线（不建议单独作为主力）：`Hysteria2` 或 `TUIC`（QUIC/UDP）

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

### 文档中心（V2bX_doc）

已将 `wyx2685/V2bX_doc` 文档仓库完整复制到本项目 `docs/` 目录，便于直接在 `pkhosn/v2bx` 内查看安装与配置文档。

- 文档首页：[`docs/README.md`](docs/README.md)
- 文档目录：[`docs/SUMMARY.md`](docs/SUMMARY.md)
- 一键安装文档：[`docs/xrayr-xia-zai-he-an-zhuang/install/one-click.md`](docs/xrayr-xia-zai-he-an-zhuang/install/one-click.md)
- 手动安装文档：[`docs/xrayr-xia-zai-he-an-zhuang/install/manual.md`](docs/xrayr-xia-zai-he-an-zhuang/install/manual.md)

### vmess TLS 自动证书模板（http/dns）

以下模板用于新增 vmess TLS 节点（示例域名 `vmess.example.com`）。

- 将 `NodeID` 改为面板中该 vmess 节点的实际 ID
- `ApiHost`、`ApiKey` 改为你自己的面板地址和 `SERVER_TOKEN`
- `http` 模式需要 80 端口可达；`dns` 模式需要 DNS API 凭据

#### http 模式（HTTP-01）

```json
{
  "Core": "xray",
  "ApiHost": "https://your-panel-domain",
  "ApiKey": "YOUR_SERVER_TOKEN",
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
  "DNSType": "UseIPv4",
  "CertConfig": {
    "CertMode": "http",
    "RejectUnknownSni": false,
    "CertDomain": "vmess.example.com",
    "CertFile": "/etc/V2bX/certs/vmess.example.com.crt",
    "KeyFile": "/etc/V2bX/certs/vmess.example.com.key",
    "Email": "admin@example.com"
  }
}
```

#### dns 模式（DNS-01，以 Cloudflare 为例）

```json
{
  "Core": "xray",
  "ApiHost": "https://your-panel-domain",
  "ApiKey": "YOUR_SERVER_TOKEN",
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
  "DNSType": "UseIPv4",
  "CertConfig": {
    "CertMode": "dns",
    "RejectUnknownSni": false,
    "CertDomain": "vmess.example.com",
    "CertFile": "/etc/V2bX/certs/vmess.example.com.crt",
    "KeyFile": "/etc/V2bX/certs/vmess.example.com.key",
    "Email": "admin@example.com",
    "Provider": "cloudflare",
    "DNSEnv": {
      "CF_DNS_API_TOKEN": "YOUR_CLOUDFLARE_TOKEN"
    }
  }
}
```

配置完成后执行：

```bash
mkdir -p /etc/V2bX/certs
systemctl restart V2bX
journalctl -u V2bX -f
```

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
