# Sing 内核 DNS 解锁（默认关闭）

项目默认的 `example/sing_origin.json` 不使用解锁 DNS。
`example/sing_origin.dns-unlock.json` 是独立的可选示例，安装及节点向导不会自动启用。
示例中的 `4.4.4.4` 来自[服务商文档](https://doc.nfdns.top/pages/793dcb/#singbox)，
仅为占位地址，必须替换成实际分配的解锁 DNS，并在服务商处授权节点出口 IP。

## 启用

1. 备份 `/etc/V2bX/config.json` 和现有 `sing_origin.json`。
2. 将可选示例另存为 `/etc/V2bX/sing_origin.dns-unlock.json`，替换
   `dns.servers` 中 `dns_custom` 的地址。例如使用 `tcp://实际DNS地址`。
   如已有自定义路由，应合并所需字段，不要直接覆盖已有设置。
3. 将主配置中需要使用该策略的 sing 内核设置为：

```json
{
  "Type": "sing",
  "OriginalPath": "/etc/V2bX/sing_origin.dns-unlock.json"
}
```

保留原有 `Log`、`NTP` 等字段。该设置对共用此 sing 内核的节点生效。
无需给节点添加 Xray 的 `DnsConfigPath`、`DNSType` 或 `EnableDNS` 参数。
如需只给部分节点启用，使用独立命名的 sing 内核并通过节点 `CoreName` 选择。

4. 重启 `V2bX`，确认服务正常、各节点监听恢复，再通过实际节点验证。
   若启动或连接失败，恢复备份后重启。不要通过修改系统 DNS 来代替本配置。

## 配置原理

DNS 规则将指定流媒体规则集和 AI 域名交给 `dns_custom`，普通域名使用 `cf`。
路由开头的 `sniff` 从支持的明文握手中识别域名，随后 `resolve` 根据 DNS 规则解析，
让实际连接采用解锁结果。只有出口 `domain_resolver.server = cf` 而没有前置
`resolve` 时，会显式指定公共 DNS，绕过解锁规则。

示例保留服务商提供的私网和域名阻断规则，启用前应检查是否符合自己的需求。
远程规则集启动时需要联网下载；私网阻断位于解析之后，也会检查解析得到的地址。
客户端仅发送 IP、且协议无法嗅探出域名时，无法按域名解锁；TLS ECH 等机制也可能限制嗅探。
优先让客户端把目标域名交给代理，而非先在客户端解析为 IP。

## 验证与关闭

先在节点主机执行 `dig @实际DNS地址 chatgpt.com A`，必要时加 `+tcp`，
确认 DNS 有响应；再使用实际代理访问普通站点和解锁站点。
临时开启 sing 内核 debug 日志可确认目标域名命中 `route(dns_custom)`，并记录实际解析结果。
OpenAI 未带 Key 时返回 HTTP 401 是接口鉴权响应，不代表账号或所有流媒体已解锁；
流媒体区域、播放和账号功能仍需分别验证。

关闭时将 sing 内核的 `OriginalPath` 改回原来的普通配置文件，再重启服务。

## 管理菜单（sing / Xray）

管理脚本选择「流媒体 DNS 解锁」，或运行 `V2bX dns-unlock`。
菜单提供开启、查看状态、关闭并恢复原配置；主菜单退出项始终排在最后。
安装后默认关闭。开启时输入实际 DNS IP，默认 TCP 53，也支持
`tcp://IP:端口` 和 `udp://IP:端口`。模板内置在二进制中，无需手动下载。

开启会识别现有 sing/Xray 内核和节点，合并配置到独立的
`/etc/V2bX/dns-unlock-随机目录/` 中，保留用户原始配置文件。
sing 绑定合并后的 OriginalPath；Xray 绑定合并后的 DnsConfigPath，
并设置对应节点 EnableDNS=true、DNSType=UseIP、SendIP=0.0.0.0。
原 DNS 服务器、路由和其他字段会保留，解锁域名规则优先。
Xray 模板需要安装包附带的 geosite.dat；缺失时校验失败，不修改运行配置。

程序先验证 DNS 查询及候选内核，再停止服务保存配置并启动，检查原有 TCP
节点监听是否恢复；失败自动尝试恢复原配置和服务。该菜单目前支持 systemd
管理且有 TCP 节点监听的主机，其他环境会明确报错，不修改配置。
Include 节点、自定义原始入站、Xray 外部入站/出站及内核选择歧义等情况需手动处理。

关闭仅恢复本功能修改的主配置字段，保留后来无关的配置修改和新增节点。
若托管字段被手动修改则停止恢复，避免覆盖。恢复元数据在
`config.json.dns-unlock.json`，启用前完整配置另存于托管目录的
`config.before.json`；目录保留供审查与恢复。菜单状态只表示菜单托管状态，
不代表手动配置的开关，也不保证所有流媒体已解锁。

启用后再新增的 Xray 节点需要重新关闭、开启一次以纳入管理；不要直接复制
托管的 EnableDNS 等字段到新节点。若原始文件本身已手动开启解锁，关闭菜单
会恢复该原始文件，仍保留其解锁行为。

Xray 若面板本身也下发 DNS 配置，现有内核会写回 DnsConfigPath，对应设置可能覆盖菜单配置；此类情况应统一由面板或本机管理，启用后需核对。多个 Xray 核心还受到现有全局 XRAY_DNS_PATH 实现的限制。
