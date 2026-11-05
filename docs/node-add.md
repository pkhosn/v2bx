# 追加节点与自动证书

需要包含 `node-add` 命令的新二进制及新版管理脚本。只有更新脚本、仍使用旧 Release 二进制时，脚本会提示升级并停止。

- 管理菜单 **18** 或 `v2bx add`：追加一个或多个节点，保留原有节点、内核与自定义字段。
- 管理菜单 **15** 或 `v2bx generate`：重新生成配置，必须输入 `REPLACE` 确认。
- 首次安装使用同一向导。直接运行：`/usr/local/V2bX/V2bX node-add --config /etc/V2bX/config.json`。

交互沿用旧管理脚本：输入面板信息、选择是否固定面板信息，再按数字选择内核、输入 Node ID、按数字选择协议；证书依次选择模式、输入域名。连续添加时回车继续，固定的面板信息自动复用。数字选项、节点 ID、域名或邮箱格式有误时原地重试。

向导查询面板节点信息确定 TLS 状态，REALITY 和无 TLS 节点不申请普通证书。面板 API Key 与 Cloudflare Token 在终端中隐藏输入。

HTTP 模式需要域名，不需要 Cloudflare Token。ACME 联系邮箱可留空；已有正常邮箱会作为默认值，不再使用旧脚本的占位邮箱。lego 注册实现支持不提供邮箱。域名必须直连本机，公网 TCP 80 必须可用于 ACME HTTP 验证；向导不会自动关闭防火墙或停止占用端口的服务。HTTP 无法使用时可以选择 Cloudflare DNS 模式，输入具有对应域名 Zone Read 与 DNS Edit 权限的 API Token。联系邮箱不是 Cloudflare 登录凭据。已有 Cloudflare 凭据可明确选择复用。

ACME 证书按域名保存在配置目录的 `certs/acme/域名/` 下，可以明确选择复用已有同域名有效证书及续期配置。自签证书每次使用独立目录；它不具有公开信任，需要客户端信任。也可指定已有证书文件。复用前检查有效期、域名与私钥匹配；运行中的自动续期沿用原有 lego 机制。

面板查询、输入或证书准备失败时不保存配置。成功后以 0600 权限原子替换配置，原文件备份为 `config.json.bak`；检测到并发修改会拒绝保存。JSON5 注释和尾逗号输入受支持，写出为格式化 JSON，注释不会保留。配置包含 API Key/DNS Token，备份同样按敏感文件管理。

追加不同内核时，原来省略 Core 的单内核节点会固定到原内核；多内核配置中省略 Core 的节点、以及无法安全补充选择的 Include 节点会要求先明确选择。不会改写路由和其他辅助文件。相同面板、协议、节点 ID 的重复配置会被拒绝。

管理脚本在保存成功后重启服务；配置监视也可能触发重载。应用配置会短暂影响所有节点。查询面板和准备证书不等于完整启动验证：节点监听端口冲突等错误仍需通过服务日志检查。直接使用 Go 命令只保存配置，不调用服务管理器。

## 本地验证

使用项目既有 Go testing，无需真实 DNS 凭据或公网 ACME：

```sh
GOEXPERIMENT=jsonv2 go test -trimpath -p 1 -count=1 -timeout 90s ./...
GOEXPERIMENT=jsonv2 go test -trimpath -p 1 -count=1 -timeout 90s -tags 'sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' ./cmd ./node
bash -n script/V2bX.sh script/initconfig.sh
GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -p 1 -trimpath -tags 'sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' -o /tmp/V2bX .
```

覆盖字段保留、跨内核追加、重复检测、旧节点内核固定、配置备份与并发修改保护、交互成功及失败不写入、REALITY 无证书、DNS 凭据采集、自签证书复用与域名检查。真实公网 HTTP/DNS 签发需要部署环境和域名授权，未在本地模拟测试中声称通过。
