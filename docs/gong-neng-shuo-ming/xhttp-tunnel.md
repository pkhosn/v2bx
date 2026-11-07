# XHTTP H3 与 Cloudflare Tunnel

本功能复用当前 Xray 内核，不引入 Xray-go 安装脚本或其他内核。默认不启用 H3，也不创建 Tunnel 服务。REALITY 已有支持，不需要为此更换内核。

## 直连 XHTTP H3

优先在面板 TLS 设置填写 ALPN 数组，例如 `["h3"]` 或 `["h2"]`，客户端订阅和后端读取同一份面板配置。后端通过既有节点轮询自动拉取并重建入站，通常在下一轮拉取后生效，无需手动修改服务器配置。

面板节点必须为 VLESS/VMess + XHTTP（或 splithttp）+ 普通 TLS，保留正常的 CertConfig 自动申请或已有证书设置。客户端使用相同路径、H3、正确的证书域名和证书校验。服务器防火墙与安全组需要放行节点的 UDP 端口。仅允许单项 `["h3"]`，避免配置看似包含 H3 实际仍启动 TCP HTTP 服务。

面板 `tls_settings.alpn`（兼容 `tlsSettings`）优先于本机设置；只有面板未提供 ALPN 时，才使用节点顶层 `TLSALPN` 作为旧面板兼容回退。面板显式空数组使用内核默认，阻止本机回退。两者都未设置时保持原行为。建议删除已有本机 `TLSALPN`，完全由面板管理。修改面板后客户端也需更新订阅。

当前 Xray 依赖的 H3 入站关闭清理存在已观察到的异常；若从 H3 切换后出现重复 UDP 监听或连接拒绝，需重启 V2bX 清理。H2 之间的参数更新使用既有自动重载。完整 H3 切换清理修复另行验证，不能保证所有切换都无需重启。

H3 使用 UDP。网络屏蔽 UDP 时此方案可能无法连接，不能保证直连 IP 或端口不会被封锁。

## 可选的固定 Cloudflare Tunnel

先安装官方 cloudflared（需支持 `tunnel run --token-file`）。菜单新增 `20. XHTTP Cloudflare Tunnel`，`21. 退出脚本`，也可运行：

```sh
/usr/local/V2bX/V2bX tunnel --config /etc/V2bX/config.json
```

准备一个独立的源站节点：显式 `Core=xray`、`ListenIP=127.0.0.1`、VLESS/VMess、XHTTP、无 TLS，并启动节点。不要直接把正在使用的公网直连节点改为回环。菜单读取面板配置并检查回环 TCP 端口可达，不会自动修改节点配置。

在 Cloudflare 控制台创建固定 Tunnel，配置公网域名到 `http://127.0.0.1:源站端口` 的映射，再在菜单输入 Tunnel Token。默认传输为 auto，可选择 http2 或 quic；该选项控制 cloudflared 到 Cloudflare 的连接，不等于客户端全程使用 UDP。

客户端订阅应连接 Cloudflare 公网域名、443、TLS，使用正确 SNI、证书校验和同一 XHTTP 路径；建议先以 packet-up 验证。面板向源站下发无 TLS，但客户端连接公网入口需要 TLS，若面板不能分别表达，需使用面板自定义订阅设置。此菜单不自动修改面板或生成订阅。Tunnel 与直连 H3 为两条不同路径，回环 HTTP 源站不要设置 TLSALPN=h3。

专属服务为 `V2bX-cloudflared.service`，Token 保存在 `/etc/V2bX/cloudflared.token`，权限 0600，不写进命令参数或服务正文。不操作其他 cloudflared 服务。菜单提供状态、日志查看指令及关闭；关闭删除专属服务与 Token，保留节点配置。

服务 active 仅表示进程运行；仍需检查注册日志、Cloudflare 路由、客户端订阅及真实代理连接。新服务器上的 Cloudflare 端到端测试待进行。

## 可重复的本地验证

使用 Go 1.25，项目现有测试框架和发布构建标签：

```sh
GOEXPERIMENT=jsonv2 go test -tags 'sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' ./... -count=1 -timeout=120s
GOEXPERIMENT=jsonv2 go build -tags 'sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' -o /tmp/V2bX-xhttp-test .
bash -n ../V2bX-script/V2bX.sh
git diff --check
```

`core/xray/inbound_test.go` 检查默认值、面板参数、本机覆盖、非法组合，并实际启动 Xray H3 服务、验证证书和代理响应。`cmd/tunnel_test.go` 使用临时目录与替代命令执行器验证服务文件、Token 权限和失败回滚；不会连接 Cloudflare 或更改本机 systemd 服务。
