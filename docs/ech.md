# 自定义 ECH 试用（第一阶段）

范围：sing 内核、VMess/VLESS 普通 TLS 入站；当前以 VMess + WebSocket 实测。Xray 服务端暂不接入自定义 ECH，选择不支持的内核会明确报错。REALITY 不与普通 TLS ECH 混用。现有菜单保持不变，节点跟随面板的自定义设置。

面板下发 `tlsSettings` 或 `tls_settings`，包含 `ech: custom`、`ech_key`、`ech_config`；私钥只通过有权限的节点 API 获取，不能进入用户订阅。`serverName` 和 `server_name` 均接受。

密钥采用当前 sing/Xray 的二进制格式：逐组 uint16 私钥长度、X25519私钥、uint16 ECHConfig长度、ECHConfig；Base64 或 `ECH KEYS` PEM 均可。客户端公开配置是包含总长度的 ECHConfigList（Base64 或 `ECH CONFIGS` PEM）。sing 客户端需要 PEM；Xray 客户端使用 Base64 ECHConfigList。

兼容早期面板的单密钥索引格式，并校验公私钥、客户端公开配置一致性。不在启动时重新生成密钥。旧面板生成的公开配置可能缺少总长度：服务端可以兼容读取，但客户端订阅仍需转换，不能声称仅更新 V2bX 即完成客户端兼容。

Cloudflare ECH 属于客户端连接对应边缘的配置，不能把 Cloudflare 公钥当作直连 VPS 的自定义 ECH。TLS证书继续使用原有申请/续期机制。ECH成功后可保护内部SNI，但外部名称与服务器IP仍可见。

验证沿用 Go testing，本机禁网容器运行：

```sh
GOEXPERIMENT=jsonv2 go test -trimpath -p 1 -count=1 -timeout 90s ./...
GOEXPERIMENT=jsonv2 go test -trimpath -p 1 -count=1 -timeout 90s -tags 'sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' ./cmd ./core/sing ./core/xray ./node
```

`TestInboundECHHandshake` 通过真正 TLS 握手，检查两端 ECHAccepted=true；普通TLS可连接；错误ECH密钥不能静默回退。`TestECHVMessWebSocketForward` 验证实际 sing 入站与客户端之间完整代理转发。设置 `V2BX_ECH_PANEL_FIXTURE` 为面板Helper生成的JSON，可用真实PHP生成密钥运行握手及转发测试。不得只凭网页打开认定ECH生效。

发布前：本机验证 → 保存远端原二进制及配置 → 部署试用版 → 面板5号选择自定义ECH → 更新客户端公开配置/订阅 → 验证公网ECH接受及转发 → 用户确认。出现失败按备份回滚，禁止输出私钥。
