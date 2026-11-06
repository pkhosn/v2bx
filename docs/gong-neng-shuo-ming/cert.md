# 自动申请证书说明

V2bX 支持多种自动申请证书配置。申请到的证书将会放在配置文件`config.json`指定的目录下。

以下是自动申请证书的相关配置文件说明。

```json
      "CertConfig": {
        // 证书申请模式，none、http、dns、self
        "CertMode": "none",
        "RejectUnknownSni": false,
        // 证书域名
        "CertDomain": "test.com",
        // 证书文件目录
        "CertFile": "/etc/V2bX/certs/acme/test.com/fullchain.cer",
        // 密钥文件目录
        "KeyFile": "/etc/V2bX/certs/acme/test.com/cert.key",
        // 申请证书时使用的用户邮箱
        "Email": "v2bx@github.com",
        // DNS解析提供者 详见https://go-acme.github.io/lego/dns/的CLI flag name列
        "Provider": "cloudflare",

        // DNS解析提供者的环境变量，详见https://go-acme.github.io/lego/dns/，以cloudflare为例
        "DNSEnv": {
          "CF_DNS_API_TOKEN": "1234567890abcdefghijklmnopqrstuvwxyz"
        }
      }
```

| 参数                 | 选项                         | 说明                                                                                                                                                                                              |
| ------------------ | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CertMode`         | `none`,`http`,`dns`,`self` | <p>获取证书的方式。</p><p><code>none</code>：强制关闭tls设置。</p><p><code>http</code>：通过http申请，需要80端口。</p><p><code>dns</code>：使用dns模式申请，需要制定相关dns服务商配置。</p><p><code>self</code>:指定文件路径手动提供，若路径无文件则使用自签名证书。</p> |
| `RejectUnknownSni` | `true`, `false`            | Xray内核专用，服务端接收到的 SNI 与证书域名不匹配即拒绝 TLS 握手，默认为`false`。                                                                                                                                             |
| `CertDomain`       | 无                          | 申请证书域名                                                                                                                                                                                          |
| `CertFile`         | 无                          | 手动指定的证书路径                                                                                                                                                                                       |
| `KeyFile`          | 无                          | 手动指定的私钥路径                                                                                                                                                                                       |
| `Provider`         | 无                          | dns提供商，所有支持的dns提供商请在此获取：[https://go-acme.github.io/lego/dns/](https://go-acme.github.io/lego/dns/)                                                                                              |
| `DNSEnv`           | 无                          | 采用DNS申请证书需要的环境变量，请参考上文链接内，自己的dns提供商所需要的参数，填写于此。请注意一行一个，填写时需符合json文件格式。                                                                                                                          |



## 目录与旧证书迁移

首次配置和新增节点使用同一个向导。HTTP/DNS 自动证书保存在配置目录的
`certs/acme/域名/` 下，同域名可复用已验证证书；自签证书由向导创建独立目录。
手动提供的证书路径保持原样。运行时仍以 `CertFile`、`KeyFile` 为准，不会擅自迁移。

旧版根目录 `fullchain.cer`、`cert.key` 可使用以下命令迁移：

```bash
# 先预览，校验证书及目标目录，不修改文件
/usr/local/V2bX/V2bX cert-migrate --config /etc/V2bX/config.json
# 停止服务以避免与自动续期同时写入；迁移成功后启动
systemctl stop V2bX
/usr/local/V2bX/V2bX cert-migrate --config /etc/V2bX/config.json --apply
# 仅在上一条成功后执行
systemctl start V2bX
```

命令仅迁移内联配置中的 HTTP/DNS 旧版标准路径，不处理手动证书、自签证书、
自定义路径及外部 Include 配置。已有目标目录会拒绝覆盖。
迁移复制证书、私钥及对应邮箱的 ACME 账户，不重新申请证书。
缺失账户文件时会明确提示，后续续期沿用原有注册机制。
全部校验成功才原子更新配置；原配置保存在 `config.json.bak`，原文件保留。
若失败，配置保持原样，本次创建的域名目录会清理；可按原配置启动服务。
需要回退时，停止服务并用备份恢复配置，再启动服务；无需重新申请证书。
