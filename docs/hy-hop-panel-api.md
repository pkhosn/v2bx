# V2Board 向节点向导提供 HY2 跳跃范围

当前本机维护的 V2Board 在
`app/Http/Controllers/V1/Server/UniProxyController.php` 的 `case 'hysteria'`
仅向后端返回 `server_port` 等字段，没有返回订阅使用的 `port`。
因此后端无法凭空获取订阅范围，旧面板需在向导手动填写。

面板维护者可在 HY2 响应中额外返回节点保存的原始 `port`：

```php
$response['port'] = $this->nodeInfo->port;
```

放在现有 `version == 2` 分支内即可。保留 `server_port` 原值，不修改节点数据、订阅生成、用户认证或私钥。
例如面板原始 `port` 为 `40000-40009`、`server_port` 为 `36005`，后端收到这两个不同字段后可在向导提示自动配置。
如果面板另有明确的 `mport` 字段，可按实际模型额外返回；不要假定数据库一定有此字段。

使用面板既有测试框架验证：HY2 端口范围原样输出、单端口仍为原值、server_port 保持整数监听端口，HY1 及其他协议响应不变。
本次 V2bX 改动未修改面板仓库或生产面板配置。
