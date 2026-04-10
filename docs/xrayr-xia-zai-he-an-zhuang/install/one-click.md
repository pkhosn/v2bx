# 使用一键脚本安装

## 软件安装

```bash
wget -N https://raw.githubusercontent.com/wyx2685/V2bX-script/master/install.sh && bash install.sh
```

配置文件路径：`/etc/V2bX` 配置文件详见：[配置文件说明](../../xrayr-pei-zhi-wen-jian-shuo-ming/config.md)

## 软件更新

```bash
v2bx update
```

## sing / xray 双配置建议

一键安装后可准备两套配置，便于随时切换内核：

- `config.sing.json`（默认）
- `config.xray.json`（备用）
- `sing_origin.json`（sing 内核的 `OriginalPath` 需要该文件）

可参考：

- `example/config.sing.json`
- `example/config.xray.json`
- `example/sing_origin.json`

切换步骤：

```bash
cp /etc/V2bX/config.sing.json /etc/V2bX/config.json
systemctl restart V2bX
```

或：

```bash
cp /etc/V2bX/config.xray.json /etc/V2bX/config.json
systemctl restart V2bX
```
