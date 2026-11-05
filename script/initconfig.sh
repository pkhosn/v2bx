#!/bin/bash
# 首次安装与追加节点共用 Go 配置向导。
# Node configuration is handled by the installed binary so JSON escaping,
# certificate preparation and atomic updates use the same implementation.
run_node_wizard() {
    local binary=/usr/local/V2bX/V2bX
    if ! "$binary" node-add --help 2>/dev/null | grep -q -- '--replace'; then
        echo "当前 V2bX 二进制不支持节点追加，请先更新至包含 node-add 的版本。"
        return 1
    fi
    if "$binary" node-add --config /etc/V2bX/config.json "$@"; then
        v2bx restart
    else
        echo "配置向导失败，未重启服务；请检查上方错误。"
        return 1
    fi
}

add_node_config() {
    run_node_wizard
}

generate_config_file() {
    run_node_wizard
}
