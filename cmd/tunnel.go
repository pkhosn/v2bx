package cmd

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkhosn/v2bx/api/panel"
	"github.com/pkhosn/v2bx/conf"
	"github.com/spf13/cobra"
)

const tunnelUnit = "V2bX-cloudflared.service"
const tunnelService = "/etc/systemd/system/" + tunnelUnit
const tunnelToken = "/etc/V2bX/cloudflared.token"

func validateTunnelToken(token string) error {
	if len(token) < 32 || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return fmt.Errorf("隧道 Token 格式无效")
	}
	b, e := base64.StdEncoding.DecodeString(token)
	if e != nil {
		b, e = base64.RawStdEncoding.DecodeString(token)
	}
	if e != nil {
		return fmt.Errorf("隧道 Token 必须是 Cloudflare 提供的 Base64 Token")
	}
	var v struct {
		Account string `json:"a"`
		ID      string `json:"t"`
		Secret  string `json:"s"`
	}
	if json.Unmarshal(b, &v) != nil || v.Account == "" || v.ID == "" || v.Secret == "" {
		return fmt.Errorf("隧道 Token 缺少必要字段")
	}
	return nil
}
func tunnelUnitText(binary, protocol string) (string, error) {
	if !filepath.IsAbs(binary) || strings.ContainsAny(binary, " \t\r\n%$\"\\;'") {
		return "", fmt.Errorf("cloudflared 路径无效")
	}
	if protocol != "quic" && protocol != "http2" && protocol != "auto" {
		return "", fmt.Errorf("隧道协议无效")
	}
	return fmt.Sprintf("[Unit]\nDescription=V2bX managed Cloudflare Tunnel\nAfter=network-online.target V2bX.service\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=%s tunnel --no-autoupdate --protocol %s run --token-file %s\nRestart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\n\n[Install]\nWantedBy=multi-user.target\n", binary, protocol, tunnelToken), nil
}
func checkTunnelNode(path string, index int, fetch func(*conf.ApiConfig) (*panel.NodeInfo, error)) (int, error) {
	data, e := os.ReadFile(path)
	if e != nil {
		return 0, e
	}
	d, e := readDocument(data)
	if e != nil {
		return 0, e
	}
	if index < 1 || index > len(d.parsed) {
		return 0, fmt.Errorf("节点序号无效")
	}
	n := d.parsed[index-1]
	if n.Options.Core != "xray" {
		return 0, fmt.Errorf("请选择明确配置 Core=xray 的节点")
	}
	if n.Options.ListenIP != "127.0.0.1" {
		return 0, fmt.Errorf("请先将此节点 ListenIP 设置为 127.0.0.1，避免暴露无 TLS 入站")
	}
	if n.ApiConfig.NodeType != "vless" && n.ApiConfig.NodeType != "vmess" {
		return 0, fmt.Errorf("仅支持 VLESS/VMess XHTTP 节点")
	}
	info, e := fetch(&n.ApiConfig)
	if e != nil {
		return 0, fmt.Errorf("读取面板节点失败")
	}
	if info == nil || info.VAllss == nil || info.Common == nil || (info.VAllss.Network != "xhttp" && info.VAllss.Network != "splithttp") || info.Security != panel.None {
		return 0, fmt.Errorf("请配置 XHTTP、无 TLS 的本机源站节点，公网 TLS 由 Cloudflare 提供")
	}
	port := info.Common.ServerPort
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("源站端口无效")
	}
	// Ensure the selected origin is reachable, without exposing it publicly.
	conn, e := net.DialTimeout("tcp", net.JoinHostPort(n.Options.ListenIP, strconv.Itoa(port)), 3*time.Second)
	if e != nil {
		return 0, fmt.Errorf("本机 XHTTP 源站未监听: %w", e)
	}
	conn.Close()
	return port, nil
}

type tunnelRunner func(string, string, ...string) ([]byte, error)

func enableTunnel(binary, protocol, token string) error {
	return enableTunnelFiles(binary, protocol, token, tunnelService, tunnelToken, hopExec)
}
func enableTunnelFiles(binary, protocol, token, servicePath, tokenPath string, run tunnelRunner) error {
	if e := validateTunnelToken(token); e != nil {
		return e
	}
	unit, e := tunnelUnitText(binary, protocol)
	if e != nil {
		return e
	}
	unit = strings.ReplaceAll(unit, tunnelToken, tokenPath)
	for _, p := range []string{servicePath, tokenPath} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			return fmt.Errorf("已有托管文件，请先检查状态或关闭；拒绝覆盖")
		}
	}
	help, e := run("", binary, "tunnel", "run", "--help")
	if e != nil {
		return e
	}
	if !strings.Contains(string(help), "--token-file") {
		return fmt.Errorf("cloudflared 版本不支持 --token-file，请升级官方程序")
	}
	if e = os.MkdirAll(filepath.Dir(tokenPath), 0700); e != nil {
		return e
	}
	write := func(path, content string, mode os.FileMode) error {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if e != nil {
			return e
		}
		_, e = f.WriteString(content)
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			os.Remove(path)
		}
		return e
	}
	if e = write(tokenPath, token, 0600); e != nil {
		return e
	}
	if e = write(servicePath, unit, 0644); e != nil {
		os.Remove(tokenPath)
		return e
	}
	_, e = run("", "systemctl", "daemon-reload")
	if e == nil {
		_, e = run("", "systemctl", "enable", "--now", tunnelUnit)
	}
	if e != nil {
		_, cleanup := run("", "systemctl", "disable", "--now", tunnelUnit)
		if cleanup != nil {
			return fmt.Errorf("启动失败且自动停止失败；保留托管文件供恢复")
		}
		os.Remove(servicePath)
		os.Remove(tokenPath)
		run("", "systemctl", "daemon-reload")
		return e
	}
	return nil
}
func disableTunnel() error { return disableTunnelFiles(tunnelService, tunnelToken, hopExec) }
func disableTunnelFiles(servicePath, tokenPath string, run tunnelRunner) error {
	b, e := os.ReadFile(servicePath)
	if e != nil {
		return e
	}
	if !strings.Contains(string(b), "Description=V2bX managed Cloudflare Tunnel\n") {
		return fmt.Errorf("非本功能管理的服务，拒绝删除")
	}
	if _, e = run("", "systemctl", "disable", "--now", tunnelUnit); e != nil {
		return e
	}
	if e = os.Remove(servicePath); e != nil {
		return e
	}
	if e = os.Remove(tokenPath); e != nil && !os.IsNotExist(e) {
		return e
	}
	_, e = run("", "systemctl", "daemon-reload")
	return e
}
func init() {
	var path string
	c := &cobra.Command{Use: "tunnel", Short: "管理可选的 XHTTP Cloudflare Tunnel", SilenceUsage: true, Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("请使用 root 运行")
		}
		lock, e := os.OpenFile("/run/V2bX-cloudflared.lock", os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			return e
		}
		defer lock.Close()
		if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			return fmt.Errorf("另一隧道操作正在进行")
		}
		defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		input := c.InOrStdin()
		w := &nodeWizard{input: input, in: bufio.NewReader(input), out: c.OutOrStdout()}
		action, e := w.choose("XHTTP Cloudflare Tunnel", []string{"开启", "查看状态", "查看日志", "关闭", "返回"}, []string{"enable", "status", "logs", "disable", "return"}, "2")
		if e != nil {
			return e
		}
		if action == "return" {
			return nil
		}
		if action == "status" {
			b, e := hopExec("", "systemctl", "show", tunnelUnit, "-p", "ActiveState", "-p", "SubState")
			fmt.Fprintln(w.out, string(b))
			fmt.Fprintln(w.out, "进程状态不代表隧道已注册或公网访问可用，需通过域名和客户端实测。")
			return e
		}
		if action == "logs" {
			fmt.Fprintln(w.out, "请在本机执行 journalctl -u V2bX-cloudflared --no-pager -n 50；分享前隐藏隧道ID与其他敏感信息。")
			return nil
		}
		ok, e := w.yesNo("仅操作 V2bX 专属隧道服务，确认继续", "n")
		if e != nil {
			return e
		}
		if !ok {
			return nil
		}
		if action == "disable" {
			if e = disableTunnel(); e != nil {
				return e
			}
			fmt.Fprintln(w.out, "专属隧道已关闭；节点配置和其他 cloudflared 服务保留。")
			return nil
		}
		binary, e := exec.LookPath("cloudflared")
		if e != nil {
			return fmt.Errorf("请先安装官方 cloudflared，并加入 PATH")
		}
		binary, e = filepath.Abs(binary)
		if e != nil {
			return e
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		d, e := readDocument(data)
		if e != nil {
			return e
		}
		for i, n := range d.parsed {
			fmt.Fprintf(w.out, "%d. 节点 %d / %s / %s\n", i+1, n.ApiConfig.NodeID, n.ApiConfig.NodeType, n.Options.Core)
		}
		s, e := w.ask("选择回环 XHTTP 节点序号", "", false)
		if e != nil {
			return e
		}
		index, e := strconv.Atoi(s)
		if e != nil {
			return fmt.Errorf("序号无效")
		}
		port, e := checkTunnelNode(path, index, func(a *conf.ApiConfig) (*panel.NodeInfo, error) {
			p, e := panel.New(a)
			if e != nil {
				return nil, e
			}
			return p.GetNodeInfo()
		})
		if e != nil {
			return e
		}
		fmt.Fprintf(w.out, "请在 Cloudflare 固定隧道中将公网域名映射到 http://127.0.0.1:%d；订阅使用该公网域名、TLS 与同一 XHTTP 路径。\n", port)
		protocol, e := w.choose("源站到 Cloudflare 的传输", []string{"自动", "HTTP2", "QUIC"}, []string{"auto", "http2", "quic"}, "1")
		if e != nil {
			return e
		}
		token, e := w.ask("固定隧道 Token（隐藏输入）", "", true)
		if e != nil {
			return e
		}
		if e = enableTunnel(binary, protocol, token); e != nil {
			return e
		}
		fmt.Fprintln(w.out, "已创建专属服务。请检查连接日志和公网客户端，尚不能认定端到端可用。")
		return nil
	}}
	c.Flags().StringVar(&path, "config", "/etc/V2bX/config.json", "配置文件路径")
	command.AddCommand(c)
}
