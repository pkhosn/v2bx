package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkhosn/v2bx/api/panel"
	"github.com/pkhosn/v2bx/common/json5"
	"github.com/pkhosn/v2bx/conf"
	"github.com/pkhosn/v2bx/core"
	"github.com/pkhosn/v2bx/node"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type configDocument struct {
	fields map[string]json.RawMessage
	nodes  []json.RawMessage
	cores  []json.RawMessage
	parsed []conf.NodeConfig
}

func readDocument(data []byte) (*configDocument, error) {
	d := &configDocument{fields: map[string]json.RawMessage{}}
	if len(data) == 0 {
		return d, nil
	}
	clean, err := io.ReadAll(json5.NewTrimNodeReader(bytes.NewReader(data)))
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(clean, &d.fields); err != nil {
		return nil, err
	}
	if d.fields == nil {
		return nil, fmt.Errorf("configuration must be an object")
	}
	if err = json.Unmarshal(valueOrArray(d.fields["Nodes"]), &d.nodes); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(valueOrArray(d.fields["Cores"]), &d.cores); err != nil {
		return nil, err
	}
	for _, raw := range d.nodes {
		var n conf.NodeConfig
		if err = json.Unmarshal(raw, &n); err != nil {
			return nil, err
		}
		d.parsed = append(d.parsed, n)
	}
	return d, nil
}
func valueOrArray(v []byte) []byte {
	if len(v) == 0 {
		return []byte("[]")
	}
	return v
}
func normalizedHost(s string) string { return strings.TrimRight(strings.ToLower(s), "/") }
func normalizedProtocol(s string) string {
	s = strings.ToLower(s)
	if s == "v2ray" {
		return "vmess"
	}
	return s
}
func (d *configDocument) checkDuplicate(a conf.ApiConfig) error {
	for _, n := range d.parsed {
		if normalizedHost(n.ApiConfig.APIHost) == normalizedHost(a.APIHost) && n.ApiConfig.NodeID == a.NodeID && normalizedProtocol(n.ApiConfig.NodeType) == a.NodeType {
			return fmt.Errorf("该面板的 %s 节点 %d 已存在", a.NodeType, a.NodeID)
		}
	}
	return nil
}
func supportsCore(c, protocol string) bool {
	switch c {
	case "xray":
		return strings.Contains("|vmess|vless|shadowsocks|trojan|", "|"+protocol+"|")
	case "sing":
		return strings.Contains("|vmess|vless|shadowsocks|trojan|tuic|anytls|hysteria|hysteria2|", "|"+protocol+"|")
	case "hysteria2":
		return protocol == "hysteria2"
	}
	return false
}
func (d *configDocument) appendNode(a conf.ApiConfig, coreType string, cert *conf.CertConfig) error {
	if err := d.checkDuplicate(a); err != nil {
		return err
	}
	if !supportsCore(coreType, a.NodeType) {
		return fmt.Errorf("内核 %s 不支持 %s", coreType, a.NodeType)
	}
	coreName := ""
	found := false
	for _, raw := range d.cores {
		var c conf.CoreConfig
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		if c.Type == coreType && !found {
			found = true
			coreName = c.Name
		}
	}
	if !found {
		// A formerly single-core configuration may omit node selection. Pin those
		// nodes before adding another core so selection does not become ambiguous.
		for i, existing := range d.parsed {
			if existing.Options.Core != "" || existing.Options.CoreName != "" {
				continue
			}
			if len(d.cores) != 1 {
				return fmt.Errorf("已有节点未指定内核且原配置包含多个内核，请先明确其 Core/CoreName")
			}
			var prior conf.CoreConfig
			if err := json.Unmarshal(d.cores[0], &prior); err != nil {
				return err
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(d.nodes[i], &raw); err != nil {
				return err
			}
			if _, included := raw["Include"]; included {
				return fmt.Errorf("外部 Include 节点未指定内核，请先在其配置中明确 Core/CoreName")
			}
			target := raw
			if options, ok := raw["Options"]; ok {
				target = map[string]json.RawMessage{}
				if err := json.Unmarshal(options, &target); err != nil {
					return err
				}
			}
			target["Core"], _ = json.Marshal(prior.Type)
			if prior.Name != "" {
				target["CoreName"], _ = json.Marshal(prior.Name)
			}
			if _, ok := raw["Options"]; ok {
				raw["Options"], _ = json.Marshal(target)
			}
			d.nodes[i], _ = json.Marshal(raw)
		}
		// Avoid colliding with an existing custom core name.
		coreName = "node-add-" + coreType
		for suffix := 1; ; suffix++ {
			collision := false
			for _, raw := range d.cores {
				var c conf.CoreConfig
				if err := json.Unmarshal(raw, &c); err != nil {
					return err
				}
				name := c.Name
				if name == "" {
					name = c.Type
				}
				if name == coreName {
					collision = true
				}
			}
			if !collision {
				break
			}
			coreName = fmt.Sprintf("node-add-%s-%d", coreType, suffix)
		}
		raw, _ := json.Marshal(map[string]any{"Type": coreType, "Name": coreName})
		d.cores = append(d.cores, raw)
	}
	n := map[string]any{"ApiHost": a.APIHost, "ApiKey": a.Key, "NodeID": a.NodeID, "NodeType": a.NodeType, "Timeout": 30, "Core": coreType, "CoreName": coreName, "ListenIP": "0.0.0.0", "SendIP": "0.0.0.0", "CertConfig": cert}
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	d.nodes = append(d.nodes, raw)
	d.parsed = append(d.parsed, conf.NodeConfig{ApiConfig: a, Options: conf.Options{Core: coreType, CoreName: coreName, CertConfig: cert}})
	return nil
}
func (d *configDocument) marshal() ([]byte, error) {
	var err error
	d.fields["Nodes"], err = json.Marshal(d.nodes)
	if err != nil {
		return nil, err
	}
	d.fields["Cores"], err = json.Marshal(d.cores)
	if err != nil {
		return nil, err
	}
	if _, ok := d.fields["Log"]; !ok {
		d.fields["Log"] = json.RawMessage(`{"Level":"info"}`)
	}
	data, err := json.MarshalIndent(d.fields, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
func saveDocument(path string, original, data []byte) error {
	current, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if !bytes.Equal(current, original) {
		return fmt.Errorf("配置已被其他程序修改，请重新运行")
	}
	write := func(destination string, content []byte) error {
		f, err := os.CreateTemp(filepath.Dir(destination), ".node-add-")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(content)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		return os.Rename(f.Name(), destination)
	}
	if original != nil {
		if err = write(path+".bak", original); err != nil {
			return err
		}
	}
	return write(path, data)
}

type nodeWizard struct {
	in     *bufio.Reader
	out    io.Writer
	input  io.Reader
	fetch  func(*conf.ApiConfig) (*panel.NodeInfo, error)
	ensure func(*conf.CertConfig) error
}

// Match the existing management script's ANSI palette.
const (
	wizardGreen  = "\033[0;32m"
	wizardYellow = "\033[0;33m"
	wizardPlain  = "\033[0m"
)

func (w *nodeWizard) ask(label, fallback string, secret bool) (string, error) {
	fmt.Fprint(w.out, label)
	if fallback != "" {
		fmt.Fprintf(w.out, " [%s]", fallback)
	}
	fmt.Fprint(w.out, ": ")
	var s string
	if f, ok := w.input.(*os.File); secret && ok && term.IsTerminal(int(f.Fd())) {
		data, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(w.out)
		if err != nil {
			return "", err
		}
		s = string(data)
	} else {
		line, err := w.in.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("输入中断，未保存配置: %w", err)
		}
		s = strings.TrimSpace(line)
	}
	if s == "" {
		s = fallback
	}
	return s, nil
}

// choose retains the numeric choices and labels from the management script.
// Invalid input stays at the current step instead of discarding prior answers.
func (w *nodeWizard) choose(title string, labels, values []string, fallback string) (string, error) {
	color := wizardYellow
	if title == "请选择节点核心类型：" {
		color = wizardGreen
	}
	fmt.Fprintln(w.out, color+title+wizardPlain)
	for i, label := range labels {
		if label != "" {
			fmt.Fprintf(w.out, "%s%d. %s%s\n", wizardGreen, i+1, label, wizardPlain)
		}
	}
	for {
		answer, err := w.ask("请输入", fallback, false)
		if err != nil {
			return "", err
		}
		number, err := strconv.Atoi(answer)
		if err == nil && number > 0 && number <= len(values) && values[number-1] != "" {
			return values[number-1], nil
		}
		fmt.Fprintln(w.out, "无效的选择，请输入上方菜单中的数字。")
	}
}
func (w *nodeWizard) yesNo(label, fallback string) (bool, error) {
	for {
		answer, err := w.ask(label, fallback, false)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(w.out, "请输入 y 或 n。")
	}
}
func (w *nodeWizard) nodeSelection() (string, string, int, error) {
	coreType, err := w.choose("请选择节点核心类型：", []string{"xray", "singbox", "hysteria2"}, []string{"xray", "sing", "hysteria2"}, "")
	if err != nil {
		return "", "", 0, err
	}
	registered := false
	for _, c := range core.RegisteredCore() {
		if c == coreType {
			registered = true
		}
	}
	if !registered {
		return "", "", 0, fmt.Errorf("当前二进制未编译 %s 内核，请安装完整版", coreType)
	}
	var id int
	for {
		answer, e := w.ask("请输入节点Node ID", "", false)
		if e != nil {
			return "", "", 0, e
		}
		id, e = strconv.Atoi(answer)
		if e == nil && id > 0 {
			break
		}
		fmt.Fprintln(w.out, "错误：请输入正整数作为Node ID。")
	}
	protocol := "hysteria2"
	if coreType != "hysteria2" {
		labels := []string{"Shadowsocks", "Vless", "Vmess", "", "", "Trojan", "", ""}
		values := []string{"shadowsocks", "vless", "vmess", "", "", "trojan", "", ""}
		if coreType == "sing" {
			labels[3], labels[4], labels[6], labels[7] = "Hysteria", "Hysteria2", "Tuic", "AnyTLS"
			values[3], values[4], values[6], values[7] = "hysteria", "hysteria2", "tuic", "anytls"
		}
		protocol, err = w.choose("请选择节点传输协议：", labels, values, "")
	}
	return coreType, protocol, id, err
}
func (w *nodeWizard) certificate(info *panel.NodeInfo, d *configDocument, dir string) (*conf.CertConfig, error) {
	c := conf.NewCertConfig()
	if info.Security != panel.Tls {
		return c, nil
	}
	domain := ""
	if info.Common != nil {
		domain = info.Common.ServerName
	}
	if info.VAllss != nil && info.VAllss.TlsSettings.ServerName != "" {
		domain = info.VAllss.TlsSettings.ServerName
	}
	var err error
	mode, err := w.choose("请选择证书申请模式：", []string{
		"http模式自动申请，节点域名已正确解析（本机80端口可用）",
		"dns模式自动申请（Cloudflare）",
		"self模式，自签证书",
		"提供已有证书文件",
	}, []string{"1", "2", "3", "4"}, "1")
	if err != nil {
		return nil, err
	}
	for {
		domain, err = w.ask("请输入节点证书域名(example.com)", domain, false)
		if err != nil {
			return nil, err
		}
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if validDomain(domain) {
			break
		}
		fmt.Fprintln(w.out, "请输入有效的证书域名（不带协议或路径）。")
		domain = ""
	}
	for _, n := range d.parsed {
		old := n.Options.CertConfig
		if old != nil && old.CertDomain == domain && (old.CertMode == "http" || old.CertMode == "dns") && node.ValidateCertificate(old) == nil {
			reuse, e := w.yesNo("找到同域名有效证书，是否复用", "y")
			if e != nil {
				return nil, e
			}
			if reuse {
				copy := *old
				return &copy, nil
			}
			break
		}
	}
	c.CertDomain = domain
	switch mode {
	case "1":
		c.CertMode = "http"
	case "2":
		c.CertMode = "dns"
		c.Provider = "cloudflare"
	case "3":
		c.CertMode = "self"
	case "4":
		c.CertMode = "file"
	default:
		return nil, fmt.Errorf("无效证书模式")
	}
	if c.CertMode == "file" {
		c.CertFile, err = w.ask("证书文件绝对路径", "", false)
		if err != nil {
			return nil, err
		}
		c.KeyFile, err = w.ask("私钥文件绝对路径", "", false)
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(c.CertFile) || !filepath.IsAbs(c.KeyFile) {
			return nil, fmt.Errorf("证书路径必须为绝对路径")
		}
	} else {
		kind := c.CertMode
		if kind == "http" || kind == "dns" {
			kind = "acme"
		}
		certDir := filepath.Join(dir, "certs", kind, domain)
		if c.CertMode == "self" { // Never share generated self-signed identities between nodes.
			certDir, err = os.MkdirTemp(filepath.Join(dir), "self-"+domain+"-")
			if err != nil {
				return nil, err
			}
		}
		c.CertFile = filepath.Join(certDir, "fullchain.cer")
		c.KeyFile = filepath.Join(certDir, "cert.key")
	}
	if c.CertMode == "http" || c.CertMode == "dns" {
		fallbackEmail := ""
		for _, n := range d.parsed {
			if old := n.Options.CertConfig; old != nil && old.Email != "" && old.Email != "v2bx@github.com" {
				fallbackEmail = old.Email
				break
			}
		}
		for {
			c.Email, err = w.ask("ACME联系邮箱（可留空，回车使用已有邮箱或不设置）", fallbackEmail, false)
			if err != nil {
				return nil, err
			}
			if c.Email == "" {
				break
			}
			address, e := mail.ParseAddress(c.Email)
			if e == nil && address.Address == c.Email {
				break
			}
			fmt.Fprintln(w.out, "邮箱格式无效，请重新输入；也可留空。")
		}
	}
	if c.CertMode == "dns" {
		for _, n := range d.parsed {
			old := n.Options.CertConfig
			if old != nil && old.Provider == "cloudflare" && len(old.DNSEnv) > 0 {
				reuse, e := w.ask("复用已有Cloudflare凭据？y/n", "n", false)
				if e != nil {
					return nil, e
				}
				if reuse == "y" {
					c.DNSEnv = old.DNSEnv
				}
				break
			}
		}
		if c.DNSEnv == nil {
			token, e := w.ask("Cloudflare API Token（Zone Read + DNS Edit，输入隐藏）", "", true)
			if e != nil {
				return nil, e
			}
			if token == "" {
				return nil, fmt.Errorf("Token不能为空")
			}
			c.DNSEnv = map[string]string{"CF_DNS_API_TOKEN": token}
		}
	}
	return c, nil
}
func validDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (w *nodeWizard) run(path string, replace bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	// Serialize cooperating wizard processes; runtime certificate locks are separate.
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("另一个配置向导正在运行")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	original, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	input := original
	if replace {
		answer, e := w.ask("重新生成将替换所有节点与内核配置，输入 REPLACE 确认", "", false)
		if e != nil {
			return e
		}
		if answer != "REPLACE" {
			return fmt.Errorf("已取消")
		}
		input = nil
	}
	d, err := readDocument(input)
	if err != nil {
		return fmt.Errorf("原配置无法读取: %w", err)
	}
	fmt.Fprintln(w.out, wizardYellow+"V2bX 配置文件生成向导"+wizardPlain)
	if !replace {
		fmt.Fprintf(w.out, "本次追加节点，保留已有 %d 个节点。\n", len(d.nodes))
	}
	fixedAPI := false
	var fixedConfig conf.ApiConfig
	firstNode := true
	for {
		a := conf.ApiConfig{Timeout: 30}
		if fixedAPI {
			a = fixedConfig
		} else {
			fallback := ""
			if len(d.parsed) > 0 {
				fallback = d.parsed[len(d.parsed)-1].ApiConfig.APIHost
			}
			for {
				a.APIHost, err = w.ask("请输入机场网址(https://example.com)", fallback, false)
				if err != nil {
					return err
				}
				u, e := url.Parse(a.APIHost)
				if e == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") && u.RawQuery == "" && u.User == nil && u.Fragment == "" {
					break
				}
				fmt.Fprintln(w.out, "无效面板地址，请重新输入。")
			}
			a.APIHost = strings.TrimRight(a.APIHost, "/")
			existingKey := ""
			for _, n := range d.parsed {
				if normalizedHost(n.ApiConfig.APIHost) == normalizedHost(a.APIHost) {
					existingKey = n.ApiConfig.Key
					break
				}
			}
			for {
				label := "请输入面板对接API Key（输入隐藏）"
				if existingKey != "" {
					label += "（回车复用该面板已有Key）"
				}
				a.Key, err = w.ask(label, "", true)
				if err != nil {
					return err
				}
				if a.Key == "" {
					a.Key = existingKey
				}
				if a.Key != "" {
					break
				}
				fmt.Fprintln(w.out, "API Key不能为空，请重新输入。")
			}
			if firstNode {
				fixedAPI, err = w.yesNo("是否设置固定的机场网址和API Key？(y/n)", "n")
				if err != nil {
					return err
				}
				if fixedAPI {
					fixedConfig = a
					fmt.Fprintln(w.out, wizardGreen+"成功固定地址"+wizardPlain)
				}
			}
		}
		firstNode = false
		coreType, protocol, id, e := w.nodeSelection()
		if e != nil {
			return e
		}
		a.NodeType, a.NodeID = protocol, id
		if err = d.checkDuplicate(a); err != nil {
			return err
		}

		info, e := w.fetch(&a)
		if e != nil {
			return fmt.Errorf("查询面板节点失败: %w", e)
		}
		if info == nil {
			return fmt.Errorf("面板未返回节点配置")
		}
		c, e := w.certificate(info, d, filepath.Dir(path))
		if e != nil {
			return e
		}
		fmt.Fprintln(w.out, "正在检查或申请证书；成功前不会保存配置。")
		if e = w.ensure(c); e != nil {
			return fmt.Errorf("证书准备失败: %w", e)
		}
		if e = d.appendNode(a, coreType, c); e != nil {
			return e
		}
		more, e := w.yesNo("是否继续添加节点配置？(回车继续，输入n或no退出)", "y")
		if e != nil {
			return e
		}
		if !more {
			break
		}
	}
	data, err := d.marshal()
	if err != nil {
		return err
	}
	if err = saveDocument(path, original, data); err != nil {
		return err
	}
	fmt.Fprintf(w.out, "配置已保存，共 %d 个节点；原配置备份为 %s.bak。应用配置会短暂重载全部节点。\n", len(d.nodes), path)
	return nil
}
func init() {
	var path string
	var replace bool
	c := &cobra.Command{Use: "node-add", Short: "交互追加节点并自动准备证书", SilenceUsage: true, Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		input := c.InOrStdin()
		w := &nodeWizard{in: bufio.NewReader(input), input: input, out: c.OutOrStdout(), ensure: node.EnsureCertificate, fetch: func(a *conf.ApiConfig) (*panel.NodeInfo, error) {
			client, err := panel.New(a)
			if err != nil {
				return nil, err
			}
			return client.GetNodeInfo()
		}}
		return w.run(path, replace)
	}}
	c.Flags().StringVar(&path, "config", "/etc/V2bX/config.json", "配置文件路径")
	c.Flags().BoolVar(&replace, "replace", false, "明确重新生成全部节点配置（需要再次输入确认）")
	command.AddCommand(c)
}
