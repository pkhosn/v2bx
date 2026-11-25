package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkhosn/v2bx/api/panel"
)

// PortHop is wizard-owned metadata. Runtime listeners still use server_port;
// the dedicated nft service restores these mappings at boot.
type nodeHop struct {
	Start  int
	End    int
	Target int
}

func (h nodeHop) validate() error {
	_, err := hopNft(h.Start, h.End, h.Target, "ipv4")
	return err
}

func panelHopRange(n *panel.NodeInfo) (string, error) {
	if n.Hysteria2 == nil {
		return "", nil
	}
	for _, raw := range []json.RawMessage{n.Hysteria2.MPort, n.Hysteria2.Port} {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			var port int
			if err = json.Unmarshal(raw, &port); err != nil || port < 1 || port > 65535 {
				return "", fmt.Errorf("面板跳跃端口格式无效")
			}
			continue // A single connection port is not a hopping range.
		}
		if s == "" {
			continue
		}
		if _, err := strconv.Atoi(s); err == nil {
			continue
		}
		if _, _, err := hopRange(s); err != nil {
			return "", fmt.Errorf("面板跳跃范围 %q 无效: %w", s, err)
		}
		return s, nil
	}
	return "", nil
}

func documentHop(raw json.RawMessage) (*nodeHop, error) {
	var n struct{ PortHop *nodeHop }
	if err := json.Unmarshal(raw, &n); err != nil {
		return nil, err
	}
	if n.PortHop != nil {
		if err := n.PortHop.validate(); err != nil {
			return nil, err
		}
	}
	return n.PortHop, nil
}
func (d *configDocument) setHop(index int, h *nodeHop) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(d.nodes[index], &raw); err != nil {
		return err
	}
	if _, included := raw["Include"]; included {
		return fmt.Errorf("外部 Include 节点请先在本机配置中明确节点设置")
	}
	if h == nil {
		delete(raw, "PortHop")
	} else {
		raw["PortHop"], _ = json.Marshal(h)
	}
	var err error
	d.nodes[index], err = json.Marshal(raw)
	return err
}

func (w *nodeWizard) configureNodeHop(info *panel.NodeInfo, old *nodeHop) (*nodeHop, error) {
	if info.Hysteria2 == nil {
		return nil, fmt.Errorf("面板未返回 Hysteria2 配置，请确认节点版本为 HY2")
	}
	target := info.Hysteria2.ServerPort
	fmt.Fprintf(w.out, "服务端口（V2bX 实际 UDP 监听端口）：%d\n", target)
	panelRange, err := panelHopRange(info)
	if err != nil {
		fmt.Fprintf(w.out, "%v，请手动填写正确范围或选择不启用。\n", err)
		panelRange = ""
	}
	fallback := ""
	if old != nil {
		fallback = fmt.Sprintf("%d-%d", old.Start, old.End)
		fmt.Fprintf(w.out, "当前连接端口范围：%s → 服务端口：%d\n", fallback, old.Target)
	}
	if panelRange != "" {
		fmt.Fprintf(w.out, "面板连接端口范围：%s\n", panelRange)
		prompt := "是否自动配置该范围的端口跳跃？(y/n)"
		if old != nil {
			prompt = "是否使用面板范围配置跳跃？（输入 n 关闭该节点跳跃）(y/n)"
		}
		ok, err := w.yesNo(prompt, "y")
		if err != nil {
			return nil, err
		}
		if !ok {
			fmt.Fprintln(w.out, "未启用端口跳跃；面板连接端口应与服务端口一致，否则客户端可能无法连接。")
			return nil, nil
		}
		fallback = panelRange
	} else {
		fmt.Fprintln(w.out, "面板未下发连接端口范围；请手动填写面板中设置的连接端口范围。")
		choice := "1"
		if old != nil {
			choice = "2"
		}
		action, err := w.choose("HY2 端口跳跃设置", []string{"不启用（已有映射将关闭）", "填写连接端口范围并自动配置"}, []string{"off", "manual"}, choice)
		if err != nil {
			return nil, err
		}
		if action == "off" {
			return nil, nil
		}
	}
	for {
		value := fallback
		if panelRange == "" {
			value, err = w.ask("请输入面板的连接端口范围（例如 30000-30999，最多 1000 个）", fallback, false)
			if err != nil {
				return nil, err
			}
		}
		a, b, e := hopRange(value)
		h := &nodeHop{Start: a, End: b, Target: target}
		if e == nil {
			e = h.validate()
		}
		if e == nil {
			fmt.Fprintf(w.out, "将自动配置：连接端口 UDP %d-%d → 服务端口 UDP %d，并设置开机恢复。云安全组需放行连接端口范围。\n", a, b, target)
			return h, nil
		}
		if panelRange != "" {
			return nil, e
		}
		fmt.Fprintln(w.out, e)
	}
}

const hopHeader = "# V2bX node wizard port hopping\n"

func renderNodeHops(hops []nodeHop) (string, error) {
	hops = append([]nodeHop(nil), hops...)
	sort.Slice(hops, func(i, j int) bool { return hops[i].Start < hops[j].Start })
	var lines strings.Builder
	for i, h := range hops {
		if err := h.validate(); err != nil {
			return "", err
		}
		if i > 0 && hops[i-1].End >= h.Start {
			return "", fmt.Errorf("跳跃范围重叠：%d-%d 与 %d-%d", hops[i-1].Start, hops[i-1].End, h.Start, h.End)
		}
		for j, other := range hops {
			if j != i && other.Target == h.Target {
				return "", fmt.Errorf("多个跳跃配置共用了 UDP 监听端口 %d", h.Target)
			}
			if other.Target >= h.Start && other.Target <= h.End {
				return "", fmt.Errorf("跳跃范围覆盖节点监听端口 %d", other.Target)
			}
		}
		rule, _ := hopNft(h.Start, h.End, h.Target, "ipv4")
		lines.WriteString(strings.Split(rule, "\n")[3] + "\n")
	}
	return hopHeader + fmt.Sprintf("table inet %s {\n chain prerouting {\n  type nat hook prerouting priority dstnat; policy accept;\n%s }\n}\n", hopTable, lines.String()), nil
}
func parseNodeHops(data []byte) ([]nodeHop, error) {
	var hops []nodeHop
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "meta nfproto") {
			continue
		}
		var h nodeHop
		n, err := fmt.Sscanf(strings.TrimSpace(line), "meta nfproto ipv4 fib daddr type local ct direction original udp dport %d-%d counter redirect to :%d", &h.Start, &h.End, &h.Target)
		if err != nil || n != 3 {
			return nil, fmt.Errorf("无法识别已有端口跳跃规则，拒绝覆盖")
		}
		hops = append(hops, h)
	}
	expected, err := renderNodeHops(hops)
	if err != nil {
		return nil, err
	}
	if string(data) == expected {
		return hops, nil
	}
	if len(hops) == 1 {
		legacy, _ := hopNft(hops[0].Start, hops[0].End, hops[0].Target, "ipv4")
		if string(data) == legacy {
			return hops, nil
		}
	}
	return nil, fmt.Errorf("规则文件包含非本功能生成的内容，拒绝覆盖")
}

// System operations are injected so rollback is tested locally without touching
// the host firewall or systemd. Only this function's dedicated files/table change.
type hopManager struct {
	rules, service, lock, nft string
	run                       func(string, string, ...string) ([]byte, error)
}

type hopRollbackError struct{ err error }

func (e *hopRollbackError) Error() string { return e.err.Error() }
func (e *hopRollbackError) Unwrap() error { return e.err }

func legacyNodeHop(target int) (*nodeHop, error) {
	data, err := hopFile(hopRules)
	if err != nil || data == nil {
		return nil, err
	}
	hops, err := parseNodeHops(data)
	if err != nil {
		return nil, err
	}
	for _, h := range hops {
		if h.Target == target {
			copy := h
			return &copy, nil
		}
	}
	return nil, nil
}

func newHopManager() *hopManager {
	return &hopManager{rules: hopRules, service: hopService, lock: "/run/V2bX-port-hop.lock", run: hopExec}
}
func hopFile(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s 不是普通文件，拒绝修改", path)
	}
	return os.ReadFile(path)
}
func writeHopFile(path string, data []byte, mode os.FileMode) error {
	if data == nil {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".port-hop-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// begin applies a complete mapping plan. finish(false) restores the previous
// rules, files and service state if saving config subsequently fails.
func (m *hopManager) begin(desired []nodeHop, touched map[int]bool, replace bool) (finish func(bool) error, err error) {
	if len(desired) == 0 && len(touched) == 0 && !replace {
		return func(bool) error { return nil }, nil
	}
	lock, err := os.OpenFile(m.lock, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	unlock := func() { syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); lock.Close() }
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("另一端口跳跃操作正在进行")
	}
	defer func() {
		if err != nil {
			unlock()
		}
	}()
	oldRules, err := hopFile(m.rules)
	if err != nil {
		return nil, err
	}
	oldUnit, err := hopFile(m.service)
	if err != nil {
		return nil, err
	}
	if (oldRules == nil) != (oldUnit == nil) {
		return nil, fmt.Errorf("已有跳跃规则/服务文件不完整，请先修复")
	}
	if oldUnit != nil && !strings.Contains(string(oldUnit), "Description=V2bX HY2 UDP port hopping\n") {
		return nil, fmt.Errorf("已有服务不属于本功能，拒绝覆盖")
	}
	var previous []nodeHop
	if oldRules != nil {
		previous, err = parseNodeHops(oldRules)
		if err != nil {
			return nil, err
		}
	}
	// Retain legacy mappings for nodes not edited by this wizard.
	if !replace {
		for _, h := range previous {
			if !touched[h.Target] {
				found := false
				for _, d := range desired {
					if h == d {
						found = true
						break
					}
				}
				if !found {
					desired = append(desired, h)
				}
			}
		}
	}
	if len(desired) == 0 && oldRules == nil {
		return func(bool) error { unlock(); return nil }, nil
	}
	rules, err := renderNodeHops(desired)
	if err != nil {
		return nil, err
	}
	if m.nft == "" {
		for _, tool := range []string{"nft", "systemctl"} {
			if _, err = exec.LookPath(tool); err != nil {
				return nil, fmt.Errorf("请先安装 %s 后选择重试", tool)
			}
		}
		m.nft, err = exec.LookPath("nft")
		if err != nil {
			return nil, err
		}
		m.nft, err = filepath.Abs(m.nft)
		if err != nil {
			return nil, err
		}
	}
	if strings.ContainsAny(m.nft, " \t\n") {
		return nil, fmt.Errorf("nft 路径不支持空白字符")
	}
	tables, err := m.run("", m.nft, "list", "tables")
	if err != nil {
		return nil, err
	}
	exists := false
	for _, line := range strings.Split(string(tables), "\n") {
		if strings.TrimSpace(line) == "table inet "+hopTable {
			exists = true
		}
	}
	if exists && oldRules == nil {
		return nil, fmt.Errorf("同名 nft 表已存在但没有本功能文件，拒绝覆盖")
	}
	var oldTable []byte
	if exists {
		oldTable, err = m.run("", m.nft, "list", "table", "inet", hopTable)
		if err != nil {
			return nil, err
		}
	}
	for _, h := range desired {
		if err = checkHopPorts(h.Start, h.End); err != nil {
			return nil, err
		}
	}
	batch := rules
	if exists {
		batch = "delete table inet " + hopTable + "\n" + batch
	}
	if _, err = m.run(batch, m.nft, "-c", "-f", "-"); err != nil {
		return nil, err
	}
	enabled, active := false, false
	if oldUnit != nil {
		state, e := m.run("", "systemctl", "is-enabled", hopUnit)
		switch strings.TrimSpace(string(state)) {
		case "enabled":
			enabled = true
		case "disabled":
		default:
			return nil, fmt.Errorf("无法确认原跳跃服务自启状态，未修改配置: %s %v", strings.TrimSpace(string(state)), e)
		}
		state, e = m.run("", "systemctl", "is-active", hopUnit)
		switch strings.TrimSpace(string(state)) {
		case "active":
			active = true
		case "inactive", "failed":
		default:
			return nil, fmt.Errorf("无法确认原跳跃服务运行状态，未修改配置: %s %v", strings.TrimSpace(string(state)), e)
		}
	}
	restore := func() error {
		var failures []error
		// Stop the new service before restoring files, then reconstruct the exact
		// original dedicated table. Other nft tables are never flushed.
		_, e := m.run("", "systemctl", "disable", "--now", hopUnit)
		failures = append(failures, e)
		failures = append(failures, writeHopFile(m.rules, oldRules, 0600), writeHopFile(m.service, oldUnit, 0644))
		_, e = m.run("", "systemctl", "daemon-reload")
		failures = append(failures, e)
		if oldUnit != nil && enabled {
			_, e = m.run("", "systemctl", "enable", hopUnit)
			failures = append(failures, e)
		}
		if oldUnit != nil && active {
			_, e = m.run("", "systemctl", "start", hopUnit)
			failures = append(failures, e)
		}
		tables, e := m.run("", m.nft, "list", "tables")
		failures = append(failures, e)
		cleanup := ""
		if strings.Contains(string(tables), "table inet "+hopTable) {
			cleanup = "delete table inet " + hopTable + "\n"
		}
		cleanup += string(oldTable)
		if cleanup != "" {
			_, e = m.run(cleanup, m.nft, "-f", "-")
			failures = append(failures, e)
		}
		return errors.Join(failures...)
	}
	finish = func(success bool) error {
		defer unlock()
		if !success {
			return restore()
		}
		return nil
	}
	apply := func() error {
		if len(desired) == 0 {
			if _, e := m.run("", "systemctl", "disable", "--now", hopUnit); e != nil {
				return e
			}
			tables, e := m.run("", m.nft, "list", "tables")
			if e != nil {
				return e
			}
			if strings.Contains(string(tables), "table inet "+hopTable) {
				if _, e = m.run("", m.nft, "delete", "table", "inet", hopTable); e != nil {
					return e
				}
			}
			if e = writeHopFile(m.rules, nil, 0600); e != nil {
				return e
			}
			if e = writeHopFile(m.service, nil, 0644); e != nil {
				return e
			}
			_, e = m.run("", "systemctl", "daemon-reload")
			return e
		}
		if e := writeHopFile(m.rules, []byte(rules), 0600); e != nil {
			return e
		}
		if e := writeHopFile(m.service, []byte(hopUnitText(m.nft)), 0644); e != nil {
			return e
		}
		if _, e := m.run("", "systemctl", "daemon-reload"); e != nil {
			return e
		}
		if _, e := m.run("", "systemctl", "enable", hopUnit); e != nil {
			return e
		}
		if _, e := m.run("", "systemctl", "restart", hopUnit); e != nil {
			return e
		}
		_, e := m.run("", m.nft, "list", "table", "inet", hopTable)
		return e
	}
	if err = apply(); err != nil {
		if rollbackErr := restore(); rollbackErr != nil {
			return nil, &hopRollbackError{fmt.Errorf("配置失败: %v；回滚失败，请检查 %s 与 %s: %w", err, m.rules, m.service, rollbackErr)}
		}
		return nil, err
	}
	return finish, nil
}
