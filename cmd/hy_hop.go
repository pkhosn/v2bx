package cmd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const hopUnit = "V2bX-port-hop.service"
const hopTable = "v2bx_hy_hop"
const hopRules = "/etc/V2bX/hy-port-hop.nft"
const hopService = "/etc/systemd/system/" + hopUnit

func hopRange(s string) (int, int, error) {
	p := strings.Split(strings.TrimSpace(s), "-")
	if len(p) != 2 {
		return 0, 0, fmt.Errorf("请输入起始-结束端口，例如 40000-40009")
	}
	a, e := strconv.Atoi(p[0])
	b, e2 := strconv.Atoi(p[1])
	if e != nil || e2 != nil || a < 1024 || b > 65535 || b < a || b-a >= 1000 {
		return 0, 0, fmt.Errorf("范围须在 1024-65535，最多 1000 个端口")
	}
	return a, b, nil
}
func hopNft(a, b, target int, family string) (string, error) {
	if _, _, e := hopRange(fmt.Sprintf("%d-%d", a, b)); e != nil {
		return "", e
	}
	if target < 1 || target > 65535 || (target >= a && target <= b) {
		return "", fmt.Errorf("监听端口无效或与跳跃范围重叠")
	}
	if family != "ipv4" && family != "ipv6" {
		return "", fmt.Errorf("IP 协议族无效")
	}
	return fmt.Sprintf("table inet %s {\n chain prerouting {\n  type nat hook prerouting priority dstnat; policy accept;\n  meta nfproto %s fib daddr type local ct direction original udp dport %d-%d counter redirect to :%d\n }\n}\n", hopTable, family, a, b, target), nil
}
func hopExec(input string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	if input != "" {
		c.Stdin = strings.NewReader(input)
	}
	b, e := c.CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s 操作失败: %s", name, strings.TrimSpace(string(b)))
	}
	return b, nil
}
func hopListener(target int) (string, error) {
	b, err := hopExec("", "systemctl", "show", "V2bX", "-p", "MainPID", "--value")
	if err != nil {
		return "", err
	}
	mainPID := strings.TrimSpace(string(b))
	if mainPID == "0" || mainPID == "" {
		return "", fmt.Errorf("V2bX 未运行")
	}
	b, err = hopExec("", "ss", "-H", "-lunp")
	if err != nil {
		return "", err
	}
	family := ""
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		host, p, e := net.SplitHostPort(f[3])
		if e != nil {
			continue
		}
		port, _ := strconv.Atoi(p)
		if port == target && strings.Contains(line, "pid="+mainPID+",") {
			if host == "0.0.0.0" {
				family = "ipv4"
			} else if host == "[::]" || host == "::" || host == "*" {
				return "", fmt.Errorf("双栈/IPv6 监听请手动配置，当前菜单仅处理明确 IPv4 通配监听")
			}
		}
	}
	if family == "" {
		return "", fmt.Errorf("未找到 V2bX 在 0.0.0.0:%d 的 UDP 监听", target)
	}
	return family, nil
}
func checkHopPorts(a, b int) error {
	// UDP bind detects all processes, including IPv6 dual-stack listeners.
	for port := a; port <= b; port++ {
		l, e := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", port))
		if e != nil {
			return fmt.Errorf("UDP %d 已占用或无法绑定: %w", port, e)
		}
		l.Close()
	}
	return nil
}
func hopUnitText(nft string) string {
	return fmt.Sprintf("[Unit]\nDescription=V2bX HY2 UDP port hopping\nAfter=network-pre.target nftables.service\nBefore=V2bX.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=%s -f %s\nExecStop=%s delete table inet %s\n\n[Install]\nWantedBy=multi-user.target\n", nft, hopRules, nft, hopTable)
}
func enableHop(a, b, target int, family string) error {
	if _, e := os.Stat(hopService); !os.IsNotExist(e) {
		return fmt.Errorf("已有端口跳跃配置，请先关闭；无法检查时也不会覆盖")
	}
	if _, e := os.Stat(hopRules); !os.IsNotExist(e) {
		return fmt.Errorf("已有规则文件，请先检查，拒绝覆盖")
	}
	if _, e := hopExec("", "nft", "list", "table", "inet", hopTable); e == nil {
		return fmt.Errorf("同名 nft 表已存在，拒绝覆盖")
	}
	if e := checkHopPorts(a, b); e != nil {
		return e
	}
	rules, e := hopNft(a, b, target, family)
	if e != nil {
		return e
	}
	if _, e = hopExec(rules, "nft", "-c", "-f", "-"); e != nil {
		return e
	}
	nft, e := exec.LookPath("nft")
	if e != nil {
		return e
	}
	nft, e = filepath.Abs(nft)
	if e != nil {
		return e
	}
	if strings.ContainsAny(nft, " \t\n") {
		return fmt.Errorf("nft 路径不支持空白字符")
	}
	if e = os.MkdirAll(filepath.Dir(hopRules), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(hopRules, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.WriteString(rules)
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		os.Remove(hopRules)
		return e
	}
	f, e = os.OpenFile(hopService, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		os.Remove(hopRules)
		return e
	}
	_, e = f.WriteString(hopUnitText(nft))
	ce = f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		_, e = hopExec("", "systemctl", "daemon-reload")
	}
	if e == nil {
		_, e = hopExec("", "systemctl", "enable", "--now", hopUnit)
	}
	if e != nil {
		_, stopErr := hopExec("", "systemctl", "disable", "--now", hopUnit)
		if stopErr != nil {
			return fmt.Errorf("%v；自动清理失败，保留 %s 和 %s 供恢复: %w", e, hopRules, hopService, stopErr)
		}
		os.Remove(hopRules)
		os.Remove(hopService)
		hopExec("", "systemctl", "daemon-reload")
		return e
	}
	return nil
}
func disableHop() error {
	b, e := os.ReadFile(hopService)
	if os.IsNotExist(e) {
		return fmt.Errorf("没有菜单管理的端口跳跃配置")
	}
	if e != nil {
		return e
	}
	if !strings.Contains(string(b), "Description=V2bX HY2 UDP port hopping\n") {
		return fmt.Errorf("服务文件不属于本功能，拒绝删除")
	}
	if _, e = hopExec("", "systemctl", "disable", "--now", hopUnit); e != nil {
		return e
	}
	// RemainAfterExit may be inactive after manual rule removal. Delete only
	// this dedicated table if it still exists, never flush the host ruleset.
	if _, e = hopExec("", "nft", "list", "table", "inet", hopTable); e == nil {
		if _, e = hopExec("", "nft", "delete", "table", "inet", hopTable); e != nil {
			return e
		}
	}
	if e = os.Remove(hopService); e != nil {
		return e
	}
	if e = os.Remove(hopRules); e != nil && !os.IsNotExist(e) {
		return e
	}
	_, e = hopExec("", "systemctl", "daemon-reload")
	return e
}
func init() {
	c := &cobra.Command{Use: "hy-hop", Short: "配置 HY2 UDP 端口跳跃（默认关闭）", SilenceUsage: true, Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("请使用 root 运行")
		}
		lock, e := os.OpenFile("/run/V2bX-port-hop.lock", os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			return e
		}
		defer lock.Close()
		if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			return fmt.Errorf("另一端口跳跃操作正在进行")
		}
		defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		input := c.InOrStdin()
		w := &nodeWizard{input: input, in: bufio.NewReader(input), out: c.OutOrStdout()}
		action, e := w.choose("HY2 端口跳跃", []string{"开启", "查看状态", "关闭", "返回"}, []string{"enable", "status", "disable", "return"}, "2")
		if e != nil {
			return e
		}
		if action == "return" {
			return nil
		}
		if action == "status" {
			b, e := os.ReadFile(hopRules)
			if os.IsNotExist(e) {
				fmt.Fprintln(w.out, "未开启菜单管理的端口跳跃。")
				return nil
			}
			if e != nil {
				return e
			}
			fmt.Fprintln(w.out, string(b))
			b, e = hopExec("", "nft", "list", "table", "inet", hopTable)
			if e != nil {
				return e
			}
			fmt.Fprintln(w.out, string(b))
			return nil
		}
		for _, tool := range []string{"nft", "systemctl", "ss"} {
			if _, e = exec.LookPath(tool); e != nil {
				return fmt.Errorf("请先安装 %s", tool)
			}
		}
		if action == "disable" {
			ok, e := w.yesNo("关闭会中断正在使用跳跃端口的连接，确认继续", "n")
			if e != nil {
				return e
			}
			if !ok {
				return nil
			}
			if e = disableHop(); e != nil {
				return e
			}
			fmt.Fprintln(w.out, "已移除端口跳跃规则，原节点监听保留。")
			return nil
		}
		fmt.Fprintln(w.out, "仅支持明确的 IPv4 UDP 通配监听；请确认目标是 HY2 节点。云防火墙需另行放行。")
		s, e := w.ask("请输入 HY2 实际 UDP 监听端口", "", false)
		if e != nil {
			return e
		}
		target, e := strconv.Atoi(s)
		if e != nil {
			return fmt.Errorf("端口必须是数字")
		}
		family, e := hopListener(target)
		if e != nil {
			return e
		}
		s, e = w.ask("请输入跳跃端口范围", "40000-40009", false)
		if e != nil {
			return e
		}
		a, b, e := hopRange(s)
		if e != nil {
			return e
		}
		if _, e = hopNft(a, b, target, family); e != nil {
			return e
		}
		fmt.Fprintf(w.out, "将配置 UDP %d-%d → %d，原监听不变。还需在面板订阅下发同一范围。\n", a, b, target)
		ok, e := w.yesNo("确认启用", "n")
		if e != nil {
			return e
		}
		if !ok {
			return nil
		}
		if e = enableHop(a, b, target, family); e != nil {
			return e
		}
		fmt.Fprintln(w.out, "端口跳跃规则已启用并设置开机恢复；请更新客户端订阅后验证。")
		return nil
	}}
	command.AddCommand(c)
}
