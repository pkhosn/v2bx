package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pkhosn/v2bx/conf"
	"github.com/pkhosn/v2bx/core"
	"github.com/spf13/cobra"
)

type unlockService interface {
	Active() bool
	Stop() error
	Start() error
	Healthy() error
}
type systemUnlockService struct{ ports []string }

func serviceOutput(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
}
func (s *systemUnlockService) Active() bool {
	b, e := serviceOutput("is-active", "V2bX")
	return e == nil && strings.TrimSpace(string(b)) == "active"
}
func (s *systemUnlockService) Stop() error {
	b, e := serviceOutput("stop", "V2bX")
	if e != nil {
		return fmt.Errorf("停止服务失败: %s", b)
	}
	return nil
}
func (s *systemUnlockService) Start() error {
	b, e := serviceOutput("start", "V2bX")
	if e != nil {
		return fmt.Errorf("启动服务失败: %s", b)
	}
	return nil
}
func (s *systemUnlockService) capturePorts() error {
	b, e := serviceOutput("show", "V2bX", "-p", "MainPID", "--value")
	if e != nil {
		return e
	}
	pid := strings.TrimSpace(string(b))
	if pid == "0" || pid == "" {
		return fmt.Errorf("服务没有有效进程")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, e = exec.CommandContext(ctx, "ss", "-H", "-ltnp").Output()
	if e != nil {
		return fmt.Errorf("需要 ss 检查节点监听: %w", e)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "pid="+pid+",") {
			f := strings.Fields(line)
			if len(f) > 3 {
				_, port, e := net.SplitHostPort(f[3])
				if e == nil {
					s.ports = append(s.ports, port)
				}
			}
		}
	}
	if len(s.ports) == 0 {
		return fmt.Errorf("未检测到 V2bX TCP 节点监听，请先确认服务正常")
	}
	return nil
}
func (s *systemUnlockService) Healthy() error {
	deadline := time.Now().Add(25 * time.Second)
	stable := 0
	for time.Now().Before(deadline) {
		ok := s.Active()
		b, e := serviceOutput("show", "V2bX", "-p", "MainPID", "--value")
		pid := strings.TrimSpace(string(b))
		if e != nil || pid == "0" {
			ok = false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		listeners, e := exec.CommandContext(ctx, "ss", "-H", "-ltnp").Output()
		cancel()
		if e != nil {
			ok = false
		}
		for _, port := range s.ports {
			found := false
			for _, line := range strings.Split(string(listeners), "\n") {
				f := strings.Fields(line)
				if len(f) > 3 && strings.Contains(line, "pid="+pid+",") {
					_, p, _ := net.SplitHostPort(f[3])
					if p == port {
						found = true
					}
				}
			}
			if !found {
				ok = false
			}
		}
		if ok {
			stable++
			if stable >= 3 {
				return nil
			}
		} else {
			stable = 0
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("服务或原有节点监听未恢复")
}

func validateUnlockFiles(d *configDocument) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("内核配置校验失败: %v", v)
		}
	}()
	// Instantiate the real built-in cores with candidate files before stopping
	// production. No panel nodes are created and original custom inbounds are
	// rejected during preparation to avoid binding production ports.
	for _, raw := range d.cores {
		var c conf.CoreConfig
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		if c.Type != "sing" && c.Type != "xray" {
			continue
		}
		if c.Type == "sing" {
			c.SingConfig.LogConfig.Output = ""
			c.SingConfig.NtpConfig.Enable = false
			original, e := unlockLoad(c.SingConfig.OriginalPath)
			if e != nil {
				return e
			}
			// Validation must not open production cache databases or API ports.
			delete(original, "experimental")
			temp, e := os.CreateTemp(filepath.Dir(c.SingConfig.OriginalPath), ".validate-*.json")
			if e != nil {
				return e
			}
			defer os.Remove(temp.Name())
			_, e = temp.Write(unlockRaw(original))
			closeErr := temp.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
			c.SingConfig.OriginalPath = temp.Name()
		}
		if c.Type == "xray" {
			c.XrayConfig.LogConfig.AccessPath = ""
			c.XrayConfig.LogConfig.ErrorPath = ""
		}
		if c.Type == "xray" && (c.XrayConfig.InboundConfigPath != "" || c.XrayConfig.OutboundConfigPath != "") {
			return fmt.Errorf("Xray 含外部入站/出站，请手动配置，避免校验影响现有监听")
		}
		instance, err := core.NewCore([]conf.CoreConfig{c})
		if err != nil {
			return fmt.Errorf("%s 配置校验失败: %w", c.Type, err)
		}
		err = instance.Start()
		closeErr := instance.Close()
		if err != nil {
			return fmt.Errorf("%s 启动校验失败: %w", c.Type, err)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func probeUnlockDNS(address string) error {
	u := strings.SplitN(address, "://", 2)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, server string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, u[0], u[1])
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	addresses, err := resolver.LookupIPAddr(ctx, "chatgpt.com")
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("解锁 DNS 查询失败，请检查地址、端口和服务商 IP 授权: %v", err)
	}
	return nil
}

// Commit only after candidate validation; restore both config and service when
// startup fails. The original user DNS/route files are never modified.
func commitUnlock(path string, original, data []byte, service unlockService) error {
	if !service.Active() {
		return fmt.Errorf("请先启动并确认 V2bX 正常，再配置 DNS 解锁")
	}
	if err := service.Stop(); err != nil {
		return err
	}
	if err := saveDocument(path, original, data); err != nil {
		startErr := service.Start()
		if startErr != nil {
			return fmt.Errorf("保存失败: %v；恢复服务失败: %w", err, startErr)
		}
		return err
	}
	err := service.Start()
	if err == nil {
		err = service.Healthy()
	}
	if err == nil {
		return nil
	}
	if e := service.Stop(); e != nil {
		return fmt.Errorf("应用失败: %v；停止失败，未覆盖配置: %w", err, e)
	}
	if e := saveDocument(path, data, original); e != nil {
		return fmt.Errorf("应用失败: %v；配置恢复失败: %w", err, e)
	}
	if e := service.Start(); e != nil {
		return fmt.Errorf("配置已回退，但恢复启动失败: %w", e)
	}
	if e := service.Healthy(); e != nil {
		return fmt.Errorf("配置已回退，但服务仍异常: %w", e)
	}
	return fmt.Errorf("应用失败，已恢复原配置及服务: %w", err)
}

func runUnlock(path, action, address string, out io.Writer, service unlockService, validate func(*configDocument) error) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".dns-unlock.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("已有 DNS 解锁操作正在执行")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	statePath := path + ".dns-unlock.json"
	var state unlockState
	stateData, stateErr := os.ReadFile(statePath)
	if stateErr != nil && !os.IsNotExist(stateErr) {
		return stateErr
	}
	if stateErr == nil {
		if err = json.Unmarshal(stateData, &state); err != nil {
			return fmt.Errorf("管理状态损坏: %w", err)
		}
	}
	if action == "status" {
		if stateErr == nil {
			fmt.Fprintf(out, "菜单托管的 DNS 解锁已开启：%s\n", state.Address)
		} else {
			fmt.Fprintln(out, "菜单托管的 DNS 解锁未开启；手动配置请查看原配置文件。")
		}
		return nil
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d, err := readDocument(original)
	if err != nil {
		return err
	}
	if action == "disable" {
		if stateErr != nil {
			fmt.Fprintln(out, "没有菜单托管的解锁配置，无需恢复。")
			return nil
		}
		if err = restoreUnlock(d, &state); err != nil {
			return err
		}
		data, e := d.marshal()
		if e != nil {
			return e
		}
		if err = commitUnlock(path, original, data, service); err != nil {
			return err
		}
		if err = os.Remove(statePath); err != nil {
			return fmt.Errorf("已恢复原配置，但管理状态删除失败: %w", err)
		}
		fmt.Fprintln(out, "已关闭菜单托管的 DNS 解锁并恢复原配置；原有手动解锁配置会保留。")
		return nil
	}
	if action != "enable" {
		return fmt.Errorf("未知操作")
	}
	if stateErr == nil {
		return fmt.Errorf("已开启，请先关闭并恢复后再更换 DNS")
	}
	address, err = unlockAddress(address)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(path), "dns-unlock-")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	next, files, err := prepareUnlock(d, dir, address)
	if err != nil {
		return err
	}
	for name, data := range files {
		if err = os.WriteFile(name, data, 0600); err != nil {
			return err
		}
	}
	if err = validate(d); err != nil {
		return err
	}
	data, err := d.marshal()
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "config.before.json"), original, 0600); err != nil {
		return err
	}
	// Persist recovery metadata before modifying production config. A failed
	// commit is removed only when the config is confirmed to be unchanged.
	stateBytes, _ := json.MarshalIndent(next, "", "  ")
	f, err := os.OpenFile(statePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(stateBytes)
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		_ = os.Remove(statePath)
		return err
	}
	if err = commitUnlock(path, original, data, service); err != nil {
		current, e := os.ReadFile(path)
		if e == nil && bytes.Equal(current, original) {
			_ = os.Remove(statePath)
		} else {
			keep = true
		}
		return err
	}
	keep = true
	fmt.Fprintf(out, "DNS 解锁已启用：%s；原配置及托管文件保存在 %s\n请通过节点验证实际流媒体访问，DNS 授权和播放区域取决于服务商。\n", address, dir)
	return nil
}

func init() {
	var path string
	c := &cobra.Command{Use: "dns-unlock", Short: "交互配置 sing/Xray 流媒体 DNS 解锁（默认关闭）", SilenceUsage: true, Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		input := c.InOrStdin()
		w := &nodeWizard{input: input, in: bufio.NewReader(input), out: c.OutOrStdout()}
		action, err := w.choose("流媒体 DNS 解锁", []string{"开启（所有 sing/Xray 节点）", "查看状态", "关闭并恢复原配置", "返回"}, []string{"enable", "status", "disable", "return"}, "2")
		if err != nil {
			return err
		}
		if action == "return" {
			return nil
		}
		address := ""
		if action == "enable" {
			address, err = w.ask("请输入 DNS 解锁地址（IP 或 tcp://IP:端口）", "", false)
			if err != nil {
				return err
			}
			address, err = unlockAddress(address)
			if err != nil {
				return err
			}
			if err = probeUnlockDNS(address); err != nil {
				return err
			}
		}
		if action != "status" {
			data, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			doc, e := readDocument(data)
			if e != nil {
				return e
			}
			fmt.Fprintf(w.out, "当前配置共 %d 个节点：\n", len(doc.parsed))
			for _, n := range doc.parsed {
				fmt.Fprintf(w.out, "  节点 %d / %s / 内核 %s %s\n", n.ApiConfig.NodeID, n.ApiConfig.NodeType, n.Options.Core, n.Options.CoreName)
			}
			fmt.Fprintln(w.out, "将调整所有 sing/Xray 节点对应配置，保留原文件；应用时会短暂重启全部节点。")
			ok, e := w.yesNo("确认继续", "n")
			if e != nil {
				return e
			}
			if !ok {
				return nil
			}
		}
		service := &systemUnlockService{}
		if action != "status" {
			if err = service.capturePorts(); err != nil {
				return err
			}
		}
		return runUnlock(path, action, address, w.out, service, validateUnlockFiles)
	}}
	c.Flags().StringVar(&path, "config", "/etc/V2bX/config.json", "配置文件路径")
	command.AddCommand(c)
}
