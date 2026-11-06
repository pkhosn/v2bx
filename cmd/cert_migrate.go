package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkhosn/v2bx/conf"
	"github.com/pkhosn/v2bx/node"
	"github.com/spf13/cobra"
)

type certificateMigration struct {
	target *conf.CertConfig
	files  map[string][]byte
}

// Only migrate the historical managed paths. Custom paths and externally
// included configurations remain under their owner's control.
func migrateCertificates(path string, apply bool, out io.Writer) (err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d, err := readDocument(original)
	if err != nil {
		return err
	}
	base := filepath.Dir(path)
	plans := map[string]*certificateMigration{}
	order := []string{}
	for i, n := range d.parsed {
		var raw map[string]json.RawMessage
		if err = json.Unmarshal(d.nodes[i], &raw); err != nil {
			return err
		}
		if _, included := raw["Include"]; included {
			continue
		}
		c := n.Options.CertConfig
		if c == nil || (c.CertMode != "http" && c.CertMode != "dns") {
			continue
		}
		if filepath.Clean(c.CertFile) != filepath.Join(base, "fullchain.cer") || filepath.Clean(c.KeyFile) != filepath.Join(base, "cert.key") {
			continue
		}
		domain := strings.ToLower(strings.TrimSuffix(c.CertDomain, "."))
		if !validDomain(domain) {
			return fmt.Errorf("节点 %d 的证书域名无效", i+1)
		}
		if err = node.ValidateCertificate(c); err != nil {
			return fmt.Errorf("节点 %d 的原证书校验失败: %w", i+1, err)
		}
		target := *c
		dir := filepath.Join(base, "certs", "acme", domain)
		target.CertFile = filepath.Join(dir, "fullchain.cer")
		target.KeyFile = filepath.Join(dir, "cert.key")
		plan, exists := plans[domain]
		if !exists {
			if _, e := os.Lstat(dir); !os.IsNotExist(e) {
				if e != nil {
					return e
				}
				return fmt.Errorf("目标目录已存在，拒绝覆盖: %s", dir)
			}
			plan = &certificateMigration{target: &target, files: map[string][]byte{}}
			for _, name := range []string{"fullchain.cer", "cert.key"} {
				plan.files[name], err = os.ReadFile(filepath.Join(base, name))
				if err != nil {
					return err
				}
			}
			plans[domain] = plan
			order = append(order, domain)
		}
		// Lego stores its account beside the certificate. Keep each referenced
		// account, including when multiple nodes share a certificate and domain.
		account := "user-" + c.Email + ".json"
		if filepath.Base(account) != account || strings.ContainsAny(account, `/\`) {
			return fmt.Errorf("节点 %d 的 ACME 邮箱不能用于账户文件名", i+1)
		}
		data, e := os.ReadFile(filepath.Join(base, "user", account))
		if e == nil {
			plan.files[filepath.Join("user", account)] = data
		} else if !os.IsNotExist(e) {
			return e
		} else {
			fmt.Fprintf(out, "提示：节点 %d 无本地 ACME 账户文件；续期时将沿用程序原有账户注册逻辑。\n", i+1)
		}
		fields := raw
		if options, ok := raw["Options"]; ok {
			fields = map[string]json.RawMessage{}
			if err = json.Unmarshal(options, &fields); err != nil {
				return err
			}
		}
		// Preserve unknown certificate fields, just as unknown node fields are kept.
		certFields := map[string]json.RawMessage{}
		if err = json.Unmarshal(fields["CertConfig"], &certFields); err != nil {
			return err
		}
		certFields["CertFile"], _ = json.Marshal(target.CertFile)
		certFields["KeyFile"], _ = json.Marshal(target.KeyFile)
		fields["CertConfig"], _ = json.Marshal(certFields)
		if _, ok := raw["Options"]; ok {
			raw["Options"], _ = json.Marshal(fields)
		}
		d.nodes[i], err = json.Marshal(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "节点 %d：%s → %s\n", i+1, base, dir)
	}
	if len(order) == 0 {
		fmt.Fprintln(out, "没有需要迁移的旧版自动证书路径。")
		return nil
	}
	if !apply {
		fmt.Fprintln(out, "仅预览，未修改任何文件。停止 V2bX 后使用 --apply 执行迁移，完成后启动服务。")
		return nil
	}
	// The service must be stopped during migration to prevent concurrent renewal.
	// Retain sources and roll back only directories created by this invocation.
	created := []string{}
	defer func() {
		if err != nil {
			for _, dir := range created {
				_ = os.RemoveAll(dir)
			}
		}
	}()
	for _, domain := range order {
		p := plans[domain]
		dir := filepath.Dir(p.target.CertFile)
		if err = os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
			return err
		}
		if err = os.Mkdir(dir, 0700); err != nil {
			return err
		}
		created = append(created, dir)
		for name, data := range p.files {
			src := filepath.Join(base, name)
			current, e := os.ReadFile(src)
			if e != nil {
				return e
			}
			if !bytes.Equal(current, data) {
				return fmt.Errorf("原证书或账户已发生变化，请停止服务后重试")
			}
			dst := filepath.Join(dir, name)
			if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
				return err
			}
			mode := os.FileMode(0600)
			if name == "fullchain.cer" {
				mode = 0644
			}
			if err = os.WriteFile(dst, data, mode); err != nil {
				return err
			}
		}
		if err = node.ValidateCertificate(p.target); err != nil {
			return fmt.Errorf("迁移后证书校验失败: %w", err)
		}
	}
	data, err := d.marshal()
	if err != nil {
		return err
	}
	if err = saveDocument(path, original, data); err != nil {
		return err
	}
	fmt.Fprintf(out, "迁移完成；配置备份为 %s.bak，原证书和账户文件均保留。启动服务后使用新路径续期。\n", path)
	return nil
}

func init() {
	var path string
	var apply bool
	c := &cobra.Command{Use: "cert-migrate", Short: "预览或迁移旧版自动证书到按域名划分的目录", SilenceUsage: true, Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		return migrateCertificates(path, apply, c.OutOrStdout())
	}}
	c.Flags().StringVar(&path, "config", "/etc/V2bX/config.json", "配置文件路径")
	c.Flags().BoolVar(&apply, "apply", false, "停止服务后执行迁移，保留旧文件并备份配置")
	command.AddCommand(c)
}
