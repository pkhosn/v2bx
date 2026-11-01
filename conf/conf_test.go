package conf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConf_LoadFromPath(t *testing.T) {
	c := New()
	if err := c.LoadFromPath("../example/config.json"); err != nil {
		t.Fatal(err)
	}
	if len(c.CoresConfig) == 0 || len(c.NodeConfig) == 0 {
		t.Fatal("example config should contain cores and nodes")
	}
}

func TestConf_Watch(t *testing.T) {
	for _, source := range []string{"config", "xray_dns", "sing_dns"} {
		t.Run(source, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			writeFile := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeFile(configPath, `{"Log":{"Level":"debug"}}`)
			var xrayDNS, singDNS string
			changedPath := configPath
			if source != "config" {
				changedPath = filepath.Join(dir, source+".json")
				writeFile(changedPath, `{}`)
				if source == "xray_dns" {
					xrayDNS = changedPath
				} else {
					singDNS = changedPath
				}
			}
			c := New()
			reloaded := make(chan string, 1)
			if err := c.Watch(configPath, xrayDNS, singDNS, func() {
				reloaded <- c.LogConfig.Level
			}); err != nil {
				t.Fatal(err)
			}
			if source == "config" {
				writeFile(changedPath, `{"Log":{"Level":"debug"}}`)
			} else {
				writeFile(changedPath, `{"servers":["localhost"]}`)
			}
			timer := time.NewTimer(10 * time.Second)
			defer timer.Stop()
			select {
			case level := <-reloaded:
				if level != "debug" {
					t.Fatalf("reloaded log level = %q, want debug", level)
				}
			case <-timer.C:
				t.Fatal("file change did not reload config within 10 seconds")
			}
		})
	}
}
