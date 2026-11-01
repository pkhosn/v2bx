package conf

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestConf_WatchRejectsInvalidConfig(t *testing.T) {
	for _, scenario := range []string{"invalid_json", "invalid_field", "missing_file"} {
		t.Run(scenario, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(configPath, []byte(`{"Log":{"Level":"debug"},"Cores":[{"Type":"xray"}],"Nodes":[{"NodeID":42}]}`), 0600); err != nil {
				t.Fatal(err)
			}
			c := New()
			if err := c.LoadFromPath(configPath); err != nil {
				t.Fatal(err)
			}
			original := *c
			reloaded := make(chan struct{}, 1)
			if err := c.Watch(configPath, "", "", func() {
				reloaded <- struct{}{}
			}); err != nil {
				t.Fatal(err)
			}
			var err error
			if scenario == "missing_file" {
				err = os.Remove(configPath)
			} else {
				body := `{"Log":`
				if scenario == "invalid_field" {
					body = `{"Log":{"Level":"error"},"Cores":"invalid"}`
				}
				err = os.WriteFile(configPath, []byte(body), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Watch waits five seconds before loading the changed file.
			timer := time.NewTimer(7 * time.Second)
			defer timer.Stop()
			select {
			case <-reloaded:
				t.Fatal("invalid config triggered a restart callback")
			case <-timer.C:
			}
			if !reflect.DeepEqual(*c, original) {
				t.Fatal("invalid config replaced the running config")
			}
		})
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
