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
			stop, err := c.WatchWithCancel(configPath, "", "", func() {
				reloaded <- struct{}{}
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(stop)
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
			stop, err := c.WatchWithCancel(configPath, xrayDNS, singDNS, func() {
				reloaded <- c.LogConfig.Level
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(stop)
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

func TestConf_WatchLifecycle(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	countWatchers := func() int {
		t.Helper()
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skip("watcher descriptor check requires procfs")
		}
		count := 0
		for _, entry := range entries {
			target, _ := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if target == "anon_inode:inotify" {
				count++
			}
		}
		return count
	}
	before := countWatchers()
	c := New()
	for _, paths := range [][3]string{
		{filepath.Join(dir, "missing"), "", ""},
		{configPath, filepath.Join(dir, "missing"), ""},
		{configPath, "", filepath.Join(dir, "missing")},
	} {
		stop, err := c.WatchWithCancel(paths[0], paths[1], paths[2], func() {})
		if err == nil || stop != nil {
			t.Fatal("missing watch path should fail")
		}
		if got := countWatchers(); got != before {
			t.Fatalf("failed setup leaked watchers: %d -> %d", before, got)
		}
	}
	reloaded := make(chan struct{}, 1)
	stop, err := c.WatchWithCancel(configPath, "", "", func() { reloaded <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	if err := os.WriteFile(configPath, []byte(`{"Log":{"Level":"debug"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Let fsnotify deliver the write so cancellation also exercises a pending reload.
	time.Sleep(100 * time.Millisecond)
	stop()
	stop()
	if got := countWatchers(); got != before {
		t.Fatalf("stop leaked watchers: %d -> %d", before, got)
	}
	select {
	case <-reloaded:
		t.Fatal("reload ran after cancellation")
	case <-time.After(6 * time.Second):
	}
	if c.LogConfig.Level != "info" {
		t.Fatal("cancelled reload changed configuration")
	}
}
