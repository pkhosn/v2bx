package conf

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch starts a watcher that runs until the process exits.
func (p *Conf) Watch(filePath, xDnsPath, sDnsPath string, reload func()) error {
	_, err := p.WatchWithCancel(filePath, xDnsPath, sDnsPath, reload)
	return err
}

// WatchWithCancel returns an idempotent stop function that waits for the watcher
// and any running reload to finish. It must not be called from reload itself.
func (p *Conf) WatchWithCancel(filePath, xDnsPath, sDnsPath string, reload func()) (func(), error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("new watcher error: %s", err)
	}
	for i, name := range []string{filePath, xDnsPath, sDnsPath} {
		if i > 0 && name == "" {
			continue
		}
		if err := watcher.Add(name); err != nil {
			watcher.Close()
			if i == 0 {
				return nil, fmt.Errorf("watch file error: %s", err)
			}
			return nil, fmt.Errorf("watch dns file error: %s", err)
		}
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		defer watcher.Close()
		var pre time.Time
		var timer *time.Timer
		var pending <-chan time.Time
		var changed string
		defer func() {
			if timer != nil {
				timer.Stop()
			}
		}()
		for {
			select {
			case <-stop:
				return
			case e, ok := <-watcher.Events:
				if !ok {
					return
				}
				if e.Has(fsnotify.Chmod) || pre.Add(10*time.Second).After(time.Now()) {
					continue
				}
				pre = time.Now()
				changed = e.Name
				timer = time.NewTimer(5 * time.Second)
				pending = timer.C
			case <-pending:
				pending = nil
				select {
				case <-stop:
					return
				default:
				}
				switch filepath.Base(strings.TrimSuffix(changed, "~")) {
				case filepath.Base(xDnsPath), filepath.Base(sDnsPath):
					log.Println("DNS file changed, reloading...")
				default:
					log.Println("config file changed, reloading...")
				}
				next := New()
				if err := next.LoadFromPath(filePath); err != nil {
					log.Printf("reload config error: %s", err)
					continue
				}
				*p = *next
				reload()
				log.Println("reload config success")
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				if err != nil {
					log.Printf("File watcher error: %s", err)
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }); <-done }, nil
}
