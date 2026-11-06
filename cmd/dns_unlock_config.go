package cmd

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed templates/sing-unlock.json
var singUnlockTemplate []byte

//go:embed templates/xray-unlock.json
var xrayUnlockTemplate []byte

type unlockPatch struct {
	Kind   string
	ID     string
	Before map[string]json.RawMessage
	After  map[string]json.RawMessage
}
type unlockState struct {
	Address string
	Patches []unlockPatch
}

func unlockAddress(input string) (string, error) {
	s := strings.TrimSpace(input)
	if !strings.Contains(s, "://") {
		if net.ParseIP(s) != nil {
			s = "tcp://" + net.JoinHostPort(s, "53")
		} else {
			s = "tcp://" + s
		}
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "tcp" && u.Scheme != "udp") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("请输入解锁 DNS 的 IP，支持 tcp://IP:端口 或 udp://IP:端口")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return "", fmt.Errorf("解锁 DNS 必须是有效 IP 地址")
	}
	port := u.Port()
	if port == "" {
		port = "53"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("DNS 端口无效")
	}
	return u.Scheme + "://" + net.JoinHostPort(ip.String(), fmt.Sprint(n)), nil
}

func unlockObject(raw []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	err := json.Unmarshal(raw, &m)
	if err == nil && m == nil {
		err = fmt.Errorf("配置必须是 JSON 对象")
	}
	return m, err
}
func unlockRaw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func unlockString(m map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(m[key], &s)
	return s
}
func unlockArray(m map[string]json.RawMessage, key string) ([]json.RawMessage, error) {
	var a []json.RawMessage
	if len(m[key]) == 0 {
		return a, nil
	}
	err := json.Unmarshal(m[key], &a)
	return a, err
}
func unlockSection(m map[string]json.RawMessage, key string) (map[string]json.RawMessage, error) {
	if len(m[key]) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	return unlockObject(m[key])
}
func unlockLoad(path string) (map[string]json.RawMessage, error) {
	if path == "" {
		return map[string]json.RawMessage{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// OriginalPath accepts JSON with comments as well as plain JSON.
	d, err := readDocument(b)
	if err != nil {
		return nil, err
	}
	return d.fields, nil
}

func mergeSingUnlock(m map[string]json.RawMessage, address string) ([]byte, error) {
	template, _ := unlockObject(singUnlockTemplate)
	dns, err := unlockSection(m, "dns")
	if err != nil {
		return nil, err
	}
	route, err := unlockSection(m, "route")
	if err != nil {
		return nil, err
	}
	outbounds, err := unlockArray(m, "outbounds")
	if err != nil {
		return nil, err
	}
	direct := ""
	used := map[string]bool{}
	for _, raw := range outbounds {
		o, e := unlockObject(raw)
		if e != nil {
			return nil, e
		}
		tag := unlockString(o, "tag")
		used[tag] = true
		if unlockString(o, "type") == "direct" && direct == "" {
			direct = tag
		}
	}
	if direct == "" {
		direct = "v2bx-unlock-direct"
		if used[direct] {
			return nil, fmt.Errorf("保留出口标签冲突: %s", direct)
		}
		outbounds = append(outbounds, unlockRaw(map[string]any{"type": "direct", "tag": direct}))
		m["outbounds"] = unlockRaw(outbounds)
	}
	servers, err := unlockArray(dns, "servers")
	if err != nil {
		return nil, err
	}
	for _, r := range servers {
		o, e := unlockObject(r)
		if e != nil {
			return nil, e
		}
		if unlockString(o, "tag") == "v2bx-unlock" {
			return nil, fmt.Errorf("DNS 标签 v2bx-unlock 已被使用")
		}
	}
	servers = append(servers, unlockRaw(map[string]any{"tag": "v2bx-unlock", "address": address, "detour": direct}))
	if len(dns["final"]) == 0 && len(servers) == 1 {
		servers = append(servers, unlockRaw(map[string]any{"tag": "v2bx-public", "address": "1.1.1.1", "detour": direct}))
		dns["final"] = unlockRaw("v2bx-public")
	}
	dns["servers"] = unlockRaw(servers)
	tDNS, _ := unlockSection(template, "dns")
	newRules, _ := unlockArray(tDNS, "rules")
	rules, err := unlockArray(dns, "rules")
	if err != nil {
		return nil, err
	}
	dns["rules"] = unlockRaw(append(newRules, rules...))
	tRoute, _ := unlockSection(template, "route")
	newSets, _ := unlockArray(tRoute, "rule_set")
	sets, err := unlockArray(route, "rule_set")
	if err != nil {
		return nil, err
	}
	// Namespace remote rule sets so user-owned sets are never replaced.
	replacements := map[string]string{}
	for i, raw := range newSets {
		s, _ := unlockObject(raw)
		tag := unlockString(s, "tag")
		replacements[tag] = "v2bx-unlock-" + tag
		s["tag"] = unlockRaw(replacements[tag])
		s["download_detour"] = unlockRaw(direct)
		newSets[i] = unlockRaw(s)
	}
	for _, raw := range sets {
		s, e := unlockObject(raw)
		if e != nil {
			return nil, e
		}
		for _, tag := range replacements {
			if unlockString(s, "tag") == tag {
				return nil, fmt.Errorf("规则集标签已被使用: %s", tag)
			}
		}
	}
	for i, raw := range newRules {
		s, _ := unlockObject(raw)
		var tags []string
		_ = json.Unmarshal(s["rule_set"], &tags)
		for j, tag := range tags {
			tags[j] = replacements[tag]
		}
		s["rule_set"] = unlockRaw(tags)
		newRules[i] = unlockRaw(s)
	}
	dns["rules"] = unlockRaw(append(newRules, rules...))
	route["rule_set"] = unlockRaw(append(sets, newSets...))
	rules, err = unlockArray(route, "rules")
	if err != nil {
		return nil, err
	}
	prefix := []json.RawMessage{unlockRaw(map[string]any{"action": "sniff"}), unlockRaw(map[string]any{"action": "resolve", "strategy": "prefer_ipv4"})}
	route["rules"] = unlockRaw(append(prefix, rules...))
	// Existing original inbounds could conflict with the running service during
	// preflight; require their owner to configure that advanced case manually.
	inbounds, err := unlockArray(m, "inbounds")
	if err != nil {
		return nil, err
	}
	if len(inbounds) > 0 {
		return nil, fmt.Errorf("原始配置含自定义 inbounds，请手动合并解锁配置")
	}
	for _, key := range []string{"endpoints", "services"} {
		rows, e := unlockArray(m, key)
		if e != nil {
			return nil, e
		}
		if len(rows) > 0 {
			return nil, fmt.Errorf("原始配置含 %s，请手动合并解锁配置", key)
		}
	}
	m["dns"] = unlockRaw(dns)
	m["route"] = unlockRaw(route)
	return json.MarshalIndent(m, "", "  ")
}

func mergeXrayUnlock(m map[string]json.RawMessage, address string) ([]byte, error) {
	template, _ := unlockObject(xrayUnlockTemplate)
	ts, _ := unlockArray(template, "servers")
	target, _ := unlockObject(ts[len(ts)-1])
	if strings.HasPrefix(address, "udp://") {
		u, _ := url.Parse(address)
		target["address"] = unlockRaw(u.Hostname())
		p, _ := strconv.Atoi(u.Port())
		target["port"] = unlockRaw(p)
	} else {
		target["address"] = unlockRaw(address)
	}
	servers, err := unlockArray(m, "servers")
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		servers = ts[:len(ts)-1]
	}
	// Place specific unlock domains before any user-defined general resolvers.
	m["servers"] = unlockRaw(append([]json.RawMessage{unlockRaw(target)}, servers...))
	if len(m["tag"]) == 0 {
		m["tag"] = unlockRaw("dns_inbound")
	}
	return json.MarshalIndent(m, "", "  ")
}

func unlockNodeID(raw map[string]json.RawMessage) (string, error) {
	api := raw
	if b, ok := raw["ApiConfig"]; ok {
		var err error
		api, err = unlockObject(b)
		if err != nil {
			return "", err
		}
	}
	return string(unlockRaw([]json.RawMessage{api["ApiHost"], api["NodeType"], api["NodeID"]})), nil
}
func unlockCoreID(raw map[string]json.RawMessage) string {
	name := unlockString(raw, "Name")
	if name == "" {
		name = unlockString(raw, "Type")
	}
	return name
}
func recordUnlockPatch(state *unlockState, kind, id string, m map[string]json.RawMessage, updates map[string]json.RawMessage) {
	p := unlockPatch{Kind: kind, ID: id, Before: map[string]json.RawMessage{}, After: updates}
	for k, v := range updates {
		p.Before[k] = m[k]
		m[k] = v
	}
	state.Patches = append(state.Patches, p)
}

func prepareUnlock(d *configDocument, dir, address string) (*unlockState, map[string][]byte, error) {
	state := &unlockState{Address: address}
	files := map[string][]byte{}
	cores := map[string]string{}
	for i, raw := range d.cores {
		m, err := unlockObject(raw)
		if err != nil {
			return nil, nil, err
		}
		id := unlockCoreID(m)
		if _, ok := cores[id]; ok {
			return nil, nil, fmt.Errorf("内核名称重复: %s", id)
		}
		kind := unlockString(m, "Type")
		cores[id] = kind
		if kind != "sing" && kind != "xray" {
			continue
		}
		key := "OriginalPath"
		if kind == "xray" {
			key = "DnsConfigPath"
		}
		old, err := unlockLoad(unlockString(m, key))
		if err != nil {
			return nil, nil, fmt.Errorf("读取 %s 原配置: %w", id, err)
		}
		filename := filepath.Join(dir, fmt.Sprintf("%s-%d.json", kind, i))
		var data []byte
		if kind == "sing" {
			data, err = mergeSingUnlock(old, address)
		} else {
			data, err = mergeXrayUnlock(old, address)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("合并 %s: %w", id, err)
		}
		files[filename] = data
		recordUnlockPatch(state, "core", id, m, map[string]json.RawMessage{key: unlockRaw(filename)})
		d.cores[i] = unlockRaw(m)
	}
	seen := map[string]bool{}
	supported := 0
	for i, raw := range d.nodes {
		m, err := unlockObject(raw)
		if err != nil {
			return nil, nil, err
		}
		if _, ok := m["Include"]; ok {
			return nil, nil, fmt.Errorf("节点 %d 使用 Include，需手动配置以保留外部配置", i+1)
		}
		id, err := unlockNodeID(m)
		if err != nil {
			return nil, nil, err
		}
		if seen[id] {
			return nil, nil, fmt.Errorf("节点标识重复，无法安全恢复")
		}
		seen[id] = true
		opt := m
		if b, ok := m["Options"]; ok {
			opt, err = unlockObject(b)
			if err != nil {
				return nil, nil, err
			}
		}
		name := unlockString(opt, "CoreName")
		if name == "" && len(cores) > 1 {
			selected := unlockString(opt, "Core")
			matches := 0
			for id, kind := range cores {
				if kind == selected {
					name = id
					matches++
				}
			}
			if matches > 1 {
				return nil, nil, fmt.Errorf("节点 %d 存在多个同类内核，请设置 CoreName", i+1)
			}
		}
		if name == "" {
			name = unlockString(opt, "Core")
		}
		if name == "" && len(cores) == 1 {
			for k := range cores {
				name = k
			}
		}
		kind, ok := cores[name]
		if !ok {
			return nil, nil, fmt.Errorf("节点 %d 的内核选择不明确，请设置 CoreName", i+1)
		}
		if kind != "sing" && kind != "xray" {
			return nil, nil, fmt.Errorf("节点 %d 的 %s 内核暂不支持 DNS 解锁", i+1, kind)
		}
		supported++
		if kind == "xray" {
			recordUnlockPatch(state, "node", id, opt, map[string]json.RawMessage{"EnableDNS": unlockRaw(true), "DNSType": unlockRaw("UseIP"), "SendIP": unlockRaw("0.0.0.0")})
			if _, ok := m["Options"]; ok {
				m["Options"] = unlockRaw(opt)
			}
			d.nodes[i] = unlockRaw(m)
		}
	}
	if supported == 0 {
		return nil, nil, fmt.Errorf("没有可配置的 sing/Xray 节点")
	}
	return state, files, nil
}

func restoreUnlock(d *configDocument, state *unlockState) error {
	for _, p := range state.Patches {
		rows := d.cores
		if p.Kind == "node" {
			rows = d.nodes
		}
		found := false
		for i, raw := range rows {
			m, err := unlockObject(raw)
			if err != nil {
				return err
			}
			id := unlockCoreID(m)
			if p.Kind == "node" {
				id, err = unlockNodeID(m)
				if err != nil {
					return err
				}
			}
			if id != p.ID {
				continue
			}
			if found {
				return fmt.Errorf("标识重复，无法安全恢复")
			}
			found = true
			fields := m
			if p.Kind == "node" {
				if b, ok := m["Options"]; ok {
					fields, err = unlockObject(b)
					if err != nil {
						return err
					}
				}
			}
			for k, v := range p.After {
				if !bytes.Equal(bytes.TrimSpace(fields[k]), bytes.TrimSpace(v)) {
					return fmt.Errorf("%s 已手动修改，停止恢复以免覆盖；请参考备份", k)
				}
			}
			for k, v := range p.Before {
				if len(v) == 0 || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
					delete(fields, k)
				} else {
					fields[k] = v
				}
			}
			if p.Kind == "node" {
				if _, ok := m["Options"]; ok {
					m["Options"] = unlockRaw(fields)
				}
			}
			rows[i] = unlockRaw(m)
		}
		// Removed nodes/cores need no restoration; unrelated edits remain intact.
	}
	return nil
}
