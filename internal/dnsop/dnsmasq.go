package dnsop

import (
	"net"
	"strings"
)

// dnsmasqEntry 是 dnsmasq 配置中一条与 DNS 相关的指令解析结果。
// Kind 取值：address / server / server-global / local / host-record / addn-hosts。
type dnsmasqEntry struct {
	// Kind 是指令类别。
	Kind string
	// Domains 是指令作用的域名列表（可多个，已归一）。
	Domains []string
	// Addr 是地址 / 上游（不含域名作用域）。
	Addr string
	// Names / Addrs 是 host-record 的名字与地址。
	Names []string
	Addrs []string
	// Path 是 addn-hosts 指向的文件。
	Path string
	// Line 是配置行号（诊断用）。
	Line int
}

// dnsmasqKind* 是解析出的指令类别常量。
const (
	dnsmasqKindAddress      = "address"
	dnsmasqKindServer       = "server"
	dnsmasqKindServerGlobal = "server-global"
	dnsmasqKindLocal        = "local"
	dnsmasqKindHostRecord   = "host-record"
	dnsmasqKindAddnHosts    = "addn-hosts"
)

// ParseDnsmasqConf 解析 dnsmasq 配置文本，只提取与 DNS 记录/上游相关的指令。
//
// 支持行尾 `\` 续行、`#` 注释。只解析不执行：addn-hosts 等引用路径由调用方按白名单决定读不读。
func ParseDnsmasqConf(text string) []dnsmasqEntry {
	entries := make([]dnsmasqEntry, 0, 16)
	lines := joinContinuation(text)
	for index, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if hash := strings.Index(line, " #"); hash >= 0 {
			line = strings.TrimSpace(line[:hash])
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		lineNo := index + 1
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "address":
			domains, addr := splitDomainScopedValue(value)
			if addr == "" || addr == "#" {
				continue
			}
			entries = append(entries, dnsmasqEntry{Kind: dnsmasqKindAddress, Domains: domains, Addr: addr, Line: lineNo})
		case "server":
			domains, addr := splitDomainScopedValue(value)
			kind := dnsmasqKindServer
			if len(domains) == 0 {
				kind = dnsmasqKindServerGlobal
			}
			if addr == "" {
				continue
			}
			entries = append(entries, dnsmasqEntry{Kind: kind, Domains: domains, Addr: addr, Line: lineNo})
		case "local":
			for _, domain := range splitSlashDomains(value) {
				entries = append(entries, dnsmasqEntry{Kind: dnsmasqKindLocal, Domains: []string{domain}, Line: lineNo})
			}
		case "host-record":
			parts := splitCommaList(value)
			if len(parts) < 2 {
				continue
			}
			entry := dnsmasqEntry{Kind: dnsmasqKindHostRecord, Line: lineNo, Names: []string{normalizeZoneName(parts[0])}}
			for _, candidate := range parts[1:] {
				if net.ParseIP(candidate) != nil {
					entry.Addrs = append(entry.Addrs, candidate)
				}
			}
			if len(entry.Addrs) == 0 {
				continue
			}
			entries = append(entries, entry)
		case "addn-hosts":
			path := strings.TrimSpace(value)
			if path == "" {
				continue
			}
			entries = append(entries, dnsmasqEntry{Kind: dnsmasqKindAddnHosts, Path: path, Line: lineNo})
		}
	}
	return entries
}

// joinContinuation 合并行尾反斜杠续行。
func joinContinuation(text string) []string {
	rawLines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(rawLines))
	buffer := ""
	for _, line := range rawLines {
		if strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") {
			buffer += strings.TrimRight(strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\"), " \t") + " "
			continue
		}
		out = append(out, buffer+line)
		buffer = ""
	}
	if buffer != "" {
		out = append(out, buffer)
	}
	return out
}

// splitDomainScopedValue 拆 `/a.com/b.com/1.2.3.4` 形式：返回域名列表与末段值。
// 不以 `/` 开头时视为全局值（域名列表为空）。
func splitDomainScopedValue(value string) ([]string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ""
	}
	if !strings.HasPrefix(value, "/") {
		return nil, value
	}
	parts := strings.Split(value, "/")
	if len(parts) < 3 {
		return nil, ""
	}
	domains := make([]string, 0, len(parts)-2)
	for _, part := range parts[1 : len(parts)-1] {
		if domain := normalizeZoneName(part); domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains, strings.TrimSpace(parts[len(parts)-1])
}

// splitSlashDomains 拆 `local=/a.com/` 形式的域名列表。
func splitSlashDomains(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "/")
	value = strings.TrimSuffix(value, "/")
	domains := make([]string, 0, 2)
	for _, part := range strings.Split(value, "/") {
		if domain := normalizeZoneName(part); domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains
}

// splitCommaList 拆逗号分隔列表并去空白。
func splitCommaList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ParseHostsFile 解析 hosts 格式文本（`IP name [name...]`），返回 A/AAAA 记录。
// 注释行与非法 IP 行跳过；记录 TTL 记为 0（hosts 文件不声明 TTL）。
func ParseHostsFile(text string) []Record {
	records := make([]Record, 0, 16)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if hash := strings.Index(line, "#"); hash >= 0 {
			line = strings.TrimSpace(line[:hash])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		recordType := "A"
		if ip.To4() == nil {
			recordType = "AAAA"
		}
		for _, name := range fields[1:] {
			normalized := normalizeZoneName(name)
			if normalized == "" {
				continue
			}
			records = append(records, Record{Name: normalized, Type: recordType, Value: fields[0], TTL: 0})
		}
	}
	return records
}

// recordTypeForAddr 按地址判断 A/AAAA。
func recordTypeForAddr(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "A"
	}
	return "AAAA"
}

// dnsmasqUpstreams 从 dnsmasq 主配置与片段目录收集上游地址（server= 指令）。
func (d Detector) dnsmasqUpstreams(paths Paths) []string {
	upstreams := make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	collect := func(text string) {
		for _, entry := range ParseDnsmasqConf(text) {
			if entry.Kind != dnsmasqKindServer && entry.Kind != dnsmasqKindServerGlobal {
				continue
			}
			addr := strings.TrimSpace(entry.Addr)
			if addr == "" || addr == "#" {
				continue
			}
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			upstreams = append(upstreams, addr)
			if len(upstreams) >= maxUpstreams {
				return
			}
		}
	}
	if data, err := d.Host.ReadFile(paths.DnsmasqConf); err == nil {
		collect(string(data))
	}
	if names, err := d.Host.ListDir(paths.DnsmasqDir); err == nil {
		for _, name := range names {
			if len(upstreams) >= maxUpstreams {
				break
			}
			if data, err := d.Host.ReadFile(paths.DnsmasqDir + "/" + name); err == nil {
				collect(string(data))
			}
		}
	}
	return upstreams
}

// bindUpstreams 从 named.conf.options 的 forwarders 收集上游。
func (d Detector) bindUpstreams(paths Paths) []string {
	optionsPath := strings.TrimSuffix(paths.BindConf, "/")
	if idx := strings.LastIndex(optionsPath, "/"); idx > 0 {
		optionsPath = optionsPath[:idx] + "/named.conf.options"
	} else {
		return nil
	}
	data, err := d.Host.ReadFile(optionsPath)
	if err != nil {
		return nil
	}
	return ParseNamedForwarders(string(data))
}
