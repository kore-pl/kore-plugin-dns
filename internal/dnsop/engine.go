package dnsop

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// 版本号提取规则：各引擎的版本输出格式不同，统一收敛成裸版本号；
// 提取不到时保留首行原文（截断），不臆造版本。
var (
	systemdVersionRE = regexp.MustCompile(`(?m)^systemd\s+([0-9][^\s]*)\s*(?:\(([^)]+)\))?`)
	dnsmasqVersionRE = regexp.MustCompile(`(?i)dnsmasq\s+version\s+([0-9][^\s]*)`)
	bindVersionRE    = regexp.MustCompile(`(?i)\bBIND\s+([0-9][0-9A-Za-z.\-]*)`)
	corednsVersionRE = regexp.MustCompile(`(?i)CoreDNS-([0-9][^\s,]*)`)
)

// Detector 组合宿主访问与只读路径配置，是 status / zones / records / query 的统一入口。
type Detector struct {
	// Host 是宿主访问抽象（生产为 OSHost，单测为内存假实现）。
	Host Host
	// Paths 是只读配置路径；零值字段回落到 DefaultPaths。
	Paths Paths
	// DefaultEngine 是配置里保存的引擎偏好（auto/四引擎之一）；
	// 方法入参未显式指定 engine 时用它，保证 config.set 保存后立即生效。
	DefaultEngine string
	// Write 是记录写入通道配置（bind9 动态更新）；只读方法不使用。
	Write WriteOptions
}

// paths 返回补齐默认值后的路径集合。
func (d Detector) paths() Paths {
	base := DefaultPaths()
	if d.Paths.BindConf != "" {
		base.BindConf = d.Paths.BindConf
	}
	if d.Paths.BindZoneDir != "" {
		base.BindZoneDir = d.Paths.BindZoneDir
	}
	if d.Paths.DnsmasqConf != "" {
		base.DnsmasqConf = d.Paths.DnsmasqConf
	}
	if d.Paths.DnsmasqDir != "" {
		base.DnsmasqDir = d.Paths.DnsmasqDir
	}
	if d.Paths.ResolvConf != "" {
		base.ResolvConf = d.Paths.ResolvConf
	}
	return base
}

// Status 检测宿主 DNS 服务并返回引擎无关的状态视图。
//
// preferred 为空或 auto 时按 enginePriority 选主引擎；指定引擎但未检测到时
// 返回 available=false + E_NO_ENGINE + 可操作 hint（ADR-0018：禁止静默失败）。
func (d Detector) Status(ctx context.Context, preferred string) StatusResult {
	paths := d.paths()
	sockets, socketErr := d.Host.Sockets(ctx, DNSPort)
	engines := []EngineStatus{
		d.probeSystemdResolved(ctx, paths),
		d.probeDnsmasq(ctx, paths),
		d.probeBind9(ctx, paths),
		d.probeCoreDNS(ctx),
	}
	assignListening(engines, sockets)

	result := StatusResult{
		Engines:           engines,
		Listening:         sockets,
		ResolvNameservers: d.resolvNameservers(paths),
		CheckedAt:         time.Now().Format(time.RFC3339),
	}
	if socketErr != nil && result.CheckedAt != "" {
		result.Hint = "监听套接字探测受限：" + socketErr.Error()
	}

	primary := ""
	if preferred != "" && preferred != EngineAuto {
		if engine, ok := findEngine(engines, preferred); ok && engine.Detected {
			primary = preferred
		} else {
			result.Engine = preferred
			result.ErrorCode = CodeNoEngine
			result.Hint = "指定的 DNS 引擎 " + preferred + " 未检测到。可选：" + strings.Join(enginePriority, " / ") +
				"；把 engine 设为 auto 让插件自动选择，或先安装并启动该服务。"
			return result
		}
	} else {
		for _, id := range enginePriority {
			if engine, ok := findEngine(engines, id); ok && engine.Detected {
				primary = id
				break
			}
		}
	}

	if primary == "" {
		result.ErrorCode = CodeNoEngine
		result.Hint = "未检测到 DNS 服务（systemd-resolved / dnsmasq / bind9 / coredns 均未运行）。" +
			"请启动其中之一：sudo systemctl enable --now systemd-resolved（Ubuntu 自带），" +
			"或 sudo apt install dnsmasq / bind9；本插件不内置 DNS 服务。"
		return result
	}

	for index := range engines {
		engines[index].Primary = engines[index].Engine == primary
	}
	engine, _ := findEngine(engines, primary)
	result.Available = true
	result.Engine = primary
	result.Version = engine.Version
	result.Upstreams = engine.Upstreams
	if len(engine.Listening) > 0 {
		result.Listening = engine.Listening
	}
	return result
}

// findEngine 按标识查引擎。
func findEngine(engines []EngineStatus, id string) (EngineStatus, bool) {
	for _, engine := range engines {
		if engine.Engine == id {
			return engine, true
		}
	}
	return EngineStatus{}, false
}

// assignListening 把宿主 53 端口套接字归属到引擎：
// 先按 ss 的属主进程名精确匹配，再用公认 stub 地址（127.0.0.53 / 127.0.0.54）兜底，
// 最后在「只检测到一个引擎」时全部归它。归属不确定就留空，不猜。
func assignListening(engines []EngineStatus, sockets []Listening) {
	detected := 0
	for _, engine := range engines {
		if engine.Detected {
			detected++
		}
	}
	buckets := make(map[string][]Listening, len(engines))
	unassigned := make([]Listening, 0, len(sockets))
	for _, socket := range sockets {
		target := ""
		if socket.Process != "" {
			target = engineProcesses[socket.Process]
		}
		if target == "" && (socket.Addr == "127.0.0.53" || socket.Addr == "127.0.0.54") {
			target = EngineSystemdResolved
		}
		if target == "" {
			unassigned = append(unassigned, socket)
			continue
		}
		buckets[target] = append(buckets[target], socket)
	}
	if detected == 1 && len(unassigned) > 0 {
		for index := range engines {
			if engines[index].Detected {
				buckets[engines[index].Engine] = append(buckets[engines[index].Engine], unassigned...)
				unassigned = nil
			}
		}
	}
	for index := range engines {
		engines[index].Listening = dedupeListening(buckets[engines[index].Engine])
	}
}

// probeSystemdResolved 探测 systemd-resolved：systemctl is-active 优先，pgrep 兜底；
// 版本取 `resolvectl --version`（该二进制与 resolved 同属 systemd，Ubuntu 上
// /usr/lib/systemd/systemd-resolved 不在 PATH，直接执行 --version 会失败）。
func (d Detector) probeSystemdResolved(ctx context.Context, paths Paths) EngineStatus {
	status := EngineStatus{
		Engine:      EngineSystemdResolved,
		Name:        engineNames[EngineSystemdResolved],
		ConfigPaths: []string{"/etc/systemd/resolved.conf"},
	}
	status.Running = d.serviceActive(ctx, "systemd-resolved") ||
		d.processRunning(ctx, "systemd-resolve", "systemd-resolved")
	if versionOut, err := d.Host.Run(ctx, "resolvectl", "--version"); err == nil {
		status.Version = parseSystemdVersion(versionOut)
	} else if versionOut, err := d.Host.Run(ctx, "systemctl", "--version"); err == nil {
		status.Version = parseSystemdVersion(versionOut)
		status.Note = "版本取自 systemctl --version（resolvectl 不可用）"
	} else {
		status.Note = "版本探测失败：resolvectl 与 systemctl 均不可用"
	}
	status.Detected = status.Running || status.Version != ""
	if statusOut, err := d.Host.Run(ctx, "resolvectl", "status"); err == nil {
		status.Upstreams = parseResolvectlUpstreams(statusOut)
	} else if status.Running {
		status.Note = strings.TrimSpace(status.Note + "；resolvectl status 不可用，上游未知")
	}
	return status
}

// probeDnsmasq 探测 dnsmasq：systemctl 优先，pgrep 兜底（libvirt 会直起 dnsmasq 进程，
// 此时 systemd 里没有同名 unit，只靠 pgrep 才能看见）。
func (d Detector) probeDnsmasq(ctx context.Context, paths Paths) EngineStatus {
	status := EngineStatus{
		Engine:      EngineDnsmasq,
		Name:        engineNames[EngineDnsmasq],
		ConfigPaths: []string{paths.DnsmasqConf, paths.DnsmasqDir},
	}
	status.Running = d.serviceActive(ctx, "dnsmasq") || d.processRunning(ctx, "dnsmasq")
	if versionOut, err := d.Host.Run(ctx, "dnsmasq", "--version"); err == nil {
		status.Version = parseDnsmasqVersion(versionOut)
	} else if _, pathErr := d.Host.LookPath("dnsmasq"); pathErr != nil {
		status.Note = "dnsmasq 命令不在 PATH，版本未知"
	}
	status.Detected = status.Running || status.Version != ""
	status.Upstreams = d.dnsmasqUpstreams(paths)
	return status
}

// probeBind9 探测 BIND9：named 的 unit 名在 Debian 系是 bind9、RHEL 系是 named。
func (d Detector) probeBind9(ctx context.Context, paths Paths) EngineStatus {
	status := EngineStatus{
		Engine:      EngineBind9,
		Name:        engineNames[EngineBind9],
		ConfigPaths: []string{paths.BindConf, filepath.Dir(paths.BindConf), paths.BindZoneDir},
	}
	status.Running = d.serviceActive(ctx, "named", "bind9") || d.processRunning(ctx, "named")
	if versionOut, err := d.Host.Run(ctx, "named", "-v"); err == nil {
		status.Version = parseBindVersion(versionOut)
	} else if _, pathErr := d.Host.LookPath("named"); pathErr != nil {
		status.Note = "named 命令不在 PATH，版本未知"
	}
	status.Detected = status.Running || status.Version != ""
	status.Upstreams = d.bindUpstreams(paths)
	return status
}

// probeCoreDNS 探测 CoreDNS。Corefile 不在只读白名单内，因此上游留空并明示原因。
func (d Detector) probeCoreDNS(ctx context.Context) EngineStatus {
	status := EngineStatus{
		Engine:      EngineCoreDNS,
		Name:        engineNames[EngineCoreDNS],
		ConfigPaths: []string{"/etc/coredns/Corefile"},
		Note:        "Corefile 不在只读白名单内，上游未解析",
	}
	status.Running = d.serviceActive(ctx, "coredns") || d.processRunning(ctx, "coredns")
	if versionOut, err := d.Host.Run(ctx, "coredns", "-version"); err == nil {
		status.Version = parseCoreDNSVersion(versionOut)
	} else if _, pathErr := d.Host.LookPath("coredns"); pathErr != nil {
		status.Note = "coredns 命令不在 PATH，版本未知"
	}
	status.Detected = status.Running || status.Version != ""
	return status
}

// serviceActive 判断 systemd unit 是否 active。
func (d Detector) serviceActive(ctx context.Context, units ...string) bool {
	for _, unit := range units {
		out, err := d.Host.Run(ctx, "systemctl", "is-active", unit)
		if err == nil && strings.TrimSpace(out) == "active" {
			return true
		}
	}
	return false
}

// processRunning 判断进程名是否在跑（只匹配精确进程名，不做模式匹配）。
func (d Detector) processRunning(ctx context.Context, names ...string) bool {
	for _, name := range names {
		out, err := d.Host.Run(ctx, "pgrep", "-x", name)
		if err == nil && strings.TrimSpace(out) != "" {
			return true
		}
	}
	return false
}

// resolvNameservers 读取 /etc/resolv.conf 的 nameserver 行（诊断锚点，读不到就空）。
func (d Detector) resolvNameservers(paths Paths) []string {
	data, err := d.Host.ReadFile(paths.ResolvConf)
	if err != nil {
		return nil
	}
	return parseResolvNameservers(string(data))
}

// parseResolvNameservers 解析 nameserver 行。
func parseResolvNameservers(text string) []string {
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, ok := seen[fields[1]]; ok {
			continue
		}
		seen[fields[1]] = struct{}{}
		out = append(out, fields[1])
	}
	return out
}

// parseResolvectlUpstreams 解析 `resolvectl status` 的 DNS Servers / Current DNS Server 行。
func parseResolvectlUpstreams(text string) []string {
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "DNS Servers:"):
			line = strings.TrimSpace(strings.TrimPrefix(line, "DNS Servers:"))
		case strings.HasPrefix(line, "Current DNS Server:"):
			line = strings.TrimSpace(strings.TrimPrefix(line, "Current DNS Server:"))
		default:
			continue
		}
		for _, field := range strings.Fields(line) {
			if _, ok := seen[field]; ok {
				continue
			}
			seen[field] = struct{}{}
			out = append(out, field)
			if len(out) >= maxUpstreams {
				return out
			}
		}
	}
	return out
}

// parseSystemdVersion 从 `systemd 259 (259.9-0ubuntu0.1)` 提取括号内版本。
func parseSystemdVersion(out string) string {
	match := systemdVersionRE.FindStringSubmatch(out)
	if match == nil {
		return firstLine(out)
	}
	if strings.TrimSpace(match[2]) != "" {
		return strings.TrimSpace(match[2])
	}
	return match[1]
}

// parseDnsmasqVersion 从 `Dnsmasq version 2.92 ...` 提取 2.92。
func parseDnsmasqVersion(out string) string {
	if match := dnsmasqVersionRE.FindStringSubmatch(out); match != nil {
		return match[1]
	}
	return firstLine(out)
}

// parseBindVersion 从 `BIND 9.20.0 (Extended Support Version) ...` 提取 9.20.0。
func parseBindVersion(out string) string {
	if match := bindVersionRE.FindStringSubmatch(out); match != nil {
		return match[1]
	}
	return firstLine(out)
}

// parseCoreDNSVersion 从 `CoreDNS-1.11.1 linux/amd64, go1.21.5, ...` 提取 1.11.1。
func parseCoreDNSVersion(out string) string {
	if match := corednsVersionRE.FindStringSubmatch(out); match != nil {
		return match[1]
	}
	return firstLine(out)
}

// firstLine 返回首行（截断 120 字节），用于版本提取失败时的诚实兜底。
func firstLine(out string) string {
	line := out
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	return truncate(line, 120)
}
