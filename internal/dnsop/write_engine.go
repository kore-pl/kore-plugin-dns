package dnsop

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// DnsmasqChannel 是 dnsmasq 写入通道标识：只写插件状态目录内的 hosts 片段，
// 绝不写 /etc/dnsmasq.d（ADR-0023 零侵入），生效由用户重启 dnsmasq 决定。
const DnsmasqChannel = "dnsmasq-hosts-fragment"

// hostsFragmentName 是插件状态目录内的片段文件名。
const hostsFragmentName = "hosts.conf"

// ReloadResult 是 dns.reload 的结果。
type ReloadResult struct {
	// Engine 是实际引擎。
	Engine string `json:"engine"`
	// Reloaded 表示已让服务重新加载。
	Reloaded bool `json:"reloaded"`
	// ReloadRequired 表示需要用户在外部重启服务（本插件不动宿主服务）。
	ReloadRequired bool `json:"reload_required"`
	// Command 是实际执行的命令（成功时非空，便于审计）。
	Command string `json:"command,omitempty"`
	// Hint 是可操作提示。
	Hint string `json:"hint,omitempty"`
}

// WriteRecord 按引擎分派记录写入：bind9 走 RFC2136 动态更新（nsupdate+TSIG，插件自身权限，
// 不经 root），dnsmasq 写插件状态目录内的 hosts 片段，其余引擎不支持写入。
func (d Detector) WriteRecord(ctx context.Context, operation string, raw json.RawMessage) (RecordWriteResult, *pluginapi.Error) {
	var params RecordWriteParams
	if perr := decodeParams(raw, &params); perr != nil {
		return RecordWriteResult{}, perr
	}
	engine, perr := d.writableEngine(ctx)
	if perr != nil {
		return RecordWriteResult{}, perr
	}
	return d.writeWithEngine(ctx, engine, operation, params)
}

// writeWithEngine 用已解析的引擎执行写入（单测直接调用，避免探测宿主）。
func (d Detector) writeWithEngine(ctx context.Context, engine, operation string, params RecordWriteParams) (RecordWriteResult, *pluginapi.Error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return RecordWriteResult{}, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "参数序列化失败: " + err.Error()}
	}
	switch engine {
	case EngineBind9:
		return d.recordWrite(ctx, operation, raw)
	case EngineDnsmasq:
		return d.dnsmasqWrite(operation, params)
	default:
		return RecordWriteResult{}, unsupportedWrite(engine)
	}
}

// writableEngine 解析当前实际引擎（auto 时按优先级探测）；没有引擎时返回 E_NO_ENGINE。
func (d Detector) writableEngine(ctx context.Context) (string, *pluginapi.Error) {
	status := d.Status(ctx, d.engineOrDefault(""))
	// 显式配置了具体引擎（非 auto）时以配置为准：探测可能因为插件无权限读配置而漏判，
	// 但用户在插件设置里写死的引擎是明确意图，写入按它分派（失败时由该引擎返回可操作错误）。
	if strings.TrimSpace(status.Engine) == "" {
		switch d.DefaultEngine {
		case EngineBind9, EngineDnsmasq:
			return d.DefaultEngine, nil
		}
	}
	if strings.TrimSpace(status.Engine) == "" {
		return "", &pluginapi.Error{
			Code:    CodeNoEngine,
			Message: "本机没有可用的 DNS 服务，无法写入记录",
			Detail:  encodeDetail(map[string]string{"hint": "装上 BIND9（推荐，支持动态更新）或 dnsmasq 后重试；只有 systemd-resolved 时不支持写入。"}),
		}
	}
	return status.Engine, nil
}

// unsupportedWrite 构造引擎不支持写入的可操作错误。
func unsupportedWrite(engine string) *pluginapi.Error {
	return &pluginapi.Error{
		Code:    pluginapi.E_UNSUPPORTED,
		Message: "引擎 " + engineTextForErr(engine) + " 不支持记录写入",
		Detail: encodeDetail(map[string]string{
			"hint":   "写入只支持 BIND9（RFC2136 动态更新，需在插件设置里填 TSIG 密钥文件）与 dnsmasq（写插件状态目录内的 hosts 片段）。" + "systemd-resolved / CoreDNS 没有可写的区域源，请改用 BIND9 托管，或在插件设置里切换引擎。",
			"engine": engine,
		}),
	}
}

// engineTextForErr 返回引擎展示名（空值不猜）。
func engineTextForErr(engine string) string {
	if name, ok := engineNames[engine]; ok {
		return name
	}
	if engine == "" {
		return "（未检测到）"
	}
	return engine
}

// dnsmasqWrite 写插件状态目录内的 hosts 片段：
//
//	host-record=<name>,<value>[,<ttl>]
//
// 只支持 A / AAAA / CNAME（dnsmasq 的 host-record 语义）；MX/TXT/SRV 需要写配置块，
// 不在零侵入范围内，返回 E_UNSUPPORTED 并说明替代方案。
func (d Detector) dnsmasqWrite(operation string, params RecordWriteParams) (RecordWriteResult, *pluginapi.Error) {
	spec, perr := d.prepareDnsmasq(spec(operation), params)
	if perr != nil {
		return RecordWriteResult{}, perr
	}
	dir := strings.TrimSpace(d.Write.FragmentDir)
	if dir == "" {
		return RecordWriteResult{}, &pluginapi.Error{
			Code:    pluginapi.E_UNSUPPORTED,
			Message: "dnsmasq 写入未启用：缺少插件状态目录",
			Detail:  encodeDetail(map[string]string{"hint": "由内核注入 KORE_STATE_DIR 后自动启用；直接运行时请设置该环境变量指向插件状态目录。"}),
		}
	}
	path := filepath.Join(dir, hostsFragmentName)
	lines, perr := readFragmentLines(path)
	if perr != nil {
		return RecordWriteResult{}, perr
	}
	next, previous, changed := applyFragment(operation, lines, spec)
	if !changed {
		return RecordWriteResult{Operation: operation, Channel: DnsmasqChannel, Zone: spec.Zone,
			Name: spec.Name, Type: spec.Type, Value: spec.Value, TTL: spec.TTL, Previous: previous,
			Changed: false, Applied: true, Verified: true, VerifiedBy: "fragment-noop",
			ReloadRequired: false, Hint: "目标状态已存在，未改动片段。"}, nil
	}
	if perr := writeFragmentLines(path, next); perr != nil {
		return RecordWriteResult{}, perr
	}
	result := RecordWriteResult{Operation: operation, Channel: DnsmasqChannel, Zone: spec.Zone,
		Name: spec.Name, Type: spec.Type, Value: spec.Value, TTL: spec.TTL, Previous: previous,
		Changed: true, Applied: true, Verified: false, ReloadRequired: true,
		Hint: "片段已写入 " + path + "；dnsmasq 需重启才生效：sudo systemctl restart dnsmasq。" + "插件不写 /etc/dnsmasq.d（零侵入），请把该片段 include 进 dnsmasq 配置或按需复制。"}
	if operation == "delete" {
		result.Value = spec.OldValue
	}
	return result, nil
}

// fragmentSpec 是已校验的片段写入上下文。
type fragmentSpec struct {
	Operation string
	Zone      string
	Name      string
	Type      string
	Value     string
	OldValue  string
	TTL       int
}

func spec(operation string) string { return operation }

// prepareDnsmasq 校验入参（名称/类型/TTL/值与区域归属），不读任何宿主文件。
func (d Detector) prepareDnsmasq(operation string, params RecordWriteParams) (fragmentSpec, *pluginapi.Error) {
	zone := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(params.Zone), "."))
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(params.Name), "."))
	recordType := strings.ToUpper(strings.TrimSpace(params.Type))
	value := strings.TrimSpace(params.Value)
	if zone == "" || !validDNSName(zone) {
		return fragmentSpec{}, invalidParam("zone 不合法：需要小写域名（例如 example.com）")
	}
	if name == "" || !validDNSName(name) {
		return fragmentSpec{}, invalidParam("name 不合法：需要完整记录名（例如 www.example.com）")
	}
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return fragmentSpec{}, invalidParam("name 不在 zone 内：记录名必须以 ." + zone + " 结尾，或等于区域名本身")
	}
	if recordType != "A" && recordType != "AAAA" && recordType != "CNAME" {
		return fragmentSpec{}, unsupportedWriteType(recordType)
	}
	if params.TTL < 0 || params.TTL > maxWriteTTL {
		return fragmentSpec{}, invalidParam("ttl 超出范围：0–" + strconv.Itoa(maxWriteTTL) + " 秒（0 表示用默认 300）")
	}
	if ttl := params.TTL; ttl == 0 {
		params.TTL = 300
	}
	out := fragmentSpec{Operation: operation, Zone: zone, Name: name, Type: recordType, TTL: params.TTL}
	switch operation {
	case "delete":
		if value != "" {
			out.OldValue = value
			out.Value = value
		}
		return out, nil
	case "add", "update":
		if value == "" {
			return fragmentSpec{}, invalidParam(operation + " 需要 value（记录值）")
		}
		if recordType == "A" || recordType == "AAAA" {
			ip := net.ParseIP(value)
			if ip == nil {
				return fragmentSpec{}, invalidParam(recordType + " 的值必须是 IP 地址")
			}
			if recordType == "A" && ip.To4() == nil {
				return fragmentSpec{}, invalidParam("A 记录需要 IPv4 地址")
			}
			if recordType == "AAAA" && ip.To4() != nil {
				return fragmentSpec{}, invalidParam("AAAA 记录需要 IPv6 地址")
			}
			value = ip.String()
		} else if !validDNSName(strings.TrimSuffix(value, ".")) {
			return fragmentSpec{}, invalidParam("CNAME 的值必须是域名（例如 target.example.com）")
		}
		out.Value = value
		return out, nil
	default:
		return fragmentSpec{}, invalidParam("未知写入操作：" + operation)
	}
}

// unsupportedWriteType 构造类型不支持写入的错误（说明 dnsmasq 的边界）。
func unsupportedWriteType(recordType string) *pluginapi.Error {
	return &pluginapi.Error{
		Code:    pluginapi.E_UNSUPPORTED,
		Message: "dnsmasq 写入不支持记录类型 " + recordType,
		Detail: encodeDetail(map[string]string{
			"hint": "dnsmasq 的 hosts 片段只支持 A / AAAA / CNAME；MX / TXT / SRV 需要写配置块（会落到 /etc/dnsmasq.d，属零侵入禁区）。" + "这类记录请改用 BIND9 区域（支持 A/AAAA/CNAME/MX/TXT/SRV）。",
			"type": recordType,
		}),
	}
}

// validDNSName 校验域名形态：小写后 1–253 字符，仅字母数字点连字符，不以点起止，无空标签。
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	for _, part := range strings.Split(name, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// readFragmentLines 读片段（不存在视为空）；同时校验文件形态，避免把脏数据当记录。
func readFragmentLines(path string) ([]string, *pluginapi.Error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "读取 hosts 片段失败: " + err.Error(),
			Detail: encodeDetail(map[string]string{"hint": "检查 " + path + " 的权限。", "path": path})}
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines, nil
}

// applyFragment 在内存里算出新片段与变更标记（幂等：无变化不落盘）。
func applyFragment(operation string, lines []string, sp fragmentSpec) ([]string, []string, bool) {
	var kept []string
	var previous []string
	for _, line := range lines {
		name, value, ok := parseHostRecord(line)
		if !ok {
			kept = append(kept, line) // 非本插件写的行原样保留
			continue
		}
		matches := name == sp.Name && (operation == "delete" || fragmentTypeOf(value) == sp.Type)
		if operation == "delete" && sp.OldValue != "" {
			matches = matches && value == sp.OldValue
		}
		if matches {
			previous = append(previous, value)
			continue
		}
		kept = append(kept, line)
	}
	changed := false
	switch operation {
	case "add":
		existing := false
		for _, line := range lines {
			if name, value, ok := parseHostRecord(line); ok && name == sp.Name && value == sp.Value {
				existing = true
				break
			}
		}
		if !existing {
			kept = append(kept, renderHostRecord(sp))
			changed = true
		}
	case "update", "delete":
		changed = len(previous) > 0 || (operation == "update")
		if operation == "update" {
			kept = append(kept, renderHostRecord(sp))
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i] < kept[j] })
	return kept, previous, changed
}

// renderHostRecord 渲染一行 dnsmasq host-record。
func renderHostRecord(sp fragmentSpec) string {
	line := "host-record=" + sp.Name + "," + sp.Value
	if sp.TTL > 0 {
		line += "," + strconv.Itoa(sp.TTL)
	}
	return line
}

// parseHostRecord 解析 host-record 行（只认本插件写出的形态）。
func parseHostRecord(line string) (string, string, bool) {
	if !strings.HasPrefix(line, "host-record=") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(line, "host-record="), ",")
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// fragmentTypeOf 按值形态推断记录类型（片段里不带类型列）。
func fragmentTypeOf(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		if ip.To4() != nil {
			return "A"
		}
		return "AAAA"
	}
	return "CNAME"
}

// writeFragmentLines 原子写片段（0600），目录 0700，不改属主。
func writeFragmentLines(path string, lines []string) *pluginapi.Error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "创建片段目录失败: " + err.Error()}
	}
	tmp := path + ".tmp"
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "写临时片段失败: " + err.Error()}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "替换片段失败: " + err.Error()}
	}
	return nil
}

// Reload 让服务重新加载：bind9 走 rndc reload（需要本机 rndc.key，非 root 通常拿不到 →
// E_NEED_ROOT + hint）；dnsmasq 返回「需要重启」的提示，插件绝不启停宿主服务。
//
// 定位（ADR-0051 §1.2）：**记录变更不需要 reload**——RFC 2136 动态更新立即生效；
// 本操作只用于「手工改过 zone 文件 / named.conf」后的重新加载，文案必须把这点说清，
// 避免用户把「改记录」和「重载服务」混为一谈。
//
// zone 是 dns.reload 唯一合法入参（可选，见 call.go 的 reloadParams）：为空表示重载整个引擎，
// 非空表示只重载该区域。用哪个引擎由 writableEngine 按配置/探测决定，调用方不能传入 engine。
func (d Detector) Reload(ctx context.Context, zone string) (ReloadResult, *pluginapi.Error) {
	engine, perr := d.writableEngine(ctx)
	if perr != nil {
		return ReloadResult{}, perr
	}
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if zone != "" && !validDNSName(zone) {
		return ReloadResult{}, invalidParam("zone 不合法：需要小写域名（例如 example.com）")
	}
	switch engine {
	case EngineSystemdResolved:
		// systemd-resolved 没有区域概念：单区域 reload 无意义，直接拒绝而不是静默忽略 zone
		// （静默忽略会让调用方以为只刷新了某个区域，实际刷的是全局缓存）。
		if zone != "" {
			return ReloadResult{}, invalidParam("systemd-resolved 没有区域概念：dns.reload 不接受 zone，省略 zone 刷新全部缓存")
		}
		return d.reloadResolvedCaches(ctx)
	case EngineBind9:
		argv := []string{"reload"}
		if zone != "" {
			argv = append(argv, zone)
		}
		// 空 zone 是「重载整个引擎」，命令与 hint 都不应留下尾随空格。
		command := strings.TrimSpace("rndc reload " + zone)
		out, err := d.Host.Run(ctx, "rndc", argv...)
		if err != nil {
			detail := map[string]string{
				"hint": "记录变更走 RFC 2136 动态更新，立即生效、不需要 reload；" +
					"本操作只在你手工改过 zone 文件或 named.conf 后才需要。" +
					"请执行 sudo " + command + " 或 sudo systemctl reload named 后重试" +
					"（rndc 要用与 named 匹配的 rndc.key，通常只有 root 可读；插件不会自行提权，也不启停宿主服务）。",
				"command": command, "error": truncate(err.Error(), 500),
			}
			if snippet := strings.TrimSpace(strings.Join(strings.Fields(out), " ")); snippet != "" {
				detail["output"] = truncate(snippet, 1000)
			}
			return ReloadResult{}, &pluginapi.Error{Code: CodeNeedRoot, Message: "E_NEED_ROOT: rndc 无法重载区域", Detail: encodeDetail(detail)}
		}
		// 成功文案同样要立住定位：只改记录不用来这里。
		hint := "区域已重新加载（本操作只用于手工改过 zone 文件或 named.conf 之后；" +
			"记录增删改走 RFC 2136 动态更新，立即生效，不需要 reload）。"
		if zone == "" {
			hint = "全部区域已重新加载（本操作只用于手工改过 zone 文件或 named.conf 之后；" +
				"记录增删改走 RFC 2136 动态更新，立即生效，不需要 reload）。"
		}
		return ReloadResult{Engine: engine, Reloaded: true, Command: command, Hint: hint}, nil
	case EngineDnsmasq:
		return ReloadResult{Engine: engine, ReloadRequired: true,
			Hint: "dnsmasq 没有安全的在线重载通道：改过 dnsmasq 配置或插件生成的 hosts 片段后，" +
				"请执行 sudo systemctl restart dnsmasq（插件不启停宿主服务）；只是增删记录时不需要做这一步。"}, nil
	default:
		return ReloadResult{}, unsupportedWrite(engine)
	}
}

// reloadResolvedCaches 经内核提权通道执行 `resolvectl flush-caches`（固定 argv、无追加参数）。
//
// 为什么走 root_actions：resolved 的缓存由系统服务持有，普通用户没有刷新权限；
// 插件进程永不自行 sudo，只能把固定 argv 交给内核以 uid=0 执行（ADR-0018）。
// argv 构造里**没有任何入参拼接**：zone 已在调用方被拒绝，engine 由 switch 决定——
// 从结构上杜绝 0.4.1 那类「engine 被当成 zone 传给 rndc」的混用。
func (d Detector) reloadResolvedCaches(ctx context.Context) (ReloadResult, *pluginapi.Error) {
	if d.Root == nil {
		return ReloadResult{}, rootChannelUnavailable()
	}
	out, err := d.Root.RunRootAction(ctx, RootActionResolvedFlush, nil)
	if err != nil {
		return ReloadResult{}, rootActionFailed(out, err)
	}
	if out.ExitCode != 0 {
		detail := map[string]string{
			"action":    RootActionResolvedFlush,
			"exit_code": strconv.Itoa(out.ExitCode),
			"hint":      "resolvectl flush-caches 返回非零：确认 systemd-resolved 正在运行（systemctl status systemd-resolved）后重试。",
		}
		if snippet := strings.TrimSpace(out.Stderr); snippet != "" {
			detail["stderr"] = truncate(snippet, 1000)
		}
		return ReloadResult{}, &pluginapi.Error{Code: pluginapi.E_UPSTREAM, Message: "E_UPSTREAM: resolvectl flush-caches 执行失败", Detail: encodeDetail(detail)}
	}
	return ReloadResult{Engine: EngineSystemdResolved, Reloaded: true, Command: ResolvedFlushCommand,
		Hint: "已刷新 systemd-resolved 缓存；该引擎没有区域概念，dns.reload 不接受 zone（始终整体刷新）。" +
			"本操作只刷新解析缓存，记录变更走 RFC 2136 动态更新、立即生效，不需要 reload。"}, nil
}
