// Package dnsop 实现 DNS 插件的引擎无关能力：服务检测、区域 / 记录解析、真实查询与 bind9 记录写入。
//
// 三条硬约束：
//  1. 不内置 DNS 服务：插件只读宿主已有的 systemd-resolved / dnsmasq / bind9 / coredns，
//     不写任何宿主配置文件、不启停任何服务；写记录只走 bind9 的 **RFC 2136 动态更新**
//     （`nsupdate` + TSIG 密钥，插件进程自身权限、不经 root）。
//  2. 引擎无关：检测层只依赖「命令固定 argv + 标准配置路径 + /proc/net 监听套接字」，
//     四种引擎共用同一套结果形状，UI 不需要按引擎分支。
//  3. 不执行不可信脚本：zone 文件与配置只按文本解析；写入值逐类型校验后才进 nsupdate 的
//     行式脚本（拒绝换行/控制字符），绝不 source / eval / 拼接 shell。
package dnsop

import "time"

// 引擎标识（对外字符串，稳定）。
const (
	// EngineAuto 表示按优先级自动选择主引擎。
	EngineAuto = "auto"
	// EngineSystemdResolved 是 systemd-resolved（127.0.0.53 stub resolver）。
	EngineSystemdResolved = "systemd-resolved"
	// EngineDnsmasq 是 dnsmasq。
	EngineDnsmasq = "dnsmasq"
	// EngineBind9 是 BIND9（named）。
	EngineBind9 = "bind9"
	// EngineCoreDNS 是 CoreDNS。
	EngineCoreDNS = "coredns"
)

// 机器可读错误码 / 状态码。E_NEED_ROOT 与 pluginapi.E_NEED_ROOT 同值，
// 这里用本地常量是为了让 dnsop 的降级口径不依赖 SDK 版本。
const (
	// WriteChannel 是记录写入通道标识（bind9 RFC 2136 动态更新）。
	WriteChannel = "bind9-dynamic-update"
	// CodeNeedRoot 表示目标文件/动作需要 root，当前进程权限不足。
	CodeNeedRoot = "E_NEED_ROOT"
	// CodeNoEngine 表示宿主没有任何被支持的 DNS 服务。
	CodeNoEngine = "E_NO_ENGINE"
	// CodeUpstream 表示查询链路本身失败（dig/nslookup/Go 解析器都不可用）。
	CodeUpstream = "E_UPSTREAM"
)

const (
	// DNSPort 是被探测的 DNS 监听端口（不支持非标端口的系统级解析）。
	DNSPort = 53
	// MaxRecords 是 dns.records 单次返回的记录上限（防止超大 zone 撑爆响应帧）。
	MaxRecords = 500
	// defaultZoneTTL 是 zone 文件既无 $TTL 也无逐条 TTL 时的兜底 TTL。
	defaultZoneTTL = 3600
	// maxUpstreams 是上游列表上限。
	maxUpstreams = 20
	// maxScannedPaths 是扫描路径清单上限（诊断用）。
	maxScannedPaths = 50
)

// enginePriority 是主引擎选择顺序：真实解析请求优先走实际在跑的系统解析器。
//
// systemd-resolved 排第一是因为它接管 /etc/resolv.conf 的 stub 模式（127.0.0.53）；
// dnsmasq / bind9 / coredns 依次递减。配置 engine 可强制指定，绕过该顺序。
var enginePriority = []string{EngineSystemdResolved, EngineDnsmasq, EngineBind9, EngineCoreDNS}

// engineNames 是引擎的中文展示名。
var engineNames = map[string]string{
	EngineSystemdResolved: "systemd-resolved",
	EngineDnsmasq:         "dnsmasq",
	EngineBind9:           "BIND9（named）",
	EngineCoreDNS:         "CoreDNS",
}

// engineProcesses 是「进程名 → 引擎」的映射，用于从 ss 的 users 列归属套接字。
var engineProcesses = map[string]string{
	"systemd-resolve":  EngineSystemdResolved,
	"systemd-resolved": EngineSystemdResolved,
	"dnsmasq":          EngineDnsmasq,
	"named":            EngineBind9,
	"coredns":          EngineCoreDNS,
}

// Listening 是一个监听套接字（DNS 端口的 TCP 或 UDP）。
type Listening struct {
	// Addr 是监听地址（去掉 %iface scope，如 127.0.0.53）。
	Addr string `json:"addr"`
	// Port 是监听端口。
	Port int `json:"port"`
	// Proto 是 tcp 或 udp。
	Proto string `json:"proto"`
	// Process 是套接字属主进程名；非 root 下 ss 不返回属主时为机器可读空串。
	Process string `json:"process,omitempty"`
}

// EngineStatus 是单个引擎的探测结果。
type EngineStatus struct {
	// Engine 是引擎标识。
	Engine string `json:"engine"`
	// Name 是中文展示名。
	Name string `json:"name"`
	// Detected 表示检测到该引擎（在跑，或版本命令可用）。
	Detected bool `json:"detected"`
	// Running 表示服务/进程确实在运行。
	Running bool `json:"running"`
	// Primary 表示它是本次选出的主引擎。
	Primary bool `json:"primary"`
	// Version 是探测到的版本；探不到为空串（不猜）。
	Version string `json:"version"`
	// Listening 是归属该引擎的监听套接字。
	Listening []Listening `json:"listening"`
	// Upstreams 是该引擎配置的上游 DNS。
	Upstreams []string `json:"upstreams"`
	// ConfigPaths 是该引擎的标准配置路径（只列不读）。
	ConfigPaths []string `json:"config_paths"`
	// Note 是降级说明（例如版本命令缺失、配置不可读）。
	Note string `json:"note,omitempty"`
	// Error 是探测失败原因（原始错误文案，便于排查）。
	Error string `json:"error,omitempty"`
}

// StatusResult 是 dns.status 的结果。
//
// available=false 时必须同时给 error_code 与 hint（ADR-0018 降级硬要求），
// 不允许返回空对象让 UI 显示「无数据」。
type StatusResult struct {
	// Available 表示宿主有可用的 DNS 服务。
	Available bool `json:"available"`
	// Engine 是主引擎标识；无引擎时为空串。
	Engine string `json:"engine"`
	// Version 是主引擎版本。
	Version string `json:"version"`
	// Listening 是主引擎的监听套接字；无法归属时退回宿主 53 端口的全部监听。
	Listening []Listening `json:"listening"`
	// Upstreams 是主引擎的上游 DNS。
	Upstreams []string `json:"upstreams"`
	// Engines 是全部候选引擎的探测明细。
	Engines []EngineStatus `json:"engines"`
	// ResolvNameservers 是 /etc/resolv.conf 里生效的 nameserver（诊断锚点）。
	ResolvNameservers []string `json:"resolv_nameservers"`
	// CheckedAt 是本次探测时间（RFC3339）。
	CheckedAt string `json:"checked_at"`
	// Hint 是可操作提示。
	Hint string `json:"hint,omitempty"`
	// ErrorCode 是机器可读状态码。
	ErrorCode string `json:"error_code,omitempty"`
}

// ZoneEntry 是一个 DNS 区域的只读视图。
type ZoneEntry struct {
	// Name 是区域名（无尾点，小写）。
	Name string `json:"name"`
	// Type 是区域类型：master / slave / static / forward / local。
	Type string `json:"type"`
	// File 是区域文件（bind）或配置来源（dnsmasq）。
	File string `json:"file"`
	// RecordsCount 是解析到的记录数；Readable=false 时该值不可信，看 Readable。
	RecordsCount int `json:"records_count"`
	// Readable 表示区域数据是否真的读到了。
	Readable bool `json:"readable"`
	// Engine 是该区域所属引擎。
	Engine string `json:"engine"`
}

// ZonesResult 是 dns.zones 的结果。
type ZonesResult struct {
	// Engine 是主引擎。
	Engine string `json:"engine"`
	// Zones 是区域列表（按名称排序）。
	Zones []ZoneEntry `json:"zones"`
	// Count 是区域数量。
	Count int `json:"count"`
	// Scanned 是实际扫描过的配置路径（诊断用）。
	Scanned []string `json:"scanned"`
	// Warnings 是非致命问题（配置不可读、路径越界等）。
	Warnings []string `json:"warnings"`
	// Hint 是可操作提示。
	Hint string `json:"hint,omitempty"`
	// ErrorCode 是机器可读状态码：全部区域都读不到且原因是被拒时为 E_NEED_ROOT。
	ErrorCode string `json:"error_code,omitempty"`
}

// Record 是一条 DNS 记录。
type Record struct {
	// Name 是记录名（绝对名，无尾点，小写）。
	Name string `json:"name"`
	// Type 是记录类型（A/AAAA/CNAME/MX/TXT/NS）。
	Type string `json:"type"`
	// Value 是记录值：TXT 去外层引号；MX 为 "优先级 目标"；其余为地址/目标名。
	Value string `json:"value"`
	// TTL 是生效 TTL（显式值优先，其次 $TTL，最后 defaultZoneTTL）。
	TTL int `json:"ttl"`
}

// RecordsResult 是 dns.records 的结果。
type RecordsResult struct {
	// Zone 是区域名。
	Zone string `json:"zone"`
	// Engine 是区域所属引擎。
	Engine string `json:"engine"`
	// File 是区域数据来源。
	File string `json:"file"`
	// Records 是记录列表（上限 MaxRecords）。
	Records []Record `json:"records"`
	// Count 是返回条数。
	Count int `json:"count"`
	// Total 是解析到的总条数（可能大于 Count）。
	Total int `json:"total"`
	// Truncated 表示因上限被截断。
	Truncated bool `json:"truncated"`
}

// Answer 是一条查询应答。
type Answer struct {
	// Name 是应答名。
	Name string `json:"name"`
	// Type 是应答类型。
	Type string `json:"type"`
	// Value 是应答值。
	Value string `json:"value"`
	// TTL 是应答 TTL；Go 解析器不返回 TTL 时为 0。
	TTL int `json:"ttl"`
}

// QueryResult 是 dns.query 的结果。
type QueryResult struct {
	// Name 是查询名（无尾点，小写）。
	Name string `json:"name"`
	// Type 是查询类型。
	Type string `json:"type"`
	// Answers 是应答集合（NXDOMAIN 时为空数组而不是 null）。
	Answers []Answer `json:"answers"`
	// Rcode 是 DNS 响应码（NOERROR / NXDOMAIN / SERVFAIL / ...）。
	Rcode string `json:"rcode"`
	// ElapsedMs 是本次查询耗时（毫秒）。
	ElapsedMs int64 `json:"elapsed_ms"`
	// Resolver 是实际使用的查询器：dig / nslookup / go。
	Resolver string `json:"resolver"`
	// Note 是降级说明（例如 dig 缺失退回 Go 解析器）。
	Note string `json:"note,omitempty"`
}

// Paths 是插件使用的只读配置路径集合（全部由 config.set 收敛，默认值见 DefaultPaths）。
type Paths struct {
	// BindConf 是 bind9 的区域声明文件。
	BindConf string
	// BindZoneDir 是 bind9 区域文件目录（区域文件允许的第二个白名单根）。
	BindZoneDir string
	// DnsmasqConf 是 dnsmasq 主配置。
	DnsmasqConf string
	// DnsmasqDir 是 dnsmasq 片段目录。
	DnsmasqDir string
	// ResolvConf 是系统解析器配置。
	ResolvConf string
}

// DefaultPaths 是各发行版的通用默认路径（Debian/Ubuntu 为主，RHEL 系可经 config.set 覆盖）。
func DefaultPaths() Paths {
	return Paths{
		BindConf:    "/etc/bind/named.conf.local",
		BindZoneDir: "/var/lib/bind",
		DnsmasqConf: "/etc/dnsmasq.conf",
		DnsmasqDir:  "/etc/dnsmasq.d",
		ResolvConf:  "/etc/resolv.conf",
	}
}

// WriteOptions 是写入通道配置（bind9 动态更新）：服务器、TSIG 密钥、超时与审计日志。
//
// Journal 为 nil 表示写通道未装配（例如缺少 KORE_STATE_DIR）——写方法一律
// fail-closed 返回 E_UNSUPPORTED + 可操作 hint，不做"改了但没记账"的静默写入。
type WriteOptions struct {
	// Server 是权威 bind9 实例地址（IP 或主机名），默认 127.0.0.1。
	Server string
	// Port 是 DNS 端口，默认 53。
	Port int
	// KeyFile 是 TSIG 密钥文件路径（nsupdate -k），空表示写入未启用。
	KeyFile string
	// Timeout 是单次更新/校验查询的超时。
	Timeout time.Duration
	// Journal 是写操作审计与回滚依据。
	Journal Journal
}

// RecordWriteParams 是 record.add / record.update / record.delete 的入参。
type RecordWriteParams struct {
	// Zone 是区域名（无尾点）。
	Zone string `json:"zone"`
	// Name 是记录名（绝对名，可带尾点）。
	Name string `json:"name"`
	// Type 是记录类型（可写：A/AAAA/CNAME/MX/TXT/SRV）。
	Type string `json:"type"`
	// Value 是新值；delete 时可省略表示删除该 name/type 的全部值。
	Value string `json:"value"`
	// OldValue 可选：update/delete 的旧值前置条件（不一致即 E_CONFLICT）。
	OldValue string `json:"old_value"`
	// TTL 是显式 TTL（秒）；0 表示默认 300 或沿用快照。
	TTL int `json:"ttl"`
}

// RecordWriteResult 是一次记录写入的真实结果：是否变化、是否已应用、是否已验证生效。
type RecordWriteResult struct {
	// Operation 是 add / update / delete。
	Operation string `json:"operation"`
	// Channel 是写入通道标识，固定 bind9-dynamic-update。
	Channel string `json:"channel"`
	// Zone / Name / Type / Value 是本次操作的目标（Value 为归一后的新值）。
	Zone  string `json:"zone"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
	// TTL 是实际使用的 TTL（秒）；delete 时为 0。
	TTL int `json:"ttl,omitempty"`
	// Previous 是写入前该 name/type 的旧值（回滚依据，最多 10 条）。
	Previous []string `json:"previous"`
	// Changed 表示目标状态与现状不同（false 时是幂等空操作）。
	Changed bool `json:"changed"`
	// Applied 表示服务器已接受且生效校验通过（幂等空操作也算 true）。
	Applied bool `json:"applied"`
	// Verified 表示写后直连权威服务器查询确认了新状态。
	Verified bool `json:"verified"`
	// VerifiedBy 是校验方式，固定 dig-direct。
	VerifiedBy string `json:"verified_by,omitempty"`
	// RolledBack 表示生效校验失败后已尝试逆操作恢复旧值；false 需人工核对。
	RolledBack bool `json:"rolled_back"`
	// Journal 是审计日志文件路径（幂等空操作为空）。
	Journal string `json:"journal,omitempty"`
	// ReloadRequired 固定 false：动态更新立即生效，无需 reload 服务。
	ReloadRequired bool `json:"reload_required"`
	// Server / Port 是实际使用的权威服务器。
	Server string `json:"server"`
	Port   int    `json:"port"`
	// Hint 是可操作提示（失败或降级时给出）。
	Hint string `json:"hint,omitempty"`
	// ErrorCode 是机器可读状态码（成功时为空）。
	ErrorCode string `json:"error_code,omitempty"`
}
