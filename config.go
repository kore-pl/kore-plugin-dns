package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pengtang1024/kore-plugin-dns/internal/dnsop"
	"github.com/pengtang1024/kore-plugin-dns/internal/plugincfg"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// embeddedInfo 是随二进制发布的内嵌清单 manifest.json（只含握手字段，不含 size_bytes）：
// version / requires_kore / capabilities 与安装期 info.json 的握手字段保持一致，
// 由 make dist 前置校验防漂移。
//
//go:embed manifest.json
var embeddedInfo []byte

// 配置环境变量（文件不存在时才生效，优先级 config.json > env > 默认值，见 PLUGIN-CONFIG §4）。
const (
	// EnvEngine 强制/指定主引擎。
	EnvEngine = "KORE_DNS_ENGINE"
	// EnvBindConf 覆盖 bind9 区域声明文件。
	EnvBindConf = "KORE_DNS_BIND_CONF"
	// EnvBindZoneDir 覆盖 bind9 区域文件目录。
	EnvBindZoneDir = "KORE_DNS_BIND_ZONE_DIR"
	// EnvDnsmasqConf 覆盖 dnsmasq 主配置。
	EnvDnsmasqConf = "KORE_DNS_DNSMASQ_CONF"
	// EnvDnsmasqDir 覆盖 dnsmasq 片段目录。
	EnvDnsmasqDir = "KORE_DNS_DNSMASQ_DIR"
	// EnvQueryTimeoutMs 覆盖查询超时（毫秒）。
	EnvQueryTimeoutMs = "KORE_DNS_QUERY_TIMEOUT_MS"
	// EnvUpdateServer 覆盖动态更新的权威服务器地址。
	EnvUpdateServer = "KORE_DNS_UPDATE_SERVER"
	// EnvUpdatePort 覆盖动态更新的 DNS 端口。
	EnvUpdatePort = "KORE_DNS_UPDATE_PORT"
	// EnvUpdateKeyFile 覆盖 TSIG 密钥文件路径（空表示写入未启用）。
	EnvUpdateKeyFile = "KORE_DNS_UPDATE_KEY_FILE"
	// EnvUpdateTimeoutMs 覆盖单次写入/校验超时（毫秒）。
	EnvUpdateTimeoutMs = "KORE_DNS_UPDATE_TIMEOUT_MS"
)

// 查询超时边界：太小会把正常网络抖动判成失败，太大则拖住内核的调用预算。
const (
	defaultQueryTimeoutMs = 3000
	minQueryTimeoutMs     = 500
	maxQueryTimeoutMs     = 30000
	defaultUpdateServer   = "127.0.0.1"
	defaultUpdatePort     = 53
	defaultUpdateTimeout  = 5000
	minUpdatePort         = 1
	maxUpdatePort         = 65535
)

// manifest 是 info.json 中插件运行期真正需要的字段，其余字段归内核校验。
type manifest struct {
	// ID 插件 id，缺省用于补 KORE_PLUGIN_ID。
	ID string `json:"id"`
	// Version 握手声明的插件版本。
	Version string `json:"version"`
	// Protocol 协议主版本，必须与 SDK 常量一致。
	Protocol string `json:"protocol"`
	// RequiresKore 握手声明的内核版本区间。
	RequiresKore string `json:"requires_kore"`
	// Capabilities 握手声明的能力，必须是清单声明的子集。
	Capabilities []string `json:"capabilities"`
}

// fileValues 是 <state_dir>/config.json 的显式形状（G-24：不引入 object/any）。
type fileValues struct {
	// Engine 是主引擎选择：auto 或四种引擎之一。
	Engine string `json:"engine"`
	// BindConf 是 bind9 区域声明文件。
	BindConf string `json:"bind_conf"`
	// BindZoneDir 是 bind9 区域文件目录。
	BindZoneDir string `json:"bind_zone_dir"`
	// DnsmasqConf 是 dnsmasq 主配置。
	DnsmasqConf string `json:"dnsmasq_conf"`
	// DnsmasqDir 是 dnsmasq 片段目录。
	DnsmasqDir string `json:"dnsmasq_dir"`
	// QueryTimeoutMs 是 dns.query 的超时（毫秒）。
	QueryTimeoutMs int `json:"query_timeout_ms"`
	// UpdateServer 是记录写入的目标权威 bind9 地址（IP 或主机名）。
	UpdateServer string `json:"update_server"`
	// UpdatePort 是记录写入的 DNS 端口。
	UpdatePort int `json:"update_port"`
	// UpdateKeyFile 是 TSIG 密钥文件（nsupdate -k）；空表示写入未启用。
	UpdateKeyFile string `json:"update_key_file"`
	// UpdateTimeoutMs 是单次写入与生效校验的超时（毫秒）。
	UpdateTimeoutMs int `json:"update_timeout_ms"`
}

// config 是插件运行期配置：配置契约（config.json）+ 环境变量 + 内嵌清单。
type config struct {
	// socket 主壳创建的 UDS 路径（KORE_PLUGIN_SOCK）。
	socket string
	// id 内核登记 id（KORE_PLUGIN_ID），缺省取清单 id。
	id string
	// token 内核注入的可选令牌（KORE_PLUGIN_TOKEN），仅随 hello 上报。
	token string
	// version 插件版本，取内嵌清单。
	version string
	// requiresKore 内核版本区间，取内嵌清单。
	requiresKore string
	// capabilities 能力声明，取内嵌清单。
	capabilities []string
	// startedAt 进程启动时刻，用于 kore.ping 的 uptime_s。
	startedAt time.Time
	// stateDir 是插件状态目录（KORE_STATE_DIR）。
	stateDir string
	// store 是配置文件的 0600 原子读写器。
	store *plugincfg.Store
	// values / source 是 config.get 的当前值与来源（file / env / default）。
	values fileValues
	source string
	// root 是内核提权通道（root_actions）；nil 表示环境变量三要素缺失（直接运行/非 kore 启动）。
	root dnsop.RootRunner
}

// loadConfig 读取配置契约与环境变量，解析内嵌清单。
func loadConfig() (*config, error) {
	var m manifest
	if err := json.Unmarshal(embeddedInfo, &m); err != nil {
		return nil, fmt.Errorf("解析内嵌 manifest.json: %w", err)
	}
	if m.Protocol != pluginapi.Protocol {
		return nil, fmt.Errorf("info.json.protocol=%q 与 SDK 协议 %q 不一致", m.Protocol, pluginapi.Protocol)
	}
	if err := plugincfg.ValidateSchema(configSchema()); err != nil {
		return nil, fmt.Errorf("config schema 非法: %w", err)
	}
	stateDir := strings.TrimSpace(os.Getenv("KORE_STATE_DIR"))
	store := plugincfg.NewStore(stateDir)
	values, source, err := resolveValues(store)
	if err != nil {
		return nil, err
	}
	cfg := &config{
		socket:       os.Getenv("KORE_PLUGIN_SOCK"),
		id:           os.Getenv("KORE_PLUGIN_ID"),
		token:        os.Getenv("KORE_PLUGIN_TOKEN"),
		version:      m.Version,
		requiresKore: m.RequiresKore,
		capabilities: m.Capabilities,
		startedAt:    time.Now(),
		stateDir:     stateDir,
		store:        store,
		values:       values,
		source:       source,
		root:         rootRunnerFromEnv(),
	}
	if cfg.id == "" {
		cfg.id = m.ID
	}
	if cfg.socket == "" {
		return nil, fmt.Errorf("缺少环境变量 KORE_PLUGIN_SOCK")
	}
	return cfg, nil
}

// defaultValues 是代码默认值（Debian/Ubuntu 路径）。
func defaultValues() fileValues {
	paths := dnsop.DefaultPaths()
	return fileValues{
		Engine:          dnsop.EngineAuto,
		BindConf:        paths.BindConf,
		BindZoneDir:     paths.BindZoneDir,
		DnsmasqConf:     paths.DnsmasqConf,
		DnsmasqDir:      paths.DnsmasqDir,
		QueryTimeoutMs:  defaultQueryTimeoutMs,
		UpdateServer:    defaultUpdateServer,
		UpdatePort:      defaultUpdatePort,
		UpdateTimeoutMs: defaultUpdateTimeout,
	}
}

// resolveValues 实现优先级 config.json > 环境变量 > 代码默认值。
func resolveValues(store *plugincfg.Store) (fileValues, string, error) {
	if store.Exists() {
		raw, _, err := store.Read()
		if err != nil {
			return fileValues{}, "", err
		}
		var values fileValues
		if err := json.Unmarshal(raw, &values); err != nil {
			return fileValues{}, "", fmt.Errorf("解析插件配置 %s: %w", store.Path(), err)
		}
		normalized, perr := validateValues(fillDefaults(values))
		if perr != nil {
			return fileValues{}, "", fmt.Errorf("插件配置 %s 非法: %s", store.Path(), perr.Message)
		}
		return normalized, plugincfg.SourceFile, nil
	}

	values := defaultValues()
	source := plugincfg.SourceDefault
	if engine := strings.TrimSpace(os.Getenv(EnvEngine)); engine != "" {
		values.Engine = engine
		source = plugincfg.SourceEnv
	}
	envPaths := []struct {
		name  string
		value *string
	}{
		{EnvBindConf, &values.BindConf},
		{EnvBindZoneDir, &values.BindZoneDir},
		{EnvDnsmasqConf, &values.DnsmasqConf},
		{EnvDnsmasqDir, &values.DnsmasqDir},
	}
	for _, item := range envPaths {
		if raw := strings.TrimSpace(os.Getenv(item.name)); raw != "" {
			*item.value = raw
			source = plugincfg.SourceEnv
		}
	}
	if raw := strings.TrimSpace(os.Getenv(EnvQueryTimeoutMs)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fileValues{}, "", fmt.Errorf("%s=%q 非法：必须是整数毫秒", EnvQueryTimeoutMs, raw)
		}
		values.QueryTimeoutMs = value
		source = plugincfg.SourceEnv
	}
	if raw := strings.TrimSpace(os.Getenv(EnvUpdateServer)); raw != "" {
		values.UpdateServer = raw
		source = plugincfg.SourceEnv
	}
	if raw := strings.TrimSpace(os.Getenv(EnvUpdateKeyFile)); raw != "" {
		values.UpdateKeyFile = raw
		source = plugincfg.SourceEnv
	}
	if raw := strings.TrimSpace(os.Getenv(EnvUpdatePort)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fileValues{}, "", fmt.Errorf("%s=%q 非法：必须是整数端口", EnvUpdatePort, raw)
		}
		values.UpdatePort = value
		source = plugincfg.SourceEnv
	}
	if raw := strings.TrimSpace(os.Getenv(EnvUpdateTimeoutMs)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fileValues{}, "", fmt.Errorf("%s=%q 非法：必须是整数毫秒", EnvUpdateTimeoutMs, raw)
		}
		values.UpdateTimeoutMs = value
		source = plugincfg.SourceEnv
	}
	normalized, perr := validateValues(fillDefaults(values))
	if perr != nil {
		return fileValues{}, "", perr
	}
	return normalized, source, nil
}

// fillDefaults 把零值字段补成默认值（config.json 允许只写关心的字段）。
func fillDefaults(values fileValues) fileValues {
	defaults := defaultValues()
	if strings.TrimSpace(values.Engine) == "" {
		values.Engine = defaults.Engine
	}
	if strings.TrimSpace(values.BindConf) == "" {
		values.BindConf = defaults.BindConf
	}
	if strings.TrimSpace(values.BindZoneDir) == "" {
		values.BindZoneDir = defaults.BindZoneDir
	}
	if strings.TrimSpace(values.DnsmasqConf) == "" {
		values.DnsmasqConf = defaults.DnsmasqConf
	}
	if strings.TrimSpace(values.DnsmasqDir) == "" {
		values.DnsmasqDir = defaults.DnsmasqDir
	}
	if values.QueryTimeoutMs == 0 {
		values.QueryTimeoutMs = defaults.QueryTimeoutMs
	}
	if strings.TrimSpace(values.UpdateServer) == "" {
		values.UpdateServer = defaults.UpdateServer
	}
	if values.UpdatePort == 0 {
		values.UpdatePort = defaults.UpdatePort
	}
	if values.UpdateTimeoutMs == 0 {
		values.UpdateTimeoutMs = defaults.UpdateTimeoutMs
	}
	return values
}

// validateValues 校验并归一化配置；启动加载与 config.set 共用同一套规则。
func validateValues(values fileValues) (fileValues, *pluginapi.Error) {
	engine := strings.ToLower(strings.TrimSpace(values.Engine))
	switch engine {
	case dnsop.EngineAuto, dnsop.EngineSystemdResolved, dnsop.EngineDnsmasq, dnsop.EngineBind9, dnsop.EngineCoreDNS:
	default:
		return fileValues{}, &pluginapi.Error{
			Code:    pluginapi.E_INVALID,
			Message: "engine 不支持 " + values.Engine + "：仅允许 auto/systemd-resolved/dnsmasq/bind9/coredns，请在插件设置里改选上述引擎",
		}
	}
	values.Engine = engine

	fields := []struct {
		name  string
		value *string
	}{
		{"bind_conf", &values.BindConf},
		{"bind_zone_dir", &values.BindZoneDir},
		{"dnsmasq_conf", &values.DnsmasqConf},
		{"dnsmasq_dir", &values.DnsmasqDir},
	}
	for _, field := range fields {
		cleaned, perr := dnsop.ValidateReadPath(field.name, *field.value)
		if perr != nil {
			return fileValues{}, perr
		}
		*field.value = cleaned
	}
	if values.QueryTimeoutMs < minQueryTimeoutMs || values.QueryTimeoutMs > maxQueryTimeoutMs {
		return fileValues{}, &pluginapi.Error{
			Code:    pluginapi.E_INVALID,
			Message: fmt.Sprintf("query_timeout_ms=%d 超出 [%d, %d]，请填入该范围内的值", values.QueryTimeoutMs, minQueryTimeoutMs, maxQueryTimeoutMs),
		}
	}
	server := strings.TrimSpace(values.UpdateServer)
	if net.ParseIP(server) == nil {
		if _, perr := dnsop.ValidateQueryName(server); perr != nil {
			return fileValues{}, invalidConfig("update_server 必须是 IP 或主机名（当前 " + server + "），请填写合法 IP 或域名后重试")
		}
	}
	values.UpdateServer = server
	if values.UpdatePort < minUpdatePort || values.UpdatePort > maxUpdatePort {
		return fileValues{}, invalidConfig(fmt.Sprintf("update_port=%d 超出 [%d, %d]，请填入该范围内的端口", values.UpdatePort, minUpdatePort, maxUpdatePort))
	}
	if keyFile := strings.TrimSpace(values.UpdateKeyFile); keyFile != "" {
		cleaned, perr := dnsop.ValidateWriteKeyPath(keyFile)
		if perr != nil {
			return fileValues{}, perr
		}
		values.UpdateKeyFile = cleaned
	}
	if values.UpdateTimeoutMs < minQueryTimeoutMs || values.UpdateTimeoutMs > maxQueryTimeoutMs {
		return fileValues{}, invalidConfig(fmt.Sprintf("update_timeout_ms=%d 超出 [%d, %d]，请填入该范围内的超时", values.UpdateTimeoutMs, minQueryTimeoutMs, maxQueryTimeoutMs))
	}
	return values, nil
}

// configSchema 是 config.get 返回的表单描述（PLUGIN-CONFIG §2）。
func configSchema() plugincfg.Schema {
	defaults := defaultValues()
	return plugincfg.Schema{
		Title: "DNS 检测、查询与记录写入配置",
		Fields: []plugincfg.Field{
			{
				Key: "engine", Label: "DNS 引擎", Type: plugincfg.TypeSelect,
				Default:  mustJSON(defaults.Engine),
				Required: true,
				Help:     "auto 按 systemd-resolved → dnsmasq → bind9 → coredns 选主引擎；也可强制指定。",
				Options:  []string{dnsop.EngineAuto, dnsop.EngineSystemdResolved, dnsop.EngineDnsmasq, dnsop.EngineBind9, dnsop.EngineCoreDNS},
			},
			{
				Key: "bind_conf", Label: "BIND 区域声明文件", Type: plugincfg.TypeString,
				Default:  mustJSON(defaults.BindConf),
				Required: true,
				Help:     "读 zone { type; file; } 声明；只读，路径必须在 /etc/bind 白名单内。",
			},
			{
				Key: "bind_zone_dir", Label: "BIND 区域文件目录", Type: plugincfg.TypeString,
				Default:  mustJSON(defaults.BindZoneDir),
				Required: true,
				Help:     "相对 file 的解析基准；白名单允许 /var/lib/bind。",
			},
			{
				Key: "dnsmasq_conf", Label: "dnsmasq 主配置", Type: plugincfg.TypeString,
				Default:  mustJSON(defaults.DnsmasqConf),
				Required: true,
				Help:     "读 address= / server= / local= / host-record= 指令；只读。",
			},
			{
				Key: "dnsmasq_dir", Label: "dnsmasq 片段目录", Type: plugincfg.TypeString,
				Default:  mustJSON(defaults.DnsmasqDir),
				Required: true,
				Help:     "扫描该目录下全部 *.conf 片段；白名单允许 /etc/dnsmasq.d。",
			},
			{
				Key: "query_timeout_ms", Label: "查询超时（毫秒）", Type: plugincfg.TypeInt,
				Default:  mustJSON(defaults.QueryTimeoutMs),
				Required: true,
				Help:     fmt.Sprintf("dns.query 的单次超时，范围 %d–%d。", minQueryTimeoutMs, maxQueryTimeoutMs),
				Min:      intPtr(minQueryTimeoutMs),
				Max:      intPtr(maxQueryTimeoutMs),
			},
			{
				Key: "update_server", Label: "动态更新服务器", Type: plugincfg.TypeString,
				Default:  mustJSON(defaults.UpdateServer),
				Required: true,
				Help:     "记录写入的目标权威 bind9 地址（IP 或主机名）。注意：127.0.0.53 是 systemd-resolved stub，不能接收动态更新。",
			},
			{
				Key: "update_port", Label: "动态更新端口", Type: plugincfg.TypeInt,
				Default:  mustJSON(defaults.UpdatePort),
				Required: true,
				Help:     fmt.Sprintf("权威 DNS 端口，范围 %d–%d。", minUpdatePort, maxUpdatePort),
				Min:      intPtr(minUpdatePort),
				Max:      intPtr(maxUpdatePort),
			},
			{
				Key: "update_key_file", Label: "TSIG 密钥文件", Type: plugincfg.TypeString,
				Default:  mustJSON(defaults.UpdateKeyFile),
				Required: false,
				Help:     "nsupdate -k 读取的 TSIG 密钥路径；留空表示不启用写入。允许 /etc/bind、/var/lib/bind、/var/lib/kore 等白名单目录。",
			},
			{
				Key: "update_timeout_ms", Label: "写入与校验超时（毫秒）", Type: plugincfg.TypeInt,
				Default:  mustJSON(defaults.UpdateTimeoutMs),
				Required: true,
				Help:     fmt.Sprintf("单次动态更新与生效校验的超时，范围 %d–%d。", minQueryTimeoutMs, maxQueryTimeoutMs),
				Min:      intPtr(minQueryTimeoutMs),
				Max:      intPtr(maxQueryTimeoutMs),
			},
		},
	}
}

// invalidConfig 构造配置校验错误（E_INVALID）。
func invalidConfig(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: message}
}

// mustJSON 把标量编成 json.RawMessage（schema 的 default 字段）。
func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return encoded
}

// intPtr 返回整数指针（schema 的 min/max）。
func intPtr(value int) *int { return &value }

// paths 把配置映射成 dnsop 的只读路径集合。
func (c *config) paths() dnsop.Paths {
	return dnsop.Paths{
		BindConf:    c.values.BindConf,
		BindZoneDir: c.values.BindZoneDir,
		DnsmasqConf: c.values.DnsmasqConf,
		DnsmasqDir:  c.values.DnsmasqDir,
		ResolvConf:  dnsop.DefaultPaths().ResolvConf,
	}
}

// detector 用当前配置构造检测器（每次调用重新构造，config.set 保存后下一次调用即生效）。
func (c *config) detector() dnsop.Detector {
	// 单条外部命令的超时必须覆盖「查询超时」与「写入/校验超时」中较大者，
	// 否则 nsupdate 或直连 dig 会被 OSHost 的默认 5s 提前掐断。
	hostTimeout := c.queryTimeout()
	if writeTimeout := c.updateTimeout(); writeTimeout > hostTimeout {
		hostTimeout = writeTimeout
	}
	return dnsop.Detector{
		Host:          dnsop.OSHost{Timeout: hostTimeout + time.Second},
		Paths:         c.paths(),
		DefaultEngine: c.values.Engine,
		Write:         c.writeOptions(),
		Root:          c.root,
	}
}

// updateTimeout 返回配置的写入/校验超时。
func (c *config) updateTimeout() time.Duration {
	return time.Duration(c.values.UpdateTimeoutMs) * time.Millisecond
}

// journalDir 返回写操作审计目录；缺少 KORE_STATE_DIR 时返回空串（写通道随之不可用）。
func (c *config) journalDir() string {
	if strings.TrimSpace(c.stateDir) == "" {
		return ""
	}
	return filepath.Join(c.stateDir, "dns-journal")
}

// writeOptions 组装写入通道；journal 为 nil 时写方法 fail-closed。
func (c *config) writeOptions() dnsop.WriteOptions {
	options := dnsop.WriteOptions{
		Server:  c.values.UpdateServer,
		Port:    c.values.UpdatePort,
		KeyFile: c.values.UpdateKeyFile,
		Timeout: c.updateTimeout(),
	}
	if dir := c.journalDir(); dir != "" {
		options.Journal = dnsop.FileJournal{Dir: dir}
	}
	// dnsmasq 写入只落插件状态目录内的片段（ADR-0023 零侵入），缺 KORE_STATE_DIR 时为空。
	if dir := strings.TrimSpace(c.stateDir); dir != "" {
		options.FragmentDir = filepath.Join(dir, "dnsmasq")
	}
	return options
}

// queryTimeout 返回配置的查询超时。
func (c *config) queryTimeout() time.Duration {
	return time.Duration(c.values.QueryTimeoutMs) * time.Millisecond
}

// configGet 组装 config.get 结果：schema + 当前值 + 来源。
func configGet(c *config) (json.RawMessage, *pluginapi.Error) {
	values, err := json.Marshal(c.values)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化当前配置失败: " + err.Error()}
	}
	result := plugincfg.GetResult{Schema: configSchema(), Values: values, Source: c.source}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化 config.get 结果失败: " + err.Error()}
	}
	return encoded, nil
}

// configSet 按「校验 → 原子写 → 更新内存 → 返回 applied」顺序保存配置（PLUGIN-CONFIG §3）。
func configSet(raw json.RawMessage, c *config) (json.RawMessage, *pluginapi.Error) {
	var params plugincfg.SetParams
	if len(raw) == 0 || string(raw) == "null" {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "缺少必填字段 values，请提供后重试"}
	}
	if raw[0] != '{' {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "params 必须是 JSON 对象，请提交 JSON 对象格式的参数"}
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "params 解析失败: " + err.Error() + "，请检查 JSON 格式后重试"}
	}
	if len(params.Values) == 0 || string(params.Values) == "null" {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "缺少必填字段 values，请提供后重试"}
	}
	// 以当前值为基线做局部更新：未提供的字段保持原值。
	candidate := c.values
	if err := json.Unmarshal(params.Values, &candidate); err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "values 解析失败: " + err.Error() + "，请检查 values 字段格式后重试"}
	}
	normalized, perr := validateValues(fillDefaults(candidate))
	if perr != nil {
		return nil, perr
	}
	if c.store.Path() == "" {
		return nil, &pluginapi.Error{
			Code:    pluginapi.E_INTERNAL,
			Message: "KORE_STATE_DIR 未设置，无法保存插件配置",
			Detail:  json.RawMessage(`{"hint":"插件由内核启动时会注入 KORE_STATE_DIR；本地单独调试请先设置该环境变量。"}`),
		}
	}
	payload, marshalErr := json.Marshal(normalized)
	if marshalErr != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化配置失败: " + marshalErr.Error()}
	}
	if writeErr := c.store.Write(payload); writeErr != nil {
		return nil, &pluginapi.Error{
			Code:    pluginapi.E_INTERNAL,
			Message: "保存插件配置失败: " + writeErr.Error(),
			Detail:  json.RawMessage(`{"hint":"检查 KORE_STATE_DIR 是否可写（目录需 0700 且属主为运行用户）。"}`),
		}
	}
	c.values = normalized
	c.source = plugincfg.SourceFile
	result := plugincfg.SetResult{Saved: true, Applied: true, RestartRequired: false, Warnings: []string{}}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化 config.set 结果失败: " + marshalErr.Error()}
	}
	return encoded, nil
}

// reload 重新从配置文件加载值（kore.reload 用），返回配置摘要。
func (c *config) reload() (json.RawMessage, *pluginapi.Error) {
	values, source, err := resolveValues(c.store)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "重载配置失败: " + err.Error()}
	}
	c.values = values
	c.source = source
	payload, marshalErr := json.Marshal(c.values)
	if marshalErr != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化配置失败: " + marshalErr.Error()}
	}
	sum := sha256.Sum256(payload)
	result := struct {
		OK           bool   `json:"ok"`
		ConfigDigest string `json:"config_digest"`
	}{OK: true, ConfigDigest: hex.EncodeToString(sum[:8])}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化 reload 结果失败: " + marshalErr.Error()}
	}
	return encoded, nil
}
