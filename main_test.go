package main

import (
	"encoding/json"
	"github.com/pengtang1024/kore-plugin-dns/internal/dnsop"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-dns/internal/plugincfg"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// testConfig 构造与生产一致但状态目录落在 t.TempDir() 的配置（不读环境变量）。
func testConfig(t *testing.T) *config {
	t.Helper()
	dir := t.TempDir()
	return &config{
		id:           "dns",
		version:      "0.2.0",
		requiresKore: ">=0.1.0 <0.2.0",
		capabilities: []string{"system:read"},
		startedAt:    time.Now(),
		stateDir:     dir,
		store:        plugincfg.NewStore(dir),
		values:       defaultValues(),
		source:       plugincfg.SourceDefault,
	}
}

// testLogger 返回丢弃输出的 logger。
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startServe 启动会话循环。
func startServe(conn net.Conn, cfg *config) <-chan error {
	done := make(chan error, 1)
	go func() {
		err := serve(conn, cfg, testLogger())
		_ = conn.Close()
		done <- err
	}()
	return done
}

// readFrame 读一帧并解码信封。
func readFrame(t *testing.T, conn net.Conn) any {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		t.Fatalf("解码帧失败: %v", err)
	}
	return env
}

// readRequest 读一帧并断言是 request。
func readRequest(t *testing.T, conn net.Conn) *pluginapi.Request {
	t.Helper()
	env := readFrame(t, conn)
	request, ok := env.(*pluginapi.Request)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 request", env)
	}
	return request
}

// readResponse 读一帧并断言是 response。
func readResponse(t *testing.T, conn net.Conn) *pluginapi.Response {
	t.Helper()
	env := readFrame(t, conn)
	response, ok := env.(*pluginapi.Response)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 response", env)
	}
	return response
}

// writeRequest 写一个请求帧。
func writeRequest(t *testing.T, conn net.Conn, method, reqID string, params json.RawMessage) {
	t.Helper()
	request := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id-" + reqID, ReqID: reqID, Method: method, Params: params,
	}
	if err := pluginapi.WriteJSON(conn, request); err != nil {
		t.Fatalf("写请求失败: %v", err)
	}
}

// writeResponse 写一个响应帧。
func writeResponse(t *testing.T, conn net.Conn, id, reqID string, result json.RawMessage) {
	t.Helper()
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: id, ReqID: reqID, Result: result}
	if err := pluginapi.WriteJSON(conn, response); err != nil {
		t.Fatalf("写响应失败: %v", err)
	}
}

// TestHandshake 校验 hello 首帧字段与三步握手（握手版本随插件版本 0.2.0）。
func TestHandshake(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	cfg := testConfig(t)
	done := make(chan error, 1)
	go func() { done <- handshake(pluginConn, cfg); _ = pluginConn.Close() }()

	request := readRequest(t, kernelConn)
	if request.Method != helloMethod {
		t.Fatalf("首帧方法=%q，期望 %q", request.Method, helloMethod)
	}
	var params helloParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		t.Fatalf("解析 hello 参数失败: %v", err)
	}
	if params.PluginID != "dns" || params.ID != "dns" {
		t.Fatalf("plugin_id/id=%q/%q，期望都是 dns", params.PluginID, params.ID)
	}
	if params.Protocol != pluginapi.Protocol || params.Version != "0.2.0" {
		t.Fatalf("protocol/version=%q/%q 不符合 §5", params.Protocol, params.Version)
	}
	if len(params.Capabilities) != 1 || params.Capabilities[0] != "system:read" {
		t.Fatalf("capabilities=%v，期望 [system:read]", params.Capabilities)
	}
	if params.PID != os.Getpid() {
		t.Fatalf("pid=%d，期望 %d", params.PID, os.Getpid())
	}
	result, err := json.Marshal(helloResult{OK: true, Protocol: pluginapi.Protocol})
	if err != nil {
		t.Fatalf("序列化握手响应失败: %v", err)
	}
	writeResponse(t, kernelConn, request.ID, request.ReqID, result)
	if err := <-done; err != nil {
		t.Fatalf("握手返回错误: %v", err)
	}
}

// TestLoadConfigDefaults 无环境变量时用内置默认路径与 auto 引擎，schema 通过自检。
func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("KORE_PLUGIN_SOCK", "/tmp/test.sock")
	t.Setenv("KORE_STATE_DIR", "")
	t.Setenv("KORE_PLUGIN_ID", "")
	t.Setenv(EnvEngine, "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}
	defaults := defaultValues()
	if cfg.values != defaults {
		t.Fatalf("默认值=%+v，期望 %+v", cfg.values, defaults)
	}
	if cfg.source != plugincfg.SourceDefault {
		t.Fatalf("source=%q，期望 default", cfg.source)
	}
	if cfg.id != "dns" || cfg.version != "0.3.1" {
		t.Fatalf("id/version=%q/%q", cfg.id, cfg.version)
	}
	if err := plugincfg.ValidateSchema(configSchema()); err != nil {
		t.Fatalf("schema 自检失败: %v", err)
	}
}

// TestLoadConfigMissingSocket 缺少 KORE_PLUGIN_SOCK 必须启动失败（不静默降级）。
func TestLoadConfigMissingSocket(t *testing.T) {
	t.Setenv("KORE_PLUGIN_SOCK", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("缺少 KORE_PLUGIN_SOCK 应返回错误")
	}
}

// TestLoadConfigBadEnvTimeout 非法环境变量在启动期就报错（带变量名）。
func TestLoadConfigBadEnvTimeout(t *testing.T) {
	t.Setenv("KORE_PLUGIN_SOCK", "/tmp/test.sock")
	t.Setenv("KORE_STATE_DIR", "")
	t.Setenv("KORE_DNS_QUERY_TIMEOUT_MS", "abc")
	if _, err := loadConfig(); err == nil {
		t.Fatal("非法 query_timeout_ms 应返回错误")
	}
}

// TestConfigEngineFeedsDetector 配置里的 engine 必须进入检测器默认值（保存即生效的关键一环）。
func TestConfigEngineFeedsDetector(t *testing.T) {
	cfg := testConfig(t)
	cfg.values.Engine = "dnsmasq"
	if got := cfg.detector().DefaultEngine; got != "dnsmasq" {
		t.Fatalf("detector.DefaultEngine=%q，期望 dnsmasq", got)
	}
	if got := cfg.detector().Paths.BindConf; got != cfg.values.BindConf {
		t.Fatalf("路径未透传: %q", got)
	}
	if cfg.queryTimeout().Milliseconds() != int64(cfg.values.QueryTimeoutMs) {
		t.Fatalf("查询超时未透传: %v", cfg.queryTimeout())
	}
}

// TestValidateWriteConfig 覆盖写入配置的校验口径：地址/端口/密钥白名单/超时。
func TestValidateWriteConfig(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fileValues)
	}{
		{"update_server 非法", func(v *fileValues) { v.UpdateServer = "not a host!" }},
		{"update_port 越界", func(v *fileValues) { v.UpdatePort = 70000 }},
		{"update_key_file 不在白名单", func(v *fileValues) { v.UpdateKeyFile = "/tmp/kore-update.key" }},
		{"update_key_file 含 ..", func(v *fileValues) { v.UpdateKeyFile = "/etc/bind/../bind/kore.key" }},
		{"update_timeout 越界", func(v *fileValues) { v.UpdateTimeoutMs = 10 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := fillDefaults(fileValues{})
			tc.mutate(&values)
			if _, perr := validateValues(values); perr == nil {
				t.Fatalf("%s 应校验失败", tc.name)
			}
		})
	}
	ok := fillDefaults(fileValues{UpdateKeyFile: "/var/lib/kore/kore-update.key"})
	if _, perr := validateValues(ok); perr != nil {
		t.Fatalf("白名单内密钥路径应通过: %s", perr.Message)
	}
}

// TestDetectorWiresWriteChannel 写通道必须随配置装配：journal 落在 state 目录、超时取较大者。
func TestDetectorWiresWriteChannel(t *testing.T) {
	cfg := testConfig(t)
	cfg.values.UpdateServer = "127.0.0.1"
	cfg.values.UpdatePort = 5353
	cfg.values.UpdateKeyFile = "/var/lib/kore/kore-update.key"
	cfg.values.UpdateTimeoutMs = 8000
	detector := cfg.detector()
	if detector.Write.Journal == nil {
		t.Fatal("配置了 KORE_STATE_DIR 时写通道必须装配 journal")
	}
	if detector.Write.Server != "127.0.0.1" || detector.Write.Port != 5353 || detector.Write.KeyFile != "/var/lib/kore/kore-update.key" {
		t.Fatalf("写通道未透传: %+v", detector.Write)
	}
	if detector.Write.Timeout.Milliseconds() != 8000 {
		t.Fatalf("写入超时=%v", detector.Write.Timeout)
	}
	journal, ok := detector.Write.Journal.(dnsop.FileJournal)
	if !ok || !strings.HasSuffix(journal.Dir, "dns-journal") {
		t.Fatalf("journal 目录=%+v，期望 <state>/dns-journal", detector.Write.Journal)
	}
	// 缺少 KORE_STATE_DIR 时 journal 必须为 nil（写方法 fail-closed）。
	cfgNoState := testConfig(t)
	cfgNoState.stateDir = ""
	if cfgNoState.detector().Write.Journal != nil {
		t.Fatal("无 state 目录时不应装配 journal")
	}
}
