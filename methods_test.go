package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// invoke 发一个请求并读回响应，然后 shutdown 收尾（每个用例独立连接、独立状态目录）。
func invoke(t *testing.T, cfg *config, method, reqID string, params json.RawMessage) *pluginapi.Response {
	t.Helper()
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := startServe(pluginConn, cfg)
	writeRequest(t, kernelConn, method, reqID, params)
	response := readResponse(t, kernelConn)
	writeRequest(t, kernelConn, "kore.shutdown", "r-shutdown", nil)
	if shutdown := readResponse(t, kernelConn); string(shutdown.Result) != `{"ok":true}` {
		t.Fatalf("shutdown 结果=%s", shutdown.Result)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
	return response
}

// TestPing 协议必选方法：结构化状态 + req_id 回显。
func TestPing(t *testing.T) {
	cfg := testConfig(t)
	response := invoke(t, cfg, "kore.ping", "r-ping", nil)
	if response.Error != nil {
		t.Fatalf("ping 失败: %v", response.Error)
	}
	if response.ReqID != "r-ping" {
		t.Fatalf("req_id=%q", response.ReqID)
	}
	var result statusResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("解析 ping 结果失败: %v", err)
	}
	if result.Status != "ready" {
		t.Fatalf("status=%q", result.Status)
	}
	if result.Goroutines <= 0 || result.RSSKB <= 0 {
		t.Fatalf("goroutines/rss 异常: %+v", result)
	}
}

// TestConfigGet config.get 返回 schema + values + source，字段与默认值齐全。
func TestConfigGet(t *testing.T) {
	cfg := testConfig(t)
	for _, method := range []string{"config.get", "dns.config.get"} {
		response := invoke(t, cfg, method, "r-get", nil)
		if response.Error != nil {
			t.Fatalf("%s 失败: %v", method, response.Error)
		}
		var result struct {
			Schema struct {
				Title  string `json:"title"`
				Fields []struct {
					Key      string          `json:"key"`
					Type     string          `json:"type"`
					Default  json.RawMessage `json:"default"`
					Required bool            `json:"required"`
					Help     string          `json:"help"`
				} `json:"fields"`
			} `json:"schema"`
			Values map[string]any `json:"values"`
			Source string         `json:"source"`
		}
		if err := json.Unmarshal(response.Result, &result); err != nil {
			t.Fatalf("解析 config.get 失败: %v", err)
		}
		if len(result.Schema.Fields) != 10 {
			t.Fatalf("字段数=%d，期望 10（4 只读路径 + engine + query 超时 + 4 写入项）", len(result.Schema.Fields))
		}
		for _, field := range result.Schema.Fields {
			// update_key_file 是写通道的开关：留空表示不启用写入，因此允许 non-required。
			required := field.Required || field.Key == "update_key_file"
			if field.Key == "" || field.Type == "" || len(field.Default) == 0 || !required || field.Help == "" {
				t.Fatalf("字段描述不完整: %+v", field)
			}
		}
		if result.Source != "default" {
			t.Fatalf("source=%q，期望 default", result.Source)
		}
		if result.Values["engine"] != "auto" {
			t.Fatalf("engine=%v，期望 auto", result.Values["engine"])
		}
	}
}

// TestConfigSetRoundTrip config.set 保存后 config.get 的 source 变 file，值生效。
func TestConfigSetRoundTrip(t *testing.T) {
	cfg := testConfig(t)
	response := invoke(t, cfg, "dns.config.set", "r-set", json.RawMessage(`{"values":{"engine":"dnsmasq","query_timeout_ms":1500}}`))
	if response.Error != nil {
		t.Fatalf("config.set 失败: %v", response.Error)
	}
	var setResult struct {
		Saved           bool     `json:"saved"`
		Applied         bool     `json:"applied"`
		RestartRequired bool     `json:"restart_required"`
		Warnings        []string `json:"warnings"`
	}
	if err := json.Unmarshal(response.Result, &setResult); err != nil {
		t.Fatalf("解析 config.set 结果失败: %v", err)
	}
	if !setResult.Saved || !setResult.Applied || setResult.RestartRequired {
		t.Fatalf("set 结果不合格: %+v", setResult)
	}
	if cfg.values.Engine != "dnsmasq" || cfg.values.QueryTimeoutMs != 1500 {
		t.Fatalf("内存值未更新: %+v", cfg.values)
	}
	if cfg.values.BindConf != "/etc/bind/named.conf.local" {
		t.Fatalf("未提供的字段应保持原值: %+v", cfg.values)
	}

	get := invoke(t, cfg, "config.get", "r-get", nil)
	if get.Error != nil {
		t.Fatalf("config.get 失败: %v", get.Error)
	}
	if !strings.Contains(string(get.Result), `"source":"file"`) {
		t.Fatalf("source 未变 file: %s", get.Result)
	}
	if !strings.Contains(string(get.Result), `"engine":"dnsmasq"`) {
		t.Fatalf("engine 未生效: %s", get.Result)
	}
}

// TestConfigSetInvalid 非法值被拒绝且不落盘、不改内存。
func TestConfigSetInvalid(t *testing.T) {
	cfg := testConfig(t)
	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"非对象", `"x"`, "params 必须是 JSON 对象"},
		{"缺 values", `{}`, "缺少必填字段 values"},
		{"未知引擎", `{"values":{"engine":"powerdns"}}`, "engine 不支持"},
		{"越界白名单", `{"values":{"bind_conf":"/etc/passwd"}}`, "只读白名单"},
		{"相对路径", `{"values":{"dnsmasq_dir":"etc/dnsmasq.d"}}`, "绝对路径"},
		{"超时越界", `{"values":{"query_timeout_ms":10}}`, "超出"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := invoke(t, cfg, "config.set", "r-bad", json.RawMessage(tc.params))
			if response.Error == nil {
				t.Fatalf("期望错误，实际成功: %s", response.Result)
			}
			if response.Error.Code != pluginapi.E_INVALID {
				t.Fatalf("错误码=%s，期望 E_INVALID", response.Error.Code)
			}
			if !strings.Contains(response.Error.Message, tc.want) {
				t.Fatalf("message=%q，未含 %q", response.Error.Message, tc.want)
			}
			if cfg.values != defaultValues() {
				t.Fatalf("校验失败不应改内存: %+v", cfg.values)
			}
			if cfg.store.Exists() {
				t.Fatal("校验失败不应写配置文件")
			}
		})
	}
}

// TestReloadDigest kore.reload 重读配置并返回非空摘要。
func TestReloadDigest(t *testing.T) {
	cfg := testConfig(t)
	response := invoke(t, cfg, "kore.reload", "r-reload", nil)
	if response.Error != nil {
		t.Fatalf("reload 失败: %v", response.Error)
	}
	var result struct {
		OK           bool   `json:"ok"`
		ConfigDigest string `json:"config_digest"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("解析 reload 结果失败: %v", err)
	}
	if !result.OK || len(result.ConfigDigest) != 16 {
		t.Fatalf("reload 结果不合格: %+v", result)
	}
}

// TestUnknownMethod 未知方法（含旧骨架方法 zone.list）统一 E_NOTFOUND。
func TestUnknownMethod(t *testing.T) {
	cfg := testConfig(t)
	for _, method := range []string{"dns.zone.list", "dns.record.rename", "dns.nope", "zone.list"} {
		response := invoke(t, cfg, method, "r-404", nil)
		if response.Error == nil || response.Error.Code != pluginapi.E_NOTFOUND {
			t.Fatalf("%s 期望 E_NOTFOUND，实际 %v", method, response.Error)
		}
	}
	// record.add 已是真实写入方法：缺参数应回 E_INVALID（参数错误），不是 E_NOTFOUND。
	missing := invoke(t, cfg, "dns.record.add", "r-param", nil)
	if missing.Error == nil || missing.Error.Code != pluginapi.E_INVALID {
		t.Fatalf("record.add 缺参应 E_INVALID，实际 %v", missing.Error)
	}
}

// TestBusinessVerb 裸名与全名都归一，非业务方法不误判。
func TestBusinessVerb(t *testing.T) {
	cases := []struct {
		method string
		ok     bool
		verb   string
	}{
		{"dns.status", true, "status"},
		{"status", true, "status"},
		{"dns.zones", true, "zones"},
		{"dns.records", true, "records"},
		{"dns.query", true, "query"},
		{"dns.config.get", false, ""},
		{"kore.ping", false, ""},
		{"dns.zone.list", false, ""},
	}
	for _, tc := range cases {
		verb, ok := businessVerb(tc.method, "dns")
		if ok != tc.ok || verb != tc.verb {
			t.Fatalf("businessVerb(%q)=(%q,%v)，期望 (%q,%v)", tc.method, verb, ok, tc.verb, tc.ok)
		}
	}
}

// TestDispatchShutdown shutdown 返回第二布尔值 true 且回 ok。
func TestDispatchShutdown(t *testing.T) {
	cfg := testConfig(t)
	response, shutdown := dispatch(&pluginapi.Request{ID: "i", ReqID: "r", Method: "kore.shutdown"}, cfg, testLogger())
	if !shutdown {
		t.Fatal("kore.shutdown 应返回 shutdown=true")
	}
	if string(response.Result) != `{"ok":true}` {
		t.Fatalf("shutdown 结果=%s", response.Result)
	}
}
