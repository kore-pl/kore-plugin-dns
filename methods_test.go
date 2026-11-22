package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// invoke 发一个请求并读回响应与 serve 结束状态（每个用例独立连接、独立 store）。
func invoke(t *testing.T, method, reqID string, params json.RawMessage) *pluginapi.Response {
	t.Helper()
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	cfg := testConfig()
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

// resultString 断言无错误并返回 result 原文。
func resultString(t *testing.T, response *pluginapi.Response) string {
	t.Helper()
	if response.Error != nil {
		t.Fatalf("意外错误: code=%s message=%s", response.Error.Code, response.Error.Message)
	}
	return string(response.Result)
}

// TestZoneList 覆盖 list 裸名/全名、req_id 回显与空列表结构化结果。
func TestZoneList(t *testing.T) {
	for _, method := range []string{"zone.list", "dns.zone.list"} {
		t.Run(method, func(t *testing.T) {
			response := invoke(t, method, "r-1", nil)
			if response.ReqID != "r-1" {
				t.Fatalf("req_id=%q，期望回显 r-1", response.ReqID)
			}
			if got := resultString(t, response); got != `{"zones":null,"count":0,"applied":false}` {
				t.Fatalf("result=%s", got)
			}
		})
	}
}

// TestRecordAdd 覆盖四类合法记录：结构化结果字段、req_id、applied=false。
func TestRecordAdd(t *testing.T) {
	cases := []struct {
		name   string
		params string
		want   string
	}{
		{
			name:   "A",
			params: `{"zone":"example.com","name":"www.example.com","type":"A","value":"192.0.2.10"}`,
			want:   `{"zone":"example.com","name":"www.example.com","type":"A","value":"192.0.2.10","ttl":3600,"applied":false,"added":true}`,
		},
		{
			name:   "AAAA",
			params: `{"zone":"example.com","name":"v6.example.com","type":"AAAA","value":"2001:db8::1"}`,
			want:   `{"zone":"example.com","name":"v6.example.com","type":"AAAA","value":"2001:db8::1","ttl":3600,"applied":false,"added":true}`,
		},
		{
			name:   "CNAME",
			params: `{"zone":"example.com","name":"alias.example.com","type":"CNAME","value":"www.example.com"}`,
			want:   `{"zone":"example.com","name":"alias.example.com","type":"CNAME","value":"www.example.com","ttl":3600,"applied":false,"added":true}`,
		},
		{
			name:   "MX",
			params: `{"zone":"example.com","name":"example.com","type":"MX","value":"10 mail.example.com","ttl":600}`,
			want:   `{"zone":"example.com","name":"example.com","type":"MX","value":"10 mail.example.com","ttl":600,"applied":false,"added":true}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := invoke(t, "dns.record.add", "r-"+tc.name, json.RawMessage(tc.params))
			if response.ReqID != "r-"+tc.name {
				t.Fatalf("req_id=%q", response.ReqID)
			}
			if got := resultString(t, response); got != tc.want {
				t.Fatalf("result=%s\n期望 %s", got, tc.want)
			}
		})
	}
}

// TestRecordAddInvalid 覆盖非法参数：缺字段、非法域名、非法 IP、不支持类型、非法 MX、越界 TTL。
func TestRecordAddInvalid(t *testing.T) {
	cases := []struct {
		name     string
		params   string
		contains string
	}{
		{name: "params 非对象", params: `"x"`, contains: "params 必须是 JSON 对象"},
		{name: "缺 zone", params: `{"name":"www.example.com","type":"A","value":"192.0.2.1"}`, contains: "缺少必填字段 zone"},
		{name: "大写域名", params: `{"zone":"Example.COM","name":"www.example.com","type":"A","value":"192.0.2.1"}`, contains: "zone 必须为小写"},
		{name: "单标签 zone", params: `{"zone":"localhost","name":"www.example.com","type":"A","value":"192.0.2.1"}`, contains: "至少两个标签"},
		{name: "路径穿越", params: `{"zone":"../etc","name":"www.example.com","type":"A","value":"192.0.2.1"}`, contains: "zone 非法"},
		{name: "非法 A", params: `{"zone":"example.com","name":"www.example.com","type":"A","value":"999.1.1.1"}`, contains: "A 记录的 value"},
		{name: "A 用 IPv6", params: `{"zone":"example.com","name":"www.example.com","type":"A","value":"2001:db8::1"}`, contains: "A 记录的 value"},
		{name: "非法 AAAA", params: `{"zone":"example.com","name":"www.example.com","type":"AAAA","value":"192.0.2.1"}`, contains: "AAAA 记录的 value"},
		{name: "不支持类型", params: `{"zone":"example.com","name":"www.example.com","type":"TXT","value":"x"}`, contains: "type 不支持"},
		{name: "非法 CNAME", params: `{"zone":"example.com","name":"a.example.com","type":"CNAME","value":"_bad"}`, contains: "value 非法"},
		{name: "非法 MX 优先级", params: `{"zone":"example.com","name":"example.com","type":"MX","value":"x mail.example.com"}`, contains: "MX 优先级"},
		{name: "MX 缺目标", params: `{"zone":"example.com","name":"example.com","type":"MX","value":"10"}`, contains: "优先级 域名"},
		{name: "TTL 越界", params: `{"zone":"example.com","name":"www.example.com","type":"A","value":"192.0.2.1","ttl":-1}`, contains: "ttl 必须在"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := invoke(t, "dns.record.add", "r-1", json.RawMessage(tc.params))
			if response.Error == nil {
				t.Fatalf("期望 E_INVALID，实际 result=%s", response.Result)
			}
			if response.Error.Code != pluginapi.E_INVALID {
				t.Fatalf("error code=%s，期望 %s", response.Error.Code, pluginapi.E_INVALID)
			}
			if !strings.Contains(response.Error.Message, tc.contains) {
				t.Fatalf("error message=%q，期望包含 %q", response.Error.Message, tc.contains)
			}
		})
	}
}

// TestUnknownMethod 未知方法回 E_NOTFOUND。
func TestUnknownMethod(t *testing.T) {
	response := invoke(t, "dns.nope", "r-1", nil)
	if response.Error == nil || response.Error.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("error=%v，期望 E_NOTFOUND", response.Error)
	}
}

// TestZoneListSeesProposal 同一会话内 record.add 的提案应被 zone.list 聚合可见。
func TestZoneListSeesProposal(t *testing.T) {
	cfg := testConfig()
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := startServe(pluginConn, cfg)
	writeRequest(t, kernelConn, "dns.record.add", "r-add", json.RawMessage(`{"zone":"example.com","name":"www.example.com","type":"A","value":"192.0.2.1"}`))
	add := readResponse(t, kernelConn)
	if add.Error != nil {
		t.Fatalf("record.add 意外错误: %v", add.Error)
	}
	writeRequest(t, kernelConn, "dns.zone.list", "r-list", nil)
	list := readResponse(t, kernelConn)
	if got := string(list.Result); got != `{"zones":[{"name":"example.com","record_count":1}],"count":1,"applied":false}` {
		t.Fatalf("zone.list result=%s", got)
	}
	writeRequest(t, kernelConn, "kore.shutdown", "r-shutdown", nil)
	if shutdown := readResponse(t, kernelConn); string(shutdown.Result) != `{"ok":true}` {
		t.Fatalf("shutdown 结果=%s", shutdown.Result)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
}
