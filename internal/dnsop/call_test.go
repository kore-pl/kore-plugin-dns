package dnsop

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// bind9ReloadHost 是「只有 bind9 在跑、rndc 可用」的假宿主：reload 用例必须离线断言 argv。
func bind9ReloadHost() *fakeHost {
	host := newFakeHost()
	host.cmds["systemctl is-active named"] = "active\n"
	host.cmds["named -v"] = "BIND 9.18.30-0ubuntu0.24.04.1-Ubuntu (Extended Support Version)\n"
	host.cmds["rndc reload"] = ""
	host.cmds["rndc reload example.com"] = ""
	return host
}

// hasCall 判断假宿主是否执行过某条「命令 + 参数」。
func hasCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

// rndcCalls 返回所有 rndc 调用（断言「没有多打/错打」用）。
func rndcCalls(calls []string) []string {
	var out []string
	for _, call := range calls {
		if strings.HasPrefix(call, "rndc ") {
			out = append(out, call)
		}
	}
	return out
}

// TestCallReloadUsesZoneParamNotEngine 是本次修复的核心断言：
// dns.reload{"zone":"Example.COM."} 只能把 zone 归一化后传给 rndc，engine 绝不参与 argv。
func TestCallReloadUsesZoneParamNotEngine(t *testing.T) {
	host := bind9ReloadHost()
	detector := Detector{Host: host}

	raw, perr := detector.Call(context.Background(), "reload", json.RawMessage(`{"zone":"Example.COM."}`), time.Second)
	if perr != nil {
		t.Fatalf("dns.reload 失败: %+v", perr)
	}
	var result ReloadResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 dns.reload 结果失败: %v（原文 %s）", err, raw)
	}
	if result.Engine != EngineBind9 || !result.Reloaded {
		t.Fatalf("bind9 应 reloaded=true: %+v", result)
	}
	if result.Command != "rndc reload example.com" {
		t.Fatalf("command=%q，期望 rndc reload example.com", result.Command)
	}
	if !hasCall(host.calls, "rndc reload example.com") {
		t.Fatalf("未执行期望的 rndc 调用：%v", rndcCalls(host.calls))
	}
	// 关键断言：engine 不会被当成 zone（历史 bug：rndc reload bind9）。
	if hasCall(host.calls, "rndc reload bind9") {
		t.Fatalf("engine 被当成 zone 传给了 rndc: %v", rndcCalls(host.calls))
	}
	for _, call := range rndcCalls(host.calls) {
		if call != "rndc reload example.com" {
			t.Fatalf("rndc 参数不符（多余/错误参数）: %q", call)
		}
	}
}

// TestCallReloadRejectsEngineParam 覆盖「多余入参」：engine 不是 dns.reload 的声明入参，
// 必须 E_INVALID 且不得触发任何 rndc（拒绝写在执行之前）。
func TestCallReloadRejectsEngineParam(t *testing.T) {
	cases := []struct {
		name   string
		params string
	}{
		{"只有 engine", `{"engine":"bind9"}`},
		{"zone 与 engine 同送", `{"zone":"example.com","engine":"bind9"}`},
		{"未声明的额外字段", `{"zone":"example.com","timeout_ms":100}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := bind9ReloadHost()
			detector := Detector{Host: host}
			_, perr := detector.Call(context.Background(), "reload", json.RawMessage(tc.params), time.Second)
			if perr == nil {
				t.Fatalf("未声明字段应 E_INVALID，实际成功")
			}
			if perr.Code != pluginapi.E_INVALID {
				t.Fatalf("code=%q，期望 E_INVALID", perr.Code)
			}
			if !strings.Contains(perr.Message, "未声明") || !strings.Contains(perr.Message, "zone") {
				t.Fatalf("错误信息未说明契约: %q", perr.Message)
			}
			if !strings.Contains(string(perr.Detail), `"allowed":"zone"`) {
				t.Fatalf("detail 未给出允许字段: %s", perr.Detail)
			}
			if calls := rndcCalls(host.calls); len(calls) != 0 {
				t.Fatalf("被拒入参不得触发 rndc，实际: %v", calls)
			}
		})
	}
}

// TestCallReloadWithoutParamsReloadsWholeEngine 覆盖「参数缺失」：空 / null / {} 合法，
// 都是重载整个引擎（argv 只有 reload），不产生尾随空格的 command。
func TestCallReloadWithoutParamsReloadsWholeEngine(t *testing.T) {
	for _, params := range []json.RawMessage{nil, json.RawMessage(`{}`), json.RawMessage(`null`)} {
		host := bind9ReloadHost()
		detector := Detector{Host: host}
		raw, perr := detector.Call(context.Background(), "reload", params, time.Second)
		if perr != nil {
			t.Fatalf("params=%q 应合法: %+v", params, perr)
		}
		var result ReloadResult
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("解析结果失败: %v", err)
		}
		if result.Command != "rndc reload" {
			t.Fatalf("params=%q command=%q，期望 rndc reload（无尾随空格）", params, result.Command)
		}
		if !hasCall(host.calls, "rndc reload") {
			t.Fatalf("params=%q 未执行 rndc reload: %v", params, rndcCalls(host.calls))
		}
		for _, call := range rndcCalls(host.calls) {
			if call != "rndc reload" {
				t.Fatalf("params=%q rndc 调用不符: %q", params, call)
			}
		}
	}
}

// TestCallReloadRejectsInvalidZone 覆盖 zone 形态非法：E_INVALID 且不执行 rndc。
func TestCallReloadRejectsInvalidZone(t *testing.T) {
	host := bind9ReloadHost()
	detector := Detector{Host: host}
	_, perr := detector.Call(context.Background(), "reload", json.RawMessage(`{"zone":"bad zone"}`), time.Second)
	if perr == nil || perr.Code != pluginapi.E_INVALID {
		t.Fatalf("非法 zone 应 E_INVALID，实际 %+v", perr)
	}
	if !strings.Contains(perr.Message, "zone") {
		t.Fatalf("错误信息未指向 zone: %q", perr.Message)
	}
	if calls := rndcCalls(host.calls); len(calls) != 0 {
		t.Fatalf("非法 zone 不得执行 rndc: %v", calls)
	}

	// 非对象 params 同样拒绝（契约只接受 JSON 对象）。
	if _, perr := detector.Call(context.Background(), "reload", json.RawMessage(`["bind9"]`), time.Second); perr == nil || perr.Code != pluginapi.E_INVALID {
		t.Fatalf("数组 params 应 E_INVALID，实际 %+v", perr)
	}
	if calls := rndcCalls(host.calls); len(calls) != 0 {
		t.Fatalf("非对象 params 不得执行 rndc: %v", calls)
	}
}
