// 本文件是「非 root 实测」：直接拉起 bin/dns，在**没有提权通道**的环境下调用 dns.reload。
//
// 为什么这样测：本机开发用户是普通用户、也没有以 root 启动 kored，能真实验证的是
// 「非 root / 通道缺失 → E_NEED_ROOT + 可操作 hint，且插件进程不自行 sudo」；
// uid=0 下 resolvectl 的真实成功路径在本机无法验证（README「未完成项」已标注未验证）。
package live

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// callRaw 发一个方法调用并返回原始 response（错误不 fatal，供降级断言使用）。
func (s *session) callRaw(t *testing.T, method string, params any) *pluginapi.Response {
	t.Helper()
	payload := map[string]any{"type": "request", "id": "raw-" + method, "req_id": "rr-" + method, "method": method}
	if params != nil {
		payload["params"] = params
	}
	if err := pluginapi.WriteJSON(s.conn, payload); err != nil {
		t.Fatalf("发送 %s 失败: %v", method, err)
	}
	raw, err := pluginapi.ReadFrame(s.conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读 %s 响应失败: %v", method, err)
	}
	envelope, err := pluginapi.DecodeFrame(raw)
	if err != nil {
		t.Fatalf("解码 %s 响应失败: %v", method, err)
	}
	response, ok := envelope.(*pluginapi.Response)
	if !ok {
		t.Fatalf("%s 响应帧类型=%T", method, envelope)
	}
	return response
}

// TestLiveReloadWithoutRootChannel 真实验证 systemd-resolved 引擎下的 reload 降级：
// 没有 KORE_KERNEL_SOCK（模拟直接运行 / 非 kore 启动）⇒ E_NEED_ROOT + hint，
// 带 zone ⇒ E_INVALID（该引擎无区域），两次失败后插件仍可 ping。
func TestLiveReloadWithoutRootChannel(t *testing.T) {
	// 显式清空通道三要素：即使父进程环境里有，也按「无提权通道」路径测。
	s := openSessionEnv(t, "KORE_KERNEL_SOCK=", "KORE_PLUGIN_TOKEN=", "KORE_PLUGIN_ID=")
	defer s.close(t)

	var status statusBody
	if err := json.Unmarshal(s.call(t, "dns.status", nil), &status); err != nil {
		t.Fatalf("解析 status 失败: %v", err)
	}
	if !status.Available || status.Engine != "systemd-resolved" {
		t.Skipf("本机主引擎不是 systemd-resolved（available=%v engine=%q），降级用例跳过", status.Available, status.Engine)
	}
	t.Logf("真实执行用户 uid=%d（0 表示 root；本机通常为非 root）", os.Geteuid())

	response := s.callRaw(t, "dns.reload", nil)
	if response.Error == nil {
		t.Fatalf("无提权通道时 reload 不得成功（会误报已刷新），实际 result=%s", response.Result)
	}
	if response.Error.Code != "E_NEED_ROOT" {
		t.Fatalf("code=%q，期望 E_NEED_ROOT；message=%q", response.Error.Code, response.Error.Message)
	}
	var detail map[string]string
	if err := json.Unmarshal(response.Error.Detail, &detail); err != nil {
		t.Fatalf("detail 不是对象: %v（%s）", err, response.Error.Detail)
	}
	hint := detail["hint"]
	if !strings.Contains(hint, "sudo") {
		t.Fatalf("hint 未给出 sudo 路径: %q", hint)
	}
	if !strings.Contains(hint, "提权通道") {
		t.Fatalf("hint 未说明提权通道: %q", hint)
	}

	zoned := s.callRaw(t, "dns.reload", map[string]any{"zone": "example.com"})
	if zoned.Error == nil || zoned.Error.Code != "E_INVALID" {
		t.Fatalf("systemd-resolved 带 zone 应 E_INVALID，实际: %+v", zoned.Error)
	}

	// 降级后仍存活（不得 panic / 退出）。
	ping := s.call(t, "kore.ping", nil)
	if len(ping) == 0 {
		t.Fatal("reload 降级后 kore.ping 无结果")
	}
}
