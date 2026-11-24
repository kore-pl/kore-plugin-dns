package dnsop

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// fakeRootRunner 记录经内核提权通道执行的 action id 与追加参数。
type fakeRootRunner struct {
	// calls 是每次调用的 (actionID, args) 记录；断言「argv 构造没有混入 engine/zone」。
	calls []rootCall
	// out / err 是预置返回。
	out RootActionOutput
	err error
}

// rootCall 是一条提权通道调用记录。
type rootCall struct {
	ActionID string
	Args     []string
}

// RunRootAction 实现 RootRunner；nil args 也原样记录（断言「没有追加参数」）。
func (f *fakeRootRunner) RunRootAction(_ context.Context, actionID string, args []string) (RootActionOutput, error) {
	f.calls = append(f.calls, rootCall{ActionID: actionID, Args: args})
	return f.out, f.err
}

// resolvedReloadHost 是「只有 systemd-resolved 在跑」的假宿主。
func resolvedReloadHost() *fakeHost {
	host := newFakeHost()
	host.cmds["systemctl is-active systemd-resolved"] = "active\n"
	host.cmds["resolvectl --version"] = "systemd 255 (255.4-1ubuntu8)\n"
	host.cmds["resolvectl status"] = "Global\n"
	return host
}

// TestReloadResolvedUsesRootChannelWithoutArgs 是本轮的核心断言：
// systemd-resolved 的 reload 必须经 root_actions 执行 `resolvectl flush-caches`，
// 且**没有任何追加参数**——engine / zone 都不能出现在 argv 里（0.4.1 把 engine 当 zone
// 传给 rndc 的同类错误不得在新通道复现）。
func TestReloadResolvedUsesRootChannelWithoutArgs(t *testing.T) {
	host := resolvedReloadHost()
	root := &fakeRootRunner{out: RootActionOutput{ExitCode: 0}}
	detector := Detector{Host: host, Root: root}

	raw, perr := detector.Call(context.Background(), "reload", nil, time.Second)
	if perr != nil {
		t.Fatalf("systemd-resolved reload 失败: %+v", perr)
	}
	var result ReloadResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析结果失败: %v（原文 %s）", err, raw)
	}
	if result.Engine != EngineSystemdResolved || !result.Reloaded {
		t.Fatalf("期望 engine=%s reloaded=true: %+v", EngineSystemdResolved, result)
	}
	if result.Command != ResolvedFlushCommand {
		t.Fatalf("command=%q，期望 %q", result.Command, ResolvedFlushCommand)
	}
	if len(root.calls) != 1 {
		t.Fatalf("提权通道调用次数=%d，期望 1 次: %+v", len(root.calls), root.calls)
	}
	call := root.calls[0]
	if call.ActionID != RootActionResolvedFlush {
		t.Fatalf("action_id=%q，期望 %q", call.ActionID, RootActionResolvedFlush)
	}
	if len(call.Args) != 0 {
		t.Fatalf("resolvectl flush-caches 不得带追加参数（engine/zone 混入风险），实际 %q", call.Args)
	}
	// 插件进程不得自己执行 rndc / resolvectl：只有内核在 uid=0 下执行。
	for _, executed := range host.calls {
		if strings.HasPrefix(executed, "rndc") {
			t.Fatalf("systemd-resolved reload 不得调用 rndc: %v", host.calls)
		}
		if strings.HasPrefix(executed, "resolvectl flush-caches") {
			t.Fatalf("插件进程不得自行执行 resolvectl flush-caches（必须走提权通道）: %v", host.calls)
		}
	}
}

// TestReloadResolvedRejectsZoneBeforeExecution 锁定「systemd-resolved 没有区域」：
// 带 zone 的 reload 必须 E_INVALID 且**不触碰**提权通道（拒绝写在执行之前）。
func TestReloadResolvedRejectsZoneBeforeExecution(t *testing.T) {
	host := resolvedReloadHost()
	root := &fakeRootRunner{out: RootActionOutput{ExitCode: 0}}
	detector := Detector{Host: host, Root: root}

	_, perr := detector.Call(context.Background(), "reload", json.RawMessage(`{"zone":"example.com"}`), time.Second)
	if perr == nil {
		t.Fatal("systemd-resolved 带 zone 的 reload 应被拒绝")
	}
	if perr.Code != pluginapi.E_INVALID {
		t.Fatalf("code=%q，期望 E_INVALID", perr.Code)
	}
	if len(root.calls) != 0 {
		t.Fatalf("被拒入参不得触碰提权通道: %+v", root.calls)
	}
}

// TestReloadResolvedMapsKernelNeedRoot 断言内核返回 E_NEED_ROOT 时原样映射，
// 并带可操作 hint（ADR-0018：降级必须显式，禁止静默失败）。
func TestReloadResolvedMapsKernelNeedRoot(t *testing.T) {
	host := resolvedReloadHost()
	root := &fakeRootRunner{err: errors.New("E_NEED_ROOT: 需要 root 权限（请用 sudo 启动 kored）")}
	detector := Detector{Host: host, Root: root}

	_, perr := detector.Call(context.Background(), "reload", nil, time.Second)
	if perr == nil {
		t.Fatal("内核拒绝时应返回错误")
	}
	if perr.Code != CodeNeedRoot {
		t.Fatalf("code=%q，期望 E_NEED_ROOT", perr.Code)
	}
	if !strings.Contains(perr.Message, "E_NEED_ROOT") {
		t.Fatalf("message 未说明需要 root: %q", perr.Message)
	}
	var detail map[string]string
	if err := json.Unmarshal(perr.Detail, &detail); err != nil {
		t.Fatalf("detail 不是对象: %v", err)
	}
	if !strings.Contains(detail["hint"], "sudo") {
		t.Fatalf("hint 未给出可操作路径: %q", detail["hint"])
	}
	if detail["action"] != RootActionResolvedFlush {
		t.Fatalf("detail.action=%q，期望 %q", detail["action"], RootActionResolvedFlush)
	}
}

// TestReloadResolvedWithoutChannelDegrades 覆盖「直接运行插件 / 非 kore 启动」：
// 没有提权通道时 E_NEED_ROOT + hint，且绝不退化为在插件进程里执行 resolvectl。
func TestReloadResolvedWithoutChannelDegrades(t *testing.T) {
	host := resolvedReloadHost()
	detector := Detector{Host: host} // Root 为 nil

	_, perr := detector.Call(context.Background(), "reload", nil, time.Second)
	if perr == nil {
		t.Fatal("无提权通道时应 E_NEED_ROOT")
	}
	if perr.Code != CodeNeedRoot {
		t.Fatalf("code=%q，期望 E_NEED_ROOT", perr.Code)
	}
	var detail map[string]string
	if err := json.Unmarshal(perr.Detail, &detail); err != nil {
		t.Fatalf("detail 不是对象: %v", err)
	}
	if !strings.Contains(detail["hint"], "sudo") || !strings.Contains(detail["hint"], "提权通道") {
		t.Fatalf("hint 未说明通道与 sudo 路径: %q", detail["hint"])
	}
	for _, executed := range host.calls {
		if strings.HasPrefix(executed, "resolvectl flush-caches") {
			t.Fatalf("无通道时不得在插件进程执行 resolvectl: %v", host.calls)
		}
	}
}

// TestReloadResolvedExitCodeFailure 断言内核执行成功但命令退出码非零时归 E_UPSTREAM，
// 保留 exit_code 与 stderr，不伪装成 E_NEED_ROOT。
func TestReloadResolvedExitCodeFailure(t *testing.T) {
	host := resolvedReloadHost()
	root := &fakeRootRunner{out: RootActionOutput{ExitCode: 1, Stderr: "Failed to flush caches: Access denied"}}
	detector := Detector{Host: host, Root: root}

	_, perr := detector.Call(context.Background(), "reload", nil, time.Second)
	if perr == nil {
		t.Fatal("非零退出码应返回错误")
	}
	if perr.Code != pluginapi.E_UPSTREAM {
		t.Fatalf("code=%q，期望 E_UPSTREAM", perr.Code)
	}
	if !strings.Contains(string(perr.Detail), "exit_code") {
		t.Fatalf("detail 未带 exit_code: %s", perr.Detail)
	}
}

// TestResolvedFlushArgvShape 锁定声明 argv 与 ADR-0022 形状表一致：
// argv[0] 必须是系统二进制目录内的绝对路径，且整条 argv 能通过 SDK 的形状校验。
func TestResolvedFlushArgvShape(t *testing.T) {
	if len(ResolvedFlushArgv) != 2 || ResolvedFlushArgv[0] != "/usr/bin/resolvectl" || ResolvedFlushArgv[1] != "flush-caches" {
		t.Fatalf("声明 argv 漂移: %q", ResolvedFlushArgv)
	}
	action := pluginapi.RootAction{
		ID:       RootActionResolvedFlush,
		Argv:     ResolvedFlushArgv,
		TimeoutS: 15,
	}
	if err := pluginapi.ValidateRootAction(action); err != nil {
		t.Fatalf("声明未通过 ADR-0022 形状校验: %v", err)
	}
}
