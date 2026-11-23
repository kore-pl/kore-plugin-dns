// Package fault 是 dns 插件的故障注入用例：kill -9 / 握手超时 / 状态目录不可写 /
// 配置文件损坏 / 依赖命令缺失降级。全部针对真实 bin/dns 二进制，不 mock、不 t.Skip。
package fault

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pluginResponse 是插件响应帧里本包关心字段的显式形状。
type pluginResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Detail  json.RawMessage `json:"detail"`
	} `json:"error"`
}

// call 在已握手的连接上发一个请求并读回响应。
func call(t *testing.T, conn net.Conn, id, method string, params any) pluginResponse {
	t.Helper()
	request := map[string]any{"type": "request", "id": id, "req_id": "r-" + id, "method": method}
	if params != nil {
		request["params"] = params
	}
	writeFrame(t, conn, request)
	_ = conn.SetDeadline(time.Now().Add(faultTimeout))
	payload, err := readFramePayload(conn)
	if err != nil {
		t.Fatalf("读 %s 响应失败: %v", method, err)
	}
	var response pluginResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("解析 %s 响应失败: %v（原文 %s）", method, err, payload)
	}
	return response
}

// startPluginEnv 在 startPlugin 基础上追加环境变量（注入只读状态目录、空 PATH 等）。
func startPluginEnv(t *testing.T, binary string, extraEnv ...string) (*exec.Cmd, func() net.Conn) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "kore.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("监听临时 UDS 失败: %v", err)
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "KORE_PLUGIN_SOCK="+sock, "KORE_LOG_LEVEL=error")
	cmd.Env = append(cmd.Env, extraEnv...)
	if err := cmd.Start(); err != nil {
		_ = listener.Close()
		t.Fatalf("启动插件失败: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
		_ = listener.Close()
	})
	accept := func() net.Conn {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			t.Fatalf("接受插件连接失败: %v", acceptErr)
		}
		return conn
	}
	return cmd, accept
}

// TestStateDirUnwritable 第三类：状态目录不可写时 config.set 必须返回结构化错误，
// 且插件继续服务（不能崩溃，也不能静默假装保存成功）。
func TestStateDirUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("当前以 root 运行，chmod 0500 无法阻止 root 写入，跳过该用例")
	}
	binary := findBinary(t)
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatalf("设置只读目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) })

	cmd, accept := startPluginEnv(t, binary, "KORE_STATE_DIR="+stateDir)
	conn := accept()
	defer func() { _ = conn.Close() }()
	handshakeWith(t, conn)

	response := call(t, conn, "id-set", "dns.config.set", map[string]any{
		"values": map[string]any{"engine": "dnsmasq"},
	})
	if response.Error == nil {
		t.Fatal("状态目录不可写时 config.set 必须失败，不能静默成功")
	}
	if response.Error.Code != "E_INTERNAL" {
		t.Fatalf("错误码=%s，期望 E_INTERNAL（不是 E_INVALID）", response.Error.Code)
	}
	if !strings.Contains(response.Error.Message, "保存插件配置失败") {
		t.Fatalf("message 未说明保存失败: %q", response.Error.Message)
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, "config.json")); !os.IsNotExist(statErr) {
		t.Fatalf("保存失败却留下了 config.json: %v", statErr)
	}

	// 插件必须仍然存活并响应 ping（保存失败不是致命错误）。
	ping := call(t, conn, "id-ping", "kore.ping", nil)
	if ping.Error != nil {
		t.Fatalf("config.set 失败后 ping 也失败（插件疑似崩溃）: %v", ping.Error)
	}
	if cmd.ProcessState != nil {
		t.Fatal("保存失败不应让插件进程退出")
	}
}

// TestCorruptConfigFailsFast 第三类补充：配置损坏时插件启动即失败（退出码 1 + stderr 明因），
// 不允许静默回退默认值——否则界面显示的值与实际行为会不一致。
func TestCorruptConfigFailsFast(t *testing.T) {
	binary := findBinary(t)
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("写入损坏配置失败: %v", err)
	}
	sock := filepath.Join(t.TempDir(), "kore.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("监听临时 UDS 失败: %v", err)
	}
	defer func() { _ = listener.Close() }()

	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "KORE_PLUGIN_SOCK="+sock, "KORE_STATE_DIR="+stateDir, "KORE_LOG_LEVEL=error")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动插件失败: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case waitErr := <-done:
		if waitErr == nil {
			t.Fatal("配置损坏时插件不应正常退出（退出码应为 1）")
		}
		exitErr, ok := waitErr.(*exec.ExitError)
		if !ok {
			t.Fatalf("退出错误类型=%T", waitErr)
		}
		if code := exitErr.ExitCode(); code != 1 {
			t.Fatalf("退出码=%d，期望 1", code)
		}
		if !strings.Contains(stderr.String(), "插件配置") {
			t.Fatalf("stderr 未说明配置损坏原因: %q", stderr.String())
		}
	case <-time.After(faultTimeout):
		_ = cmd.Process.Kill()
		t.Fatal("配置损坏时插件未在预算内退出（疑似静默回退或挂起）")
	}
}

// TestDependencyMissingDegrades 第四类：PATH 清空（ss / systemctl / dig / nslookup 全不可用）时，
// 检测显式降级（available=false + E_NO_ENGINE + hint），查询回退 Go 解析器仍能工作。
func TestDependencyMissingDegrades(t *testing.T) {
	binary := findBinary(t)
	cmd, accept := startPluginEnv(t, binary, "PATH=/nonexistent", "KORE_STATE_DIR="+t.TempDir())
	conn := accept()
	defer func() { _ = conn.Close() }()
	handshakeWith(t, conn)

	status := call(t, conn, "id-status", "dns.status", nil)
	if status.Error != nil {
		t.Fatalf("依赖缺失时 dns.status 不应报错（应显式降级）: %v", status.Error)
	}
	var statusBody struct {
		Available bool   `json:"available"`
		ErrorCode string `json:"error_code"`
		Hint      string `json:"hint"`
		Engines   []struct {
			Engine string `json:"engine"`
		} `json:"engines"`
	}
	if err := json.Unmarshal(status.Result, &statusBody); err != nil {
		t.Fatalf("解析 status 失败: %v", err)
	}
	if statusBody.Available {
		t.Fatalf("PATH 为空时不应检测到引擎：%s", status.Result)
	}
	if statusBody.ErrorCode != "E_NO_ENGINE" || statusBody.Hint == "" {
		t.Fatalf("降级不合格：code=%q hint=%q", statusBody.ErrorCode, statusBody.Hint)
	}
	if len(statusBody.Engines) != 4 {
		t.Fatalf("engines=%d，期望仍返回 4 个候选（诚实报告未知）", len(statusBody.Engines))
	}

	// 查询链路：dig/nslookup 不可用 → Go 解析器；localhost 走本机 hosts，不依赖外网。
	query := call(t, conn, "id-query", "dns.query", map[string]any{"name": "localhost", "type": "A"})
	if query.Error != nil {
		t.Fatalf("依赖缺失时 dns.query 应回退 Go 解析器: %v", query.Error)
	}
	var queryBody struct {
		Resolver string `json:"resolver"`
		Rcode    string `json:"rcode"`
		Answers  []struct {
			Value string `json:"value"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(query.Result, &queryBody); err != nil {
		t.Fatalf("解析 query 失败: %v", err)
	}
	if queryBody.Resolver != "go" {
		t.Fatalf("resolver=%q，期望 go（PATH 为空时只能回退标准库）", queryBody.Resolver)
	}
	if queryBody.Rcode != "NOERROR" || len(queryBody.Answers) == 0 {
		t.Fatalf("localhost A 查询应成功：%s", query.Result)
	}

	if cmd.ProcessState != nil {
		t.Fatal("依赖缺失不应让插件退出")
	}
}
