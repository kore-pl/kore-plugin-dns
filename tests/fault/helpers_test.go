// Package fault 是 dns 插件的基础级故障注入测试（kill / timeout 两类）。
// 测试直接拉起真实 bin/dns 二进制（黑盒），不 mock、不 t.Skip。
package fault

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// faultTimeout 是单类故障测试的整体超时预算。
const faultTimeout = 10 * time.Second

// helloTimeoutLimit 覆盖插件 2s 握手超时 + 退出余量，用于断言插件不会永久挂起。
const helloTimeoutLimit = 6 * time.Second

// findBinary 从测试目录向上找仓根的 bin/dns；找不到直接失败（不跳过）。
func findBinary(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目录失败: %v", err)
	}
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "bin", "dns")
		if st, statErr := os.Stat(candidate); statErr == nil && !st.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("未找到 bin/dns，请先执行 make build（起点目录 %s）", dir)
	return ""
}

// startPlugin 在临时 UDS 上拉起真实插件进程，返回进程与连接函数。
func startPlugin(t *testing.T, binary string) (*exec.Cmd, func() net.Conn) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "kore.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("监听临时 UDS 失败: %v", err)
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "KORE_PLUGIN_SOCK="+sock, "KORE_LOG_LEVEL=error")
	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		t.Fatalf("启动插件失败: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
		_ = ln.Close()
	})
	accept := func() net.Conn {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			t.Fatalf("接受插件连接失败: %v", acceptErr)
		}
		return conn
	}
	return cmd, accept
}

// writeFrame 写一帧 kore.plugin.v1 消息（4 字节大端长度 + JSON 载荷）。
func writeFrame(t *testing.T, conn net.Conn, v any) {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化帧失败: %v", err)
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := conn.Write(append(header, payload...)); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
}

// readFull 读满 len(buf) 字节。
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// readFramePayload 读一帧完整载荷（不预设帧类型），连接关闭时返回错误。
func readFramePayload(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := readFull(conn, header); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(header))
	if n <= 0 || n > 1<<20 {
		return nil, fmt.Errorf("帧长 %d 超出合理范围", n)
	}
	payload := make([]byte, n)
	if _, err := readFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// handshakeWith 扮演内核侧：读插件主动发来的 kore.hello 请求，回 ok 响应完成握手。
func handshakeWith(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(faultTimeout))
	payload, err := readFramePayload(conn)
	if err != nil {
		t.Fatalf("读 kore.hello 请求失败: %v", err)
	}
	if !strings.Contains(string(payload), `"method":"kore.hello"`) {
		t.Fatalf("首帧不是 kore.hello: %s", payload)
	}
	var request struct {
		ID    string `json:"id"`
		ReqID string `json:"req_id"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatalf("解析 hello 请求失败: %v", err)
	}
	response := map[string]any{
		"type": "response", "id": request.ID, "req_id": request.ReqID,
		"result": map[string]any{"ok": true, "protocol": "kore.plugin.v1"},
	}
	writeFrame(t, conn, response)
	_ = conn.SetDeadline(time.Time{})
}

// isTimeoutOrClosed 判断错误是否为超时或连接关闭（两者都证明插件不再服务）。
func isTimeoutOrClosed(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "closed") ||
		strings.Contains(msg, "broken pipe") || strings.Contains(msg, "reset") ||
		strings.Contains(msg, "eof")
}
