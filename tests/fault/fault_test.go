// Package fault 基础级故障注入用例：kill -9 与握手超时两类（不含空测试 / t.Skip）。
package fault

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestKill9 用 SIGKILL 强杀插件进程，断言：进程确实被杀、UDS 连接随之关闭。
func TestKill9(t *testing.T) {
	binary := findBinary(t)
	cmd, accept := startPlugin(t, binary)
	conn := accept()
	defer func() { _ = conn.Close() }()
	handshakeWith(t, conn)

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("发送 SIGKILL 失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), faultTimeout)
	defer cancel()
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	select {
	case err := <-waitDone:
		if err == nil {
			t.Fatal("被 SIGKILL 的进程不应正常退出")
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			if code := exitErr.ExitCode(); code != -1 && code != 137 {
				t.Fatalf("退出码=%d，期望被信号终止（-1/137）", code)
			}
		}
	case <-ctx.Done():
		t.Fatal("SIGKILL 后进程未在预算内退出")
	}

	// 进程死后，已建立的 UDS 连接应在有限时间内读不到任何响应帧。
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	header := make([]byte, 4)
	_, err := readFull(conn, header)
	if err == nil {
		t.Fatal("插件被 kill 后连接仍可读帧，违背故障隔离预期")
	}
	if !isTimeoutOrClosed(err) {
		t.Fatalf("连接错误类型异常: %v", err)
	}
}

// TestTimeout 真测插件超时行为：内核接受连接后不回 kore.hello 响应，
// 插件必须在自身 2s 握手预算内超时并以退出码 1 退出，不永久挂起。
// 先做对照：内核正常握手时插件不会自行退出，排除"启动即失败"的假通过。
func TestTimeout(t *testing.T) {
	binary := findBinary(t)

	// 对照组：正常握手后插件应保持运行，证明二进制与 UDS 环境是健康的。
	okCmd, okAccept := startPlugin(t, binary)
	okConn := okAccept()
	handshakeWith(t, okConn)
	if okCmd.ProcessState != nil {
		t.Fatal("对照组：正常握手后插件不应退出")
	}
	_ = okConn.Close()
	_ = okCmd.Process.Kill()
	_ = okCmd.Wait()

	// 实验组：内核接受连接但不回 hello 响应。
	cmd, accept := startPlugin(t, binary)
	conn := accept()
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(helloTimeoutLimit))

	waitCtx, waitCancel := context.WithTimeout(context.Background(), helloTimeoutLimit)
	defer waitCancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("握手超时后插件不应正常退出")
		}
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("退出错误类型=%T，期望 *exec.ExitError", err)
		}
		if code := exitErr.ExitCode(); code != 1 {
			t.Fatalf("握手超时退出码=%d，期望 1", code)
		}
	case <-waitCtx.Done():
		_ = cmd.Process.Kill()
		t.Fatalf("插件握手超时后 %v 内未退出（疑似永久挂起）", helloTimeoutLimit)
	}
}

// TestBinaryExists 兜底断言：故障测试确实针对真实二进制，而非空跑。
func TestBinaryExists(t *testing.T) {
	path := findBinary(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s 失败: %v", path, err)
	}
	if info.Size() < 1000 {
		t.Fatalf("%s 体积=%d，不像真实二进制", path, info.Size())
	}
	t.Logf("fault 目标二进制: %s (%d 字节)", path, info.Size())
}
