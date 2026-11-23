// Package fault 的写入通道降级用例：宿主没有 bind9 区域声明时，
// record.add 必须给出可操作错误（E_NOTFOUND + hint），不得崩溃、不得产生写入痕迹。
package fault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteWithoutBindZone 在无 bind9 区域的主机上调用 dns.record.add：
// 期望 E_NOTFOUND（不是 500/panic，也不是 applied=true 的假成功），且插件继续服务。
func TestWriteWithoutBindZone(t *testing.T) {
	binary := findBinary(t)
	stateDir := t.TempDir()
	// 显式指向不存在的 bind 配置（白名单内的路径），确保与宿主实际配置无关。
	cmd, accept := startPluginEnv(t, binary,
		"KORE_STATE_DIR="+stateDir,
		"KORE_DNS_BIND_CONF=/etc/bind/kore-fault-missing.conf",
		"KORE_DNS_DNSMASQ_CONF=/etc/dnsmasq.conf",
	)
	conn := accept()
	defer func() { _ = conn.Close() }()
	handshakeWith(t, conn)

	response := call(t, conn, "w-1", "dns.record.add", map[string]any{
		"zone": "fault.example", "name": "www.fault.example", "type": "A", "value": "10.0.0.9",
	})
	if response.Error == nil {
		t.Fatalf("无 bind9 区域时写入不应成功: result=%s", response.Result)
	}
	if response.Error.Code != "E_NOTFOUND" {
		t.Fatalf("错误码=%q，期望 E_NOTFOUND（message=%q）", response.Error.Code, response.Error.Message)
	}
	var detail map[string]string
	if err := json.Unmarshal(response.Error.Detail, &detail); err != nil || detail["hint"] == "" {
		t.Fatalf("降级必须带可操作 hint: err=%v detail=%s", err, response.Error.Detail)
	}
	if !strings.Contains(detail["hint"], "bind_conf") {
		t.Fatalf("hint 应指向 bind_conf 配置: %q", detail["hint"])
	}

	// fail-closed：没有进入写动作，不应产生 journal 目录。
	if _, err := os.Stat(filepath.Join(stateDir, "dns-journal")); !os.IsNotExist(err) {
		t.Fatalf("写入失败不应产生 journal: %v", err)
	}

	// 插件仍然存活：ping 正常应答。
	ping := call(t, conn, "w-2", "kore.ping", nil)
	if ping.Error != nil || len(ping.Result) == 0 {
		t.Fatalf("写失败后插件应继续服务: error=%v", ping.Error)
	}
	_ = cmd.Process.Kill()
}
