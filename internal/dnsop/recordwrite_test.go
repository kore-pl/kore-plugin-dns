package dnsop

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// memJournal 记录写操作审计条目（单测断言用，不落盘）。
type memJournal struct {
	entries []JournalEntry
	err     error
}

// Append 追加一条并返回固定路径。
func (m *memJournal) Append(entry JournalEntry) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	m.entries = append(m.entries, entry)
	return "/tmp/dns-journal/updates.jsonl", nil
}

const (
	testBindConf = "/etc/bind/named.conf.local"
	testZoneFile = "/var/lib/bind/example.com.zone"
	testKeyFile  = "/etc/bind/kore-update.key"
)

// newWriteDetector 构造带 bind9 区域、TSIG 密钥与写入通道的检测器。
func newWriteDetector(t *testing.T) (*Detector, *fakeHost, *memJournal) {
	t.Helper()
	host := newFakeHost()
	host.binaries["nsupdate"] = true
	host.binaries["dig"] = true
	host.files[testBindConf] = `zone "example.com" { type master; file "` + testZoneFile + `"; };`
	host.files[testZoneFile] = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns.example.com. admin.example.com. 1 3600 600 86400 300\nwww IN A 10.0.0.1\n"
	host.files[testKeyFile] = "key \"kore-update\" {\n  algorithm hmac-sha256;\n  secret \"c2VjcmV0\";\n};\n"
	journal := &memJournal{}
	return &Detector{
		Host:  host,
		Paths: Paths{BindConf: testBindConf, BindZoneDir: "/var/lib/bind", DnsmasqConf: "/etc/dnsmasq.conf", DnsmasqDir: "/etc/dnsmasq.d", ResolvConf: "/etc/resolv.conf"},
		Write: WriteOptions{Server: "127.0.0.1", Port: 53, KeyFile: testKeyFile, Timeout: 2 * time.Second, Journal: journal},
	}, host, journal
}

// digArgsKey 拼出 queryDirect 的固定 argv 键。
func digArgsKey(name, recordType string) string {
	return cmdKey("dig", []string{
		"+time=2", "+tries=1", "+noall", "+comments", "+answer",
		"-p", "53", "@127.0.0.1", name + ".", recordType,
	})
}

// digAnswer 生成 dig 应答（空应答只带头部 status）。
func digAnswer(recordType, value string) string {
	head := ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
	if value == "" {
		return head
	}
	return head + ";; ANSWER SECTION:\n" + fmt.Sprintf("%s. 300 IN %s %s\n", "www.example.com", recordType, value)
}

// nsupdateKey 是固定 argv 键。
func nsupdateKey() string {
	return cmdKey("nsupdate", []string{"-k", testKeyFile, "-p", "53"})
}

// mustWrite 调用写方法并要求成功。
func mustWrite(t *testing.T, detector *Detector, method string, params string) RecordWriteResult {
	t.Helper()
	result, perr := callWrite(t, detector, method, params)
	if perr != nil {
		t.Fatalf("%s 失败: %s/%s detail=%s", method, perr.Code, perr.Message, perr.Detail)
	}
	return result
}

// callWrite 调用写方法并返回结果与错误。
func callWrite(t *testing.T, detector *Detector, method, params string) (RecordWriteResult, *pluginapi.Error) {
	t.Helper()
	ctx := context.Background()
	switch method {
	case "add":
		return detector.RecordAdd(ctx, json.RawMessage(params))
	case "update":
		return detector.RecordUpdate(ctx, json.RawMessage(params))
	case "delete":
		return detector.RecordDelete(ctx, json.RawMessage(params))
	}
	t.Fatalf("未知方法 %s", method)
	return RecordWriteResult{}, nil
}

// TestRecordAddWritesAndVerifies 覆盖真实写入主链路：快照 → 原子 UPDATE → 直连校验 → 审计。
func TestRecordAddWritesAndVerifies(t *testing.T) {
	detector, host, journal := newWriteDetector(t)
	key := digArgsKey("www.example.com", "A")
	host.cmdSeq[key] = []string{digAnswer("A", ""), digAnswer("A", "10.0.0.9")}
	host.inputOutputs[nsupdateKey()] = ""

	result := mustWrite(t, detector, "add", `{"zone":"example.com","name":"www.example.com","type":"A","value":"10.0.0.9"}`)
	if !result.Changed || !result.Applied || !result.Verified || result.RolledBack {
		t.Fatalf("写入结果不合格: %+v", result)
	}
	if result.Channel != WriteChannel || result.VerifiedBy != "dig-direct" || result.ReloadRequired {
		t.Fatalf("通道/校验字段不合格: %+v", result)
	}
	if len(host.inputs) != 1 {
		t.Fatalf("应只跑一次 nsupdate，实际 %d 次", len(host.inputs))
	}
	script := host.inputs[0].stdin
	for _, want := range []string{
		"server 127.0.0.1\n", "zone example.com\n", "prereq nxrrset www.example.com. A\n",
		"update add www.example.com. 300 A 10.0.0.9\n", "send\n",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("更新脚本缺少 %q：\n%s", want, script)
		}
	}
	if len(journal.entries) != 2 || journal.entries[0].Phase != "intent" || journal.entries[1].Result != "applied" {
		t.Fatalf("审计条目不合格: %+v", journal.entries)
	}
	if result.Journal == "" {
		t.Fatal("成功写入应返回 journal 路径")
	}
}

// TestRecordAddConflictAndIdempotent 覆盖「已存在不同值 = 冲突」与「同值 = 幂等空操作」。
func TestRecordAddConflictAndIdempotent(t *testing.T) {
	detector, host, _ := newWriteDetector(t)
	key := digArgsKey("www.example.com", "A")
	host.cmdSeq[key] = []string{digAnswer("A", "10.0.0.1"), digAnswer("A", "10.0.0.1"), digAnswer("A", "10.0.0.1")}

	_, perr := callWrite(t, detector, "add", `{"zone":"example.com","name":"www.example.com","type":"A","value":"10.0.0.9"}`)
	if perr == nil || perr.Code != pluginapi.E_CONFLICT {
		t.Fatalf("已存在不同值应 E_CONFLICT，实际 %v", perr)
	}
	if len(host.inputs) != 0 {
		t.Fatal("冲突时不得下发任何更新")
	}

	same := mustWrite(t, detector, "add", `{"zone":"example.com","name":"www.example.com","type":"A","value":"10.0.0.1"}`)
	if same.Changed || !same.Applied || !same.Verified {
		t.Fatalf("同值 add 应为幂等空操作: %+v", same)
	}
	if len(host.inputs) != 0 {
		t.Fatal("幂等空操作不得下发更新")
	}
}

// TestRecordUpdateAndTTLUsesSnapshot 覆盖 update 的 prereq/delete/add 与沿用快照 TTL。
func TestRecordUpdateAndTTLUsesSnapshot(t *testing.T) {
	detector, host, _ := newWriteDetector(t)
	key := digArgsKey("www.example.com", "A")
	host.cmdSeq[key] = []string{digAnswer("A", "10.0.0.1"), digAnswer("A", "10.0.0.2")}
	host.inputOutputs[nsupdateKey()] = ""

	result := mustWrite(t, detector, "update", `{"zone":"example.com","name":"www.example.com","type":"A","value":"10.0.0.2"}`)
	if result.TTL != 300 || result.Previous[0] != "10.0.0.1" {
		t.Fatalf("应沿用快照 TTL/旧值: %+v", result)
	}
	script := host.inputs[0].stdin
	for _, want := range []string{
		"prereq yxrrset www.example.com. A\n",
		"update delete www.example.com. A\n",
		"update add www.example.com. 300 A 10.0.0.2\n",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("update 脚本缺少 %q：\n%s", want, script)
		}
	}
}

// TestRecordUpdateMissing 记录不存在时 update 回 E_NOTFOUND 且不下发。
func TestRecordUpdateMissing(t *testing.T) {
	detector, host, _ := newWriteDetector(t)
	host.cmds[digArgsKey("www.example.com", "A")] = digAnswer("A", "")
	_, perr := callWrite(t, detector, "update", `{"zone":"example.com","name":"www.example.com","type":"A","value":"10.0.0.2"}`)
	if perr == nil || perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("不存在应 E_NOTFOUND，实际 %v", perr)
	}
	if len(host.inputs) != 0 {
		t.Fatal("不存在时不得下发")
	}
}

// TestRecordDeleteAndIdempotent 覆盖 delete 的生效校验与幂等。
func TestRecordDeleteAndIdempotent(t *testing.T) {
	detector, host, _ := newWriteDetector(t)
	key := digArgsKey("www.example.com", "A")
	host.cmdSeq[key] = []string{digAnswer("A", "10.0.0.1"), digAnswer("A", ""), digAnswer("A", "")}
	host.inputOutputs[nsupdateKey()] = ""

	result := mustWrite(t, detector, "delete", `{"zone":"example.com","name":"www.example.com","type":"A"}`)
	if !result.Changed || !result.Applied || !result.Verified {
		t.Fatalf("delete 结果不合格: %+v", result)
	}
	script := host.inputs[0].stdin
	if !strings.Contains(script, "prereq yxrrset www.example.com. A\n") ||
		!strings.Contains(script, "update delete www.example.com. A\n") {
		t.Fatalf("delete 脚本不合格：\n%s", script)
	}

	again := mustWrite(t, detector, "delete", `{"zone":"example.com","name":"www.example.com","type":"A"}`)
	if again.Changed || !again.Applied {
		t.Fatalf("已不存在时 delete 应为幂等空操作: %+v", again)
	}
}

// TestRecordWriteRollbackOnVerifyFailure 更新未生效时必须尝试逆操作并在错误里如实上报。
func TestRecordWriteRollbackOnVerifyFailure(t *testing.T) {
	detector, host, journal := newWriteDetector(t)
	key := digArgsKey("www.example.com", "A")
	// 快照有旧值 → 校验仍是旧值（新值没生效）→ 回滚后校验拿回旧值。
	host.cmdSeq[key] = []string{digAnswer("A", "10.0.0.1"), digAnswer("A", "10.0.0.1"), digAnswer("A", "10.0.0.1")}
	host.inputSeq[nsupdateKey()] = []string{"", ""}

	_, perr := callWrite(t, detector, "update", `{"zone":"example.com","name":"www.example.com","type":"A","value":"10.0.0.2"}`)
	if perr == nil || perr.Code != pluginapi.E_UPSTREAM {
		t.Fatalf("生效校验失败应 E_UPSTREAM，实际 %v", perr)
	}
	if len(host.inputs) != 2 {
		t.Fatalf("应下发更新 + 一次回滚，实际 %d 次", len(host.inputs))
	}
	if !strings.Contains(host.inputs[1].stdin, "update add www.example.com. 300 A 10.0.0.1") {
		t.Fatalf("回滚脚本应恢复旧值：\n%s", host.inputs[1].stdin)
	}
	if !strings.Contains(string(perr.Detail), `"rolled_back":"true"`) {
		t.Fatalf("错误 detail 应披露 rolled_back=true：%s", perr.Detail)
	}
	if len(journal.entries) != 2 || journal.entries[1].Result != "verify_failed" {
		t.Fatalf("失败也要留审计: %+v", journal.entries)
	}
}

// TestRecordWriteValidation 覆盖类型/名字/值/脚本注入面的拒绝口径。
func TestRecordWriteValidation(t *testing.T) {
	detector, host, _ := newWriteDetector(t)
	cases := []struct {
		name   string
		params string
		code   string
	}{
		{"名字不在 zone 内", `{"zone":"example.com","name":"www.other.org","type":"A","value":"10.0.0.9"}`, pluginapi.E_INVALID},
		{"类型不可写", `{"zone":"example.com","name":"www.example.com","type":"SOA","value":"10.0.0.9"}`, pluginapi.E_INVALID},
		{"A 值非法", `{"zone":"example.com","name":"www.example.com","type":"A","value":"not-an-ip"}`, pluginapi.E_INVALID},
		{"值里注入换行", "{\"zone\":\"example.com\",\"name\":\"www.example.com\",\"type\":\"TXT\",\"value\":\"a\\nb\"}", pluginapi.E_INVALID},
		{"值里注入分号", `{"zone":"example.com","name":"www.example.com","type":"CNAME","value":"target;rm"}`, pluginapi.E_INVALID},
		{"TXT 超长", `{"zone":"example.com","name":"www.example.com","type":"TXT","value":"` + strings.Repeat("a", 256) + `"}`, pluginapi.E_INVALID},
		{"TTL 越界", `{"zone":"example.com","name":"www.example.com","type":"A","value":"10.0.0.9","ttl":999999}`, pluginapi.E_INVALID},
		{"MX 形状非法", `{"zone":"example.com","name":"www.example.com","type":"MX","value":"mail.example.com"}`, pluginapi.E_INVALID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, perr := callWrite(t, detector, "add", tc.params)
			if perr == nil || perr.Code != tc.code {
				t.Fatalf("期望 %s，实际 %v", tc.code, perr)
			}
			if len(host.inputs) != 0 {
				t.Fatal("参数非法时不得下发任何更新")
			}
		})
	}
}

// TestRecordWriteTXT 覆盖 TXT 的引号渲染与直连校验。
func TestRecordWriteTXT(t *testing.T) {
	detector, host, _ := newWriteDetector(t)
	key := digArgsKey("_acme.example.com", "TXT")
	host.cmdSeq[key] = []string{digAnswer("TXT", ""), ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; ANSWER SECTION:\n_acme.example.com. 300 IN TXT \"hello world\"\n"}
	host.inputOutputs[nsupdateKey()] = ""

	result := mustWrite(t, detector, "add",
		`{"zone":"example.com","name":"_acme.example.com","type":"TXT","value":"hello world"}`)
	if !result.Applied || !result.Verified {
		t.Fatalf("TXT 写入应生效: %+v", result)
	}
	if !strings.Contains(host.inputs[0].stdin, `update add _acme.example.com. 300 TXT "hello world"`) {
		t.Fatalf("TXT 应带引号渲染：\n%s", host.inputs[0].stdin)
	}
}

// TestRecordWriteChannelGuards 覆盖写通道的 fail-closed 分支（未配密钥/缺命令/无 journal）。
func TestRecordWriteChannelGuards(t *testing.T) {
	params := `{"zone":"example.com","name":"www.example.com","type":"A","value":"10.0.0.9"}`
	t.Run("未装配 journal", func(t *testing.T) {
		detector, _, _ := newWriteDetector(t)
		detector.Write.Journal = nil
		_, perr := callWrite(t, detector, "add", params)
		if perr == nil || perr.Code != pluginapi.E_UNSUPPORTED {
			t.Fatalf("期望 E_UNSUPPORTED，实际 %v", perr)
		}
	})
	t.Run("未配置 TSIG 密钥", func(t *testing.T) {
		detector, _, _ := newWriteDetector(t)
		detector.Write.KeyFile = ""
		_, perr := callWrite(t, detector, "add", params)
		if perr == nil || perr.Code != pluginapi.E_UNSUPPORTED {
			t.Fatalf("期望 E_UNSUPPORTED，实际 %v", perr)
		}
	})
	t.Run("密钥不可读", func(t *testing.T) {
		detector, host, _ := newWriteDetector(t)
		delete(host.files, testKeyFile)
		_, perr := callWrite(t, detector, "add", params)
		if perr == nil || perr.Code != pluginapi.E_INVALID {
			t.Fatalf("期望 E_INVALID，实际 %v", perr)
		}
	})
	t.Run("缺 nsupdate", func(t *testing.T) {
		detector, host, _ := newWriteDetector(t)
		host.binaries["nsupdate"] = false
		_, perr := callWrite(t, detector, "add", params)
		if perr == nil || perr.Code != pluginapi.E_UPSTREAM {
			t.Fatalf("期望 E_UPSTREAM，实际 %v", perr)
		}
	})
	t.Run("缺 dig", func(t *testing.T) {
		detector, host, _ := newWriteDetector(t)
		host.binaries["dig"] = false
		_, perr := callWrite(t, detector, "add", params)
		if perr == nil || perr.Code != pluginapi.E_UPSTREAM {
			t.Fatalf("期望 E_UPSTREAM，实际 %v", perr)
		}
	})
}

// TestRecordWriteZoneGuards 覆盖区域归属判定：未知区域 E_NOTFOUND、dnsmasq 区域 E_UNSUPPORTED。
func TestRecordWriteZoneGuards(t *testing.T) {
	t.Run("未知区域", func(t *testing.T) {
		detector, _, _ := newWriteDetector(t)
		_, perr := callWrite(t, detector, "add", `{"zone":"unknown.org","name":"www.unknown.org","type":"A","value":"10.0.0.9"}`)
		if perr == nil || perr.Code != pluginapi.E_NOTFOUND {
			t.Fatalf("期望 E_NOTFOUND，实际 %v", perr)
		}
	})
	t.Run("dnsmasq 区域不可写", func(t *testing.T) {
		detector, host, _ := newWriteDetector(t)
		host.files["/etc/dnsmasq.conf"] = "address=/dnsmasq.example/10.0.0.1\n"
		_, perr := callWrite(t, detector, "add", `{"zone":"dnsmasq.example","name":"www.dnsmasq.example","type":"A","value":"10.0.0.9"}`)
		if perr == nil || perr.Code != pluginapi.E_UNSUPPORTED {
			t.Fatalf("期望 E_UNSUPPORTED，实际 %v", perr)
		}
	})
}

// TestFileJournalAppend 落盘 journal：JSONL、0600、路径可回读。
func TestFileJournalAppend(t *testing.T) {
	dir := t.TempDir()
	journal := FileJournal{Dir: dir}
	path, err := journal.Append(JournalEntry{Phase: "intent", Operation: "add", Zone: "example.com", Name: "www.example.com", Type: "A", Value: "10.0.0.9", Server: "127.0.0.1", Port: 53})
	if err != nil {
		t.Fatalf("追加 journal 失败: %v", err)
	}
	if _, err := journal.Append(JournalEntry{Phase: "result", Operation: "add", Result: "applied", Server: "127.0.0.1", Port: 53}); err != nil {
		t.Fatalf("追加第二条失败: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal 权限=%o，期望 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 journal: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("journal 行数=%d，期望 2", len(lines))
	}
	var entry JournalEntry
	if err := json.Unmarshal([]byte(lines[1]), &entry); err != nil {
		t.Fatalf("journal 不是合法 JSON: %v", err)
	}
	if entry.Phase != "result" || entry.Result != "applied" || entry.TS == "" {
		t.Fatalf("journal 条目不合格: %+v", entry)
	}
	if !strings.HasSuffix(path, "updates.jsonl") {
		t.Fatalf("journal 路径=%q", path)
	}
}
