// Package fault 的方法级故障注入用例：补齐 dns 业务方法中除 record.add 之外的写通道
// （record.update / record.delete / addRecord / updateRecord / deleteRecord）与只读方法
// （zones / records / reload / config.get）在宿主依赖缺失时的行为。
//
// 断言只取外部可观察量：协议错误码、错误 detail.hint 文本、插件状态目录字节指纹、失败后插件是否仍服务。
// 判据集中三条：① 失败必须显式（机器可读错误码 + 可操作 hint），绝不静默返回空列表 / 空成功；
// ② 失败发生在任何写动作之前（不产生 journal、状态目录零变化）；③ 失败不影响后续调用。
// 本文件只新增用例，不改动任何既有断言。
package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 缺失的宿主配置路径：都落在插件只读白名单内，且本文件不创建它们（因此与宿主实际安装无关）。
const (
	// missingBindConf 是 bind9 区域声明文件；它不存在 ⇒ 宿主没有任何 bind9 区域。
	missingBindConf = "/etc/bind/kore-fault-missing.conf"
	// missingDnsmasqConf 是 dnsmasq 主配置；多数主机不存在，存在也不影响本文件断言。
	missingDnsmasqConf = "/etc/dnsmasq.conf"
	// faultZone / faultName 是假区域与假记录名，不会与真实宿主声明重合。
	faultZone = "fault.example"
	faultName = "www.fault.example"
)

// startWithState 用统一的降级环境拉起真实插件：临时状态目录 + 缺失的 bind/dnsmasq 配置，并完成握手。
// extraEnv 中的同名变量覆盖前面的值（os/exec 对重复键取最后一条）。
func startWithState(t *testing.T, binary string, extraEnv ...string) (*exec.Cmd, net.Conn, string) {
	t.Helper()
	stateDir := t.TempDir()
	env := append([]string{
		"KORE_STATE_DIR=" + stateDir,
		"KORE_DNS_BIND_CONF=" + missingBindConf,
		"KORE_DNS_DNSMASQ_CONF=" + missingDnsmasqConf,
	}, extraEnv...)
	cmd, accept := startPluginEnv(t, binary, env...)
	conn := accept()
	t.Cleanup(func() { _ = conn.Close() })
	handshakeWith(t, conn)
	return cmd, conn, stateDir
}

// snapshotState 记录状态目录的字节指纹（相对路径 → 模式|大小|sha256）；用于断言失败路径零落盘。
func snapshotState(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		digest := "-"
		if !entry.IsDir() {
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			sum := sha256.Sum256(body)
			digest = hex.EncodeToString(sum[:])
		}
		snapshot[rel] = info.Mode().String() + "|" + strconv.FormatInt(info.Size(), 10) + "|" + digest
		return nil
	})
	if err != nil {
		t.Fatalf("快照状态目录 %s 失败: %v", root, err)
	}
	return snapshot
}

// assertStateUnchanged 断言状态目录前后完全一致：既不能改写已有条目，也不能新增任何条目
// （journal / 配置 / dnsmasq 片段都算落盘，失败路径一律不允许）。
func assertStateUnchanged(t *testing.T, root string, before map[string]string, label string) {
	t.Helper()
	after := snapshotState(t, root)
	for path, want := range before {
		got, ok := after[path]
		if !ok {
			t.Fatalf("%s：状态目录条目被删除 %s", label, path)
		}
		if got != want {
			t.Fatalf("%s：状态目录条目被改写 %s（%s → %s）", label, path, want, got)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Fatalf("%s：失败路径在状态目录新增条目 %s", label, path)
		}
	}
}

// errorDetail 解出错误体的 detail 对象（本插件用它承载 hint / command 等可操作信息）。
func errorDetail(t *testing.T, response pluginResponse) map[string]string {
	t.Helper()
	if response.Error == nil {
		t.Fatal("期望错误响应，实际成功")
	}
	detail := make(map[string]string)
	if len(response.Error.Detail) == 0 {
		return detail
	}
	if err := json.Unmarshal(response.Error.Detail, &detail); err != nil {
		t.Fatalf("detail 不是扁平字符串对象: %v（原文 %s）", err, response.Error.Detail)
	}
	return detail
}

// requireFailure 断言响应是失败，且没有回半截结果体（失败不得带 applied=true 之类的假成功）。
func requireFailure(t *testing.T, response pluginResponse, method string) {
	t.Helper()
	if response.Error == nil {
		t.Fatalf("%s 应当失败，实际成功: result=%s", method, response.Result)
	}
	if len(response.Result) != 0 {
		t.Fatalf("%s 失败却回了结果体: %s", method, response.Result)
	}
}

// requireCode 断言错误码并返回 detail。
func requireCode(t *testing.T, response pluginResponse, method, want string) map[string]string {
	t.Helper()
	requireFailure(t, response, method)
	if response.Error.Code != want {
		t.Fatalf("%s 错误码=%q，期望 %q（message=%q）", method, response.Error.Code, want, response.Error.Message)
	}
	return errorDetail(t, response)
}

// requireHintContains 断言 detail.hint 非空且包含全部片段，返回 hint 原文。
func requireHintContains(t *testing.T, detail map[string]string, fragments ...string) string {
	t.Helper()
	hint := detail["hint"]
	if hint == "" {
		t.Fatalf("降级必须带可操作 hint: detail=%v", detail)
	}
	for _, fragment := range fragments {
		if !strings.Contains(hint, fragment) {
			t.Fatalf("hint 未包含 %q: %q", fragment, hint)
		}
	}
	return hint
}

// requireJournalAbsent 断言写通道没有落任何审计记录：写动作必须在 journal 之前就被拒绝。
func requireJournalAbsent(t *testing.T, stateDir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(stateDir, "dns-journal")); !os.IsNotExist(err) {
		t.Fatalf("写失败却创建了 journal 目录（err=%v）", err)
	}
}

// requireAlive 断言失败后插件进程仍在服务（写失败不是致命错误）。
func requireAlive(t *testing.T, cmd *exec.Cmd, conn net.Conn, id string) {
	t.Helper()
	if cmd.ProcessState != nil {
		t.Fatalf("失败后插件进程已退出: %v", cmd.ProcessState)
	}
	ping := call(t, conn, id, "kore.ping", nil)
	if ping.Error != nil || len(ping.Result) == 0 {
		t.Fatalf("失败后插件不再响应 kore.ping: error=%v", ping.Error)
	}
}

// TestZonesWithoutEngineFailsExplicitly 断言 dns.zones 在 bind 不可用时不返回「看起来正常」的空列表：
// 契约是用 result.error_code + hint 显式降级，因此三件事必须同时成立——
// ① 真的尝试扫描过配置里的 bind_conf（scanned 包含该路径，排除短路返回空）；
// ② 空列表时 error_code=E_NO_ENGINE 且 hint 说明是哪个引擎不可用；
// ③ zones 是 [] 而不是 null，插件随后仍能服务。
//
// 环境同时清空 PATH 并显式指定 bind9：两条「不可用」理由都成立，结论不依赖宿主是否装了 DNS 服务。
func TestZonesWithoutEngineFailsExplicitly(t *testing.T) {
	binary := findBinary(t)
	cmd, conn, _ := startWithState(t, binary, "PATH=/nonexistent", "KORE_DNS_ENGINE=bind9")

	response := call(t, conn, "zb-1", "dns.zones", nil)
	if response.Error != nil {
		t.Fatalf("dns.zones 约定用 result.error_code 表达降级，不应返回协议级错误: %v", response.Error)
	}
	var body struct {
		Engine    string          `json:"engine"`
		Zones     json.RawMessage `json:"zones"`
		Count     int             `json:"count"`
		Scanned   []string        `json:"scanned"`
		Warnings  []string        `json:"warnings"`
		Hint      string          `json:"hint"`
		ErrorCode string          `json:"error_code"`
	}
	if err := json.Unmarshal(response.Result, &body); err != nil {
		t.Fatalf("解析 dns.zones 失败: %v（原文 %s）", err, response.Result)
	}
	if string(body.Zones) == "null" || len(body.Zones) == 0 {
		t.Fatalf("zones 必须是数组（空也应是 []）: %s", response.Result)
	}
	if body.Engine != "bind9" {
		t.Fatalf("engine=%q，期望回显显式指定的 bind9", body.Engine)
	}
	scannedBind := false
	for _, path := range body.Scanned {
		if path == missingBindConf {
			scannedBind = true
		}
	}
	if !scannedBind {
		t.Fatalf("scanned 未包含 bind_conf %s（疑似短路返回空列表）: %v", missingBindConf, body.Scanned)
	}

	var entries []struct {
		Name   string `json:"name"`
		Engine string `json:"engine"`
	}
	if err := json.Unmarshal(body.Zones, &entries); err != nil {
		t.Fatalf("解析 zones 条目失败: %v", err)
	}
	if body.Count != len(entries) {
		t.Fatalf("count=%d 与实际条目数 %d 不一致", body.Count, len(entries))
	}
	if body.Count == 0 {
		// 核心断言：空列表必须带机器可读状态码 + 可操作 hint，否则就是「让用户以为没有 zone」的静默降级。
		if body.ErrorCode != "E_NO_ENGINE" {
			t.Fatalf("空区域列表的 error_code=%q，期望 E_NO_ENGINE（hint=%q）", body.ErrorCode, body.Hint)
		}
		if !strings.Contains(body.Hint, "指定的 DNS 引擎 bind9 未检测到") {
			t.Fatalf("hint 未说明是哪个引擎不可用: %q", body.Hint)
		}
	} else {
		// 宿主确实声明了区域（例如 /etc/dnsmasq.d 里有 address=）：有数据时不允许再给 error_code。
		if body.ErrorCode != "" {
			t.Fatalf("count=%d 却给了 error_code=%q（有数据不能装错误）", body.Count, body.ErrorCode)
		}
		for _, entry := range entries {
			if entry.Name == "" || entry.Engine == "" {
				t.Fatalf("区域条目字段残缺: %+v", entry)
			}
		}
	}
	if body.Hint == "" {
		t.Fatalf("zones 结果必须带 hint（无论有无区域）: %s", response.Result)
	}

	// 失败后其它调用仍可用：状态探测与 ping 都要正常。
	status := call(t, conn, "zb-2", "dns.status", nil)
	if status.Error != nil {
		t.Fatalf("zones 降级后 dns.status 不可用: %v", status.Error)
	}
	requireAlive(t, cmd, conn, "zb-3")
}

// TestRecordsUnknownZoneFailsExplicitly 断言 dns.records 对未声明区域返回结构化错误，
// 而不是空记录列表（空列表会被界面渲染成「该区域没有记录」）。断言：E_NOTFOUND + message 指明未知区域
// + detail.hint 非空，且重复调用行为稳定、失败不落盘、插件继续服务。
func TestRecordsUnknownZoneFailsExplicitly(t *testing.T) {
	binary := findBinary(t)
	cmd, conn, stateDir := startWithState(t, binary, "KORE_DNS_ENGINE=bind9")
	before := snapshotState(t, stateDir)

	first := call(t, conn, "rc-1", "dns.records", map[string]any{"zone": faultZone})
	detail := requireCode(t, first, "dns.records", "E_NOTFOUND")
	if !strings.Contains(first.Error.Message, "未知区域") {
		t.Fatalf("message 未指明区域未知: %q", first.Error.Message)
	}
	requireHintContains(t, detail)

	// 同一请求再来一次：失败必须稳定（不是首次偶发），且第二次仍然不落盘。
	second := call(t, conn, "rc-2", "dns.records", map[string]any{"zone": faultZone})
	secondDetail := requireCode(t, second, "dns.records", "E_NOTFOUND")
	secondHint := requireHintContains(t, secondDetail)
	if secondHint != detail["hint"] {
		t.Fatalf("同一缺失区域两次 hint 不一致：%q vs %q", detail["hint"], secondHint)
	}

	assertStateUnchanged(t, stateDir, before, "dns.records")
	requireAlive(t, cmd, conn, "rc-3")
}

// TestRecordUpdateDeleteFailClosedWithoutBindZone 把 TestWriteWithoutBindZone 的手法复用到
// record.update / record.delete：无 bind9 区域声明时必须 E_NOTFOUND（不是 500，也不是 applied=true），
// hint 指向配置里的区域声明文件，并且整个失败路径在 journal 之前就终止——状态目录字节零变化。
func TestRecordUpdateDeleteFailClosedWithoutBindZone(t *testing.T) {
	binary := findBinary(t)
	cmd, conn, stateDir := startWithState(t, binary, "KORE_DNS_ENGINE=bind9")
	before := snapshotState(t, stateDir)

	cases := []struct {
		method string
		params map[string]any
	}{
		{"dns.record.update", map[string]any{
			"zone": faultZone, "name": faultName, "type": "A", "value": "10.0.0.9",
		}},
		{"dns.record.delete", map[string]any{
			"zone": faultZone, "name": faultName, "type": "A",
		}},
	}
	for index, item := range cases {
		response := call(t, conn, fmt.Sprintf("wu-%d", index), item.method, item.params)
		detail := requireCode(t, response, item.method, "E_NOTFOUND")
		requireHintContains(t, detail, missingBindConf)
	}

	requireJournalAbsent(t, stateDir)
	assertStateUnchanged(t, stateDir, before, "record.update/record.delete")

	// 失败后只读方法仍可用（写通道坏掉不该连累读取）。
	zones := call(t, conn, "wu-read", "dns.zones", nil)
	if zones.Error != nil {
		t.Fatalf("写失败后 dns.zones 不可用: %v", zones.Error)
	}
	requireAlive(t, cmd, conn, "wu-ping")
}

// TestLegacyWriteAliasesMirrorRecordMethods 断言三个兼容别名（addRecord / updateRecord / deleteRecord）
// 与对应 record.* 在写入语义上一致：同一失败场景下错误码相同、可操作 hint 逐字相同，
// 且都不产生 journal、都不改状态目录。别名不许有自己的一套语义。
func TestLegacyWriteAliasesMirrorRecordMethods(t *testing.T) {
	binary := findBinary(t)
	cmd, conn, stateDir := startWithState(t, binary, "KORE_DNS_ENGINE=bind9")
	before := snapshotState(t, stateDir)

	pairs := []struct {
		legacy    string
		canonical string
		params    map[string]any
	}{
		{"dns.addRecord", "dns.record.add", map[string]any{
			"zone": faultZone, "name": faultName, "type": "A", "value": "10.0.0.9",
		}},
		{"dns.updateRecord", "dns.record.update", map[string]any{
			"zone": faultZone, "name": faultName, "type": "A", "value": "10.0.0.9",
		}},
		{"dns.deleteRecord", "dns.record.delete", map[string]any{
			"zone": faultZone, "name": faultName, "type": "A",
		}},
	}
	for index, pair := range pairs {
		legacy := call(t, conn, fmt.Sprintf("al-%d", index), pair.legacy, pair.params)
		legacyDetail := requireCode(t, legacy, pair.legacy, "E_NOTFOUND")
		legacyHint := requireHintContains(t, legacyDetail, missingBindConf)

		canonical := call(t, conn, fmt.Sprintf("ac-%d", index), pair.canonical, pair.params)
		canonicalDetail := requireCode(t, canonical, pair.canonical, "E_NOTFOUND")
		canonicalHint := requireHintContains(t, canonicalDetail, missingBindConf)

		if legacyHint != canonicalHint {
			t.Fatalf("%s 与 %s 的 hint 不一致（别名语义分叉）：%q vs %q",
				pair.legacy, pair.canonical, legacyHint, canonicalHint)
		}
	}

	requireJournalAbsent(t, stateDir)
	assertStateUnchanged(t, stateDir, before, "三个兼容写别名")
	requireAlive(t, cmd, conn, "al-ping")
}

// TestLegacyWriteAliasFailsClosedWithoutEngine 断言别名在「本机根本没有 DNS 引擎」时同样显式失败：
// 别名先解析引擎再进写通道，因此报错层级比 record.* 更靠前（E_NO_ENGINE 而不是 E_NOTFOUND）——
// 这不是语义分叉，两条路径都在任何写动作之前 fail-closed；本用例把当前优先级固定下来：
// ① 别名给 E_NO_ENGINE + 指向装 BIND9/dnsmasq 的 hint；② record.* 在同一环境给 E_NOTFOUND；
// ③ 两者都不落盘、插件都继续服务。若将来把别名并入 record.*，本断言应随之更新。
func TestLegacyWriteAliasFailsClosedWithoutEngine(t *testing.T) {
	binary := findBinary(t)
	cmd, conn, stateDir := startWithState(t, binary, "PATH=/nonexistent")
	before := snapshotState(t, stateDir)

	params := map[string]any{"zone": faultZone, "name": faultName, "type": "A", "value": "10.0.0.9"}
	legacy := call(t, conn, "ne-1", "dns.addRecord", params)
	legacyDetail := requireCode(t, legacy, "dns.addRecord", "E_NO_ENGINE")
	requireHintContains(t, legacyDetail, "BIND9")

	canonical := call(t, conn, "ne-2", "dns.record.add", params)
	requireCode(t, canonical, "dns.record.add", "E_NOTFOUND")

	requireJournalAbsent(t, stateDir)
	assertStateUnchanged(t, stateDir, before, "无引擎时的写别名")
	requireAlive(t, cmd, conn, "ne-ping")
}

// TestReloadDegradesExplicitly 覆盖 dns.reload 的两条降级路径：
// ① bind9 但没有可用的 rndc（PATH 清空）⇒ E_NEED_ROOT + 指向 rndc/root 的 hint，不能假装 reloaded=true；
// ② dnsmasq ⇒ 返回 reload_required=true 且 command 为空，插件绝不启停宿主服务（零侵入）。
// 两条都断言状态目录零变化。
func TestReloadDegradesExplicitly(t *testing.T) {
	t.Run("bind9 缺 rndc 时显式要求 root", func(t *testing.T) {
		binary := findBinary(t)
		_, conn, stateDir := startWithState(t, binary, "KORE_DNS_ENGINE=bind9", "PATH=/nonexistent")
		before := snapshotState(t, stateDir)

		response := call(t, conn, "rl-1", "dns.reload", nil)
		detail := requireCode(t, response, "dns.reload", "E_NEED_ROOT")
		if !strings.Contains(response.Error.Message, "rndc") {
			t.Fatalf("message 未说明是 rndc 失败: %q", response.Error.Message)
		}
		requireHintContains(t, detail, "rndc", "root")

		assertStateUnchanged(t, stateDir, before, "dns.reload(bind9)")
	})

	t.Run("dnsmasq 只报告需要重启", func(t *testing.T) {
		binary := findBinary(t)
		cmd, conn, stateDir := startWithState(t, binary, "KORE_DNS_ENGINE=dnsmasq")
		before := snapshotState(t, stateDir)

		response := call(t, conn, "rl-2", "dns.reload", nil)
		if response.Error != nil {
			t.Fatalf("dnsmasq 的 reload 应返回「需要重启」而不是错误: %v", response.Error)
		}
		var body struct {
			Engine         string `json:"engine"`
			Reloaded       bool   `json:"reloaded"`
			ReloadRequired bool   `json:"reload_required"`
			Command        string `json:"command"`
			Hint           string `json:"hint"`
		}
		if err := json.Unmarshal(response.Result, &body); err != nil {
			t.Fatalf("解析 dns.reload 失败: %v（原文 %s）", err, response.Result)
		}
		if body.Engine != "dnsmasq" {
			t.Fatalf("engine=%q，期望 dnsmasq", body.Engine)
		}
		if body.Reloaded {
			t.Fatalf("插件没有重载 dnsmasq，reloaded 不能是 true: %s", response.Result)
		}
		if !body.ReloadRequired {
			t.Fatalf("dnsmasq 必须报告 reload_required=true: %s", response.Result)
		}
		if body.Command != "" {
			t.Fatalf("插件不应执行任何宿主命令，command 必须为空: %q", body.Command)
		}
		if !strings.Contains(body.Hint, "systemctl restart dnsmasq") {
			t.Fatalf("hint 未给出人工重启命令: %q", body.Hint)
		}

		assertStateUnchanged(t, stateDir, before, "dns.reload(dnsmasq)")
		requireAlive(t, cmd, conn, "rl-3")
	})
}

// TestConfigGetWithoutEngineTools 覆盖 config.get：宿主命令全不可用时它仍要能返回完整表单
// （读取只依赖配置与内嵌 schema，不依赖 ss/dig/systemctl）。断言 schema 字段数、必填标记、
// 引擎选项与当前值来源，并验证它是纯读——两次调用字节一致、状态目录零变化。
func TestConfigGetWithoutEngineTools(t *testing.T) {
	binary := findBinary(t)
	cmd, conn, stateDir := startWithState(t, binary, "PATH=/nonexistent")

	response := call(t, conn, "cg-1", "dns.config.get", nil)
	if response.Error != nil {
		t.Fatalf("config.get 不应依赖宿主命令，实际失败: %v", response.Error)
	}
	var body struct {
		Schema struct {
			Title  string `json:"title"`
			Fields []struct {
				Key      string   `json:"key"`
				Type     string   `json:"type"`
				Required bool     `json:"required"`
				Help     string   `json:"help"`
				Options  []string `json:"options"`
			} `json:"fields"`
		} `json:"schema"`
		Values struct {
			Engine   string `json:"engine"`
			BindConf string `json:"bind_conf"`
		} `json:"values"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(response.Result, &body); err != nil {
		t.Fatalf("解析 config.get 失败: %v（原文 %s）", err, response.Result)
	}
	if body.Schema.Title == "" || len(body.Schema.Fields) != 10 {
		t.Fatalf("schema 不完整：title=%q fields=%d", body.Schema.Title, len(body.Schema.Fields))
	}
	var engineOptions int
	for _, field := range body.Schema.Fields {
		if field.Key == "" || field.Type == "" || field.Help == "" {
			t.Fatalf("字段缺少 key/type/help（小白看不懂的表单）: %+v", field)
		}
		if field.Key == "engine" {
			engineOptions = len(field.Options)
		}
		if field.Key == "update_key_file" && field.Required {
			t.Fatalf("update_key_file 是可选字段（留空表示不启用写入），required 不能是 true")
		}
	}
	if engineOptions != 5 {
		t.Fatalf("engine 选项=%d，期望 auto + 四个引擎共 5 个", engineOptions)
	}
	if body.Source != "env" {
		t.Fatalf("source=%q，期望 env（本轮通过环境变量注入路径）", body.Source)
	}
	if body.Values.Engine != "auto" {
		t.Fatalf("values.engine=%q，期望默认 auto", body.Values.Engine)
	}
	if body.Values.BindConf != missingBindConf {
		t.Fatalf("values.bind_conf=%q，期望回显注入的 %q", body.Values.BindConf, missingBindConf)
	}

	// 纯读：两次调用结果字节一致，且不落任何文件。
	again := call(t, conn, "cg-2", "dns.config.get", nil)
	if again.Error != nil {
		t.Fatalf("第二次 config.get 失败: %v", again.Error)
	}
	if string(again.Result) != string(response.Result) {
		t.Fatalf("config.get 两次结果不一致（疑似读路径有写副作用）：\n%s\n%s", response.Result, again.Result)
	}
	assertStateUnchanged(t, stateDir, snapshotState(t, stateDir), "dns.config.get")
	requireAlive(t, cmd, conn, "cg-3")
}
