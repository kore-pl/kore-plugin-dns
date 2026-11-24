package dnsop

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// detailHint 把 detail JSON 里的 hint 取出来（走 JSON 解码，避免被转义符干扰断言）。
func detailHint(t *testing.T, detail json.RawMessage) string {
	t.Helper()
	var payload map[string]string
	if err := json.Unmarshal(detail, &payload); err != nil {
		t.Fatalf("detail 不是 JSON 对象: %v (%s)", err, detail)
	}
	return payload["hint"]
}

// zoneGuideMarkers 是「四段可复制命令」的判据标记。
// 少任何一段，用户复制后都不能把 zone 建起来（正则无关，按命令原文匹配）。
var zoneGuideMarkers = []struct {
	label string
	text  string
}{
	{"zone 声明块", `zone "`},
	{"动态更新授权", `allow-update { key "kore-update"; };`},
	{"语法校验", "named-checkzone "},
	{"重新读取配置", "sudo rndc reconfig"},
	{"验证查询", "dig @127.0.0.1 "},
	{"四段编号", "# 1) 声明 zone"},
}

// guideComplete 判定一段文案是否含全部四段命令；测试用它做正反例自证。
func guideComplete(text string) bool {
	for _, marker := range zoneGuideMarkers {
		if !strings.Contains(text, marker.text) {
			return false
		}
	}
	return true
}

// bind9TestHost 构造一个「装了 bind9、但 named.conf 里还没有 zone」的假宿主。
func bind9TestHost() *fakeHost {
	host := newFakeHost()
	host.binaries["named"] = true
	host.cmds["named -v"] = "BIND 9.20.1\n"
	host.files["/etc/bind/named.conf.local"] = "// 还没有声明任何 zone\n"
	return host
}

// TestZoneGuideCounterExamples 是断言的**反例自证**：
// 旧文案（只有一句「不存在」）必须被判为不完整；四段命令任意一段被删也必须被判为不完整。
// 这样「断言通过」不是靠正则宽松，而是靠判据真的能区分「一句话」与「可执行的完整命令块」。
func TestZoneGuideCounterExamples(t *testing.T) {
	guide := zoneSetupGuide("missing.example", "/etc/bind/named.conf.local")
	if !guideComplete(guide) {
		t.Fatalf("正例不合格：生成的引导缺段\n%s", guide)
	}

	oldCopy := "未知区域：missing.example（可选区域为空）"
	if guideComplete(oldCopy) {
		t.Fatal("反例失效：只有一句「不存在」的旧文案竟被判为含四段命令")
	}

	for _, marker := range zoneGuideMarkers {
		broken := strings.ReplaceAll(guide, marker.text, "")
		if guideComplete(broken) {
			t.Fatalf("反例失效：删掉「%s」后仍被判为完整", marker.label)
		}
	}
}

// TestZoneSetupGuideIsCopyable 断言命令块里域名/路径已按本次查询填好，且不含内部术语。
func TestZoneSetupGuideIsCopyable(t *testing.T) {
	guide := zoneSetupGuide("Lab.Example.", "/etc/bind/named.conf.local")
	for _, want := range []string{
		`zone "lab.example" {`,
		`file "/var/lib/bind/lab.example.zone";`,
		"sudo named-checkzone lab.example /var/lib/bind/lab.example.zone",
		"dig @127.0.0.1 lab.example SOA +short",
		"ns.lab.example.",
		"请换成你实际使用的名字",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("引导缺少 %q：\n%s", want, guide)
		}
	}
	for _, jargon := range []string{"root_actions", "形状表", "ADR", "capability", "提权通道", "bind_conf", "生命周期", "实例"} {
		if strings.Contains(guide, jargon) {
			t.Fatalf("引导含内部术语 %q：\n%s", jargon, guide)
		}
	}
}

// TestRecordsUnknownZonePrintsCopyableGuide 未知 zone 不能只回一句「不存在」。
func TestRecordsUnknownZonePrintsCopyableGuide(t *testing.T) {
	detector := Detector{Host: zonesHost(), Paths: DefaultPaths()}
	_, perr := detector.Records(context.Background(), "missing.example")
	if perr == nil || perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("期望 E_NOTFOUND，实际 %v", perr)
	}
	hint := detailHint(t, perr.Detail)
	if !guideComplete(hint) {
		t.Fatalf("未知区域未输出四段命令：%s", hint)
	}
	if !strings.Contains(hint, `zone "missing.example"`) {
		t.Fatalf("命令块未按本次查询填域名：%s", hint)
	}
	if !strings.Contains(hint, "可用区域") {
		t.Fatalf("原有「可用区域」提示被丢掉：%s", hint)
	}
	if !containsPolite(hint) {
		t.Fatalf("新文案缺「请/应/需/例/如」：%s", hint)
	}
}

// TestZonesEmptyPrintsCopyableGuide 空区域列表要给「怎么建第一个 zone」，而不是一句「没有区域」。
func TestZonesEmptyPrintsCopyableGuide(t *testing.T) {
	detector := Detector{Host: bind9TestHost(), Paths: DefaultPaths()}
	result, perr := detector.Zones(context.Background(), EngineAuto)
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	if result.Count != 0 || result.ErrorCode != "" {
		t.Fatalf("期望「有引擎但无区域」，实际 %+v", result)
	}
	if !guideComplete(result.Hint) {
		t.Fatalf("空列表未输出四段命令：%s", result.Hint)
	}
	if !strings.Contains(result.Hint, `zone "`+zoneGuideExampleZone+`"`) {
		t.Fatalf("空列表应使用示例域名：%s", result.Hint)
	}
	if !containsPolite(result.Hint) {
		t.Fatalf("新文案缺「请/应/需/例/如」：%s", result.Hint)
	}
}

// TestRecordWriteUnknownZonePrintsCopyableGuide 记录写入命中未知 zone 时同样给命令，而不是死路。
func TestRecordWriteUnknownZonePrintsCopyableGuide(t *testing.T) {
	detector, _, _ := newWriteDetector(t)
	_, perr := callWrite(t, detector, "add", `{"zone":"unknown.org","name":"www.unknown.org","type":"A","value":"10.0.0.9"}`)
	if perr == nil || perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("期望 E_NOTFOUND，实际 %v", perr)
	}
	hint := detailHint(t, perr.Detail)
	if !guideComplete(hint) {
		t.Fatalf("写入未知区域未输出四段命令：%s", hint)
	}
	if !strings.Contains(hint, `zone "unknown.org"`) {
		t.Fatalf("命令块未按请求填域名：%s", hint)
	}
}

// TestReloadCopySaysDynamicUpdateNeedsNoReload ① 的断言：成功与失败文案都必须把
// 「记录变更走动态更新、立即生效、不需要 reload」说清，避免用户把改记录当成要重载服务。
func TestReloadCopySaysDynamicUpdateNeedsNoReload(t *testing.T) {
	success := bind9TestHost()
	success.cmds["rndc reload"] = "server reload successful\n"
	result, perr := (Detector{Host: success, Paths: DefaultPaths()}).Reload(context.Background(), "")
	if perr != nil {
		t.Fatalf("bind9 reload 意外失败: %v", perr)
	}
	assertNoReloadNeeded(t, result.Hint)

	failure := bind9TestHost()
	failure.cmdErrs["rndc reload"] = errors.New("connect failed: no rndc.key")
	_, perr = (Detector{Host: failure, Paths: DefaultPaths()}).Reload(context.Background(), "")
	if perr == nil || perr.Code != CodeNeedRoot {
		t.Fatalf("期望 E_NEED_ROOT，实际 %v", perr)
	}
	detail := detailHint(t, perr.Detail)
	assertNoReloadNeeded(t, detail)
	if !strings.Contains(detail, "sudo rndc reload") {
		t.Fatalf("失败 hint 应保留可直接执行的 sudo 命令：%s", detail)
	}
	if !containsPolite(detail) {
		t.Fatalf("新文案缺「请/应/需/例/如」：%s", detail)
	}

	// 反例自证：改成旧的「区域已重新加载」一句话，断言必须不通过。
	if reloadCopyIsClear("区域已重新加载。") {
		t.Fatal("反例失效：旧文案竟被判为已说明「动态更新不需要 reload」")
	}
}

// reloadCopyIsClear 是 ① 的判据：必须同时出现「动态更新」「不需要 reload」与定位说明。
func reloadCopyIsClear(text string) bool {
	return strings.Contains(text, "动态更新") &&
		strings.Contains(text, "不需要 reload") &&
		(strings.Contains(text, "手工改过 zone 文件") || strings.Contains(text, "手工改过"))
}

func assertNoReloadNeeded(t *testing.T, text string) {
	t.Helper()
	if !reloadCopyIsClear(text) {
		t.Fatalf("文案未说明「记录变更不需要 reload」：%s", text)
	}
}

// TestReadDeniedHintOffersTwoAlternatives ③：读不到区域文件时给两条自助替代，而不是只让提权。
func TestReadDeniedHintOffersTwoAlternatives(t *testing.T) {
	host := newFakeHost()
	host.files["/etc/bind/named.conf.local"] = `zone "secret.example" { type master; file "/etc/bind/db.secret"; };`
	host.permission["/etc/bind/db.secret"] = true
	detector := Detector{Host: host, Paths: DefaultPaths()}

	_, perr := detector.Records(context.Background(), "secret.example")
	if perr == nil || perr.Code != CodeNeedRoot {
		t.Fatalf("期望 E_NEED_ROOT，实际 %v", perr)
	}
	detail := detailHint(t, perr.Detail)
	for _, want := range []string{"chmod 0644", "/var/lib/kore/dns", "include", "dns.query"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("降级 hint 缺少 %q：%s", want, detail)
		}
	}
	if !containsPolite(detail) {
		t.Fatalf("新文案缺「请/应/需/例/如」：%s", detail)
	}

	// 反例自证：只给「sudo 启动 kored」的旧 hint 必须被判为没给自助替代。
	if readHintOffersFallback("读取 /etc/bind/db.secret 需要 root 权限：请用 sudo 启动 kored。") {
		t.Fatal("反例失效：旧 hint 竟被判为含两条替代路径")
	}
}

// readHintOffersFallback 是 ③ 的判据：两条替代必须同时出现。
func readHintOffersFallback(text string) bool {
	return strings.Contains(text, "chmod 0644") && strings.Contains(text, "/var/lib/kore/dns")
}

// TestZoneFileUnderKoreDirIsReadable 证明第②条替代不是文案谎言：
// 区域文件放进 /var/lib/kore/dns（新增只读白名单根）后，插件以自身用户就能读到记录。
func TestZoneFileUnderKoreDirIsReadable(t *testing.T) {
	host := newFakeHost()
	host.files["/etc/bind/named.conf.local"] = `zone "kore.example" { type master; file "/var/lib/kore/dns/kore.example.zone"; };`
	host.files["/var/lib/kore/dns/kore.example.zone"] = "$TTL 300\nwww IN A 192.0.2.7\n"
	detector := Detector{Host: host, Paths: DefaultPaths()}

	if !WithinReadRoots("/var/lib/kore/dns/kore.example.zone") {
		t.Fatal("/var/lib/kore 未进入只读白名单：hint 给的替代路径不可用（文案与实现不一致）")
	}
	result, perr := detector.Records(context.Background(), "kore.example")
	if perr != nil {
		t.Fatalf("/var/lib/kore/dns 下的区域应可读，实际 %v", perr)
	}
	if result.Count != 1 || result.Records[0].Value != "192.0.2.7" {
		t.Fatalf("记录读取不对：%+v", result.Records)
	}
}

// containsPolite 是 G-33 A3 的判据：新增文案 ≥8 字且含「请/应/需/例/如」。
func containsPolite(text string) bool {
	if len([]rune(text)) < 8 {
		return false
	}
	for _, p := range []string{"请", "应", "需", "例", "如"} {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}
