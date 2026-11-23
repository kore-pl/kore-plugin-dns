package dnsop

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// zonesHost 构造「bind9 两个区域 + dnsmasq 两个区域」的假宿主。
func zonesHost() *fakeHost {
	host := newFakeHost()
	host.files["/etc/bind/named.conf.local"] = `// 本地
zone "example.com" {
	type master;
	file "/etc/bind/db.example.com";
};
zone "lab.internal" {
	type master;
	file "/var/lib/bind/db.lab";
};
`
	host.files["/etc/bind/db.example.com"] = bindZoneFixture
	host.files["/var/lib/bind/db.lab"] = "www 300 IN A 10.0.0.1\n"
	host.files["/etc/dnsmasq.conf"] = "server=8.8.8.8\naddress=/home.lan/192.168.1.10\n"
	host.dirs["/etc/dnsmasq.d"] = []string{"lab.conf"}
	host.files["/etc/dnsmasq.d/lab.conf"] = `address=/lab.example/192.168.1.11
host-record=www.lab.example,192.168.1.12
addn-hosts=/etc/dnsmasq.d/hosts
`
	host.files["/etc/dnsmasq.d/hosts"] = "192.168.1.13 host.lab.example\n"
	return host
}

// TestZonesAggregated bind9 与 dnsmasq 的区域聚合成统一视图（含记录数与可读性）。
func TestZonesAggregated(t *testing.T) {
	detector := Detector{Host: zonesHost(), Paths: DefaultPaths()}
	result, perr := detector.Zones(context.Background(), EngineAuto)
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	if result.Count != 4 {
		t.Fatalf("区域数=%d，期望 4：%+v", result.Count, result.Zones)
	}
	index := make(map[string]ZoneEntry, len(result.Zones))
	for _, zone := range result.Zones {
		index[zone.Name] = zone
	}
	cases := []struct {
		name    string
		zoneTyp string
		engine  string
		records int
	}{
		{"example.com", "master", EngineBind9, 7},
		{"lab.internal", "master", EngineBind9, 1},
		{"home.lan", "static", EngineDnsmasq, 1},
		{"lab.example", "static", EngineDnsmasq, 3},
	}
	for _, tc := range cases {
		zone, ok := index[tc.name]
		if !ok {
			t.Fatalf("缺少区域 %s：%+v", tc.name, result.Zones)
		}
		if zone.Type != tc.zoneTyp || zone.Engine != tc.engine {
			t.Fatalf("%s 类型/引擎=%s/%s，期望 %s/%s", tc.name, zone.Type, zone.Engine, tc.zoneTyp, tc.engine)
		}
		if !zone.Readable {
			t.Fatalf("%s 应可读", tc.name)
		}
		if zone.RecordsCount != tc.records {
			t.Fatalf("%s 记录数=%d，期望 %d", tc.name, zone.RecordsCount, tc.records)
		}
		if zone.File == "" {
			t.Fatalf("%s 缺 file 字段", tc.name)
		}
	}
	if len(result.Scanned) == 0 {
		t.Fatal("scanned 应为空时也不能是 nil")
	}
}

// TestRecordsBind 读取 bind 区域记录：六类记录齐全、排序稳定、字段完整。
func TestRecordsBind(t *testing.T) {
	detector := Detector{Host: zonesHost(), Paths: DefaultPaths()}
	result, perr := detector.Records(context.Background(), "Example.COM.")
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	if result.Zone != "example.com" || result.Engine != EngineBind9 {
		t.Fatalf("zone/engine=%s/%s", result.Zone, result.Engine)
	}
	if result.Total != 7 || result.Count != 7 || result.Truncated {
		t.Fatalf("count/total/truncated=%d/%d/%v", result.Count, result.Total, result.Truncated)
	}
	types := make(map[string]int, 6)
	for _, record := range result.Records {
		types[record.Type]++
	}
	for _, want := range []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"} {
		if types[want] == 0 {
			t.Fatalf("缺少 %s 记录：%+v", want, result.Records)
		}
	}
}

// TestRecordsDnsmasq 读取 dnsmasq 区域记录（address + host-record + addn-hosts）。
func TestRecordsDnsmasq(t *testing.T) {
	detector := Detector{Host: zonesHost(), Paths: DefaultPaths()}
	result, perr := detector.Records(context.Background(), "lab.example")
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	if result.Engine != EngineDnsmasq || result.Count != 3 {
		t.Fatalf("engine/count=%s/%d：%+v", result.Engine, result.Count, result.Records)
	}
	values := make(map[string]string, len(result.Records))
	for _, record := range result.Records {
		values[record.Name] = record.Value
	}
	if values["lab.example"] != "192.168.1.11" {
		t.Fatalf("address 记录缺失：%v", values)
	}
	if values["www.lab.example"] != "192.168.1.12" {
		t.Fatalf("host-record 记录缺失：%v", values)
	}
	if values["host.lab.example"] != "192.168.1.13" {
		t.Fatalf("addn-hosts 记录缺失：%v", values)
	}
}

// TestRecordsUnknownZone 未知区域返回 E_NOTFOUND + 可用区域提示（不返回空列表）。
func TestRecordsUnknownZone(t *testing.T) {
	detector := Detector{Host: zonesHost(), Paths: DefaultPaths()}
	_, perr := detector.Records(context.Background(), "missing.example")
	if perr == nil || perr.Code != "E_NOTFOUND" {
		t.Fatalf("期望 E_NOTFOUND，实际 %v", perr)
	}
	if !strings.Contains(string(perr.Detail), "available") && !strings.Contains(string(perr.Detail), "可用区域") {
		t.Fatalf("detail 缺少可用区域提示：%s", perr.Detail)
	}
	if !strings.Contains(perr.Message, "missing.example") {
		t.Fatalf("message 未带区域名：%q", perr.Message)
	}
}

// TestRecordsPermission 区域文件不可读：Zones 给 readable=false + warning，Records 给 E_NEED_ROOT。
func TestRecordsPermission(t *testing.T) {
	host := newFakeHost()
	host.files["/etc/bind/named.conf.local"] = `zone "secret.example" { type master; file "/etc/bind/db.secret"; };`
	host.permission["/etc/bind/db.secret"] = true
	detector := Detector{Host: host, Paths: DefaultPaths()}

	zones, perr := detector.Zones(context.Background(), EngineAuto)
	if perr != nil {
		t.Fatalf("Zones 意外错误: %v", perr)
	}
	if zones.Count != 1 || zones.Zones[0].Readable {
		t.Fatalf("不可读区域应 readable=false：%+v", zones.Zones)
	}
	if len(zones.Warnings) == 0 || !strings.Contains(zones.Warnings[0], "root") {
		t.Fatalf("warnings 未说明需要 root：%v", zones.Warnings)
	}

	_, perr = detector.Records(context.Background(), "secret.example")
	if perr == nil || perr.Code != CodeNeedRoot {
		t.Fatalf("期望 E_NEED_ROOT，实际 %v", perr)
	}
	if !strings.Contains(string(perr.Detail), "sudo") {
		t.Fatalf("detail 缺少可操作 hint：%s", perr.Detail)
	}
}

// TestZonesPermissionBlocked 配置本身不可读：返回 E_NEED_ROOT + hint，而不是空列表。
func TestZonesPermissionBlocked(t *testing.T) {
	host := newFakeHost()
	host.permission["/etc/bind/named.conf.local"] = true
	host.permission["/etc/dnsmasq.conf"] = true
	host.permission["/etc/dnsmasq.d"] = true
	detector := Detector{Host: host, Paths: DefaultPaths()}

	result, perr := detector.Zones(context.Background(), EngineAuto)
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	if result.Count != 0 {
		t.Fatalf("应无区域：%+v", result.Zones)
	}
	if result.ErrorCode != CodeNeedRoot || !strings.Contains(result.Hint, "root") {
		t.Fatalf("降级不合格：code=%q hint=%q", result.ErrorCode, result.Hint)
	}
}

// TestRecordsTruncate 超过 500 条时截断并标记 truncated，total 保留真实条数。
func TestRecordsTruncate(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("$TTL 60\n")
	for index := 0; index < MaxRecords+50; index++ {
		fmt.Fprintf(&builder, "h%d IN A 10.0.%d.%d\n", index, index/256, index%256)
	}
	host := newFakeHost()
	host.files["/etc/bind/named.conf.local"] = `zone "many.example" { type master; file "/etc/bind/db.many"; };`
	host.files["/etc/bind/db.many"] = builder.String()
	detector := Detector{Host: host, Paths: DefaultPaths()}

	result, perr := detector.Records(context.Background(), "many.example")
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	if result.Count != MaxRecords || result.Total != MaxRecords+50 || !result.Truncated {
		t.Fatalf("截断不合格：count=%d total=%d truncated=%v", result.Count, result.Total, result.Truncated)
	}
}

// TestZonesNothingInstalled 四种引擎与配置都不存在：hint 说明各引擎的区域来源，而不是报错。
func TestZonesNothingInstalled(t *testing.T) {
	detector := Detector{Host: newFakeHost(), Paths: DefaultPaths()}
	result, perr := detector.Zones(context.Background(), EngineAuto)
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	if result.Count != 0 || result.ErrorCode != CodeNoEngine {
		t.Fatalf("无引擎时应 E_NO_ENGINE：%+v", result)
	}
	if !strings.Contains(result.Hint, "systemd-resolved") || !strings.Contains(result.Hint, "区域") {
		t.Fatalf("hint 未解释区域来源：%q", result.Hint)
	}
}
