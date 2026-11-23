package dnsop

import (
	"strings"
	"testing"
)

// bindZoneFixture 是一份典型的 BIND zone 文件：含 SOA 多行括号、缩进续行、
// 显式 TTL、相对名、绝对名与引号包裹的 TXT。
const bindZoneFixture = `$TTL 3600
$ORIGIN example.com.
@	IN	SOA	ns1.example.com. root.example.com. (
			2024010101 ; serial
			7200       ; refresh
			3600       ; retry
			1209600    ; expire
			3600 )     ; minimum
	IN	NS	ns1.example.com.
	IN	MX	10 mail.example.com.
	IN	TXT	"v=spf1 -all"
www	600	IN	A	192.0.2.10
v6	IN	AAAA	2001:db8::1
alias	IN	CNAME	www
mail	IN	A	192.0.2.20
`

// TestParseZoneFile 覆盖 A/AAAA/CNAME/MX/TXT/NS 六类记录、owner 继承与 TTL 规则。
func TestParseZoneFile(t *testing.T) {
	parsed := ParseZoneFile(bindZoneFixture, "example.com")
	if parsed.Origin != "example.com" {
		t.Fatalf("origin=%q", parsed.Origin)
	}
	// SOA 不在支持类型内，应被跳过：NS + MX + TXT + A + AAAA + CNAME + A = 7 条。
	if parsed.Total != 7 || len(parsed.Records) != 7 {
		t.Fatalf("记录数=%d/%d，期望 7", parsed.Total, len(parsed.Records))
	}
	index := make(map[string]Record, len(parsed.Records))
	for _, record := range parsed.Records {
		index[record.Name+"|"+record.Type] = record
	}
	cases := []struct {
		key   string
		value string
		ttl   int
	}{
		{"example.com|NS", "ns1.example.com", 3600},
		{"example.com|MX", "10 mail.example.com", 3600},
		{"example.com|TXT", "v=spf1 -all", 3600},
		{"www.example.com|A", "192.0.2.10", 600},
		{"v6.example.com|AAAA", "2001:db8::1", 3600},
		{"alias.example.com|CNAME", "www.example.com", 3600},
		{"mail.example.com|A", "192.0.2.20", 3600},
	}
	for _, tc := range cases {
		record, ok := index[tc.key]
		if !ok {
			t.Fatalf("缺少记录 %s（实际：%v）", tc.key, keysOf(index))
		}
		if record.Value != tc.value {
			t.Fatalf("%s 值=%q，期望 %q", tc.key, record.Value, tc.value)
		}
		if record.TTL != tc.ttl {
			t.Fatalf("%s TTL=%d，期望 %d", tc.key, record.TTL, tc.ttl)
		}
	}
}

// TestParseZoneFileNoOrigin 无 $ORIGIN 时用参数兜底，绝对名不被再拼 origin。
func TestParseZoneFileNoOrigin(t *testing.T) {
	text := "www 300 IN A 192.0.2.1\nabsolute.lab. 300 IN A 192.0.2.2\n@ IN NS ns1.lab.\n"
	parsed := ParseZoneFile(text, "lab.")
	got := make(map[string]string, len(parsed.Records))
	for _, record := range parsed.Records {
		got[record.Name] = record.Value
	}
	if got["www.lab"] != "192.0.2.1" {
		t.Fatalf("相对名未展开: %v", got)
	}
	if got["absolute.lab"] != "192.0.2.2" {
		t.Fatalf("绝对名被重复拼接: %v", got)
	}
	if got["lab"] != "ns1.lab" {
		t.Fatalf("@ 未映射到 origin: %v", got)
	}
}

// TestParseZoneFileComments 注释不污染记录：行尾注释、整行注释与引号内的分号都要正确区分。
func TestParseZoneFileComments(t *testing.T) {
	text := `; 整行注释
www IN A 192.0.2.1 ; 行尾注释
txt IN TXT "a;b"
`
	parsed := ParseZoneFile(text, "example.com")
	if len(parsed.Records) != 2 {
		t.Fatalf("记录数=%d，期望 2：%+v", len(parsed.Records), parsed.Records)
	}
	for _, record := range parsed.Records {
		if strings.Contains(record.Value, "行尾注释") {
			t.Fatalf("注释混入记录值：%+v", record)
		}
	}
	if parsed.Records[1].Value != "a;b" {
		t.Fatalf("引号内分号被误当注释：%q", parsed.Records[1].Value)
	}
}

// TestParseZoneFileUnsupportedOnly 只有 SOA/未知类型时返回空记录且不 panic。
func TestParseZoneFileUnsupportedOnly(t *testing.T) {
	text := "@ IN SOA ns1.example.com. root.example.com. ( 1 2 3 4 5 )\n_sip._tcp IN SRV 0 1 5060 sip.example.com.\n"
	parsed := ParseZoneFile(text, "example.com")
	if len(parsed.Records) != 0 {
		t.Fatalf("不应产出记录：%+v", parsed.Records)
	}
}

// TestParseNamedConf 解析 zone 块的 name/type/file（含注释与引号名）。
func TestParseNamedConf(t *testing.T) {
	text := `// 本地区域
zone "example.com" {
	type master;
	file "/etc/bind/db.example.com";
};

# another
zone "lab.internal" {
    type slave;
    file "db.lab";
    masters { 192.0.2.53; };
};
`
	decls := ParseNamedConf(text)
	if len(decls) != 2 {
		t.Fatalf("zone 数量=%d，期望 2：%+v", len(decls), decls)
	}
	if decls[0].Name != "example.com" || decls[0].Type != "master" || decls[0].File != "/etc/bind/db.example.com" {
		t.Fatalf("第一个 zone 解析错误：%+v", decls[0])
	}
	if decls[1].Name != "lab.internal" || decls[1].Type != "slave" || decls[1].File != "db.lab" {
		t.Fatalf("第二个 zone 解析错误：%+v", decls[1])
	}
}

// TestParseNamedForwarders 解析 forwarders 块里的上游地址（忽略非 IP）。
func TestParseNamedForwarders(t *testing.T) {
	text := `options {
	forwarders { 8.8.8.8; 1.1.1.1; };
	forward only;
};`
	got := ParseNamedForwarders(text)
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "1.1.1.1" {
		t.Fatalf("forwarders=%v", got)
	}
}

// TestParseNamedConfBroken 残缺声明不 panic、不产半条记录。
func TestParseNamedConfBroken(t *testing.T) {
	for _, text := range []string{"", "zone", `zone "x"`, `zone "x" { type`, `zone "x" { }`} {
		decls := ParseNamedConf(text)
		for _, decl := range decls {
			if decl.Name == "" {
				t.Fatalf("残缺输入 %q 产出空名声明", text)
			}
		}
	}
}

// keysOf 返回 map 的键列表（失败信息用）。
func keysOf[T any](values map[string]T) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	return out
}
