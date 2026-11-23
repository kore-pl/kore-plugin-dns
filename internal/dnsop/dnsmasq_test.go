package dnsop

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseSS 解析 ss 输出：%iface scope 去掉、属主进程提取、同地址 tcp/udp 各保留一条。
func TestParseSS(t *testing.T) {
	out := `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
udp   UNCONN 0      0      192.168.122.1:53     0.0.0.0:*    users:(("dnsmasq",pid=2214,fd=5))
udp   UNCONN 0      0         127.0.0.54:53     0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.53%lo:53     0.0.0.0:*
tcp   LISTEN 0      4096      127.0.0.54:53     0.0.0.0:*
tcp   LISTEN 0      4096      127.0.0.1:8080    0.0.0.0:*
`
	items := parseSS(out, 53)
	if len(items) != 4 {
		t.Fatalf("套接字数量=%d，期望 4（8080 应被过滤，tcp/udp 各算一条）：%+v", len(items), items)
	}
	seen := make(map[string]Listening, len(items))
	for _, item := range items {
		seen[item.Proto+"|"+item.Addr] = item
	}
	if dnsmasq, ok := seen["udp|192.168.122.1"]; !ok || dnsmasq.Process != "dnsmasq" {
		t.Fatalf("dnsmasq 套接字解析错误：%+v", items)
	}
	if _, ok := seen["tcp|127.0.0.53"]; !ok {
		t.Fatalf("%%lo scope 未剥离：%+v", items)
	}
	if _, ok := seen["udp|127.0.0.54"]; !ok {
		t.Fatalf("无属主进程的套接字应保留：%+v", items)
	}
}

// TestParseProcNet 用真实 /proc/net 形态的样例行验证解析（tcp 只要 LISTEN、udp 只要 07）。
func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   7: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27727 1
  56: 017AA8C0:0035 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 27729 1
`
	items := parseProcNet(tcp, "tcp", true, 53)
	if len(items) != 1 {
		t.Fatalf("tcp 结果=%d，期望 1（非 LISTEN 应剔除）：%+v", len(items), items)
	}
	if items[0].Addr != "127.0.0.53" || items[0].Port != 53 || items[0].Proto != "tcp" {
		t.Fatalf("tcp 解析错误：%+v", items[0])
	}

	udp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 8623: 017AA8C0:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 13981 2
 8624: 0100007F:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 13982 2
`
	items = parseProcNet(udp, "udp", false, 53)
	if len(items) != 1 || items[0].Addr != "192.168.122.1" {
		t.Fatalf("udp 解析错误：%+v", items)
	}
}

// TestDecodeProcNetAddr IPv4/IPv6 地址列解码（小端分组）。
func TestDecodeProcNetAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"3500007F", "127.0.0.53", true},
		{"017AA8C0", "192.168.122.1", true},
		{"00000000000000000000000001000000", "::1", true},
		{"ZZ", "", false},
	}
	for _, tc := range cases {
		got, ok := decodeProcNetAddr(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("解码 %q 得 (%q,%v)，期望 (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestSplitAddrPort 各种地址写法。
func TestSplitAddrPort(t *testing.T) {
	cases := []struct {
		in   string
		addr string
		port int
		ok   bool
	}{
		{"127.0.0.53%lo:53", "127.0.0.53", 53, true},
		{"[::]:53", "::", 53, true},
		{"*:53", "0.0.0.0", 53, true},
		{"127.0.0.1:8080", "127.0.0.1", 8080, true},
		{"bad", "", 0, false},
	}
	for _, tc := range cases {
		addr, port, ok := splitAddrPort(tc.in)
		if addr != tc.addr || port != tc.port || ok != tc.ok {
			t.Fatalf("拆 %q 得 (%q,%d,%v)，期望 (%q,%d,%v)", tc.in, addr, port, ok, tc.addr, tc.port, tc.ok)
		}
	}
}

// TestParseDnsmasqConf dnsmasq 四类指令解析：address / server（含全局与条件转发）/ local / host-record。
func TestParseDnsmasqConf(t *testing.T) {
	text := `# 注释
server=8.8.8.8
address=/lab.example/192.168.1.10
address=/a.example/b.example/192.168.1.11
server=/corp.example/10.0.0.1
local=/lan/
host-record=www.lab.example,192.168.1.12,2001:db8::12
addn-hosts=/etc/dnsmasq.d/hosts
`
	entries := ParseDnsmasqConf(text)
	want := []dnsmasqEntry{
		{Kind: dnsmasqKindServerGlobal, Addr: "8.8.8.8", Line: 2},
		{Kind: dnsmasqKindAddress, Domains: []string{"lab.example"}, Addr: "192.168.1.10", Line: 3},
		{Kind: dnsmasqKindAddress, Domains: []string{"a.example", "b.example"}, Addr: "192.168.1.11", Line: 4},
		{Kind: dnsmasqKindServer, Domains: []string{"corp.example"}, Addr: "10.0.0.1", Line: 5},
		{Kind: dnsmasqKindLocal, Domains: []string{"lan"}, Line: 6},
		{Kind: dnsmasqKindHostRecord, Names: []string{"www.lab.example"}, Addrs: []string{"192.168.1.12", "2001:db8::12"}, Line: 7},
		{Kind: dnsmasqKindAddnHosts, Path: "/etc/dnsmasq.d/hosts", Line: 8},
	}
	if len(entries) != len(want) {
		t.Fatalf("条目数=%d，期望 %d：%+v", len(entries), len(want), entries)
	}
	for index := range want {
		if !reflect.DeepEqual(entries[index], want[index]) {
			t.Fatalf("第 %d 条=%+v，期望 %+v", index, entries[index], want[index])
		}
	}
}

// TestParseDnsmasqConfContinuation 行尾反斜杠续行与注释剥离。
func TestParseDnsmasqConfContinuation(t *testing.T) {
	text := "address=/x.example/1.2.3.4 \\\n  # 注释\nserver=/y.example/5.6.7.8\n"
	entries := ParseDnsmasqConf(text)
	// 第一行因续行反斜杠把下一行（纯注释）并进同一条逻辑行；第二行是独立的 server。
	if len(entries) != 2 || entries[0].Kind != dnsmasqKindAddress || entries[1].Kind != dnsmasqKindServer {
		t.Fatalf("续行/注释解析异常：%+v", entries)
	}
}

// TestParseHostsFile hosts 格式解析：IPv4→A、IPv6→AAAA、注释与非法行跳过。
func TestParseHostsFile(t *testing.T) {
	text := `# 注释
127.0.0.1 localhost.localdomain localhost
::1 ip6-localhost
not-an-ip bad.example
192.168.1.5 host.lab.example # 行尾注释
`
	records := ParseHostsFile(text)
	if len(records) != 4 {
		t.Fatalf("记录数=%d，期望 4：%+v", len(records), records)
	}
	if records[0].Type != "A" || records[0].Value != "127.0.0.1" {
		t.Fatalf("IPv4 记录错误：%+v", records[0])
	}
	if records[2].Type != "AAAA" || records[2].Value != "::1" {
		t.Fatalf("IPv6 记录错误：%+v", records[2])
	}
	if records[3].Name != "host.lab.example" || records[3].Value != "192.168.1.5" {
		t.Fatalf("行尾注释未剥离：%+v", records[3])
	}
}

// TestWithinReadRoots 路径白名单：只放通四个根，前缀不能靠字符串包含绕过。
func TestWithinReadRoots(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/bind/named.conf.local", true},
		{"/etc/bind", true},
		{"/var/lib/bind/db.example", true},
		{"/etc/dnsmasq.d/libvirt-daemon", true},
		{"/etc/dnsmasq.conf", true},
		{"/etc/bind-evil/x", false},
		{"/etc/passwd", false},
		{"/var/lib/bindX/x", false},
		{"relative/path", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := WithinReadRoots(tc.path); got != tc.want {
			t.Fatalf("WithinReadRoots(%q)=%v，期望 %v", tc.path, got, tc.want)
		}
	}
}

// TestValidateReadPath 配置路径校验：相对路径、.. 逃逸、越界都拒绝；合法路径 Clean 后返回。
func TestValidateReadPath(t *testing.T) {
	if _, perr := ValidateReadPath("bind_conf", "/etc/passwd"); perr == nil {
		t.Fatal("越界路径应被拒绝")
	}
	if _, perr := ValidateReadPath("bind_conf", "etc/bind/x"); perr == nil {
		t.Fatal("相对路径应被拒绝")
	}
	if _, perr := ValidateReadPath("bind_conf", "/etc/bind/../passwd"); perr == nil {
		t.Fatal(".. 逃逸应被拒绝")
	}
	got, perr := ValidateReadPath("bind_conf", "/etc/bind//named.conf.local")
	if perr != nil {
		t.Fatalf("合法路径被拒: %v", perr)
	}
	if got != "/etc/bind/named.conf.local" {
		t.Fatalf("Clean 后路径=%q", got)
	}
}

// TestValidateQueryName 查询名校验：大写归一、允许尾点、拒绝空格/空标签/超长。
func TestValidateQueryName(t *testing.T) {
	ok, perr := ValidateQueryName("Example.COM.")
	if perr != nil || ok != "example.com" {
		t.Fatalf("合法名归一失败: %q %v", ok, perr)
	}
	for _, bad := range []string{"", " ", "a..b", "a b.com", "-bad.com", strings.Repeat("a", 300) + ".com"} {
		if _, perr := ValidateQueryName(bad); perr == nil {
			t.Fatalf("非法名 %q 应被拒绝", bad)
		}
	}
}
