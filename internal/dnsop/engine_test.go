package dnsop

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// systemdHost 构造「只有 systemd-resolved 在跑」的假宿主（本机真实形态的最小化）。
func systemdHost() *fakeHost {
	host := newFakeHost()
	host.cmds["systemctl is-active systemd-resolved"] = "active\n"
	host.cmds["resolvectl --version"] = "systemd 259 (259.9-0ubuntu0.1)\n+PAM +AUDIT +SELINUX\n"
	host.cmds["resolvectl status"] = `Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 2 (enp5s0)
    Current Scopes: DNS
Current DNS Server: 2408:8899::8
       DNS Servers: 223.5.5.5 223.6.6.6 2408:8899::8 2408:8888::8
     Default Route: yes
`
	host.files["/etc/resolv.conf"] = "# managed\nnameserver 127.0.0.53\noptions edns0 trust-ad\n"
	host.sockets = []Listening{
		{Addr: "127.0.0.53", Port: 53, Proto: "udp"},
		{Addr: "127.0.0.53", Port: 53, Proto: "tcp"},
	}
	return host
}

// TestStatusSystemdResolved 本机真实形态：systemd-resolved 被识别为主引擎，版本/上游/监听齐全。
func TestStatusSystemdResolved(t *testing.T) {
	detector := Detector{Host: systemdHost(), Paths: DefaultPaths()}
	result := detector.Status(context.Background(), EngineAuto)

	if !result.Available {
		t.Fatalf("应 available=true，实际 %+v", result)
	}
	if result.Engine != EngineSystemdResolved {
		t.Fatalf("主引擎=%q，期望 systemd-resolved", result.Engine)
	}
	if result.Version != "259.9-0ubuntu0.1" {
		t.Fatalf("版本=%q，期望 259.9-0ubuntu0.1", result.Version)
	}
	if len(result.Upstreams) != 4 {
		t.Fatalf("上游=%v，期望 4 个", result.Upstreams)
	}
	if result.Upstreams[0] != "2408:8899::8" || result.Upstreams[1] != "223.5.5.5" {
		t.Fatalf("上游顺序/内容异常: %v", result.Upstreams)
	}
	if len(result.Listening) != 2 {
		t.Fatalf("监听=%v，期望 2 条", result.Listening)
	}
	if len(result.ResolvNameservers) != 1 || result.ResolvNameservers[0] != "127.0.0.53" {
		t.Fatalf("resolv.conf nameserver=%v，期望 [127.0.0.53]", result.ResolvNameservers)
	}
	if result.ErrorCode != "" || result.Hint != "" {
		t.Fatalf("可用时不应有 error_code/hint：%q/%q", result.ErrorCode, result.Hint)
	}
	// 只允许固定 argv：调用必须落在探测用的命令族内，证明没有拼接 shell。
	for _, call := range detector.Host.(*fakeHost).calls {
		name := strings.Fields(call)[0]
		switch name {
		case "systemctl", "resolvectl", "pgrep", "dnsmasq", "named", "coredns":
		default:
			t.Fatalf("出现非预期命令调用: %q", call)
		}
		if strings.ContainsAny(call, "|&;`$><\n") {
			t.Fatalf("argv 含 shell 元字符: %q", call)
		}
	}
}

// TestStatusNoEngine 四种引擎都不在时给 available=false + E_NO_ENGINE + 可操作 hint（禁止空列表冒充）。
func TestStatusNoEngine(t *testing.T) {
	detector := Detector{Host: newFakeHost(), Paths: DefaultPaths()}
	result := detector.Status(context.Background(), EngineAuto)

	if result.Available {
		t.Fatalf("无引擎时不应 available=true：%+v", result)
	}
	if result.ErrorCode != CodeNoEngine {
		t.Fatalf("error_code=%q，期望 %s", result.ErrorCode, CodeNoEngine)
	}
	if !strings.Contains(result.Hint, "未检测到 DNS 服务") || !strings.Contains(result.Hint, "systemctl") {
		t.Fatalf("hint 不可操作: %q", result.Hint)
	}
	if result.Engine != "" {
		t.Fatalf("无引擎时 engine 应为空，实际 %q", result.Engine)
	}
	if len(result.Engines) != 4 {
		t.Fatalf("engines=%d，期望 4 个候选", len(result.Engines))
	}
}

// TestStatusPriority systemd-resolved 与 dnsmasq 同时在跑时按优先级选 systemd-resolved，
// 且 dnsmasq 的监听（地址无法归属）不被误算进主引擎。
func TestStatusPriority(t *testing.T) {
	host := systemdHost()
	host.cmds["pgrep -x dnsmasq"] = "2214\n2215\n"
	host.cmds["dnsmasq --version"] = "Dnsmasq version 2.92  Copyright (c) 2000-2025 Simon Kelley\n"
	host.sockets = append(host.sockets, Listening{Addr: "192.168.122.1", Port: 53, Proto: "udp"})
	detector := Detector{Host: host, Paths: DefaultPaths()}

	result := detector.Status(context.Background(), EngineAuto)
	if result.Engine != EngineSystemdResolved {
		t.Fatalf("主引擎=%q，期望 systemd-resolved（优先级最高）", result.Engine)
	}
	for _, engine := range result.Engines {
		if engine.Engine != EngineDnsmasq {
			continue
		}
		if !engine.Detected || !engine.Running {
			t.Fatalf("dnsmasq 应被检测到并标记 running：%+v", engine)
		}
		if engine.Version != "2.92" {
			t.Fatalf("dnsmasq 版本=%q，期望 2.92", engine.Version)
		}
		if engine.Primary {
			t.Fatal("dnsmasq 不应是主引擎")
		}
	}
}

// TestStatusForcedEngine 指定引擎：存在则用它，不存在则 E_NO_ENGINE + hint。
func TestStatusForcedEngine(t *testing.T) {
	host := systemdHost()
	host.cmds["pgrep -x dnsmasq"] = "2214\n"
	detector := Detector{Host: host, Paths: DefaultPaths()}

	ok := detector.Status(context.Background(), EngineDnsmasq)
	if !ok.Available || ok.Engine != EngineDnsmasq {
		t.Fatalf("强制 dnsmasq 应可用：%+v", ok)
	}

	missing := detector.Status(context.Background(), EngineBind9)
	if missing.Available {
		t.Fatalf("强制 bind9（未检测到）不应可用：%+v", missing)
	}
	if missing.ErrorCode != CodeNoEngine || !strings.Contains(missing.Hint, "bind9") {
		t.Fatalf("强制缺失引擎的降级不合格: code=%q hint=%q", missing.ErrorCode, missing.Hint)
	}
}

// TestStatusInvalidEngine 非法引擎名被拒绝（防拼写错误被静默当成 auto）。
func TestStatusInvalidEngine(t *testing.T) {
	detector := Detector{Host: systemdHost(), Paths: DefaultPaths()}
	result := detector.Status(context.Background(), "powerdns")
	if result.Available || result.ErrorCode != CodeNoEngine {
		t.Fatalf("未知引擎应降级：%+v", result)
	}
}

// TestVersionParsers 四种引擎的版本输出格式各自收敛成裸版本号。
func TestVersionParsers(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) string
		in   string
		want string
	}{
		{"systemd-paren", parseSystemdVersion, "systemd 259 (259.9-0ubuntu0.1)\n+PAM", "259.9-0ubuntu0.1"},
		{"systemd-bare", parseSystemdVersion, "systemd 255", "255"},
		{"dnsmasq", parseDnsmasqVersion, "Dnsmasq version 2.92  Copyright (c) 2000-2025 Simon Kelley", "2.92"},
		{"bind", parseBindVersion, "BIND 9.20.0 (Extended Support Version) <id:abc>", "9.20.0"},
		{"coredns", parseCoreDNSVersion, "CoreDNS-1.11.1 linux/amd64, go1.21.5, 4e7b1f5", "1.11.1"},
		{"unknown-first-line", parseBindVersion, "something odd", "something odd"},
		{"empty", parseDnsmasqVersion, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn(tc.in); got != tc.want {
				t.Fatalf("解析 %q 得 %q，期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestAssignListening 套接字归属：进程名精确匹配 > 127.0.0.5x 启发式 > 单引擎兜底。
func TestAssignListening(t *testing.T) {
	engines := []EngineStatus{
		{Engine: EngineSystemdResolved, Detected: true},
		{Engine: EngineDnsmasq, Detected: true},
		{Engine: EngineBind9, Detected: false},
		{Engine: EngineCoreDNS, Detected: false},
	}
	sockets := []Listening{
		{Addr: "127.0.0.53", Port: 53, Proto: "udp"},
		{Addr: "192.168.122.1", Port: 53, Proto: "udp", Process: "dnsmasq"},
		{Addr: "10.0.0.1", Port: 53, Proto: "tcp"},
	}
	assignListening(engines, sockets)
	if len(engines[0].Listening) != 1 || engines[0].Listening[0].Addr != "127.0.0.53" {
		t.Fatalf("systemd-resolved 监听=%v", engines[0].Listening)
	}
	if len(engines[1].Listening) != 1 || engines[1].Listening[0].Addr != "192.168.122.1" {
		t.Fatalf("dnsmasq 监听=%v", engines[1].Listening)
	}
	if len(engines[2].Listening) != 0 || len(engines[3].Listening) != 0 {
		t.Fatalf("未检测到的引擎不应获得监听：%v / %v", engines[2].Listening, engines[3].Listening)
	}

	// 只有一个引擎在跑时，无法归属的套接字兜底归它。
	single := []EngineStatus{{Engine: EngineCoreDNS, Detected: true}}
	assignListening(single, []Listening{{Addr: "10.0.0.1", Port: 53, Proto: "tcp"}})
	if len(single[0].Listening) != 1 {
		t.Fatalf("单引擎兜底失败：%v", single[0].Listening)
	}
}

// TestParseResolvNameservers 解析 /etc/resolv.conf 的 nameserver 行（去重、忽略注释）。
func TestParseResolvNameservers(t *testing.T) {
	text := "# comment\nnameserver 127.0.0.53\nnameserver 8.8.8.8\nnameserver 8.8.8.8\nsearch .\n"
	got := parseResolvNameservers(text)
	if len(got) != 2 || got[0] != "127.0.0.53" || got[1] != "8.8.8.8" {
		t.Fatalf("nameserver=%v", got)
	}
}

// TestCallUsesDefaultEngine 配置里保存的 engine 必须在方法入参未指定时生效
// （否则 dns.config.set 保存的引擎选择形同虚设）。
func TestCallUsesDefaultEngine(t *testing.T) {
	host := systemdHost()
	host.cmds["pgrep -x dnsmasq"] = "2214\n"
	detector := Detector{Host: host, Paths: DefaultPaths(), DefaultEngine: EngineDnsmasq}
	result, perr := detector.Call(context.Background(), "status", nil, 0)
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	var status StatusResult
	if err := json.Unmarshal(result, &status); err != nil {
		t.Fatalf("解析 status 失败: %v", err)
	}
	if status.Engine != EngineDnsmasq {
		t.Fatalf("engine=%q，期望配置里的 dnsmasq", status.Engine)
	}

	// 入参显式指定时覆盖配置。
	explicit, perr := detector.Call(context.Background(), "status", json.RawMessage(`{"engine":"systemd-resolved"}`), 0)
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	var explicitStatus StatusResult
	if err := json.Unmarshal(explicit, &explicitStatus); err != nil {
		t.Fatalf("解析 status 失败: %v", err)
	}
	if explicitStatus.Engine != EngineSystemdResolved {
		t.Fatalf("显式 engine 未生效：%q", explicitStatus.Engine)
	}
}
