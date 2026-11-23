package dnsop

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// digAnswerFixture 是 dig `+noall +comments +answer` 的真实输出形态。
const digAnswerFixture = `;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24916
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; ANSWER SECTION:
example.com.		1	IN	A	198.18.3.216

`

// digNxdomainFixture 是 NXDOMAIN 的 dig 输出（无 ANSWER SECTION）。
const digNxdomainFixture = `;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 4501
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0

`

// digHost 构造只有 dig 的假宿主。
func digHost(output string) *fakeHost {
	host := newFakeHost()
	host.binaries["dig"] = true
	host.cmds["dig +time=3 +tries=1 +noall +comments +answer example.com. A"] = output
	host.cmds["dig +time=3 +tries=1 +noall +comments +answer missing.example. A"] = digNxdomainFixture
	return host
}

// TestQueryDig dig 成功路径：固定 argv、rcode、应答值与 TTL 都要正确。
func TestQueryDig(t *testing.T) {
	host := digHost(digAnswerFixture)
	detector := Detector{Host: host, Paths: DefaultPaths()}
	result, perr := detector.Query(context.Background(), "Example.COM", "", 3*time.Second)
	if perr != nil {
		t.Fatalf("意外错误: %v", perr)
	}
	if result.Resolver != "dig" || result.Rcode != "NOERROR" {
		t.Fatalf("resolver/rcode=%s/%s", result.Resolver, result.Rcode)
	}
	if result.Name != "example.com" || result.Type != "A" {
		t.Fatalf("name/type=%s/%s", result.Name, result.Type)
	}
	if len(result.Answers) != 1 {
		t.Fatalf("应答数=%d：%+v", len(result.Answers), result.Answers)
	}
	answer := result.Answers[0]
	if answer.Name != "example.com" || answer.Type != "A" || answer.Value != "198.18.3.216" || answer.TTL != 1 {
		t.Fatalf("应答解析错误：%+v", answer)
	}
	if result.ElapsedMs < 0 {
		t.Fatalf("elapsed_ms 非法：%d", result.ElapsedMs)
	}
	// 断言 argv 是固定形态：名字带尾点（绝对名），类型独立成参。
	if len(host.calls) != 1 || host.calls[0] != "dig +time=3 +tries=1 +noall +comments +answer example.com. A" {
		t.Fatalf("命令 argv 不是预期固定形态：%v", host.calls)
	}
}

// TestQueryNXDomain NXDOMAIN 是合法结果（answers 空数组、rcode 正确），不能当错误。
func TestQueryNXDomain(t *testing.T) {
	detector := Detector{Host: digHost(digAnswerFixture), Paths: DefaultPaths()}
	result, perr := detector.Query(context.Background(), "missing.example", "A", 3*time.Second)
	if perr != nil {
		t.Fatalf("NXDOMAIN 不应是错误: %v", perr)
	}
	if result.Rcode != "NXDOMAIN" {
		t.Fatalf("rcode=%q，期望 NXDOMAIN", result.Rcode)
	}
	if result.Answers == nil || len(result.Answers) != 0 {
		t.Fatalf("answers 应为空数组而非 nil：%+v", result.Answers)
	}
}

// TestQueryFallbackNslookup dig 执行失败时回退 nslookup，并在输出里给出结果。
func TestQueryFallbackNslookup(t *testing.T) {
	host := newFakeHost()
	host.binaries["dig"] = true
	host.binaries["nslookup"] = true
	host.cmdErrs["dig +time=3 +tries=1 +noall +comments +answer example.com. A"] = errors.New("dig 退出码 9")
	host.cmds["nslookup -type=A -timeout=3 example.com."] = `Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	example.com
Address: 93.184.216.34
`
	detector := Detector{Host: host, Paths: DefaultPaths()}
	result, perr := detector.Query(context.Background(), "example.com", "A", 3*time.Second)
	if perr != nil {
		t.Fatalf("回退失败: %v", perr)
	}
	if result.Resolver != "nslookup" || result.Rcode != "NOERROR" {
		t.Fatalf("resolver/rcode=%s/%s", result.Resolver, result.Rcode)
	}
	if len(result.Answers) != 1 || result.Answers[0].Value != "93.184.216.34" {
		t.Fatalf("nslookup 应答解析错误：%+v", result.Answers)
	}
	// 服务器自身的 Address 行（带 #53）不能被当成应答。
	for _, answer := range result.Answers {
		if strings.Contains(answer.Value, "#53") {
			t.Fatalf("把服务器地址当成应答了：%+v", answer)
		}
	}
}

// TestQueryNslookupNXDomain nslookup 的 "** server can't find" 需要判成 NXDOMAIN。
func TestQueryNslookupNXDomain(t *testing.T) {
	result := parseNslookupOutput(`** server can't find missing.example: NXDOMAIN
`, "missing.example", "A")
	if result.Rcode != "NXDOMAIN" || len(result.Answers) != 0 {
		t.Fatalf("rcode/answers=%s/%v", result.Rcode, result.Answers)
	}
}

// TestQueryInvalidParams 非法 name/type 在触达命令前就被拒绝。
func TestQueryInvalidParams(t *testing.T) {
	host := digHost(digAnswerFixture)
	detector := Detector{Host: host, Paths: DefaultPaths()}
	if _, perr := detector.Query(context.Background(), "bad name", "A", time.Second); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("非法 name 期望 E_INVALID，实际 %v", perr)
	}
	if _, perr := detector.Query(context.Background(), "example.com", "HACK", time.Second); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("非法 type 期望 E_INVALID，实际 %v", perr)
	}
	if len(host.calls) != 0 {
		t.Fatalf("校验失败不应执行任何命令：%v", host.calls)
	}
}

// TestQueryAllResolversMissing 三路都不可用时给 E_UPSTREAM + attempts，而不是空结果。
func TestQueryAllResolversMissing(t *testing.T) {
	host := newFakeHost()
	host.binaries["dig"] = true
	host.cmdErrs["dig +time=3 +tries=1 +noall +comments +answer example.com. A"] = errors.New("dig 执行失败")
	detector := Detector{Host: host, Paths: DefaultPaths()}
	// 显式指定 Go 解析器也不可用：用一个必然解析失败的保留域名 + 极短超时。
	_, perr := detector.Query(context.Background(), "invalid.invalid", "A", 200*time.Millisecond)
	if perr == nil {
		t.Skip("本机 Go 解析器把 invalid.invalid 解析成功了，跳过该环境相关用例")
	}
	if perr.Code != CodeUpstream || !strings.Contains(string(perr.Detail), "attempts") {
		t.Fatalf("期望 E_UPSTREAM + attempts，实际 %v / %s", perr, perr.Detail)
	}
}

// TestParseDigAnswers 多答案与 TXT/MX 值归一。
func TestParseDigAnswers(t *testing.T) {
	out := `;; ANSWER SECTION:
example.com.		300	IN	MX	10 mail.example.com.
example.com.		300	IN	TXT	"v=spf1 -all"
`
	answers := parseDigAnswers(out)
	if len(answers) != 2 {
		t.Fatalf("应答数=%d：%+v", len(answers), answers)
	}
	if answers[0].Type != "MX" || answers[0].Value != "10 mail.example.com." {
		t.Fatalf("MX 解析错误：%+v", answers[0])
	}
	if answers[1].Type != "TXT" || answers[1].Value != "v=spf1 -all" {
		t.Fatalf("TXT 解析错误：%+v", answers[1])
	}
}
