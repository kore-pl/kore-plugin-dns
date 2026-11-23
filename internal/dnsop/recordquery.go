package dnsop

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// queryDirect 直接向指定 DNS 服务器查询（`dig @server -p port`），不经系统 resolver。
//
// 写入路径必须用它而不是 d.Query：d.Query 走 /etc/resolv.conf（可能是
// systemd-resolved stub 或本地缓存），既看不到权威结果，也会把缓存旧值当成现状。
func (d Detector) queryDirect(ctx context.Context, server string, port int, name, recordType string, timeout time.Duration) (QueryResult, error) {
	seconds := int(timeout.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	args := []string{
		"+time=" + strconv.Itoa(seconds),
		"+tries=1",
		"+noall",
		"+comments",
		"+answer",
		"-p", strconv.Itoa(port),
		"@" + server,
		name + ".",
		recordType,
	}
	started := time.Now()
	out, err := d.Host.Run(ctx, "dig", args...)
	elapsed := time.Since(started).Milliseconds()
	if err != nil {
		return QueryResult{}, fmt.Errorf("执行 dig @%s -p %d 失败: %w", server, port, err)
	}
	rcode := ""
	if match := digStatusRE.FindStringSubmatch(out); match != nil {
		rcode = match[1]
	}
	if rcode == "" {
		return QueryResult{}, fmt.Errorf("dig @%s 输出缺少 status 行", server)
	}
	answers := parseDigAnswers(out)
	return QueryResult{
		Name:      name,
		Type:      recordType,
		Answers:   answers,
		Rcode:     rcode,
		ElapsedMs: elapsed,
		Resolver:  "dig-direct",
	}, nil
}

// answerValues 返回指定类型的应答值（按记录类型归一，便于与写入值比较与回滚）。
func answerValues(recordType string, answers []Answer) []string {
	values := make([]string, 0, len(answers))
	seen := make(map[string]struct{}, len(answers))
	for _, answer := range answers {
		if !strings.EqualFold(answer.Type, recordType) {
			continue
		}
		value := canonicalAnswerValue(recordType, answer.Value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

// canonicalAnswerValue 把应答值归一到可比较形式（域名去尾点小写、地址用标准写法）。
func canonicalAnswerValue(recordType, value string) string {
	trimmed := strings.TrimSpace(value)
	switch strings.ToUpper(recordType) {
	case "A", "AAAA":
		if ip := net.ParseIP(trimmed); ip != nil {
			return ip.String()
		}
		return trimmed
	case "CNAME":
		return strings.ToLower(strings.TrimSuffix(trimmed, "."))
	case "MX", "SRV":
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			return trimmed
		}
		target := strings.ToLower(strings.TrimSuffix(fields[len(fields)-1], "."))
		return strings.Join(fields[:len(fields)-1], " ") + " " + target
	default:
		return trimmed
	}
}

// answersContain 判断应答集合里是否已有目标值。
func answersContain(recordType string, answers []Answer, want string) bool {
	target := canonicalAnswerValue(recordType, want)
	for _, value := range answerValues(recordType, answers) {
		if value == target {
			return true
		}
	}
	return false
}

// previousRecords 把应答集合转成回滚用的记录快照。
func previousRecords(recordType string, answers []Answer) []Record {
	out := make([]Record, 0, len(answers))
	for _, answer := range answers {
		if !strings.EqualFold(answer.Type, recordType) {
			continue
		}
		value := canonicalAnswerValue(recordType, answer.Value)
		if value == "" {
			continue
		}
		out = append(out, Record{Name: answer.Name, Type: recordType, Value: value, TTL: answer.TTL})
	}
	return out
}
