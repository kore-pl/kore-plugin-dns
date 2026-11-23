package dnsop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// digStatusRE 匹配 dig 头部的响应码：`;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24916`。
var digStatusRE = regexp.MustCompile(`status:\s*([A-Z]+)`)

// defaultQueryTimeout 是未配置查询超时时的兜底值。
const defaultQueryTimeout = 3 * time.Second

// Query 真实查询一条 DNS 记录（验证解析是否生效）：dig → nslookup → Go 解析器三级回退。
//
// 三级回退的意义：dig/nslookup 缺失的宿主机（精简镜像）仍能靠 Go 解析器工作；
// 反过来，dig 能给出 rcode 与 TTL，比 Go 解析器信息更全，因此优先。
func (d Detector) Query(ctx context.Context, name, recordType string, timeout time.Duration) (QueryResult, *pluginapi.Error) {
	normalizedName, perr := ValidateQueryName(name)
	if perr != nil {
		return QueryResult{}, perr
	}
	normalizedType, perr := ValidateQueryType(recordType)
	if perr != nil {
		return QueryResult{}, perr
	}
	if timeout <= 0 {
		timeout = defaultQueryTimeout
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()

	var problems []string
	if _, err := d.Host.LookPath("dig"); err == nil {
		result, err := d.queryWithDig(queryCtx, normalizedName, normalizedType, timeout)
		if err == nil {
			return result, nil
		}
		problems = append(problems, "dig: "+err.Error())
	}
	if _, err := d.Host.LookPath("nslookup"); err == nil {
		result, err := d.queryWithNslookup(queryCtx, normalizedName, normalizedType, timeout)
		if err == nil {
			return result, nil
		}
		problems = append(problems, "nslookup: "+err.Error())
	}
	result, err := d.queryWithGo(queryCtx, normalizedName, normalizedType)
	if err == nil {
		result.Note = "宿主无 dig/nslookup，已回退 Go 解析器（TTL 与 rcode 精度下降）"
		return result, nil
	}
	problems = append(problems, "go: "+err.Error())
	return QueryResult{}, &pluginapi.Error{
		Code:    CodeUpstream,
		Message: "DNS 查询失败（dig / nslookup / Go 解析器均不可用）",
		Detail:  encodeDetail(map[string]string{"hint": "确认宿主装了 dig 或 nslookup，或检查 /etc/resolv.conf 与网络连通性。", "attempts": strings.Join(problems, "；")}),
	}
}

// queryWithDig 用固定 argv 的 dig 查询并解析 rcode / answer。
func (d Detector) queryWithDig(ctx context.Context, name, recordType string, timeout time.Duration) (QueryResult, error) {
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
		name + ".",
		recordType,
	}
	started := time.Now()
	out, err := d.Host.Run(ctx, "dig", args...)
	elapsed := time.Since(started).Milliseconds()
	if err != nil {
		return QueryResult{}, fmt.Errorf("执行 dig 失败: %w", err)
	}
	rcode := ""
	if match := digStatusRE.FindStringSubmatch(out); match != nil {
		rcode = match[1]
	}
	if rcode == "" {
		return QueryResult{}, fmt.Errorf("dig 输出缺少 status 行")
	}
	answers := parseDigAnswers(out)
	if answers == nil {
		answers = make([]Answer, 0)
	}
	return QueryResult{
		Name:      name,
		Type:      recordType,
		Answers:   answers,
		Rcode:     rcode,
		ElapsedMs: elapsed,
		Resolver:  "dig",
	}, nil
}

// parseDigAnswers 解析 ANSWER SECTION：`name ttl class type rdata...`。
func parseDigAnswers(out string) []Answer {
	answers := make([]Answer, 0, 4)
	inAnswer := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			inAnswer = false
			continue
		}
		if strings.HasPrefix(line, ";; ANSWER SECTION:") {
			inAnswer = true
			continue
		}
		if !inAnswer || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		ttl, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		answers = append(answers, Answer{
			Name:  normalizeZoneName(fields[0]),
			Type:  strings.ToUpper(fields[3]),
			Value: normalizeAnswerValue(fields[3], fields[4:]),
			TTL:   ttl,
		})
	}
	return answers
}

// normalizeAnswerValue 归一应答值：TXT 去引号，其余原样拼接。
func normalizeAnswerValue(recordType string, rdata []string) string {
	value := strings.Join(rdata, " ")
	if strings.EqualFold(recordType, "TXT") {
		value = strings.Trim(value, "\"")
		value = strings.ReplaceAll(value, "\" \"", " ")
	}
	return value
}

// queryWithNslookup 用固定 argv 的 nslookup 查询（dig 缺失时的二级回退）。
func (d Detector) queryWithNslookup(ctx context.Context, name, recordType string, timeout time.Duration) (QueryResult, error) {
	seconds := int(timeout.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	args := []string{"-type=" + recordType, "-timeout=" + strconv.Itoa(seconds), name + "."}
	started := time.Now()
	out, err := d.Host.Run(ctx, "nslookup", args...)
	elapsed := time.Since(started).Milliseconds()
	// nslookup 在 NXDOMAIN 时退出码非 0，但输出里仍有可判定的响应码，因此先解析再判失败。
	result := parseNslookupOutput(out, name, recordType)
	result.ElapsedMs = elapsed
	result.Resolver = "nslookup"
	if result.Rcode == "" && err != nil {
		return QueryResult{}, fmt.Errorf("执行 nslookup 失败: %w", err)
	}
	if result.Rcode == "" {
		return QueryResult{}, fmt.Errorf("nslookup 输出无法判定响应码")
	}
	if result.Answers == nil {
		result.Answers = make([]Answer, 0)
	}
	return result, nil
}

// parseNslookupOutput 解析 nslookup 文本输出：响应码 + Name/Address 对（含 MX/TXT 特例）。
func parseNslookupOutput(out, name, recordType string) QueryResult {
	result := QueryResult{Name: name, Type: recordType, Rcode: "NOERROR", Answers: make([]Answer, 0, 2)}
	upper := strings.ToUpper(out)
	for _, code := range []string{"NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP"} {
		if strings.Contains(upper, code) {
			result.Rcode = code
			break
		}
	}
	lastName := name
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Name:"):
			lastName = normalizeZoneName(strings.TrimSpace(strings.TrimPrefix(line, "Name:")))
		case strings.HasPrefix(line, "Address:") && strings.Contains(line, ":") && !strings.Contains(line, "#53"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "Address:"))
			recordTypeOfValue := "A"
			if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
				recordTypeOfValue = "AAAA"
			}
			result.Answers = append(result.Answers, Answer{Name: lastName, Type: recordTypeOfValue, Value: value})
		case strings.Contains(line, "mail exchanger ="):
			parts := strings.SplitN(line, "mail exchanger =", 2)
			priority := ""
			if idx := strings.Index(line, "preference ="); idx >= 0 {
				priority = strings.TrimSpace(strings.SplitN(line[idx+len("preference ="):], ",", 2)[0])
			}
			value := strings.TrimSpace(parts[1])
			if priority != "" {
				value = priority + " " + value
			}
			result.Answers = append(result.Answers, Answer{Name: name, Type: "MX", Value: value})
		case strings.HasPrefix(line, "text ="):
			value := strings.TrimSpace(strings.TrimPrefix(line, "text ="))
			value = strings.Trim(value, "\"")
			result.Answers = append(result.Answers, Answer{Name: name, Type: "TXT", Value: value})
		}
	}
	return result
}

// queryWithGo 用标准库解析器查询（无外部命令依赖的三级回退）。
func (d Detector) queryWithGo(ctx context.Context, name, recordType string) (QueryResult, error) {
	result := QueryResult{Name: name, Type: recordType, Rcode: "NOERROR", Answers: make([]Answer, 0, 2), Resolver: "go"}
	resolver := net.DefaultResolver
	started := time.Now()
	var err error
	switch recordType {
	case "A", "AAAA":
		var hosts []string
		hosts, err = resolver.LookupHost(ctx, name)
		for _, host := range hosts {
			ip := net.ParseIP(host)
			if ip == nil {
				continue
			}
			if recordType == "A" && ip.To4() == nil {
				continue
			}
			if recordType == "AAAA" && ip.To4() != nil {
				continue
			}
			result.Answers = append(result.Answers, Answer{Name: name, Type: recordType, Value: host})
		}
	case "CNAME":
		var cname string
		cname, err = resolver.LookupCNAME(ctx, name)
		if err == nil && cname != "" {
			result.Answers = append(result.Answers, Answer{Name: name, Type: "CNAME", Value: normalizeZoneName(cname)})
		}
	case "MX":
		var records []*net.MX
		records, err = resolver.LookupMX(ctx, name)
		for _, record := range records {
			result.Answers = append(result.Answers, Answer{
				Name: name, Type: "MX",
				Value: strconv.FormatUint(uint64(record.Pref), 10) + " " + normalizeZoneName(record.Host),
			})
		}
	case "NS":
		var records []*net.NS
		records, err = resolver.LookupNS(ctx, name)
		for _, record := range records {
			result.Answers = append(result.Answers, Answer{Name: name, Type: "NS", Value: normalizeZoneName(record.Host)})
		}
	case "TXT":
		var records []string
		records, err = resolver.LookupTXT(ctx, name)
		for _, record := range records {
			result.Answers = append(result.Answers, Answer{Name: name, Type: "TXT", Value: record})
		}
	case "SRV":
		var cname string
		var records []*net.SRV
		cname, records, err = resolver.LookupSRV(ctx, "", "", name)
		for _, record := range records {
			value := strconv.FormatUint(uint64(record.Priority), 10) + " " +
				strconv.FormatUint(uint64(record.Weight), 10) + " " +
				strconv.FormatUint(uint64(record.Port), 10) + " " + normalizeZoneName(record.Target)
			result.Answers = append(result.Answers, Answer{Name: name, Type: "SRV", Value: value})
		}
		if cname != "" && len(records) == 0 {
			result.Answers = append(result.Answers, Answer{Name: name, Type: "CNAME", Value: normalizeZoneName(cname)})
		}
	case "PTR":
		var names []string
		names, err = resolver.LookupAddr(ctx, name)
		for _, record := range names {
			result.Answers = append(result.Answers, Answer{Name: name, Type: "PTR", Value: normalizeZoneName(record)})
		}
	case "CAA", "SOA":
		return QueryResult{}, fmt.Errorf("Go 解析器不支持查询 %s，请安装 dig 或 nslookup", recordType)
	default:
		return QueryResult{}, fmt.Errorf("不支持的查询类型 %s", recordType)
	}
	result.ElapsedMs = time.Since(started).Milliseconds()
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			switch {
			case dnsErr.IsNotFound:
				result.Rcode = "NXDOMAIN"
				result.Answers = make([]Answer, 0)
				return result, nil
			case dnsErr.IsTimeout:
				result.Rcode = "SERVFAIL"
			default:
				result.Rcode = "SERVFAIL"
			}
		}
		if result.Rcode != "NOERROR" {
			return result, nil
		}
		return QueryResult{}, err
	}
	sortAnswers(result.Answers)
	return result, nil
}

// sortAnswers 按类型 + 值排序，保证同一查询多次运行输出稳定。
func sortAnswers(answers []Answer) {
	sort.Slice(answers, func(i, j int) bool {
		if answers[i].Type != answers[j].Type {
			return answers[i].Type < answers[j].Type
		}
		return answers[i].Value < answers[j].Value
	})
}
