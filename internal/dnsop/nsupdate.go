package dnsop

import (
	"net"
	"strconv"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// writeTypeWhitelist 是允许写入的记录类型：只放行叶子/服务记录，
// NS/SOA/PTR 等区域结构记录不外露（改错会破坏整个区域）。
var writeTypeWhitelist = map[string]struct{}{
	"A": {}, "AAAA": {}, "CNAME": {}, "MX": {}, "TXT": {}, "SRV": {},
}

// 写入默认值与上限。
const (
	// DefaultWriteTTL 是未显式给 ttl 时的动态记录 TTL（秒）。
	DefaultWriteTTL = 300
	// maxWriteTTL 是允许的显式 TTL 上限（秒），与常见负缓存上限同量级。
	maxWriteTTL = 86400
	// maxPreviousRecords 是回滚时最多恢复的旧记录条数（防超大 RRset 撑爆脚本）。
	maxPreviousRecords = 10
)

// validateWriteType 校验可写记录类型。
func validateWriteType(raw string) (string, *pluginapi.Error) {
	trimmed := strings.ToUpper(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", invalidParam("缺少必填字段 type")
	}
	if _, ok := writeTypeWhitelist[trimmed]; !ok {
		return "", invalidParam("type 不支持写入 " + raw + "：写入仅允许 A/AAAA/CNAME/MX/TXT/SRV（NS/SOA/PTR 属区域结构，不开放）")
	}
	return trimmed, nil
}

// normalizeWriteValue 校验并归一写入值，返回用于比较与脚本渲染的规范形式。
//
// 安全边界：值最终进入 nsupdate 的行式脚本，因此拒绝控制字符（换行会注入新指令）；
// 非 TXT 值额外拒绝 `;`（nsupdate 的注释符）。各类型的语义（IP、优先级、端口）单独复核。
func normalizeWriteValue(recordType, raw string) (string, *pluginapi.Error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", invalidParam("缺少必填字段 value")
	}
	if strings.ContainsAny(value, "\r\n\t\x00") {
		return "", invalidParam("value 不能包含换行/制表/空字节")
	}
	switch recordType {
	case "A":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return "", invalidParam("A 记录的 value 必须是 IPv4 地址")
		}
		return ip.To4().String(), nil
	case "AAAA":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return "", invalidParam("AAAA 记录的 value 必须是 IPv6 地址")
		}
		return ip.String(), nil
	case "CNAME":
		name, perr := ValidateQueryName(value)
		if perr != nil {
			return "", invalidParam("CNAME 目标非法: " + perr.Message)
		}
		return name, nil
	case "MX":
		return normalizePriorityTarget(value, "MX", "优先级 目标")
	case "SRV":
		return normalizeSRV(value)
	case "TXT":
		if len(value) > 255 {
			return "", invalidParam("TXT 单条字符串不能超过 255 字节")
		}
		return value, nil
	default:
		return "", invalidParam("type 不支持写入 " + recordType)
	}
}

// normalizePriorityTarget 归一 `优先级 目标` 形式（MX）。
func normalizePriorityTarget(value, recordType, shape string) (string, *pluginapi.Error) {
	if strings.ContainsRune(value, ';') {
		return "", invalidParam(recordType + " 的 value 不能包含 ;")
	}
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return "", invalidParam(recordType + " 的 value 必须是「" + shape + "」")
	}
	priority, err := strconv.Atoi(fields[0])
	if err != nil || priority < 0 || priority > 65535 {
		return "", invalidParam(recordType + " 的优先级必须是 0–65535")
	}
	target, perr := ValidateQueryName(fields[1])
	if perr != nil {
		return "", invalidParam(recordType + " 的目标非法: " + perr.Message)
	}
	return strconv.Itoa(priority) + " " + target, nil
}

// normalizeSRV 归一 `优先级 权重 端口 目标` 形式。
func normalizeSRV(value string) (string, *pluginapi.Error) {
	if strings.ContainsRune(value, ';') {
		return "", invalidParam("SRV 的 value 不能包含 ;")
	}
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return "", invalidParam("SRV 的 value 必须是「优先级 权重 端口 目标」")
	}
	numbers := make([]int, 3)
	for index := 0; index < 3; index++ {
		parsed, err := strconv.Atoi(fields[index])
		if err != nil || parsed < 0 || parsed > 65535 {
			return "", invalidParam("SRV 的优先级/权重/端口必须是 0–65535")
		}
		numbers[index] = parsed
	}
	if numbers[2] == 0 {
		return "", invalidParam("SRV 的端口不能为 0")
	}
	target, perr := ValidateQueryName(fields[3])
	if perr != nil {
		return "", invalidParam("SRV 的目标非法: " + perr.Message)
	}
	return strconv.Itoa(numbers[0]) + " " + strconv.Itoa(numbers[1]) + " " +
		strconv.Itoa(numbers[2]) + " " + target, nil
}

// renderWriteValue 把规范值渲染成 nsupdate 脚本里的 rdata（域名补尾点、TXT 加引号转义）。
func renderWriteValue(recordType, value string) string {
	switch recordType {
	case "CNAME":
		return ensureFQDN(value)
	case "MX":
		fields := strings.Fields(value)
		if len(fields) == 2 {
			return fields[0] + " " + ensureFQDN(fields[1])
		}
	case "SRV":
		fields := strings.Fields(value)
		if len(fields) == 4 {
			return strings.Join(fields[:3], " ") + " " + ensureFQDN(fields[3])
		}
	case "TXT":
		escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
		return `"` + escaped + `"`
	}
	return value
}

// ensureFQDN 给域名补结尾点（空目标 "." 原样返回）。
func ensureFQDN(name string) string {
	if name == "" || name == "." || strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// buildUpdateScript 生成一次原子动态更新（prereq + update + send 同一条消息）。
//
// 原子性来自 RFC 2136：整条 UPDATE 消息里的 prereq 与 update 由服务器一次性应用，
// 任一 prereq 不满足则整条消息不生效——不是客户端「先删后加」的两条独立请求。
func buildUpdateScript(spec recordWriteSpec) string {
	fqdn := ensureFQDN(spec.Name)
	var b strings.Builder
	b.WriteString("server " + spec.Server + "\n")
	b.WriteString("zone " + spec.Zone + "\n")
	switch spec.Operation {
	case "add":
		b.WriteString("prereq nxrrset " + fqdn + " " + spec.Type + "\n")
		b.WriteString("update add " + fqdn + " " + strconv.Itoa(spec.TTL) + " " + spec.Type + " " + spec.Rendered + "\n")
	case "update":
		b.WriteString("prereq yxrrset " + fqdn + " " + spec.Type + "\n")
		if spec.OldValue != "" {
			b.WriteString("prereq yxrrset " + fqdn + " " + spec.Type + " " + renderWriteValue(spec.Type, spec.OldValue) + "\n")
		}
		b.WriteString("update delete " + fqdn + " " + spec.Type + "\n")
		b.WriteString("update add " + fqdn + " " + strconv.Itoa(spec.TTL) + " " + spec.Type + " " + spec.Rendered + "\n")
	case "delete":
		if spec.OldValue != "" {
			b.WriteString("prereq yxrrset " + fqdn + " " + spec.Type + " " + renderWriteValue(spec.Type, spec.OldValue) + "\n")
			b.WriteString("update delete " + fqdn + " " + spec.Type + " " + renderWriteValue(spec.Type, spec.OldValue) + "\n")
		} else {
			b.WriteString("prereq yxrrset " + fqdn + " " + spec.Type + "\n")
			b.WriteString("update delete " + fqdn + " " + spec.Type + "\n")
		}
	}
	b.WriteString("send\n")
	return b.String()
}

// buildRollbackScript 生成逆操作脚本：add → 删掉刚加的；update/delete → 恢复旧记录。
// 回滚是 best-effort（不带 prereq），失败会在结果里如实上报 rolled_back=false。
func buildRollbackScript(spec recordWriteSpec) string {
	fqdn := ensureFQDN(spec.Name)
	var b strings.Builder
	b.WriteString("server " + spec.Server + "\n")
	b.WriteString("zone " + spec.Zone + "\n")
	switch spec.Operation {
	case "add":
		b.WriteString("update delete " + fqdn + " " + spec.Type + " " + spec.Rendered + "\n")
	case "update":
		b.WriteString("update delete " + fqdn + " " + spec.Type + "\n")
		for index, record := range spec.Previous {
			if index >= maxPreviousRecords {
				break
			}
			b.WriteString("update add " + fqdn + " " + strconv.Itoa(rollbackTTL(record)) + " " +
				spec.Type + " " + renderWriteValue(spec.Type, record.Value) + "\n")
		}
	case "delete":
		for index, record := range spec.Previous {
			if index >= maxPreviousRecords {
				break
			}
			b.WriteString("update add " + fqdn + " " + strconv.Itoa(rollbackTTL(record)) + " " +
				spec.Type + " " + renderWriteValue(spec.Type, record.Value) + "\n")
		}
	}
	b.WriteString("send\n")
	return b.String()
}

// rollbackTTL 返回恢复旧记录时使用的 TTL（快照有就用快照，否则默认值）。
func rollbackTTL(record Record) int {
	if record.TTL > 0 {
		return record.TTL
	}
	return DefaultWriteTTL
}

// nsupdateArgv 是固定 argv：密钥与端口由插件注入，server/zone/update 全部走 stdin 脚本。
// RPC 的 zone/name/type/value 只参与已校验的脚本行，永不进入 argv。
func nsupdateArgv(spec recordWriteSpec) []string {
	return []string{"-k", spec.KeyFile, "-p", strconv.Itoa(spec.Port)}
}

// nsupdateReportedFailure 判断 nsupdate 输出是否含失败标记。
// nsupdate 的退出码不可靠（通信失败也可能返回 0），所以成功与否以「生效校验」为准，
// 这里只用于给出更精确的错误文案与回滚判断。
func nsupdateReportedFailure(output string) bool {
	lower := strings.ToLower(output)
	for _, marker := range []string{
		"update failed", "failed:", "refused", "notauth", "notzone", "servfail",
		"timed out", "communication with", "could not read key", "bad key",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// classifyNsupdateFailure 把 nsupdate 的失败输出映射成可操作错误（按原因给不同 hint）。
func classifyNsupdateFailure(output, runErr string) *pluginapi.Error {
	text := strings.ToLower(output + " " + runErr)
	hint := "检查 update_server/update_port 指向 bind9 实例、TSIG 密钥与 zone 的 allow-update/update-policy 配置。"
	switch {
	case strings.Contains(text, "refused"), strings.Contains(text, "notauth"):
		hint = "服务器拒绝更新：确认 zone 已配置 allow-update { key \"kore-update\"; };（或 update-policy），" +
			"且 update_key_file 与服务器 TSIG 名称/密钥一致。"
	case strings.Contains(text, "notzone"), strings.Contains(text, "not a zone"):
		hint = "服务器不管理该 zone：确认 update_server 是该 zone 的权威服务器，且 zone 名与 named.conf 一致。"
	case strings.Contains(text, "timed out"), strings.Contains(text, "communication with"),
		strings.Contains(text, "connection refused"):
		hint = "连接更新服务器失败：update_server/update_port 必须指向真正的 bind9 权威实例" +
			"（127.0.0.53 的 systemd-resolved stub 不能接收动态更新）。"
	case strings.Contains(text, "could not read key"), strings.Contains(text, "bad key"):
		hint = "TSIG 密钥不可用：确认 update_key_file 存在且 kore 运行用户可读（chgrp + 0640），名称与服务器 key 一致。"
	}
	detail := map[string]string{"hint": hint}
	if snippet := strings.TrimSpace(strings.Join(strings.Fields(output), " ")); snippet != "" {
		detail["nsupdate_output"] = truncate(snippet, 2000)
	}
	if runErr != "" {
		detail["exec_error"] = truncate(runErr, 500)
	}
	return &pluginapi.Error{
		Code:    pluginapi.E_UPSTREAM,
		Message: "DNS 动态更新失败（nsupdate）",
		Detail:  encodeDetail(detail),
	}
}
