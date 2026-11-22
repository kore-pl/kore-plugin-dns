package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// domainMaxLen 是 RFC 1035 域名长度上限（含尾点后的规范化长度）。
const domainMaxLen = 253

// labelMaxLen 是单个 DNS 标签的长度上限（RFC 1035 §2.3.4）。
const labelMaxLen = 63

// labelRE 约束单个标签：字母数字开头结尾，中间可含连字符，拒绝下划线与路径分隔符。
var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// supportedTypes 是本插件接受的记录类型白名单（基础级仅四类）。
var supportedTypes = map[string]struct{}{
	"A": {}, "AAAA": {}, "CNAME": {}, "MX": {},
}

// invalidParam 构造 E_INVALID 错误体（§9）。
func invalidParam(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: msg}
}

// validateDomain 校验区域名：非空、≤253、小写、标签合法、至少两个标签。
// 拒绝大写与路径穿越字符（../、/），防止区域名被用作路径或注入指令。
func validateDomain(field, domain string) *pluginapi.Error {
	if domain == "" {
		return invalidParam("缺少必填字段 " + field)
	}
	if len(domain) > domainMaxLen {
		return invalidParam(field + " 超过 253 字符")
	}
	if domain != strings.ToLower(domain) {
		return invalidParam(field + " 必须为小写")
	}
	// 规范化尾点：FQDN 允许结尾一个点，校验时用去点形式。
	name := strings.TrimSuffix(domain, ".")
	if name == "" {
		return invalidParam(field + " 非法：不能只含尾点")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return invalidParam(field + " 非法：至少两个标签")
	}
	for _, label := range labels {
		if len(label) > labelMaxLen {
			return invalidParam(field + " 非法：标签超过 63 字符")
		}
		if !labelRE.MatchString(label) {
			return invalidParam(field + " 非法：仅允许小写字母数字与连字符")
		}
	}
	return nil
}

// validateType 校验记录类型是否在白名单内。
func validateType(recordType string) *pluginapi.Error {
	if recordType == "" {
		return invalidParam("缺少必填字段 type")
	}
	upper := strings.ToUpper(recordType)
	if _, ok := supportedTypes[upper]; !ok {
		return invalidParam(fmt.Sprintf("type 不支持 %q：仅允许 A/AAAA/CNAME/MX", recordType))
	}
	return nil
}

// validateValue 按记录类型校验 value：A/AAAA 用 net.ParseIP 严格解析，
// CNAME 复用域名校验，MX 要求 "优先级 域名" 形式且优先级在 0..65535。
func validateValue(recordType, value string) *pluginapi.Error {
	if value == "" {
		return invalidParam("缺少必填字段 value")
	}
	upper := strings.ToUpper(recordType)
	switch upper {
	case "A":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil || strings.Contains(value, ":") {
			return invalidParam("A 记录的 value 必须是 IPv4 地址")
		}
	case "AAAA":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return invalidParam("AAAA 记录的 value 必须是 IPv6 地址")
		}
	case "CNAME":
		if perr := validateDomain("value", value); perr != nil {
			return perr
		}
	case "MX":
		return validateMX(value)
	}
	return nil
}

// validateMX 校验 MX 值：单个空格分隔的十进制优先级（0..65535）与目标域名。
func validateMX(value string) *pluginapi.Error {
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return invalidParam("MX 记录的 value 必须是 \"优先级 域名\"")
	}
	priority := 0
	if _, err := fmt.Sscanf(parts[0], "%d", &priority); err != nil || priority < 0 || priority > 65535 {
		return invalidParam("MX 优先级必须是 0..65535 的十进制整数")
	}
	if parts[0] != fmt.Sprintf("%d", priority) {
		return invalidParam("MX 优先级必须是规范十进制整数")
	}
	return validateDomain("MX 目标", parts[1])
}
