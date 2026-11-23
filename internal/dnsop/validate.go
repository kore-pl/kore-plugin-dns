package dnsop

import (
	"regexp"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// queryTypeWhitelist 是 dns.query 接受的记录类型（只读查询，不放通任意 rdata）。
var queryTypeWhitelist = map[string]struct{}{
	"A": {}, "AAAA": {}, "CNAME": {}, "MX": {}, "NS": {}, "TXT": {}, "SRV": {}, "CAA": {}, "SOA": {}, "PTR": {},
}

// queryLabelRE 约束查询名标签：字母数字下划线开头结尾，中间可含连字符。
var queryLabelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// maxQueryNameLen 是查询名长度上限（RFC 1035）。
const maxQueryNameLen = 253

// ValidateQueryName 归一化并校验查询名：允许大写输入（归一小写）、允许尾点（绝对名）。
// 拒绝空白、shell 元字符、路径分隔符、空标签与超长——即使命令走固定 argv，也不接受脏输入。
func ValidateQueryName(name string) (string, *pluginapi.Error) {
	raw := strings.TrimSpace(name)
	if raw == "" {
		return "", invalidParam("缺少必填字段 name")
	}
	if len(raw) > maxQueryNameLen+1 {
		return "", invalidParam("name 超过 253 字符")
	}
	normalized := strings.ToLower(raw)
	normalized = strings.TrimSuffix(normalized, ".")
	if normalized == "" {
		return "", invalidParam("name 非法：不能只含尾点")
	}
	labels := strings.Split(normalized, ".")
	for _, label := range labels {
		if label == "" {
			return "", invalidParam("name 非法：存在空标签")
		}
		if !queryLabelRE.MatchString(label) {
			return "", invalidParam("name 非法：仅允许字母数字、连字符与下划线")
		}
	}
	return normalized, nil
}

// ValidateQueryType 校验记录类型，空值按 A 处理。
func ValidateQueryType(recordType string) (string, *pluginapi.Error) {
	trimmed := strings.TrimSpace(recordType)
	if trimmed == "" {
		return "A", nil
	}
	upper := strings.ToUpper(trimmed)
	if _, ok := queryTypeWhitelist[upper]; !ok {
		return "", invalidParam("type 不支持 " + trimmed + "：仅允许 A/AAAA/CNAME/MX/NS/TXT/SRV/CAA/SOA/PTR")
	}
	return upper, nil
}

// invalidParam 构造 E_INVALID 错误体。
func invalidParam(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: message}
}

// needRoot 构造 E_NEED_ROOT 错误体 + 可操作 hint（ADR-0018 降级硬要求）。
func needRoot(path string) *pluginapi.Error {
	detail := encodeDetail(map[string]string{
		"hint": "读取 " + path + " 需要 root 权限：请用 sudo 启动 kored，或把该路径加入 kore 的 root_actions 只读动作（见 docs/DECISIONS/0018-privilege-model.md）。",
		"path": path,
	})
	return &pluginapi.Error{
		Code:    CodeNeedRoot,
		Message: "E_NEED_ROOT: 非 root 无法读取 " + path,
		Detail:  detail,
	}
}

// readRoots 是只读路径白名单：插件只允许读这四个位置（GB-04 路径白名单）。
// /etc/dnsmasq.conf 是单文件配置，与 /etc/dnsmasq.d 同域，因此单列。
var readRoots = []string{"/etc/bind", "/etc/dnsmasq.d", "/var/lib/bind", "/etc/dnsmasq.conf"}

// AllowedReadRoots 返回只读白名单根（配置校验与文档共用）。
func AllowedReadRoots() []string {
	out := make([]string, len(readRoots))
	copy(out, readRoots)
	return out
}

// WithinReadRoots 判断绝对路径是否落在只读白名单内（路径必须已 Clean，且不允许 .. 逃逸）。
func WithinReadRoots(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") {
		return false
	}
	for _, root := range readRoots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// ValidateReadPath 校验配置里的只读路径：绝对路径、已 Clean、无 ..、落在白名单内。
func ValidateReadPath(field, path string) (string, *pluginapi.Error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", invalidParam("缺少必填字段 " + field)
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "", invalidParam(field + " 必须是绝对路径")
	}
	cleaned := cleanPath(trimmed)
	if strings.Contains(cleaned, "..") {
		return "", invalidParam(field + " 不允许包含 ..")
	}
	if !WithinReadRoots(cleaned) {
		return "", invalidParam(field + " 不在只读白名单内（允许：" + strings.Join(readRoots, "、") + "）")
	}
	return cleaned, nil
}

// cleanPath 归一绝对路径（不用 filepath.Clean 以避免平台差异带来的语义偏差）。
func cleanPath(path string) string {
	parts := strings.Split(path, "/")
	stack := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, "..")
		default:
			stack = append(stack, part)
		}
	}
	return "/" + strings.Join(stack, "/")
}
