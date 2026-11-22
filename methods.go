package main

import (
	"encoding/json"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// defaultTTL 是 record.add 未指定 ttl 时的默认值（RFC 1912 常用 1 小时）。
const defaultTTL = 3600

// maxTTL 是 record.add 接受的 ttl 上限（2^31-1，避免下游溢出）。
const maxTTL = 2147483647

// statusResult 是 kore.ping 的结果（PLUGIN-PROTOCOL §7.1）。
type statusResult struct {
	Status     string `json:"status"`
	UptimeS    int64  `json:"uptime_s"`
	Goroutines int    `json:"goroutines"`
	RSSKB      int64  `json:"rss_kb"`
}

// zoneParams 是 dns.zone.list 的入参（当前无必填字段，预留 zone 过滤）。
type zoneParams struct {
	Zone string `json:"zone"`
}

// recordParams 是 dns.record.add 的入参；所有字段显式类型，不用 any/object。
type recordParams struct {
	Zone  string `json:"zone"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   *int   `json:"ttl,omitempty"`
}

// dispatch 把请求分发为响应帧；第二个返回值表示收到 kore.shutdown。
func dispatch(request *pluginapi.Request, cfg config, logger *slog.Logger) (*pluginapi.Response, bool) {
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID}
	switch request.Method {
	case "kore.shutdown":
		response.Result = json.RawMessage(`{"ok":true}`)
		logger.Info("收到 kore.shutdown，优雅退出")
		return response, true
	case "kore.ping":
		response.Result = pingResult(cfg)
		return response, false
	case "kore.reload":
		response.Result = json.RawMessage(`{"ok":true,"config_digest":""}`)
		return response, false
	}
	verb, ok := businessVerb(request.Method, cfg.id)
	if !ok {
		response.Error = notFound(request.Method)
		return response, false
	}
	if perr := handleDNSVerb(verb, request.Params, response, cfg); perr != nil {
		response.Error = perr
		response.Result = nil
	}
	return response, false
}

// handleDNSVerb 执行 DNS 方法：zone.list 返回提案区域视图，record.add 校验并登记提案；
// 两者都不实际改动宿主 DNS 服务（基础级骨架口径）。
func handleDNSVerb(verb string, params json.RawMessage, response *pluginapi.Response, cfg config) *pluginapi.Error {
	switch verb {
	case "zone.list":
		var p zoneParams
		if perr := parseObject(params, &p); perr != nil {
			return perr
		}
		zones := cfg.store.zones()
		if p.Zone != "" {
			zones = filterZones(zones, p.Zone)
		}
		response.Result = encode(zoneListResult{Zones: zones, Count: len(zones), Applied: false})
		return nil
	case "record.add":
		p, perr := parseRecord(params)
		if perr != nil {
			return perr
		}
		return addRecordProposal(p, response, cfg)
	default:
		return notFound(verb)
	}
}

// parseObject 校验 params 为 JSON 对象并解析到目标结构；空/null 视为空对象。
func parseObject[T any](raw json.RawMessage, dst *T) *pluginapi.Error {
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return invalidParam("params 解析失败: " + err.Error())
		}
	}
	return nil
}

// parseRecord 解析并校验 record.add 全部字段，返回规范化的记录类型大写形式。
func parseRecord(raw json.RawMessage) (recordParams, *pluginapi.Error) {
	var p recordParams
	if perr := parseObject(raw, &p); perr != nil {
		return p, perr
	}
	if perr := validateDomain("zone", p.Zone); perr != nil {
		return p, perr
	}
	if perr := validateDomain("name", p.Name); perr != nil {
		return p, perr
	}
	if perr := validateType(p.Type); perr != nil {
		return p, perr
	}
	p.Type = strings.ToUpper(p.Type)
	if perr := validateValue(p.Type, p.Value); perr != nil {
		return p, perr
	}
	if p.TTL != nil && (*p.TTL < 0 || *p.TTL > maxTTL) {
		return p, invalidParam("ttl 必须在 0..2147483647")
	}
	return p, nil
}

// addRecordProposal 把校验通过的记录登记为提案并回结构化结果（applied=false）。
func addRecordProposal(p recordParams, response *pluginapi.Response, cfg config) *pluginapi.Error {
	ttl := defaultTTL
	if p.TTL != nil {
		ttl = *p.TTL
	}
	entry := recordEntry{Zone: p.Zone, Name: p.Name, Type: p.Type, Value: p.Value, TTL: ttl}
	added := cfg.store.addRecord(entry)
	response.Result = encode(recordAddResult{
		Zone: p.Zone, Name: p.Name, Type: p.Type, Value: p.Value,
		TTL: ttl, Applied: false, Added: added,
	})
	return nil
}

// filterZones 按区域名精确过滤（zone.list 的可选 zone 参数）。
func filterZones(zones []zoneEntry, zone string) []zoneEntry {
	var out []zoneEntry
	for _, z := range zones {
		if z.Name == zone {
			out = append(out, z)
		}
	}
	return out
}

// businessVerb 把 <id>.<verb> 或裸 <verb> 归一为动词名。
func businessVerb(method, id string) (string, bool) {
	verb := strings.TrimPrefix(method, id+".")
	switch verb {
	case "zone.list", "record.add":
		return verb, true
	default:
		return "", false
	}
}

// notFound 构造 E_NOTFOUND 错误体（§9）。
func notFound(method string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法：" + method}
}

// pingResult 组装 kore.ping 结果。
func pingResult(cfg config) json.RawMessage {
	return encode(statusResult{
		Status:     "ready",
		UptimeS:    int64(time.Since(cfg.startedAt).Seconds()),
		Goroutines: runtime.NumGoroutine(),
		RSSKB:      rssKB(),
	})
}
