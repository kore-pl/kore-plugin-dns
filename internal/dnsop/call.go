package dnsop

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// Methods 返回 DNS 业务方法名（不含 config.* 与 kore.* 协议方法）。
// 前四个只读；后三个是 bind9 动态更新写入（RFC 2136，无需 root）。
func Methods() []string {
	return []string{"status", "zones", "records", "query", "record.add", "record.update", "record.delete", "addRecord", "updateRecord", "deleteRecord", "reload"}
}

// statusParams 是 dns.status / dns.zones 的入参：engine 可选，用于强制/过滤引擎。
type statusParams struct {
	Engine string `json:"engine"`
}

// reloadParams 是 dns.reload 的入参：只有一个可选的 zone。
// 契约以 README 方法表为准（`{zone?}` → `rndc reload [zone]`）；engine 不是本方法入参——
// reload 用哪个引擎由插件配置/探测决定（见 writableEngine）。
type reloadParams struct {
	Zone string `json:"zone"`
}

// recordsParams 是 dns.records 的入参。
type recordsParams struct {
	Zone string `json:"zone"`
}

// queryParams 是 dns.query 的入参。
type queryParams struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Call 执行一个 DNS 业务方法（只读 + 记录写入），返回结构化 JSON 结果或结构化错误。
func (d Detector) Call(ctx context.Context, method string, params json.RawMessage, queryTimeout time.Duration) (json.RawMessage, *pluginapi.Error) {
	switch method {
	case "status":
		var p statusParams
		if perr := decodeParams(params, &p); perr != nil {
			return nil, perr
		}
		if perr := validateEngineParam(p.Engine); perr != nil {
			return nil, perr
		}
		result := d.Status(ctx, d.engineOrDefault(p.Engine))
		return encodeResult("dns.status", result)
	case "zones":
		var p statusParams
		if perr := decodeParams(params, &p); perr != nil {
			return nil, perr
		}
		if perr := validateEngineParam(p.Engine); perr != nil {
			return nil, perr
		}
		result, perr := d.Zones(ctx, d.engineOrDefault(p.Engine))
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.zones", result)
	case "records":
		var p recordsParams
		if perr := decodeParams(params, &p); perr != nil {
			return nil, perr
		}
		result, perr := d.Records(ctx, p.Zone)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.records", result)
	case "query":
		var p queryParams
		if perr := decodeParams(params, &p); perr != nil {
			return nil, perr
		}
		result, perr := d.Query(ctx, p.Name, p.Type, queryTimeout)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.query", result)
	case "record.add":
		result, perr := d.RecordAdd(ctx, params)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.record.add", result)
	case "record.update":
		result, perr := d.RecordUpdate(ctx, params)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.record.update", result)
	case "record.delete":
		result, perr := d.RecordDelete(ctx, params)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.record.delete", result)
	case "addRecord":
		result, perr := d.WriteRecord(ctx, "add", params)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.addRecord", result)
	case "updateRecord":
		result, perr := d.WriteRecord(ctx, "update", params)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.updateRecord", result)
	case "deleteRecord":
		result, perr := d.WriteRecord(ctx, "delete", params)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.deleteRecord", result)
	case "reload":
		p, perr := decodeReloadParams(params)
		if perr != nil {
			return nil, perr
		}
		result, perr := d.Reload(ctx, p.Zone)
		if perr != nil {
			return nil, perr
		}
		return encodeResult("dns.reload", result)
	default:
		return nil, &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知 DNS 方法：" + method}
	}
}

// engineOrDefault 返回入参引擎；入参为空时用配置里的 DefaultEngine（仍可能为空 → auto）。
func (d Detector) engineOrDefault(engine string) string {
	if engine != "" {
		return engine
	}
	return d.DefaultEngine
}

// validateEngineParam 校验可选 engine 参数取值。
func validateEngineParam(engine string) *pluginapi.Error {
	switch engine {
	case "", EngineAuto, EngineSystemdResolved, EngineDnsmasq, EngineBind9, EngineCoreDNS:
		return nil
	default:
		return invalidParam("engine 不支持 " + engine + "：仅允许 auto/systemd-resolved/dnsmasq/bind9/coredns，请改选上述引擎")
	}
}

// decodeReloadParams 解析 dns.reload 的入参：只接受可选 zone，未声明字段 fail-closed。
//
// 历史缺陷（3b538e6 发现）：reload 曾复用 statusParams 并把 p.Engine 当 zone 传下去，
// 于是 {"engine":"bind9"} 实际执行 `rndc reload bind9`。这里对未声明字段直接 E_INVALID，
// 字段名写错时不再静默落到别的参数上。
func decodeReloadParams(raw json.RawMessage) (reloadParams, *pluginapi.Error) {
	var p reloadParams
	if len(raw) == 0 || string(raw) == "null" {
		return p, nil
	}
	if raw[0] != '{' {
		return p, invalidParam("params 必须是 JSON 对象，请提交 JSON 对象格式的参数")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		if field, ok := unknownJSONField(err); ok {
			return p, &pluginapi.Error{
				Code:    pluginapi.E_INVALID,
				Message: "params 含未声明的字段 " + field + "：dns.reload 只接受可选 zone（引擎由插件配置/探测决定），请删除该字段后重试",
				Detail: encodeDetail(map[string]string{
					"field":   field,
					"allowed": "zone",
					"hint":    "重载整个引擎省略 zone；只重载某个区域写 {\"zone\":\"example.com\"}。要指定引擎请改插件配置 engine 后调用。",
				}),
			}
		}
		return p, invalidParam("params 解析失败: " + err.Error() + "，请检查 JSON 格式后重试")
	}
	return p, nil
}

// unknownJSONField 从 encoding/json 的 unknown field 错误里取出字段名。
func unknownJSONField(err error) (string, bool) {
	const marker = `unknown field "`
	msg := err.Error()
	index := strings.Index(msg, marker)
	if index < 0 {
		return "", false
	}
	rest := msg[index+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end <= 0 {
		return "", false
	}
	return rest[:end], true
}

// decodeParams 把 params 解析到目标结构；空 / null 视为空对象，非对象报 E_INVALID。
func decodeParams[T any](raw json.RawMessage, dst *T) *pluginapi.Error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] != '{' {
		return invalidParam("params 必须是 JSON 对象，请提交 JSON 对象格式的参数")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return invalidParam("params 解析失败: " + err.Error() + "，请检查 JSON 格式后重试")
	}
	return nil
}

// encodeResult 序列化结果；失败按 E_INTERNAL 返回（不返回半截 JSON）。
func encodeResult[T any](method string, value T) (json.RawMessage, *pluginapi.Error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: method + " 结果序列化失败: " + err.Error()}
	}
	return encoded, nil
}
