package dnsop

import (
	"context"
	"encoding/json"
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
		var p statusParams
		if perr := decodeParams(params, &p); perr != nil {
			return nil, perr
		}
		result, perr := d.Reload(ctx, p.Engine)
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
		return invalidParam("engine 不支持 " + engine + "：仅允许 auto/systemd-resolved/dnsmasq/bind9/coredns")
	}
}

// decodeParams 把 params 解析到目标结构；空 / null 视为空对象，非对象报 E_INVALID。
func decodeParams[T any](raw json.RawMessage, dst *T) *pluginapi.Error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] != '{' {
		return invalidParam("params 必须是 JSON 对象")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return invalidParam("params 解析失败: " + err.Error())
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
