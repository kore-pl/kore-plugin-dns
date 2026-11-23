package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"github.com/pengtang1024/kore-plugin-dns/internal/dnsop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// callTimeout 是单次业务方法的总预算（含子进程）：内核调用默认 5s 级，留出充裕余量。
const callTimeout = 20 * time.Second

// statusResult 是 kore.ping 的结果（PLUGIN-PROTOCOL §7.1）。
type statusResult struct {
	// Status 是插件状态，固定 ready（能应答 ping 就是在服务）。
	Status string `json:"status"`
	// UptimeS 是进程运行秒数。
	UptimeS int64 `json:"uptime_s"`
	// Goroutines 是当前 goroutine 数。
	Goroutines int `json:"goroutines"`
	// RSSKB 是当前常驻内存（KiB）。
	RSSKB int64 `json:"rss_kb"`
}

// dispatch 把请求分发为响应帧；第二个返回值表示收到 kore.shutdown。
func dispatch(request *pluginapi.Request, cfg *config, logger *slog.Logger) (*pluginapi.Response, bool) {
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
		result, perr := cfg.reload()
		if perr != nil {
			response.Error = perr
			return response, false
		}
		response.Result = result
		return response, false
	case cfg.id + ".config.get", "config.get":
		result, perr := configGet(cfg)
		if perr != nil {
			response.Error = perr
			return response, false
		}
		response.Result = result
		return response, false
	case cfg.id + ".config.set", "config.set":
		result, perr := configSet(request.Params, cfg)
		if perr != nil {
			response.Error = perr
			return response, false
		}
		response.Result = result
		return response, false
	}

	verb, ok := businessVerb(request.Method, cfg.id)
	if !ok {
		response.Error = notFound(request.Method)
		return response, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	result, perr := cfg.detector().Call(ctx, verb, request.Params, cfg.queryTimeout())
	if perr != nil {
		response.Error = perr
		return response, false
	}
	response.Result = result
	return response, false
}

// businessVerb 把 <id>.<verb> 或裸 <verb> 归一为 DNS 方法动词名。
func businessVerb(method, id string) (string, bool) {
	verb := strings.TrimPrefix(method, id+".")
	for _, candidate := range dnsop.Methods() {
		if verb == candidate {
			return verb, true
		}
	}
	return "", false
}

// notFound 构造 E_NOTFOUND 错误体（§9）。
func notFound(method string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法：" + method}
}

// pingResult 组装 kore.ping 结果。
func pingResult(cfg *config) json.RawMessage {
	payload, err := json.Marshal(statusResult{
		Status:     "ready",
		UptimeS:    int64(time.Since(cfg.startedAt).Seconds()),
		Goroutines: runtime.NumGoroutine(),
		RSSKB:      rssKB(),
	})
	if err != nil {
		return json.RawMessage(`{"status":"ready"}`)
	}
	return payload
}
