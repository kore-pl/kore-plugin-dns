// Package live 是本机真实环境的验收用例：直接拉起 bin/dns，向真实宿主问 dns.status /
// dns.zones / dns.records / dns.query。本机没有任何受支持 DNS 服务时跳过（不算通过），
// 检测到则必须给出真实引擎、真实监听与真实解析结果。
package live

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// liveTimeout 是单次调用的等待预算。
const liveTimeout = 20 * time.Second

// findBinary 从测试目录向上找仓根 bin/dns；不存在则从源码临时构建（与 fault 测试同策略）。
func findBinary(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目录失败: %v", err)
	}
	root := ""
	for depth := 0; depth < 5; depth++ {
		candidate := filepath.Join(dir, "bin", "dns")
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate
		}
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			root = dir
			break
		}
		dir = filepath.Dir(dir)
	}
	if root == "" {
		t.Fatalf("未找到仓根（含 go.mod）")
	}
	built := filepath.Join(t.TempDir(), "dns")
	cmd := exec.Command("go", "build", "-o", built, ".")
	cmd.Dir = root
	if output, buildErr := cmd.CombinedOutput(); buildErr != nil {
		t.Fatalf("临时构建 dns 失败: %v\n%s", buildErr, output)
	}
	return built
}

// session 是一条已完成握手的插件连接。
type session struct {
	conn net.Conn
	cmd  *exec.Cmd
}

// openSession 在临时 UDS 上拉起插件并完成 kore.hello 握手。
func openSession(t *testing.T) *session {
	t.Helper()
	binary := findBinary(t)
	sock := filepath.Join(t.TempDir(), "kore.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("监听 UDS 失败: %v", err)
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"KORE_PLUGIN_SOCK="+sock,
		"KORE_STATE_DIR="+t.TempDir(),
		"KORE_LOG_LEVEL=error",
	)
	if err := cmd.Start(); err != nil {
		_ = listener.Close()
		t.Fatalf("启动插件失败: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = listener.Close()
	})
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("接受连接失败: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(liveTimeout))
	payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读 kore.hello 失败: %v", err)
	}
	envelope, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		t.Fatalf("解码 kore.hello 失败: %v", err)
	}
	request, ok := envelope.(*pluginapi.Request)
	if !ok || request.Method != "kore.hello" {
		t.Fatalf("首帧不是 kore.hello: %+v", envelope)
	}
	if err := pluginapi.WriteJSON(conn, &pluginapi.Response{
		Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID,
		Result: json.RawMessage(`{"ok":true,"protocol":"kore.plugin.v1"}`),
	}); err != nil {
		t.Fatalf("写 hello 响应失败: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &session{conn: conn, cmd: cmd}
}

// call 发一个方法调用并返回 raw result（错误时直接失败并打印错误体）。
func (s *session) call(t *testing.T, method string, params any) json.RawMessage {
	t.Helper()
	payload := map[string]any{"type": "request", "id": "id-" + method, "req_id": "r-" + method, "method": method}
	if params != nil {
		payload["params"] = params
	}
	if err := pluginapi.WriteJSON(s.conn, payload); err != nil {
		t.Fatalf("发送 %s 失败: %v", method, err)
	}
	_ = s.conn.SetDeadline(time.Now().Add(liveTimeout))
	raw, err := pluginapi.ReadFrame(s.conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读 %s 响应失败: %v", method, err)
	}
	envelope, err := pluginapi.DecodeFrame(raw)
	if err != nil {
		t.Fatalf("解码 %s 响应失败: %v", method, err)
	}
	response, ok := envelope.(*pluginapi.Response)
	if !ok {
		t.Fatalf("%s 响应帧类型=%T", method, envelope)
	}
	if response.Error != nil {
		t.Fatalf("%s 返回错误: code=%s message=%s detail=%s", method, response.Error.Code, response.Error.Message, response.Error.Detail)
	}
	return response.Result
}

// close 发 kore.shutdown 并等待进程退出。
func (s *session) close(t *testing.T) {
	t.Helper()
	_ = pluginapi.WriteJSON(s.conn, &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id-shutdown", ReqID: "r-shutdown", Method: "kore.shutdown",
	})
	_, _ = pluginapi.ReadFrame(s.conn, pluginapi.MaxFrameSize)
	_ = s.conn.Close()
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("优雅退出失败: %v", err)
		}
	case <-time.After(liveTimeout):
		_ = s.cmd.Process.Kill()
		t.Fatal("kore.shutdown 后插件未退出")
	}
}

// statusBody 是 dns.status 的结果形状。
type statusBody struct {
	Available         bool     `json:"available"`
	Engine            string   `json:"engine"`
	Version           string   `json:"version"`
	Upstreams         []string `json:"upstreams"`
	ResolvNameservers []string `json:"resolv_nameservers"`
	ErrorCode         string   `json:"error_code"`
	Hint              string   `json:"hint"`
	Listening         []struct {
		Addr  string `json:"addr"`
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	} `json:"listening"`
	Engines []struct {
		Engine   string `json:"engine"`
		Detected bool   `json:"detected"`
		Running  bool   `json:"running"`
		Version  string `json:"version"`
	} `json:"engines"`
}

// TestLiveStatus 本机真实引擎检测：引擎标识必须属于四种受支持引擎，监听/上游与 resolv.conf 自洽。
func TestLiveStatus(t *testing.T) {
	s := openSession(t)
	defer s.close(t)
	var status statusBody
	if err := json.Unmarshal(s.call(t, "dns.status", nil), &status); err != nil {
		t.Fatalf("解析 status 失败: %v", err)
	}
	t.Logf("真实检测：available=%v engine=%q version=%q upstreams=%v listening=%v resolv=%v",
		status.Available, status.Engine, status.Version, status.Upstreams, status.Listening, status.ResolvNameservers)
	if !status.Available {
		if status.ErrorCode == "" || status.Hint == "" {
			t.Fatalf("不可用时必须给 error_code + hint（ADR-0018）：%+v", status)
		}
		t.Skipf("本机没有受支持的 DNS 服务，真实查询用例跳过：%s", status.Hint)
	}
	switch status.Engine {
	case "systemd-resolved", "dnsmasq", "bind9", "coredns":
	default:
		t.Fatalf("engine=%q 不在受支持集合内", status.Engine)
	}
	if len(status.Listening) == 0 {
		t.Fatalf("检测到引擎却没有监听套接字：%+v", status)
	}
	if len(status.Engines) != 4 {
		t.Fatalf("engines=%d，期望 4", len(status.Engines))
	}
	for _, engine := range status.Engines {
		t.Logf("引擎明细：engine=%s detected=%v running=%v version=%q", engine.Engine, engine.Detected, engine.Running, engine.Version)
	}
	if status.Engine == "systemd-resolved" && len(status.ResolvNameservers) == 0 {
		t.Fatalf("systemd-resolved 场景应有 resolv.conf nameserver：%+v", status)
	}
}

// TestLiveZonesAndRecords 真实区域：有区域则逐条读取记录；无区域则 hint 必须解释原因。
func TestLiveZonesAndRecords(t *testing.T) {
	s := openSession(t)
	defer s.close(t)
	var zones struct {
		Engine    string   `json:"engine"`
		Count     int      `json:"count"`
		Scanned   []string `json:"scanned"`
		Warnings  []string `json:"warnings"`
		ErrorCode string   `json:"error_code"`
		Hint      string   `json:"hint"`
		Zones     []struct {
			Name         string `json:"name"`
			Type         string `json:"type"`
			File         string `json:"file"`
			RecordsCount int    `json:"records_count"`
			Readable     bool   `json:"readable"`
		} `json:"zones"`
	}
	if err := json.Unmarshal(s.call(t, "dns.zones", nil), &zones); err != nil {
		t.Fatalf("解析 zones 失败: %v", err)
	}
	t.Logf("真实区域：engine=%q count=%d scanned=%v warnings=%v", zones.Engine, zones.Count, zones.Scanned, zones.Warnings)
	if zones.Count == 0 {
		if zones.Hint == "" {
			t.Fatalf("无区域时必须给 hint（不能空列表冒充没有数据）：%+v", zones)
		}
		t.Logf("本机无区域定义（正常：systemd-resolved 不管理区域文件），hint=%s", zones.Hint)
		return
	}
	for _, zone := range zones.Zones {
		if zone.Name == "" || zone.Type == "" {
			t.Fatalf("区域字段不完整：%+v", zone)
		}
		if !zone.Readable {
			t.Logf("区域 %s 不可读（%s），跳过记录读取", zone.Name, zone.File)
			continue
		}
		var records struct {
			Zone    string `json:"zone"`
			Count   int    `json:"count"`
			Total   int    `json:"total"`
			Records []struct {
				Name  string `json:"name"`
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"records"`
		}
		if err := json.Unmarshal(s.call(t, "dns.records", map[string]any{"zone": zone.Name}), &records); err != nil {
			t.Fatalf("解析 records(%s) 失败: %v", zone.Name, err)
		}
		if records.Count != len(records.Records) {
			t.Fatalf("区域 %s count=%d 与记录数 %d 不一致", zone.Name, records.Count, len(records.Records))
		}
		for _, record := range records.Records {
			switch record.Type {
			case "A", "AAAA", "CNAME", "MX", "TXT", "NS":
			default:
				t.Fatalf("区域 %s 返回了非支持类型：%+v", zone.Name, record)
			}
			if record.Name == "" || record.Value == "" {
				t.Fatalf("区域 %s 记录字段为空：%+v", zone.Name, record)
			}
		}
		head := "（空）"
		if len(records.Records) > 0 {
			head = records.Records[0].Name + " " + records.Records[0].Type + " " + records.Records[0].Value
		}
		t.Logf("区域 %s：%d/%d 条记录，首条=%s", zone.Name, records.Count, records.Total, head)
	}
}

// TestLiveQuery 真实 DNS 查询：必须真的经由 dig / nslookup / Go 解析器返回结果。
func TestLiveQuery(t *testing.T) {
	s := openSession(t)
	defer s.close(t)
	var status statusBody
	if err := json.Unmarshal(s.call(t, "dns.status", nil), &status); err != nil {
		t.Fatalf("解析 status 失败: %v", err)
	}
	if !status.Available {
		t.Skipf("本机没有受支持的 DNS 服务，跳过真实查询：%s", status.Hint)
	}
	var result struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Rcode     string `json:"rcode"`
		Resolver  string `json:"resolver"`
		ElapsedMs int64  `json:"elapsed_ms"`
		Answers   []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
			TTL   int    `json:"ttl"`
		} `json:"answers"`
	}
	raw := s.call(t, "dns.query", map[string]any{"name": "example.com", "type": "A"})
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 query 失败: %v", err)
	}
	t.Logf("真实查询 example.com A：%s", raw)
	if result.Name != "example.com" || result.Type != "A" {
		t.Fatalf("name/type=%q/%q", result.Name, result.Type)
	}
	switch result.Resolver {
	case "dig", "nslookup", "go":
	default:
		t.Fatalf("resolver=%q 不在 dig/nslookup/go 内", result.Resolver)
	}
	if result.Rcode == "" || result.ElapsedMs < 0 {
		t.Fatalf("rcode/elapsed_ms 非法：%+v", result)
	}
	if result.Rcode == "NOERROR" && len(result.Answers) == 0 {
		t.Fatalf("NOERROR 却无应答：%s", raw)
	}
	if result.Rcode != "NOERROR" {
		t.Logf("本次查询 rcode=%s（可能无外网），只校验结构化输出", result.Rcode)
	}
}

// TestLiveRecordsUnknownZone 未知区域必须是 E_NOTFOUND + 可操作 detail，而不是空记录。
func TestLiveRecordsUnknownZone(t *testing.T) {
	s := openSession(t)
	defer s.close(t)
	request := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id-unknown", ReqID: "r-unknown", Method: "dns.records",
		Params: json.RawMessage(`{"zone":"does-not-exist.invalid"}`),
	}
	if err := pluginapi.WriteJSON(s.conn, request); err != nil {
		t.Fatalf("发送请求失败: %v", err)
	}
	_ = s.conn.SetDeadline(time.Now().Add(liveTimeout))
	raw, err := pluginapi.ReadFrame(s.conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读响应失败: %v", err)
	}
	envelope, err := pluginapi.DecodeFrame(raw)
	if err != nil {
		t.Fatalf("解码响应失败: %v", err)
	}
	response, ok := envelope.(*pluginapi.Response)
	if !ok {
		t.Fatalf("响应帧类型=%T", envelope)
	}
	if response.Error == nil || response.Error.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("期望 E_NOTFOUND，实际 %+v", response.Error)
	}
	if !strings.Contains(string(response.Error.Detail), "hint") {
		t.Fatalf("detail 缺少 hint：%s", response.Error.Detail)
	}
	t.Logf("未知区域降级：code=%s message=%s detail=%s", response.Error.Code, response.Error.Message, response.Error.Detail)
}
