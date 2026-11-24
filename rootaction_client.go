package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pengtang1024/kore-plugin-dns/internal/dnsop"
)

// rootActionTimeout 是插件经内核 root-action 通道执行动作的 HTTP 层上限；
// 动作本身的上限由 info.json 的 timeout_s（15s）兜底，这里只防 HTTP 永久挂住。
const rootActionTimeout = 15 * time.Second

// maxRootActionBody 是 root-action 响应体的读取上限（stdout/stderr 各 ≤1 MiB，留余量）。
const maxRootActionBody = 4 << 20

// rootActionRequest / rootActionResponse / rootActionError 是提权通道的 JSON 契约。
// 显式定形（G-24：不引入 object/any）。
type rootActionRequest struct {
	ActionID string   `json:"action_id"`
	Args     []string `json:"args,omitempty"`
}

type rootActionResponse struct {
	Executed bool   `json:"executed"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Unit     string `json:"unit"`
}

type rootActionError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// rootActionClient 是插件→内核提权通道的客户端（ADR-0018 / ADR-0049）。
//
// 传输：内核 UDS 上的 HTTP（KORE_KERNEL_SOCK 由 supervisor 注入）；
// 身份：KORE_PLUGIN_TOKEN bearer——内核只允许插件调用自己声明的 root_actions，
// 且要求该插件已获 system:admin。插件自身永不 exec sudo / setuid。
type rootActionClient struct {
	pluginID string
	token    string
	client   *http.Client
}

// newRootActionClient 在三个环境变量齐备时构造客户端；缺一返回 nil（通道不可用）。
func newRootActionClient() *rootActionClient {
	socket := os.Getenv("KORE_KERNEL_SOCK")
	token := os.Getenv("KORE_PLUGIN_TOKEN")
	pluginID := os.Getenv("KORE_PLUGIN_ID")
	if socket == "" || token == "" || pluginID == "" {
		return nil
	}
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}
	return &rootActionClient{
		pluginID: pluginID,
		token:    token,
		client:   &http.Client{Transport: transport, Timeout: rootActionTimeout},
	}
}

// kernelRootRunner 把 HTTP 客户端适配成 dnsop.RootRunner（业务层只依赖接口）。
type kernelRootRunner struct {
	client *rootActionClient
}

// RunRootAction 经内核执行一个声明过的 root 动作，返回输出与退出码。
// 错误信息保留内核错误码与 hint，便于上层拼可操作提示（不吞错、不改写成成功）。
func (r kernelRootRunner) RunRootAction(ctx context.Context, actionID string, args []string) (dnsop.RootActionOutput, error) {
	body, err := json.Marshal(rootActionRequest{ActionID: actionID, Args: args})
	if err != nil {
		return dnsop.RootActionOutput{}, fmt.Errorf("序列化 root-action 请求失败：%w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://kore/api/v1/plugins/"+r.client.pluginID+"/root-action", bytes.NewReader(body))
	if err != nil {
		return dnsop.RootActionOutput{}, fmt.Errorf("构造 root-action 请求失败：%w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.client.token)
	resp, err := r.client.client.Do(req)
	if err != nil {
		return dnsop.RootActionOutput{}, fmt.Errorf("调用内核 root-action 失败：%w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRootActionBody))
	if err != nil {
		return dnsop.RootActionOutput{}, fmt.Errorf("读取 root-action 响应失败：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var protocolErr rootActionError
		if json.Unmarshal(raw, &protocolErr) == nil && protocolErr.Code != "" {
			hint := ""
			if protocolErr.Hint != "" {
				hint = "（" + protocolErr.Hint + "）"
			}
			return dnsop.RootActionOutput{}, fmt.Errorf("%s: %s%s", protocolErr.Code, protocolErr.Message, hint)
		}
		return dnsop.RootActionOutput{}, fmt.Errorf("内核 root-action 返回 HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var result rootActionResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return dnsop.RootActionOutput{}, fmt.Errorf("解析 root-action 响应失败：%w", err)
	}
	return dnsop.RootActionOutput{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode}, nil
}

// rootRunnerFromEnv 在通道三要素齐备时返回调用面；缺一返回 nil（上层按 E_NEED_ROOT 降级）。
func rootRunnerFromEnv() dnsop.RootRunner {
	client := newRootActionClient()
	if client == nil {
		return nil
	}
	return kernelRootRunner{client: client}
}
