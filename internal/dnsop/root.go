package dnsop

import (
	"context"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 本文件定义插件对内核提权通道（root_actions，ADR-0018 / ADR-0049）的依赖面。
//
// 边界：插件进程**永不** exec sudo / setuid / 直接写 /etc；需要 root 的动作只能在
// info.json 声明固定 argv，由内核在 uid=0 下执行。argv 必须落在 ADR-0022 的受控
// 命令形状表内（pkg/pluginapi/rootpolicy.go），否则安装/启用期即 E_INVALID。
//
// 当前形状表（SDK v0.1.3–v0.1.5 一致）只有 13 个命令：nginx / ufw / iptables /
// systemctl / crontab / chmod / chown / docker / nft / resolvectl / unbound-control /
// dig / fail2ban-client。**没有 rndc、没有 named-checkzone、也没有任何能写文件内容的
// 命令**（无 install / tee / sed / cp），因此 bind9 的 `rndc reload` 与 zone 文件写入
// 无法经本通道完成——这不是本插件能靠声明解决的，必须由 kore 侧新增形状并发布新
// SDK（ADR-0022 属安全边界变更）。相关反例由 root_action_declaration_test.go 钉住。

// RootActionResolvedFlush 是「刷新 systemd-resolved 缓存」动作的 id。
//
// 它是形状表内**唯一**能为 dns.reload 提供真实 root 执行的 DNS 动作：
// `resolvectl flush-caches` 是固定 argv、无追加参数、无副作用文件写入。
// id 与 info.json 的 root_actions[].id 必须逐字一致（测试守护）。
const RootActionResolvedFlush = "resolved-flush-caches"

// ResolvedFlushArgv 是声明给内核的固定 argv，也是 info.json 的唯一真源（测试逐字比对）。
//
// 用绝对路径而不是命令名：审计里能看到实际执行的程序，且不受 kored 进程 PATH 影响。
// /usr/bin 在 sysBinaryDirs 白名单内（合并 /usr 的 systemd 发行版均在此）。
var ResolvedFlushArgv = []string{"/usr/bin/resolvectl", "flush-caches"}

// ResolvedFlushCommand 是结果里展示给用户的可读命令（不含绝对路径）。
const ResolvedFlushCommand = "resolvectl flush-caches"

// RootActionOutput 是内核 root-action 执行结果（pluginapi 结果里本插件需要的子集）。
type RootActionOutput struct {
	// Stdout / Stderr 是内核采集的输出（各截断 1 MiB）。
	Stdout string
	// Stderr 用于失败时的可操作提示。
	Stderr string
	// ExitCode 是被调命令的真实退出码；-1 表示启动失败或超时被 kill。
	ExitCode int
}

// RootRunner 是插件→内核提权通道的调用面：nil 表示通道未注入（按降级处理）。
//
// confirm 不在接口里：本插件只声明只读/可逆动作（irreversible=false），不需要一次性令牌。
type RootRunner interface {
	// RunRootAction 经内核执行 info.json 声明过的动作，返回输出与退出码。
	RunRootAction(ctx context.Context, actionID string, args []string) (RootActionOutput, error)
}

// rootChannelUnavailable 构造「提权通道未注入」的 E_NEED_ROOT（ADR-0018 降级硬要求）。
//
// 触发场景：直接运行 bin/dns 联调（没有 KORE_KERNEL_SOCK 等三项注入）、或 kored 以
// 非 root 启动（内核侧拒绝并返回 E_NEED_ROOT）。禁止静默退化为「在插件进程里 sudo」。
func rootChannelUnavailable() *pluginapi.Error {
	return &pluginapi.Error{
		Code:    CodeNeedRoot,
		Message: "E_NEED_ROOT: 提权通道不可用，无法刷新 systemd-resolved 缓存",
		Detail: encodeDetail(map[string]string{
			"hint": "该动作需要 root：请用 sudo 启动 kored（内核以 uid=0 执行声明过的 root_actions），" +
				"或手工执行 sudo resolvectl flush-caches；直接运行插件时没有提权通道，插件也不会自行 sudo。",
			"action": RootActionResolvedFlush,
		}),
	}
}

// rootActionFailed 把通道错误映射成结构化错误：内核明确 E_NEED_ROOT 时保留该码，
// 其余（HTTP/协议/执行失败）归 E_UPSTREAM——不把非权限错误伪装成 root 问题。
func rootActionFailed(out RootActionOutput, err error) *pluginapi.Error {
	detail := map[string]string{
		"action": RootActionResolvedFlush,
		"error":  truncate(err.Error(), 500),
	}
	code := pluginapi.E_UPSTREAM
	message := "E_UPSTREAM: 提权通道执行 resolvectl flush-caches 失败"
	if strings.Contains(err.Error(), CodeNeedRoot) {
		code = CodeNeedRoot
		message = "E_NEED_ROOT: 刷新 systemd-resolved 缓存需要 root"
		detail["hint"] = "请用 sudo 启动 kored（非 root 时内核提权通道返回 E_NEED_ROOT），" +
			"或手工执行 sudo resolvectl flush-caches。"
	} else {
		detail["hint"] = "确认内核与插件版本匹配、root_actions 声明未被拒绝；" +
			"必要时手工执行 sudo resolvectl flush-caches 并查看内核审计日志。"
	}
	if snippet := strings.TrimSpace(out.Stderr); snippet != "" {
		detail["stderr"] = truncate(snippet, 1000)
	}
	return &pluginapi.Error{Code: code, Message: message, Detail: encodeDetail(detail)}
}
