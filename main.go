// Package main 是 kore 的 dns 插件：引擎无关的 DNS 管理（只读）。
//
// 插件不内置 DNS 服务，只检测并读取宿主已有的 systemd-resolved / dnsmasq / bind9 /
// coredns：dns.status 报引擎与监听/上游，dns.zones / dns.records 解析区域文件，
// dns.query 做真实查询，dns.config.get/set 管插件配置。改 zone 属于写操作，需要 root，
// 因此本版本只读；写路径按 ADR-0018 的 root_actions 通道另行落地。
//
// 协议面（kore.plugin.v1）：连接内核注入的 UDS → kore.hello 握手 → 会话循环
// 读 request、按 method 分发并回 response；stdout 留给协议，日志一律写 stderr。
package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
)

// main 按退出码区分失败：0 优雅退出、1 启动或协议失败。
func main() {
	logger := newLogger(os.Getenv("KORE_LOG_LEVEL"))
	if err := run(logger); err != nil {
		logger.Error("插件退出", "err", err)
		os.Exit(1)
	}
}

// run 依次完成建连、hello 握手与会话循环；收到 kore.shutdown 后返回 nil。
func run(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	conn, err := net.Dial("unix", cfg.socket)
	if err != nil {
		return fmt.Errorf("连接主壳 socket %s: %w", cfg.socket, err)
	}
	defer func() { _ = conn.Close() }()
	if err := handshake(conn, cfg); err != nil {
		return err
	}
	logger.Info("hello 完成", "plugin_id", cfg.id, "version", cfg.version)
	return serve(conn, cfg, logger)
}
