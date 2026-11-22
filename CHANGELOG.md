# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.1.1] - 2026-11-23

- build: 位级可复现打包（stage chmod + tar --mode 归一、size_bytes 收敛），二进制改嵌 manifest.json，消除同版本 sha 漂移

## [0.1.0] - 2026-11-22

### 新增

- 首个 M5 批1 DNS 区域 / 记录管理插件骨架（`depth_level = basic`，`lifecycle = lazy`），协议 `kore.plugin.v1`，能力 `system:read`。
- `kore.hello` 三步握手：发 `kore.hello`（§5 全字段 + `id`/`token` 别名）→ 读响应帧 → 校验 `ok`/`id`/协议主版本。
- 会话循环：读帧 → 按 `method` 分发 → 写 `response`，回显 `id` 与 `req_id`；未知方法回 `E_NOTFOUND`。
- DNS 方法 `dns.zone.list` / `dns.record.add`：只做参数校验与结构化返回（`applied:false`），**不实际改动宿主 DNS 服务**。
- 语法校验：`zone` / `name` / CNAME 目标 / MX 目标域名白名单（小写、≥2 标签、标签 ≤63、总长 ≤253）；`A`/`AAAA` 用 `net.ParseIP` 严格解析；`MX` 校验优先级与目标；`ttl` 范围 `0..2147483647`；`type` 白名单 A/AAAA/CNAME/MX。
- 同会话提案注册表：`record.add` 登记的提案可由 `zone.list` 聚合可见，进程内内存实现，不落盘。
- `Makefile`：`build` / `dist`（回填 `size_bytes`、包内 `SHA256SUMS`、包旁 `.sha256`、显式条目 + gzip -9n 确定性打包）/ `check` / `fault` / `clean`。
- 单测：`net.Pipe` 模拟主壳侧，覆盖握手、两类 DNS 方法、四类合法记录、非法参数矩阵、`req_id` 回显与提案可见性。
- 基础级故障注入（`tests/fault/`）：`kill`（SIGKILL 强杀 + 连接中断断言）与 `timeout`（内核不回 hello 时插件 2s 超时退出，含正常握手对照组）两类。

### 说明

- 真实 DNS 服务下发、记录删除 / 修改、回滚五步记录留待后续版本；`depth_level` 升级生产级时补齐磁盘满 / cgroup 两类故障注入。
