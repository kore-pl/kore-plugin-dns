# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.2.0] - 2026-11-23

### 新增（从 noop 到 L1.5 真实 DNS 管理）

- **引擎无关检测** `dns.status`：`systemd-resolved` / `dnsmasq` / `bind9` / `coredns` 四引擎探测，返回 `{available, engine, version, listening[], upstreams[], engines[], resolv_nameservers}`；运行判定 `systemctl is-active` + `pgrep -x` 双路，版本取各引擎原生命令，上游分别取 `resolvectl status` / `server=` / `forwarders`。
- **监听套接字探测**：`ss -lntup 'sport = :53'` 优先，`ss` 缺失时解析 `/proc/net/{tcp,tcp6,udp,udp6}`；套接字归属按「ss 属主进程 → stub 地址启发式 → 单引擎兜底」，归属不确定留空不猜。
- **区域列表** `dns.zones`：解析 bind9 `named.conf` 的 `zone "x" { type; file; }` 块（含引号、注释、相对 file）与 dnsmasq 的 `address=` / `server=` / `local=` / `host-record=` / `addn-hosts=` 指令，返回 `{name, type, file, records_count, readable, engine}`。
- **区域记录** `dns.records {zone}`：纯文本解析 bind zone 文件，支持 `A` / `AAAA` / `CNAME` / `MX` / `TXT` / `NS`，覆盖 `$ORIGIN` / `$TTL` / 省略 owner 的缩进续行 / 括号多行记录 / 行内与整行注释 / 引号 TXT；上限 500 条并给 `truncated` / `total`。
- **真实查询** `dns.query {name, type?}`：`dig` → `nslookup` → Go 解析器三级回退，固定 argv、名字补尾点防 search 域干扰，返回 `{answers[], rcode, elapsed_ms, resolver}`；`NXDOMAIN` 是正常结果而非错误。
- **配置契约** `dns.config.get` / `dns.config.set`：`engine` + 四个只读路径 + `query_timeout_ms`，0600 原子写、`config.json > env > 默认值`、保存即生效；`kore.reload` 重读并返回 `config_digest`。
- **只读路径白名单**：`/etc/bind`、`/var/lib/bind`、`/etc/dnsmasq.d`、`/etc/dnsmasq.conf`；配置与区域文件路径必须绝对、无 `..`、Clean 后前缀匹配。
- **ADR-0018 降级**：无引擎 → `available=false` + `E_NO_ENGINE` + 可操作 hint；区域文件被拒 → `readable=false` + warning，`dns.records` → `E_NEED_ROOT` + `detail.hint`；未知区域 → `E_NOTFOUND` + 可用区域提示；查询三路全挂 → `E_UPSTREAM` + `attempts`。
- `tests/live/` 真实主机验收（无 DNS 服务时跳过而非假通过）；本机实测：`systemd-resolved 259.9-0ubuntu0.1`（主）+ `dnsmasq 2.92`（libvirt，非主），`example.com A → 198.18.3.216`（dig，6ms）。
- `Makefile` 补 `fault` 目标（README 早已引用但目标缺失）。

### 变更

- **移除骨架方法** `zone.list` / `record.add`（只登记进程内提案、`applied:false`），由真实只读方法替代；`dns.zone.list` / `dns.record.add` 现在返回 `E_NOTFOUND`。
- 版本 `0.1.1` → `0.2.0`；`info.json` / `manifest.json` 同步。
- `dispatch` / `serve` / `handshake` 改为持有 `*config`，使 `config.set` 保存后同一进程内下一次调用即生效。

### 测试

- 单测：引擎检测四种引擎 + 优先级 + 强制指定 + 无引擎降级、监听解析（ss / `/proc/net`）、bind 与 dnsmasq 配置解析、zone 六类记录与注释/续行边界、路径白名单、500 条截断、权限降级、dig/nslookup 解析与回退。
- 故障注入扩到五类：`kill -9` / 握手超时 / 状态目录不可写（`E_INTERNAL` 且进程存活）/ 配置损坏启动即失败（退出码 1 + stderr 明因）/ `PATH` 清空降级（`E_NO_ENGINE` + Go 解析器）。

### 说明（诚实口径）

- 本机无 `/etc/bind`、`/var/lib/bind`、`/etc/dnsmasq.conf`，`/etc/dnsmasq.d/libvirt-daemon` 只有 `bind-interfaces` / `except-interface`，因此 `dns.zones` 在本机返回 0 区域 + 解释性 hint；bind/dnsmasq 区域解析由构造配置的单测覆盖。
- 写操作仍需 root，按 ADR-0018 走 `root_actions`；本版本无写方法，故**未声明** `root_actions`（不声明永不执行的动作）。
- `depth_level` 保持 `basic`：G-20 要求的磁盘满 / cgroup 超限两类规范故障注入未做，不冒充 `production`。

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
