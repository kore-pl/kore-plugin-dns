## 0.5.1 — 2026-11-24

### 变更（可用性：把「做不到」变成「用户能自己做到」）

- **`dns.reload` 文案立住定位**：成功结果与失败 hint 都写明「记录变更走 RFC 2136 动态更新、立即生效、
  不需要 reload；本操作只用于手工改过 zone 文件或 named.conf 之后」。bind9 成功文案从「区域已重新加载」
  改为带定位的整句（旧文案容易被误读成「改记录也要 reload」）；失败 hint 保留可直接执行的
  `sudo rndc reload [zone]` 与 `sudo systemctl reload named`，并去掉用户看不懂的内部形状表说明。
- **未知 zone / 空区域列表给四段可复制命令**（ADR-0051 §5.1.2）：`dns.records` 命中未知区域、`dns.zones`
  为空、`record.*` 写入未声明区域时，`detail.hint` 直接输出 zone 块（含 `allow-update { key ... }`）、
  最小区域文件、`named-checkzone`、`rndc reconfig`、`dig` 验证；域名与文件路径按本次操作填好，
  `kore-update` 明示为 TSIG 密钥名占位。插件**不执行**这些命令、不写宿主文件、不新增 root 动作。
- **记录读取降级补两条自助替代**（ADR-0051 §5.1.3）：`E_NEED_ROOT` 与区域文件不可读的 hint 从
  「sudo 启动 kored」改为 ① `sudo chmod 0644 <区域文件>`；② 放进 `/var/lib/kore/dns` 并在 named.conf 里
  `include`（同时把 `/var/lib/kore` 加入插件只读白名单，保证这条替代路径真的可读，不是文案谎言）；
  另给 `dns.query` 直查兜底。
- 文档：README 新增「新建 zone：面板给命令，用户执行（0.5.1）」小节，降级表 / 路径白名单 / 未完成项同步；
  `info.json` + `manifest.json` 版本同步。

### 测试

- 新增 `internal/dnsop/ux_guide_test.go`：四段命令存在性 + 域名填充 + **反例自证**（只有一句话的旧文案、
  逐段删掉任一命令都必须判不合格）、reload 文案正反例、读取降级两条替代、`/var/lib/kore/dns` 下的区域
  真实可读（证明替代路径有效）。
- `root_action_declaration_test.go` **未改动**：`root_actions` 仍只有 `resolved-flush-caches`，
  `TestBlockedDNSActionsRejectedByPolicy` 继续钉住 `rndc` / `named-checkzone` / 写文件动作必须被拒。

### 判定

- patch bump `0.5.0 → 0.5.1`：只有提示文案、只读路径白名单（新增 Kore 自有目录）与文档变化，
  无新方法、无新入参、无新 root 动作、无协议/schema 变更。

## 0.5.0 — 2026-11-24

### 新增

- **`root_actions` 声明 + 提权通道（ADR-0018 / ADR-0049）**：新增 `resolved-flush-caches` →
  `/usr/bin/resolvectl flush-caches`（固定 argv、无追加参数、`irreversible=false`），`requires_root: true`。
- **`dns.reload` 支持 systemd-resolved**：该引擎没有区域概念，经内核提权通道刷新缓存（此前是
  `E_UNSUPPORTED`）；带 `zone` 入参 → `E_INVALID`（不静默忽略）；通道缺失或 kored 非 root →
  `E_NEED_ROOT` + `sudo` hint，插件绝不自行 `sudo` / 直接执行 `resolvectl`。

### 说明（范围收窄，不是省略）

- 本轮**不声明** `rndc reload` / `rndc reconfig` / `named-checkzone` / 写 zone 文件：ADR-0022 的受控形状表
  （SDK v0.1.3–v0.1.5 一致）只有 13 个命令，没有 `rndc`、没有 `named-checkzone`、也没有任何写文件内容的命令，
  声明会被内核在安装/启用期以 `E_INVALID` 拒绝（插件不可用）。扩表属安全边界变更，需 kore 侧 ADR + 新 SDK。
- bind9 的 `dns.reload` 行为不变（`rndc reload [zone]`，失败 `E_NEED_ROOT`），hint 增补「形状表未开放 rndc」的说明。

### 测试

- 新增 `internal/dnsop/root_reload_test.go`：断言 resolved 分支**实际调用的 action_id 与零追加参数**
  （防 `engine`/`zone` 混入 argv 的同类错误复现）、带 zone 时拒绝且不触碰通道、内核 `E_NEED_ROOT` 映射与 hint、
  通道缺失降级、非零退出码归 `E_UPSTREAM`、声明 argv 通过 `ValidateRootAction`。
- 新增 `root_action_declaration_test.go`：声明 ↔ 代码一一对应（删声明即失败）、逐条跑 SDK 校验；
  `TestBlockedDNSActionsRejectedByPolicy` 断言 `rndc` / `named-checkzone` / 写文件动作**必须**被形状表拒绝。

### 判定

- 新增对外能力（reload 对 systemd-resolved 可用）+ 新增协议声明 `root_actions` → minor bump `0.4.2 → 0.5.0`。
- **未验证**：本机为普通用户，uid=0 下 `resolvectl flush-caches` 的真实成功路径未实测（只验证了非 root 报错与通道缺失降级）。

## 0.4.2 — 2026-11-24

### 变更

- **`depth_level`：`production` → `basic`**。依据 `kore/docs/PLUGIN-CATALOG.md` §6.1 升级判据①（边界用例：异常输入 / 并发 / 权限不足 / 资源耗尽各 ≥1 例并进 CI）**不满足**——本仓无 `tests/boundary/`，`grep -rn "t.Parallel" tests/` 命中 0。故障注入（判据②）已通过，但两条须同时满足；此前声明 `production` 属**过度声明**，索引的 `basic` 才是正确值。**非降级缺陷**，不涉及代码、能力与方法契约变化；补齐边界用例后再升 production。

## 0.4.1 — 2026-11-24

### 修复

- **`dns.reload` 把 `engine` 入参当成 `zone` 传给 `rndc`**（3b538e6 发现）：`call.go` 曾复用 `statusParams`
  并执行 `d.Reload(ctx, p.Engine)`，于是 `{"engine":"bind9"}` 实际执行 `rndc reload bind9`（把引擎名当区域名，
  必然失败且错误信息误导去查 zone）；同时声明的 `{"zone":"example.com"}` 反而被忽略。
  现在按 README 契约 `{zone?}` 解析并下传 `zone`，省略 zone 时执行 `rndc reload`（重载整个引擎）。
- 入参严格校验：`dns.reload` 的未声明字段（含 `engine`）→ `E_INVALID` + `detail.allowed=zone`，
  拒绝发生在执行之前（不再有「静默落到别的参数」的路径）。`zone` 非法同样 `E_INVALID` 且不执行 `rndc`。
- `ReloadResult.command` 在「重载整个引擎」时不再带尾随空格（`rndc reload`）。

### 测试

- 新增 `internal/dnsop/call_test.go`：断言 `{"zone":"Example.COM."}` → `rndc reload example.com`、
  **`{"engine":"bind9"}` 不产生 `rndc reload bind9` 且不触发任何 `rndc`**、空/`{}`/`null` → `rndc reload`、
  非法 zone 与非对象 params → `E_INVALID` 不执行。

### 判定

- 契约未变（仍是 `{zone?}`），不涉及 kore 协议/schema 变更 → 无 ADR、无主版本递增；仅插件行为修复 → patch。

## 0.4.0 — 2026-11-23

### 新增

- `dns.addRecord` / `dns.updateRecord` / `dns.deleteRecord`：记录写入（入参 `{zone,name,type,ttl,value,previous?}`）。
  按引擎分派：**bind9** 走 RFC2136 动态更新（`nsupdate` + TSIG 密钥，插件自身权限、不经 root、写前快照+写后校验+失败回滚）；
  **dnsmasq** 只写插件状态目录内的 hosts 片段（`<KORE_STATE_DIR>/dnsmasq/hosts.conf`，**不写 `/etc/dnsmasq.d`**，零侵入），
  支持 A/AAAA/CNAME，MX/TXT/SRV 返回 `E_UNSUPPORTED` 并给替代方案；systemd-resolved / CoreDNS → `E_UNSUPPORTED`。
  非 root 且未配 TSIG 密钥 → `E_NEED_ROOT` + hint（不回 401）；重复删除/重复新增为幂等空操作（`changed=false, applied=true`）。
- `dns.reload`：bind9 执行 `rndc reload [zone]`（拿不到 rndc 权限时 `E_NEED_ROOT` + hint）；dnsmasq 返回
  `reload_required=true` + 重启提示（插件不启停宿主服务）。

### 变更

- `capabilities` 增加 `system:admin`（写方法需要）；`method_capabilities` 新增 4 条 admin 声明，读方法保持 `system:read`。
- 不做：zone 文件整体编辑、TSIG 密钥生成、写 `/etc/dnsmasq.d`。需要用户提供：bind9 侧 `allow-update`/`update-policy` 与 TSIG 密钥文件路径（插件设置 `update_key_file`）。

# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.3.2] - 2026-11-23

### Changed

- 测试解耦版本号：`main_test.go` 不再硬编码发布版本字面量，改为断言 `version` 符合
  MAJOR.MINOR.PATCH 且内嵌清单、`info.json`、`manifest.json` 三处同步（Gitea dns#1 技术债），
  此后 bump 无需改测试；本次 bump 仅版本号变化，方法契约与行为不变。

## [0.3.1] - 2026-11-23

### Changed

- 提升为 `production` 深度等级（故障注入测试已覆盖）

## [0.3.0] - 2026-11-23

从「引擎无关只读」升级为**可写**：新增 bind9 记录写入（RFC 2136 动态更新），不需要 root、不需要 reload 服务。

### 新增（写路径：bind9 动态更新）

- **三个写方法**：`dns.record.add` / `dns.record.update` / `dns.record.delete`（`{zone, name, type, value, ttl?, old_value?}`），可写类型 `A` / `AAAA` / `CNAME` / `MX` / `TXT` / `SRV`；返回 `{operation, channel, previous[], changed, applied, verified, rolled_back, journal, reload_required, server, port, hint, error_code}`。
- **原子性**：每个操作是**一条 RFC 2136 UPDATE 消息**（`prereq` + `update delete`/`update add` 同一条消息，服务器原子应用），不是客户端「先删后加两条独立请求」。写前直连权威快照旧值，写后直连 `dig @server` 校验新状态；校验失败自动逆操作回滚并再次校验，`detail.rolled_back` 如实披露。
- **备份与审计**：下发前先写 journal `<KORE_STATE_DIR>/dns-journal/updates.jsonl`（0600，intent + result 两条，fsync），journal 写失败即中止写操作（不出现「改了但没记账」）；旧值快照同时进结果 `previous[]`，作为回滚依据（动态更新没有本地 zone 文件可备份）。
- **幂等与冲突**：add 同值幂等（`changed=false, applied=true`，不下发）、异值 `E_CONFLICT`；update 记录不存在 `E_NOTFOUND`、`old_value` 不匹配 `E_CONFLICT`；delete 不存在幂等。
- **注入面收敛**：`nsupdate` argv 固定（仅 `-k` 密钥、`-p` 端口），zone/name/type/value 全部走 stdin 脚本并逐类型校验（拒绝换行/控制字符，非 TXT 拒绝 `;`，name 必须在 zone 内，TTL 0–86400，TXT ≤255 字节）；`update_key_file` 限白名单目录（`/etc/bind`、`/var/lib/bind`、`/var/lib/kore` 等）。
- **零 root 依赖**：以插件用户 + TSIG 密钥执行，不写宿主配置、不启停服务、不声明 `root_actions` / `requires_root`，因此**不依赖内核 allowlist / root_actions 扩展**（ADR-0018 的提权通道本版用不上）。
- **降级（不静默）**：非 bind9 区域 → `E_UNSUPPORTED`+hint；区域不在 `bind_conf`（或不可读）→ `E_NOTFOUND`+hint；未配置 `update_key_file` → `E_UNSUPPORTED`+如何生成 TSIG；缺 `nsupdate`/`dig` → `E_UPSTREAM`；服务器拒绝 → `E_UPSTREAM` + `nsupdate_output` + 按 REFUSED/NOTAUTH/NOTZONE/连接失败分类的 hint。
- **配置契约新增 4 项**：`update_server`（默认 `127.0.0.1`）、`update_port`（默认 `53`）、`update_key_file`（空=写入未启用）、`update_timeout_ms`（默认 `5000`）；环境变量 `KORE_DNS_UPDATE_*` 兜底；config schema 6 → 10 个字段。
- **method_capabilities（7 条）**：`status`/`zones`/`records`/`query` → `system:read`；`record.add`/`record.update`/`record.delete` → `system:admin`。插件自身 `capabilities` 保持 `system:read`（调用方授权与插件自身权限分离）。
- 版本 `0.2.0` → `0.3.0`（新增对外方法与配置字段 → minor）；`manifest.json` 同步。

### 测试

- `internal/dnsop/recordwrite_test.go`：真实写入主链路（快照 → 原子 UPDATE → 直连校验 → journal 两条）、幂等/冲突、update 沿用快照 TTL、delete 幂等、校验失败自动回滚、类型/名字/值/TTL/注入拒绝、写通道 fail-closed（无 journal/无密钥/密钥不可读/缺 nsupdate/缺 dig）、区域归属（未知 `E_NOTFOUND` / dnsmasq `E_UNSUPPORTED`）、journal 落盘 0600 JSONL。
- `tests/fault/write_channel_test.go`：无 bind9 区域时写方法返回 `E_NOTFOUND`+hint、不产生 journal、插件继续服务（真二进制 + 真 UDS）。
- `main_test.go`：写入配置校验（地址/端口/密钥白名单/超时）与 detector 写通道装配。

### 诚实披露（未连真实 DNS 服务）

- 本机（2026-11-23）**没有运行中的 bind9、也没有 `rndc`/`named`**；`nsupdate` 与 `dig` 已安装，但无开启 `allow-update` 的权威实例可连。写入链路由 mock 宿主单测覆盖 argv 形状、脚本内容、校验与回滚，**未在真实 DNS 服务上验证生效**——不把单测说成端到端实测。
- 只支持 bind9：新建/删除 zone 需改 `named.conf`（root 配置面）不在本版；dnsmasq / systemd-resolved / CoreDNS 无动态更新接口，写入一律 `E_UNSUPPORTED`。
- `depth_level` 保持 `basic`：G-20 要求的「磁盘满 / cgroup 超限」两类规范故障注入仍未补，不冒充 `production`。

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
