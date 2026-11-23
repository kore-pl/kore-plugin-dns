# kore-plugin-dns

kore 的 **DNS 检测 / 区域读取 / 真实查询插件**（L1.5，只读）。`info.json.depth_level = "basic"`：功能达 L1.5，故障注入尚未覆盖规范要求的四类（见「未完成项」）。

## 定位与边界

- **引擎无关**：同一套结果形状覆盖 `systemd-resolved` / `dnsmasq` / `bind9` / `coredns`，UI 不需要按引擎分支。
- **不内置 DNS 服务**：插件只检测、只读取、只查询宿主已有服务，不安装、不启停、不写任何宿主配置。
- **只读**：本版本没有任何写方法。改 zone 属于写操作、需要 root，按 [ADR-0018](../../kore/docs/DECISIONS/0018-privilege-model.md) 走内核 `root_actions` 通道（`systemd-run --uid=0`）另批落地——插件自己永不提权，也绝不 `exec sudo`。
- 协议：`kore.plugin.v1`，`lifecycle = lazy`，唯一外部依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1`（其余为标准库）。
- 能力声明 `system:read`：只读文件与只读命令，无写系统操作。

## 方法表

| 方法（裸名 / 全名） | 行为 |
| --- | --- |
| `dns.status` / `status` | 检测 DNS 服务：主引擎、版本、监听套接字、上游；可选 `engine` 强制指定（`auto` / `systemd-resolved` / `dnsmasq` / `bind9` / `coredns`） |
| `dns.zones` / `zones` | 区域列表（bind9 `named.conf` 的 zone 块 + dnsmasq 的 `address=` / `server=` / `local=`），含 `records_count` / `readable` |
| `dns.records` / `records` | 区域记录：`{zone}` → `A` / `AAAA` / `CNAME` / `MX` / `TXT` / `NS`，最多 500 条（`truncated` 标记） |
| `dns.query` / `query` | 真实查询 `{name, type?}` → `{answers[], rcode, elapsed_ms, resolver}`；`dig` → `nslookup` → Go 解析器三级回退 |
| `dns.config.get` / `dns.config.set` | 配置契约（引擎、四个只读路径、查询超时），0600 原子落盘、保存即生效 |
| `kore.ping` / `kore.reload` / `kore.shutdown` | 协议必选方法；`kore.reload` 重读配置并返回 `config_digest` |

### 检测口径（可复现）

| 引擎 | 运行判定 | 版本来源 | 上游来源 |
| --- | --- | --- | --- |
| `systemd-resolved` | `systemctl is-active systemd-resolved`，兜底 `pgrep -x systemd-resolve` | `resolvectl --version`（Ubuntu 上 `/usr/lib/systemd/systemd-resolved` 不在 PATH） | `resolvectl status` 的 `DNS Servers:` / `Current DNS Server:` |
| `dnsmasq` | `systemctl is-active dnsmasq`，兜底 `pgrep -x dnsmasq`（libvirt 直起进程时 systemd 无同名 unit） | `dnsmasq --version` | 配置里的 `server=` |
| `bind9` | `systemctl is-active named` / `bind9`，兜底 `pgrep -x named` | `named -v` | `named.conf.options` 的 `forwarders` |
| `coredns` | `systemctl is-active coredns`，兜底 `pgrep -x coredns` | `coredns -version` | 未解析（Corefile 不在只读白名单内，`note` 明示） |

- **主引擎选择**：`engine=auto` 时按 `systemd-resolved → dnsmasq → bind9 → coredns` 取第一个已检测者；配置保存的 `engine` 作为默认值，方法入参 `engine` 可临时覆盖。
- **监听套接字**：优先 `ss -lntup 'sport = :53'`（非 root 拿不到属主进程，只取地址/协议），`ss` 不可用时解析 `/proc/net/{tcp,tcp6,udp,udp6}`。归属规则：ss 属主进程名精确匹配 → `127.0.0.53/127.0.0.54` stub 地址启发式 → 只检测到一个引擎时全部归它；无法确定就留空，**不猜**。
- **命令全部固定 argv、不经 shell**：`systemctl is-active <unit>` / `pgrep -x <name>` / `resolvectl status` / `dnsmasq --version` / `named -v` / `coredns -version` / `ss -lntup 'sport = :53'` / `dig +time=N +tries=1 +noall +comments +answer <name>. <TYPE>` / `nslookup -type=<TYPE> -timeout=N <name>.`。

### 降级口径（ADR-0018：禁止静默失败）

| 场景 | 结果 |
| --- | --- |
| 四种引擎都不在 | `dns.status` → `available=false` + `error_code=E_NO_ENGINE` + 可操作 `hint`（含安装/启动命令），`engines` 仍返回 4 个候选的探测明细 |
| 强制指定引擎但未检测到 | `available=false` + `E_NO_ENGINE` + 列出可选引擎 |
| 区域文件存在但当前用户读不到 | `dns.zones` → `readable=false` + `warnings`；`dns.records` → `E_NEED_ROOT` + `detail.hint`（含 `sudo` 指引） |
| 区域声明本身读不到 | `dns.zones` → 空列表 + `error_code=E_NEED_ROOT` + `hint`（不是「没有区域」） |
| 未知区域 | `E_NOTFOUND` + `detail.hint`（列出可用区域） |
| `dig` / `nslookup` 都缺失 | `dns.query` 回退 Go 解析器，`resolver="go"` + `note` 说明精度下降 |
| 三级查询全部失败 | `E_UPSTREAM` + `detail.attempts`（逐条失败原因） |

### 路径白名单（只读）

插件只读这四个位置，配置里的路径必须落在白名单内（绝对路径、无 `..`、Clean 后前缀匹配）：

```
/etc/bind          # bind9 区域声明与区域文件
/var/lib/bind      # bind9 区域文件（Debian 系默认 zone 目录）
/etc/dnsmasq.d     # dnsmasq 片段目录
/etc/dnsmasq.conf  # dnsmasq 单文件配置（与 /etc/dnsmasq.d 同域，单列）
```

区域文件解析是**纯文本解析**：不展开 `include`、不执行任何脚本、不写回文件；`addn-hosts` 指向的文件同样必须在白名单内，越界只记 warning 并跳过。

## 配置契约

`<KORE_STATE_DIR>/config.json`，0600 原子写；优先级 `config.json > 环境变量 > 默认值`，保存后下一次方法调用即生效（`restart_required=false`）。

| 字段 | 类型 | 默认值 | 环境变量兜底 |
| --- | --- | --- | --- |
| `engine` | select | `auto` | `KORE_DNS_ENGINE` |
| `bind_conf` | string | `/etc/bind/named.conf.local` | `KORE_DNS_BIND_CONF` |
| `bind_zone_dir` | string | `/var/lib/bind` | `KORE_DNS_BIND_ZONE_DIR` |
| `dnsmasq_conf` | string | `/etc/dnsmasq.conf` | `KORE_DNS_DNSMASQ_CONF` |
| `dnsmasq_dir` | string | `/etc/dnsmasq.d` | `KORE_DNS_DNSMASQ_DIR` |
| `query_timeout_ms` | int (500–30000) | `3000` | `KORE_DNS_QUERY_TIMEOUT_MS` |

协议环境变量：

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `KORE_PLUGIN_SOCK` | 是 | 主壳创建的 UDS 路径 |
| `KORE_STATE_DIR` | 保存配置时必需 | 插件状态目录；未设置时 `config.set` 返回 `E_INTERNAL` 并说明原因 |
| `KORE_PLUGIN_ID` | 否 | 内核登记 id，缺省取内嵌 `manifest.json.id` |
| `KORE_PLUGIN_TOKEN` | 否 | 内核注入令牌；当前只随 `kore.hello` 上报 |
| `KORE_LOG_LEVEL` | 否 | `debug`/`info`/`warn`/`error`，缺省 `warn`；日志只写 stderr |

`stdout` 只留给协议帧，任何日志都不得写 stdout。

## 构建与打包

```bash
make build   # CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/dns .
make dist    # 产出 dist/dns-0.2.0.tar.gz（info.json + bin/dns + SHA256SUMS）与同名 .sha256
make check   # gofmt → go vet → go test -timeout 200s
make fault   # 先 build，再跑 tests/fault 的故障注入
go test ./tests/live/ -v   # 真实主机验收（无 DNS 服务时跳过，不算通过）
```

`dist` 按包内实际字节数回填 `info.json.size_bytes`（仓库清单保持 `0`，由打包脚本写入真实值）；tar 首条目固定为 `info.json`，两次出包 sha256 一致，干净树复现一致。

本地联调依赖**不提交**的 `go.work`（`use .` + `use ../kore/pkg/pluginapi`）；跨仓 `replace` 禁止写入 `go.mod`（G-17）。

## 本机真实检测结果（2026-11-23，Ubuntu 26.04 / uid 1000）

`go test ./tests/live/ -v` 的实测输出（可复跑）：

```
available=true engine="systemd-resolved" version="259.9-0ubuntu0.1"
upstreams=[2408:8899::8 223.5.5.5 223.6.6.6 2408:8888::8 fdfe:dcba:9876::2 198.18.0.2]
listening=[{127.0.0.53 53 tcp} {127.0.0.54 53 tcp} {127.0.0.53 53 udp} {127.0.0.54 53 udp}]
resolv=[127.0.0.53]
引擎明细：systemd-resolved detected=true running=true version="259.9-0ubuntu0.1"
引擎明细：dnsmasq          detected=true running=true version="2.92"     # libvirt 实例，监听 192.168.122.1:53，非主引擎
引擎明细：bind9            detected=false running=false version=""
引擎明细：coredns          detected=false running=false version=""
真实区域：count=0 scanned=[/etc/bind/named.conf.local /etc/dnsmasq.conf /etc/dnsmasq.d/libvirt-daemon]
真实查询 example.com A：{"answers":[{"name":"example.com","type":"A","value":"198.18.3.216","ttl":1}],"rcode":"NOERROR","elapsed_ms":6,"resolver":"dig"}
```

诚实说明：本机 **没有** `/etc/bind`、`/var/lib/bind`、`/etc/dnsmasq.conf`；`/etc/dnsmasq.d/libvirt-daemon` 只有 `bind-interfaces` / `except-interface` 两行，不产生区域。因此 `dns.zones` 在本机返回 0 条区域 + 解释性 hint；`dns.records` 走 `E_NOTFOUND` 路径。bind 区域解析与 dnsmasq 区域解析由单元测试用构造的配置覆盖（`internal/dnsop/*_test.go`），不是靠「本机没有」蒙过去。

## 测试

| 位置 | 覆盖 |
| --- | --- |
| `internal/dnsop/*_test.go` | 引擎检测（mock 宿主：四种引擎、优先级、强制指定、无引擎降级）、ss 与 `/proc/net` 监听解析、bind `named.conf` zone 块与 forwarders、zone 文件六类记录（owner 继承 / `$TTL` / `$ORIGIN` / 括号续行 / 注释 / 引号 TXT）、dnsmasq 五类指令与 hosts 文件、路径白名单、500 条截断、权限降级（`E_NEED_ROOT`）、dig/nslookup 输出解析与三级回退 |
| `tests/fault/` | `kill -9`、握手超时、状态目录不可写（`config.set` → `E_INTERNAL` 且进程存活）、配置损坏启动即失败（退出码 1 + stderr 明因）、`PATH` 清空时显式降级 + Go 解析器兜底 |
| `tests/live/` | 真实主机：引擎检测、区域与记录、`example.com` A 真实查询、未知区域 `E_NOTFOUND` |

## 未完成项（后续版本）

- **写操作**（改 zone / reload）：需要 root，按 ADR-0018 声明 `requires_root` + `root_actions` 经内核代理执行；本版本无写方法，因此**没有**声明 `root_actions`——不声明永远不会执行的动作，避免启用时让用户逐条确认空动作。
- `SRV` / `CAA` / `SOA` / `PTR` 的记录读取（查询侧已支持）；`$INCLUDE` 展开（当前忽略，避免越出白名单）。
- dnsmasq 条件转发与 libvirt 实例的配置位于 `/var/lib/libvirt/dnsmasq/`（不在只读白名单内），只做进程检测，不读其区域。
- CoreDNS 的 `Corefile` 上游解析（当前只报版本与进程状态）。
- `depth_level` 仍是 `basic`：G-20 要求的「磁盘满 / cgroup 超限」两类规范故障注入未做，因此不冒充 `production`。
- 前端页面（本仓库无 `web/`）。
