# kore-plugin-dns

kore 的 **DNS 检测 / 区域读取 / 真实查询 / 记录写入插件**（L1.5 → 可写：仅 bind9 动态更新）。`info.json.depth_level = "basic"`：功能达 L1.5，故障注入尚未覆盖规范要求的四类（见「未完成项」）。

## 定位与边界

- **引擎无关**：同一套结果形状覆盖 `systemd-resolved` / `dnsmasq` / `bind9` / `coredns`，UI 不需要按引擎分支。
- **不内置 DNS 服务**：插件只检测、只读取、只查询宿主已有服务，不安装、不启停、不写任何宿主配置。
- **可写但不需要 root**：`record.add` / `record.update` / `record.delete` 走 bind9 的 **RFC 2136 动态更新**（固定 argv 的 `nsupdate -k <TSIG>`，脚本走 stdin），以插件自身用户执行；不写宿主配置文件、**记录变更不需要 reload**（立即生效）、不经 `root_actions`。`dns.reload` 只用于手工改过 zone 文件或 `named.conf` 之后的重新加载。插件永不提权，也绝不 `exec sudo`。
- **唯一的 root 动作（0.5.0）**：`resolved-flush-caches` → `/usr/bin/resolvectl flush-caches`，由内核以 uid=0 执行，供 `dns.reload` 在 systemd-resolved 引擎下刷新缓存。`requires_root: true` 只声明这一条；bind9 的 `rndc` / zone 写入**没有**声明（理由见下文「root_actions 边界」）。
- 协议：`kore.plugin.v1`，`lifecycle = lazy`，唯一外部依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.3`（其余为标准库）。
- 能力声明保持 `system:read`（插件自身只需读文件/只读命令；动态更新用插件用户的 TSIG 密钥，不需要宿主特权），另声明 `system:admin` 作为提权通道的调用前提。方法级 `method_capabilities` 把**调用方**要求下沉：4 个只读方法（`status` / `zones` / `records` / `query`）`system:read`，7 个写方法（`record.add/update/delete`、`addRecord/updateRecord/deleteRecord`、`reload`）`system:admin`。

## 方法表

| 方法（裸名 / 全名） | 行为 |
| --- | --- |
| `dns.status` / `status` | 检测 DNS 服务：主引擎、版本、监听套接字、上游；可选 `engine` 强制指定（`auto` / `systemd-resolved` / `dnsmasq` / `bind9` / `coredns`） |
| `dns.zones` / `zones` | 区域列表（bind9 `named.conf` 的 zone 块 + dnsmasq 的 `address=` / `server=` / `local=`），含 `records_count` / `readable` |
| `dns.records` / `records` | 区域记录：`{zone}` → `A` / `AAAA` / `CNAME` / `MX` / `TXT` / `NS`，最多 500 条（`truncated` 标记） |
| `dns.query` / `query` | 真实查询 `{name, type?}` → `{answers[], rcode, elapsed_ms, resolver}`；`dig` → `nslookup` → Go 解析器三级回退 |
| `dns.record.add` / `record.add` | 新增记录 `{zone, name, type, value, ttl?}`：快照 → 原子动态更新 → 直连权威查询校验 → 未生效自动回滚；同值幂等、异值 `E_CONFLICT` |
| `dns.record.update` / `record.update` | 改记录 `{zone, name, type, value, old_value?, ttl?}`：同一条 UPDATE 消息内先删后加（原子），可带旧值前置条件 |
| `dns.record.delete` / `record.delete` | 删记录 `{zone, name, type, value?}`：省略 value 删除该 name/type 全部值；不存在时幂等 |
| `dns.addRecord` / `updateRecord` / `deleteRecord` | 0.4.0 兼容写入口 `{zone, name, type, ttl?, value, old_value?}`：按引擎分派——bind9 走 RFC 2136（同 `record.*` 通道），dnsmasq 写插件状态目录内的 hosts 片段（只支持 `A`/`AAAA`/`CNAME`，其余类型 `E_UNSUPPORTED`），systemd-resolved / CoreDNS 不支持 |
| `dns.reload` | **记录变更不需要它**（RFC 2136 动态更新立即生效）；只用于手工改过 zone 文件 / `named.conf` 之后。`{zone?}` → 按引擎：**bind9** 执行 `rndc reload [zone]`（省略 zone = 重载整个引擎）；**systemd-resolved** 经内核提权通道执行 `resolvectl flush-caches`（无区域概念，带 zone → `E_INVALID`）；**dnsmasq** 返回 `reload_required=true`（插件不启停宿主服务）；返回 `{engine, reloaded, reload_required, command?, hint}`；**不接受 `engine`**（引擎由配置/探测决定，未声明字段 → `E_INVALID`）；拿不到 root/提权通道时 `E_NEED_ROOT` + hint |
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
| 区域文件存在但当前用户读不到 | `dns.zones` → `readable=false` + `warnings`；`dns.records` → `E_NEED_ROOT` + `detail.hint`（两条自助替代：`chmod 0644`，或放进 `/var/lib/kore/dns` 并 `include`；也可用 `dns.query` 直查） |
| 区域声明本身读不到 | `dns.zones` → 空列表 + `error_code=E_NEED_ROOT` + `hint`（不是「没有区域」） |
| 未知区域 | `E_NOTFOUND` + `detail.hint`（列出可用区域 + **可直接复制的建 zone 四段命令**，见「新建 zone」） |
| `dig` / `nslookup` 都缺失 | `dns.query` 回退 Go 解析器，`resolver="go"` + `note` 说明精度下降 |
| 三级查询全部失败 | `E_UPSTREAM` + `detail.attempts`（逐条失败原因） |
| `dns.reload` 传了未声明的入参（如 `engine`） | `E_INVALID` + `detail.allowed=zone`；被拒入参不会被执行（不再把 engine 当 zone 传给 `rndc`） |
| `dns.reload`（systemd-resolved）且 kored 非 root / 无提权通道 | `E_NEED_ROOT` + `detail.hint`（`sudo` 启动 kored 或手工 `sudo resolvectl flush-caches`）；插件进程绝不自行执行 |
| `dns.reload`（systemd-resolved）带 `zone` | `E_INVALID`（该引擎没有区域概念，省略 zone 即整体刷新缓存；不静默忽略 zone） |

## 记录写入（bind9 动态更新）

`dns.record.add` / `record.update` / `record.delete` 的写路径**只支持 bind9**，机制是 RFC 2136 动态更新 ——
不重写 zone 文件、不改 `named.conf`、不 reload 服务：

1. **前置条件**（部署侧一次性配置，插件不替用户改）：
   - bind9 zone 开启 `allow-update { key "kore-update"; };`（或等价 `update-policy`）；
   - 生成 TSIG 密钥（如 `tsig-keygen kore-update > /etc/bind/kore-update.key`），kore 运行用户可读（`chgrp` + `0640` 或放到 `/var/lib/kore`）；
   - `update_server` / `update_port` 指向**权威 bind9 实例**（不是 `127.0.0.53` 的 systemd-resolved stub）。
2. **执行顺序**：直连权威快照旧值 → 写 journal `intent` → `nsupdate` 下发（prereq + update 同一条消息，服务器原子应用）→ 直连 `dig` 校验新状态 → 失败则逆操作回滚并再校验 → 写 journal `result`。
3. **为何不需要 root**：`nsupdate` 以插件用户身份运行，授权靠 TSIG 密钥与服务器 ACL；journal 与旧值快照落在 `<KORE_STATE_DIR>/dns-journal/updates.jsonl`（0600），作为"保留备份 + 回滚依据"（动态更新没有本地 zone 文件可备份）。
4. **生效判定**：`applied` = 服务器接受且校验通过；`verified` = 直连权威查询确认；`reload_required` 恒为 `false`。`changed=false` 是幂等空操作（未下发任何更新）。
5. **降级（不静默）**：非 bind9 区域 → `E_UNSUPPORTED` + hint；区域不在 `bind_conf` 中（或不可读）→ `E_NOTFOUND` + hint；未配置 `update_key_file` → `E_UNSUPPORTED` + 如何生成密钥；缺 `nsupdate` / `dig` → `E_UPSTREAM`；服务器拒绝 → `E_UPSTREAM` + `nsupdate_output` + 按 REFUSED/NOTAUTH/NOTZONE/连接失败分类的 hint；校验失败 → 自动回滚并在 `detail.rolled_back` 披露结果。
6. **安全边界**：`nsupdate` argv 固定（只有 `-k` 密钥与 `-p` 端口），zone/name/type/value 全部进 stdin 脚本且逐类型校验（拒绝换行/控制字符，非 TXT 拒绝 `;`）；`name` 必须在 `zone` 内；可写类型仅 `A/AAAA/CNAME/MX/TXT/SRV`（NS/SOA/PTR 等区域结构不开放）。
7. **新建 zone 不在面板里做**（要改 `named.conf`，属一次性系统配置，ADR-0051 裁决 A）：面板不提供「新建 zone」按钮，但 `dns.zones` 为空 / `dns.records` 命中未知 zone 时**会直接给出四段可复制命令**（zone 块含 `allow-update`、区域文件、`named-checkzone`、`rndc reconfig`、`dig` 验证），见下一节「新建 zone」。
8. **其余不支持**：systemd-resolved / CoreDNS 写入、`$INCLUDE` 展开与 zone 文件编辑；bind9 的 `rndc reload` 经 `root_actions` 执行也**尚不支持**（形状表未开放 `rndc`，见「root_actions 边界」）。

### 新建 zone：面板给命令，用户执行（0.5.1）

ADR-0051 裁决 A：**不扩形状表，v1 面板没有「新建 zone」按钮**。代价明说，但「做不到」不能变成死路——

`dns.zones` 返回空列表、`dns.records` / `record.*` 命中未知 zone 时，`detail.hint` 直接输出下面的四段命令
（域名、区域文件路径已按本次操作填好，`kore-update` 是 TSIG 密钥名占位，需换成实际名字）：

```bash
# 1) 声明 zone（写进 /etc/bind/named.conf.local；BIND 9.11 请把 type primary 改成 type master）
zone "example.com" {
    type primary;
    file "/var/lib/bind/example.com.zone";
    allow-update { key "kore-update"; };
};

# 1b) 区域文件不存在时先建一个最小可用的（已存在请跳过，不要覆盖）
sudo test -e /var/lib/bind/example.com.zone || sudo tee /var/lib/bind/example.com.zone >/dev/null <<'ZONE'
$TTL 300
@   IN SOA ns.example.com. admin.example.com. (2026112401 3600 600 86400 300)
@   IN NS  ns.example.com.
ns  IN A   127.0.0.1
ZONE

# 2) 校验 zone 语法与文件路径
sudo named-checkzone example.com /var/lib/bind/example.com.zone

# 3) 让 named 读取新配置（新建 zone 用 reconfig；只改已有 zone 文件时用 rndc reload example.com）
sudo rndc reconfig

# 4) 验证
dig @127.0.0.1 example.com SOA +short
```

- 这些命令**由用户手工执行**：插件不执行、不写宿主文件、不新增 root 动作（`root_action_declaration_test.go` 仍钉住 `rndc` / `named-checkzone` / 写文件动作必须被形状表拒绝）。
- 建好后记录增删改继续走面板（RFC 2136 动态更新），**不需要再 reload**。
- 区域文件读不到时还有两条自助替代：`sudo chmod 0644 <zone 文件>`，或把文件放进 `/var/lib/kore/dns` 并在 `named.conf` 中 `include`（该目录已在插件只读白名单内）。

### 兼容写入口与 reload（0.4.0）

`dns.addRecord` / `dns.updateRecord` / `dns.deleteRecord` 是同一套写入能力的兼容入口，入参与
`record.*` 同源（`old_value` 是旧值前置条件），差别在**按引擎分派**：

- **bind9** → RFC 2136 动态更新，链路同上一节（快照 → journal → 下发 → 校验 → 失败回滚）。
- **dnsmasq** → 只写插件状态目录里的 hosts 片段 `<KORE_STATE_DIR>/dnsmasq/hosts.conf`，**不写 `/etc/dnsmasq.d`**（零侵入），
  支持 `A` / `AAAA` / `CNAME`；`MX` / `TXT` / `SRV` 返回 `E_UNSUPPORTED` 并给替代方案。
- 重复新增 / 重复删除是幂等空操作（`changed=false, applied=true`）；非 root 且未配 TSIG 密钥 → `E_NEED_ROOT` + hint。

`dns.reload` 与 `kore.reload` 不同：`kore.reload` 只重读插件配置，`dns.reload` 会让 **bind9 重新加载区域**（`rndc reload [zone]`）。
动态更新本身立即生效、不需要 reload，这个方法是给手工改过 zone 文件或想看服务端确认的场景用的。

入参契约只有可选的 `zone`：省略表示重载整个引擎，写了表示只重载该区域。**`engine` 不是 `dns.reload` 的入参**——
用哪个引擎由插件配置（`engine`）与宿主探测决定；传 `engine` 等未声明字段返回 `E_INVALID`，不会被执行，
也不会被当成 zone（0.4.0 的 `{"engine":"bind9"}` → `rndc reload bind9` 缺陷在 0.4.1 修复）。

### root_actions 边界（0.5.0）

`info.json` 只声明**一条** root 动作，因为这是 ADR-0022 受控形状表（`kore/pkg/pluginapi/rootpolicy.go`）里
唯一能承载 DNS 重载语义的形状：

| id | argv（固定） | 用途 | 追加参数 |
| --- | --- | --- | --- |
| `resolved-flush-caches` | `/usr/bin/resolvectl` `flush-caches` | `dns.reload`（systemd-resolved 引擎）刷新缓存 | **禁止**（形状表无 Tail） |

**为什么不是 `rndc reload` / `rndc reconfig` / `named-checkzone` / 写 zone 文件**：形状表目前只有 13 个命令
（`nginx` / `ufw` / `iptables` / `systemctl` / `crontab` / `chmod` / `chown` / `docker` / `nft` / `resolvectl` /
`unbound-control` / `dig` / `fail2ban-client`），**没有 `rndc`、没有 `named-checkzone`、也没有任何能写文件内容的命令**
（无 `install` / `tee` / `sed` / `cp`），且 `systemctl` 只开放只读子命令（无 `reload`）。
声明这些动作会被内核在安装/启用期以 `E_INVALID` 拒绝（插件直接不可用），所以本版**不声明**；
`root_action_declaration_test.go::TestBlockedDNSActionsRejectedByPolicy` 把这条边界钉成可执行断言。
扩表属安全边界变更，必须走 kore 侧 ADR-0022 增补 + 新 SDK 版本，插件侧无法绕过。

**argv 构造防混用**：`dns.reload` 的 resolved 分支传 `action_id` + **零追加参数**（`zone` 已在调用方被拒绝、
`engine` 从不是入参）；`internal/dnsop/root_reload_test.go` 断言实际 `actionID` 与 `args`，并断言插件进程
既不执行 `rndc` 也不自行执行 `resolvectl`。bind9 分支仍是 `rndc reload [zone]`，由既有用例逐字断言
`rndc reload example.com` 且**不存在** `rndc reload bind9`。

**非 root / 通道缺失**：kored 非 root 时内核返回 `E_NEED_ROOT`，插件原样映射并给 `sudo` hint；
直接运行 `bin/dns`（无 `KORE_KERNEL_SOCK` / `KORE_PLUGIN_TOKEN` / `KORE_PLUGIN_ID`）时同样 `E_NEED_ROOT`，
**绝不**退化为在插件进程里 `sudo` 或直接执行 `resolvectl`。

### 路径白名单（只读）

插件只读这五个位置，配置里的路径必须落在白名单内（绝对路径、无 `..`、Clean 后前缀匹配）：

```
/etc/bind          # bind9 区域声明与区域文件
/var/lib/bind      # bind9 区域文件（Debian 系默认 zone 目录）
/etc/dnsmasq.d     # dnsmasq 片段目录
/etc/dnsmasq.conf  # dnsmasq 单文件配置（与 /etc/dnsmasq.d 同域，单列）
/var/lib/kore      # Kore 自有目录：区域文件读不到时的替代落点（0.5.1 起）
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
| `update_server` | string（IP 或主机名） | `127.0.0.1` | `KORE_DNS_UPDATE_SERVER` |
| `update_port` | int (1–65535) | `53` | `KORE_DNS_UPDATE_PORT` |
| `update_key_file` | string（白名单目录内的绝对路径） | 空（写入未启用） | `KORE_DNS_UPDATE_KEY_FILE` |
| `update_timeout_ms` | int (500–30000) | `5000` | `KORE_DNS_UPDATE_TIMEOUT_MS` |

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
make dist    # 产出 dist/dns-0.5.2.tar.gz（info.json + bin/dns + SHA256SUMS）与同名 .sha256
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
| `internal/dnsop/recordwrite_test.go` | 写入主链路（快照 → 原子 UPDATE → 直连校验 → journal 两条）、同值幂等/异值 `E_CONFLICT`、update 沿用快照 TTL、delete 幂等、校验失败自动回滚（逆操作脚本 + `rolled_back`）、类型/名字/值/TTL/注入拒绝、写通道 fail-closed（无 journal / 无密钥 / 密钥不可读 / 缺 nsupdate / 缺 dig）、区域归属（未知 `E_NOTFOUND` / dnsmasq `E_UNSUPPORTED`）、journal 落盘 0600 JSONL |
| `internal/dnsop/root_reload_test.go` | 提权通道：resolved reload 的 `action_id` + **零追加参数**（防 engine/zone 混入）、带 zone 拒绝且不触碰通道、内核 `E_NEED_ROOT` 映射与 hint、通道缺失降级、非零退出码 `E_UPSTREAM`、声明 argv 过 `ValidateRootAction` |
| `internal/dnsop/ux_guide_test.go` | 0.5.1 文案：未知 zone / 空列表含四段可复制命令（含反例自证：旧一句话文案与删段文案必须判不合格）、reload 文案必须说明「动态更新不需要 reload」（含反例）、读取降级两条替代 + `/var/lib/kore/dns` 真实可读 |
| `root_action_declaration_test.go` | 声明 ↔ 代码一一对应（删声明即失败）、SDK 校验逐条通过、`TestBlockedDNSActionsRejectedByPolicy` 钉住 `rndc`/`named-checkzone`/写文件动作必须被形状表拒绝 |
| `tests/fault/` | `kill -9`、握手超时、状态目录不可写（`config.set` → `E_INTERNAL` 且进程存活）、配置损坏启动即失败（退出码 1 + stderr 明因）、`PATH` 清空时显式降级 + Go 解析器兜底 |
| `tests/live/` | 真实主机：引擎检测、区域与记录、`example.com` A 真实查询、未知区域 `E_NOTFOUND` |

## 未完成项（后续版本）

- **写路径的真实服务器验收未做**：本机（2026-11-23）没有运行中的 bind9、也没有 `rndc`；`nsupdate` / `dig` 已安装，但无 `allow-update` 的权威实例可连。写入链路由 mock 宿主单测覆盖（argv、脚本形状、校验、回滚、journal），**未连真实 DNS 服务**（不说成"已实测生效"）。
- **zone 生命周期**：新建/删除 zone 需要改 `named.conf` 与 zone 文件（一次性系统配置），本版不在面板里做，由面板给出四段可复制命令、用户手工执行（ADR-0051）。
- **bind9 重载 / zone 写入经提权通道未落地**：`rndc`、`named-checkzone` 与写文件命令都不在 ADR-0022 的形状表内，声明即被安装期拒绝；需 kore 侧扩展形状表 + 新 SDK 后才能补（本版只声明 `resolved-flush-caches`，bind9 reload 仍需 `sudo`）。
- **root 成功路径未在本机验证**：本机以普通用户运行，只能验证「非 root → `E_NEED_ROOT` + hint」与「通道缺失 → `E_NEED_ROOT`」；`resolvectl flush-caches` 以 uid=0 执行的真实成功路径**未验证**（不写成已实测）。
- **dnsmasq / systemd-resolved / CoreDNS 写入**：没有等价的动态更新接口，写方法对它们一律 `E_UNSUPPORTED`（不静默失败）。
- `SRV` / `CAA` / `SOA` / `PTR` 的记录读取（查询侧已支持）；`$INCLUDE` 展开（当前忽略，避免越出白名单）。
- dnsmasq 条件转发与 libvirt 实例的配置位于 `/var/lib/libvirt/dnsmasq/`（不在只读白名单内），只做进程检测，不读其区域。
- CoreDNS 的 `Corefile` 上游解析（当前只报版本与进程状态）。
- `depth_level` 仍是 `basic`：G-20 要求的「磁盘满 / cgroup 超限」两类规范故障注入未做，因此不冒充 `production`。
- 前端页面（本仓库无 `web/`）。

<!-- oss:begin -->
## 开源与贡献

[![CI](https://github.com/kore-pl/kore-plugin-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/kore-pl/kore-plugin-dns/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)

本仓库是 **kore** 的 `DNS 区域 / 记录管理插件`（id `dns`），独立仓库、独立版本线、独立 CI（少触发：push main / tag / PR / 手动）。内核与协议见 [kore](https://github.com/kore-pl/kore)。

- **许可**：MIT（inbound = outbound，不要求 CLA）；提交用 `git commit -s` 签 DCO。
- **贡献**：[CONTRIBUTING.md](CONTRIBUTING.md)（构建、门禁、发版、边界）。
- **安全**：[SECURITY.md](SECURITY.md)——漏洞不要开公开 issue。
- **行为准则**：[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
- **兼容性**：`protocol: kore.plugin.v1` · `requires_kore: >=0.1.0 <0.2.0` · `lifecycle: lazy` · 深度等级 `basic`。
- **验证方式**：本地 `make check` 优先（CI 只在 push main / tag / PR / 手动跑；发布前 `make dist` 连跑两次核对 sha 一致）。
- **发布产物**：`make dist` → `dist/dns-0.5.2.tar.gz` + `.sha256`（位级可复现，连跑两次 sha 相同）。
- **相关仓库**：[索引 kore-plugins](https://github.com/kore-pl/kore-plugins) · [协议文档](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-PROTOCOL.md) · [SDK 指南](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-SDK.md)

<!-- oss:end -->
