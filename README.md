# kore-plugin-dns

kore 的 **M5 批1 DNS 区域 / 记录管理插件**（基础级骨架）。`info.json.depth_level = "basic"`。

## 定位与边界

- 协议：`kore.plugin.v1`，`lifecycle = lazy`，唯一外部依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1`（其余为标准库）。
- **当前批次（0.1.0）只做参数校验与结构化返回，不实际改动宿主 DNS 服务**：`record.add` 只在进程内登记提案，`zone.list` 返回提案视图，`applied` 恒为 `false`。
- 能力声明 `system:read`：本骨架不执行任何写系统操作；真实下发留待后续版本（届时能力与 `depth_level` 同步升级，走 G-06 / G-20）。
- 基础级口径：故障注入只做 `kill` / `timeout` 两类（`tests/fault/`），四类齐全（磁盘满 / cgroup 超限）为生产级要求，延 v1.1。

## 方法表

| 方法（裸名 / 全名） | 行为 |
| --- | --- |
| `dns.zone.list` / `zone.list` | 返回 `{"zones":[...],"count":N,"applied":false}`；可选 `zone` 精确过滤 |
| `dns.record.add` / `record.add` | 校验 `zone` / `name` / `type` / `value` / `ttl` → 登记提案并返回结构化结果（`applied:false`） |
| `kore.ping` / `kore.reload` / `kore.shutdown` | 协议必选方法；`kore.reload` 无外部配置，`config_digest` 为空 |

`type` 白名单：`A` / `AAAA` / `CNAME` / `MX`（大小写不敏感，结果统一大写）。

校验规则：

- `zone` / `name` / CNAME 目标 / MX 目标：小写、标签以字母数字开头结尾、≥2 标签、标签 ≤63、总长 ≤253；拒绝大写、`_`、路径分隔符与 `..`。
- `A`：`net.ParseIP` 严格 IPv4；`AAAA`：严格 IPv6（两者拒绝彼此）。
- `MX`：`"优先级 域名"` 形式，优先级为 `0..65535` 规范十进制整数。
- `ttl`：可选，`0..2147483647`，缺省 `3600`。

响应帧一律回显请求的 `id` 与 `req_id`；未知方法回 `E_NOTFOUND`；参数非法回 `E_INVALID`。

## 环境变量

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `KORE_PLUGIN_SOCK` | 是 | 主壳创建的 UDS 路径 |
| `KORE_PLUGIN_ID` | 否 | 内核登记 id，缺省取内嵌 `info.json.id` |
| `KORE_PLUGIN_TOKEN` | 否 | 内核注入令牌；当前只随 `kore.hello` 上报 |
| `KORE_LOG_LEVEL` | 否 | `debug`/`info`/`warn`/`error`，缺省 `warn`；日志只写 stderr |

`stdout` 只留给协议帧，任何日志都不得写 stdout。

## 构建与打包

```bash
make build   # CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/dns .
make dist    # 产出 dist/dns-0.1.0.tar.gz（info.json + bin/dns + SHA256SUMS）与同名 .sha256
make check   # gofmt → go vet → go test -timeout 200s
make fault   # 先 build，再跑 tests/fault 的 kill/timeout 两类故障注入
```

`dist` 会按包内实际字节数回填 `info.json.size_bytes`（仓库里的清单保持 `0`，由打包脚本写入真实值）；tar 首条目固定为 `info.json`，两次出包 sha256 一致。

本地联调依赖**不提交**的 `go.work`（`use .` + `use ../kore/pkg/pluginapi`）；跨仓 `replace` 禁止写入 `go.mod`（G-17）。

## 未完成项（后续版本）

- `record.add` 的真实 DNS 服务下发与 `zone.list` 的真实区域数据源。
- 记录删除 / 修改方法与回滚五步记录。
- 生产级四类故障注入（磁盘满 / cgroup 超限）与 `depth_level` 升级。
