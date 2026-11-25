# kore-plugin-dns 使用说明

kore 的 DNS 检测 / 区域读取 / 真实查询 / 记录写入插件（id `dns`）：同一套结果形状覆盖 systemd-resolved、dnsmasq、bind9、CoreDNS；不内置 DNS 服务，不安装、不启停、不写宿主配置。

## 安装与兼容性

由 kore 内核安装发布的 tar.gz；仓库可独立构建（`make build` / `make dist`）。协议 `kore.plugin.v1`，`requires_kore: >=0.1.0 <0.2.0`，`lifecycle=lazy`，深度等级 `basic`（故障注入尚未覆盖规范要求的两类）。记录写入以插件自身用户执行，不经 root_actions；唯一 root 动作是 `resolved-flush-caches`（由内核以 uid=0 执行）。

## 方法

| 方法 | 入参 | 结果要点 |
| --- | --- | --- |
| `dns.status` | `{engine?}` | 主引擎、版本、监听套接字、上游；`engine` 可强制指定 auto / systemd-resolved / dnsmasq / bind9 / coredns |
| `dns.zones` | `{}` | bind9 zone 块、dnsmasq 指令形成的区域，含 `records_count` / `readable` |
| `dns.records` | `{zone}` | A / AAAA / CNAME / MX / TXT / NS 记录，最多 500 条并带 `truncated` |
| `dns.query` | `{name, type?}` | 真实查询结果 `{answers[], rcode, elapsed_ms, resolver}`，dig → nslookup → Go 解析器三级回退 |
| `dns.record.add/update/delete` | `{zone,name,type,value,ttl?}` | bind9 RFC 2136 动态更新：快照 → 原子 UPDATE → 直连校验 → 失败回滚；同值幂等、异值 `E_CONFLICT` |
| `dns.addRecord/updateRecord/deleteRecord` | `{zone,name,type,value,old_value?}` | 0.4.0 兼容写入口：bind9 走动态更新，dnsmasq 写插件状态目录内 hosts 片段，其余引擎 `E_UNSUPPORTED` |
| `dns.reload` | `{zone?}` | 仅用于手工改过 zone / named.conf 后：bind9 `rndc reload`，systemd-resolved 经提权通道 `resolvectl flush-caches`，dnsmasq 返回 `reload_required=true`。**记录变更不需要 reload** |
| `dns.config.get/set` | 配置契约 | 引擎、四个只读路径、查询超时；0600 原子落盘、保存即生效 |
| `kore.ping/reload/shutdown` | `{}` | 协议必选方法 |

## 判读与安全边界

- `method_capabilities` 把 4 个只读方法标 `system:read`，7 个写方法标 `system:admin`；能力声明即授权面。
- 路径白名单限定只读区域文件；读不到区域给可复制命令提示（`E_NOTFOUND`）。
- 写路径 fail-closed：无 journal / 无 TSIG 密钥 / 密钥不可读 / 缺 nsupdate 时拒绝写入；journal 以 0600 JSONL 落盘。
- 未知区域 `E_NOTFOUND`，dnsmasq 不支持的记录类型 `E_UNSUPPORTED`，不静默失败。
- 写真实服务器尚未在本机验收（本机没有 allow-update 的 bind9），写入链路以 mock 宿主单测覆盖，不写成「已实测生效」。

## 构建与验证

```bash
make check                 # gofmt + go vet + go test -timeout 200s（含 race）
go test ./tests/live/...   # 真实主机读取与查询
make build && make dist    # 静态二进制与确定性 tar.gz
```

## 安全与贡献

漏洞不要开公开 issue，按 [SECURITY.md](SECURITY.md) 私密披露；贡献见 [CONTRIBUTING.md](CONTRIBUTING.md)。MIT 许可。
