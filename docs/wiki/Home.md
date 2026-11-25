# DNS 区域 / 记录管理插件 Wiki

语言：简体中文（本 Wiki 以简体中文为主，完整七语言说明见仓库 `docs/DETAIL*.md`）。

页面：[Home](https://github.com/kore-pl/kore-plugin-dns/wiki/Home) · [Installation](https://github.com/kore-pl/kore-plugin-dns/wiki/Installation) · [Configuration](https://github.com/kore-pl/kore-plugin-dns/wiki/Configuration) · [Usage](https://github.com/kore-pl/kore-plugin-dns/wiki/Usage) · [FAQ](https://github.com/kore-pl/kore-plugin-dns/wiki/FAQ) · [Changelog](https://github.com/kore-pl/kore-plugin-dns/wiki/Changelog)

## 这是什么

DNS 区域 / 记录管理插件（id `dns`）是 kore 的DNS 检测、区域读取、真实查询与记录写入：引擎无关（systemd-resolved / dnsmasq / bind9 / CoreDNS），不内置 DNS 服务、不写宿主配置。

## 核心能力

- 四种引擎检测结果形状一致
- 区域与记录读取（A/AAAA/CNAME/MX/TXT/NS，500 条截断）
- 真实查询 dig → nslookup → Go 解析器三级回退
- bind9 走 RFC 2136 动态更新：快照 → 原子 UPDATE → 直连校验 → 失败回滚
- jsonl journal 0600，写路径 fail-closed
- 唯一 root 动作 resolved-flush-caches 经内核提权通道执行

协议 `kore.plugin.v1`，`lifecycle=lazy`，深度等级见仓库 `info.json`。内核、协议与 SDK 文档见 [kore](https://github.com/kore-pl/kore)。

## 快速开始

1. 安装：见 [Installation](https://github.com/kore-pl/kore-plugin-dns/wiki/Installation)。
2. 配置：见 [Configuration](https://github.com/kore-pl/kore-plugin-dns/wiki/Configuration)。
3. 调用：见 [Usage](https://github.com/kore-pl/kore-plugin-dns/wiki/Usage) 与仓库 README 的方法表。
4. 遇到问题：见 [FAQ](https://github.com/kore-pl/kore-plugin-dns/wiki/FAQ)。
