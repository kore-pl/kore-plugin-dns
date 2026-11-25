# DNS 区域 / 记录管理插件 Wiki

语言：简体中文（本 Wiki 以简体中文为主，完整七语言说明见仓库 `docs/DETAIL*.md`）。

页面：[Home](https://github.com/kore-pl/kore-plugin-dns/wiki/Home) · [Installation](https://github.com/kore-pl/kore-plugin-dns/wiki/Installation) · [Configuration](https://github.com/kore-pl/kore-plugin-dns/wiki/Configuration) · [Usage](https://github.com/kore-pl/kore-plugin-dns/wiki/Usage) · [FAQ](https://github.com/kore-pl/kore-plugin-dns/wiki/FAQ) · [Changelog](https://github.com/kore-pl/kore-plugin-dns/wiki/Changelog)

## 常见问题

### 改记录要 reload 吗？

不要。RFC 2136 动态更新立即生效；dns.reload 只用于手工改过 zone 文件或 named.conf 之后。

### 为什么写权限大小写成 E_NEED_ROOT？

只有 resolved-flush-caches 声明了 root 动作；bind9 的 rndc/zone 写不在 ADR-0022 形状表内，当前不支持。

### dnsmasq 能写哪些类型？

只支持 A/AAAA/CNAME 的 hosts 片段；其余类型 E_UNSUPPORTED。

### 真实服务器写入验证过吗？

本机没有 allow-update 的 bind9；写入链路以 mock 宿主单测覆盖，不声称已实测生效。

### 去哪里报 bug / 提需求？

在仓库开 issue；安全漏洞不要开公开 issue，按 [SECURITY.md](https://github.com/kore-pl/kore-plugin-dns/blob/main/SECURITY.md) 私密披露。
