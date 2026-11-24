package dnsop

import "strings"

// zoneGuideExampleZone 是「一个区域都没有」时使用的示例域名：字段带示例值，
// 不要求用户自己想一个合法域名（ADR-0051 §5.1.2）。
const zoneGuideExampleZone = "example.com"

// zoneSetupGuide 生成「新建 zone」的一次性可复制命令块（ADR-0051 §5.1.2 / §3.3）。
//
// 为什么是「给命令」而不是「面板按钮」：新建 zone 要改 named 的配置文件、给区域文件路径，
// 属于一次性系统配置，v1 不在面板里做（ADR-0051 裁决 A「不扩形状表」）。
// 插件只生成文本，**不执行其中任何命令、不写任何宿主文件、不新增 root 动作**。
//
// zone 会按本次查询填进所有命令（不是空模板）；bindConf 是配置里的 named.conf 路径。
func zoneSetupGuide(zone, bindConf string) string {
	zone = normalizeZoneName(zone)
	if zone == "" {
		zone = zoneGuideExampleZone
	}
	bindConf = strings.TrimSpace(bindConf)
	if bindConf == "" {
		bindConf = DefaultPaths().BindConf
	}
	zoneFile := "/var/lib/bind/" + zone + ".zone"
	ns := "ns." + zone
	admin := "admin." + zone
	// serial 只是示例值：提示用户每次改完要调大，避免手工编辑后 not loaded 的假故障。
	const serial = "2026112401"

	var b strings.Builder
	b.WriteString("新建 zone 不在面板里做（它要改 named 的配置文件，属一次性系统配置）：")
	b.WriteString("请把下面四段命令整段复制到终端按顺序执行，域名与路径已按本次操作填好。\n\n")

	b.WriteString("# 1) 声明 zone：把这段写进 " + bindConf + "\n")
	b.WriteString("#    kore-update 是 TSIG 密钥名，请换成你实际使用的名字（生成：sudo tsig-keygen kore-update > /etc/bind/kore-update.key）；\n")
	b.WriteString("#    还没配密钥就先删掉 allow-update 那行——这样 zone 能生效，但面板无法写记录。\n")
	b.WriteString("#    BIND 9.11（如 RHEL8）不认 type primary，请把下面这行改成 type master。\n")
	b.WriteString("zone \"" + zone + "\" {\n")
	b.WriteString("    type primary;\n")
	b.WriteString("    file \"" + zoneFile + "\";\n")
	b.WriteString("    allow-update { key \"kore-update\"; };\n")
	b.WriteString("};\n\n")

	b.WriteString("# 1b) 区域文件不存在时先建一个最小可用的（已存在请跳过，不要覆盖；SOA 的 serial 每次改完要调大）\n")
	b.WriteString("sudo test -e " + zoneFile + " || sudo tee " + zoneFile + " >/dev/null <<'ZONE'\n")
	b.WriteString("$TTL 300\n")
	b.WriteString("@   IN SOA " + ns + ". " + admin + ". (" + serial + " 3600 600 86400 300)\n")
	b.WriteString("@   IN NS  " + ns + ".\n")
	b.WriteString("ns  IN A   127.0.0.1\n")
	b.WriteString("ZONE\n\n")

	b.WriteString("# 2) 校验 zone 语法与文件路径（区域名和 file 路径要和第 1 段完全一致）\n")
	b.WriteString("sudo named-checkzone " + zone + " " + zoneFile + "\n\n")

	b.WriteString("# 3) 让 named 读取新配置（新建 zone 用 reconfig；只改了已有 zone 文件时用 sudo rndc reload " + zone + "）\n")
	b.WriteString("sudo rndc reconfig\n\n")

	b.WriteString("# 4) 验证（有 SOA 输出就算生效；没有输出请看 named 日志：journalctl -u named 或 /var/log/syslog）\n")
	b.WriteString("dig @127.0.0.1 " + zone + " SOA +short\n\n")

	b.WriteString("执行完回到面板刷新，zone 会出现在区域列表里；之后加/改/删记录直接用面板：")
	b.WriteString("记录走 RFC 2136 动态更新、立即生效，不需要再 reload。")
	return b.String()
}

// readFallbackHints 给出「区域文件读不到」时的两条自助替代（ADR-0051 §5.1.3）。
//
// 两条路径都让插件以自身用户读到数据，不需要把 kored 提到 root：
//  1. 文件对 Kore 运行用户可读（0644，目录 0755）；
//  2. 文件放进 Kore 自有目录 /var/lib/kore/dns（在插件只读白名单内）并在 named.conf 中 include。
func readFallbackHints(path string) string {
	target := strings.TrimSpace(path)
	if target == "" {
		target = "区域文件"
	}
	return "请任选一种方式修复（都不需要以 root 运行 Kore）：" +
		"① 让 Kore 运行用户能读该文件：sudo chmod 0644 " + target + "（所在目录需 0755 可进入）；" +
		"② 把区域文件放进 Kore 自有目录：sudo install -d -m 0755 /var/lib/kore/dns 后把文件放进去，" +
		"在 named.conf 的 zone 块里把 file 指向该目录，并在 " + DefaultPaths().BindConf +
		" 里 include 该目录的声明（例：include \"/var/lib/kore/dns/*.conf\";），再执行 sudo rndc reconfig；" +
		"改完回到面板刷新。"
}

// readDeniedHint 是「区域文件读不到」的统一文案：先给两条自助替代，再给 dns.query 兜底。
func readDeniedHint(path string) string {
	return readFallbackHints(path) + "只想先看记录内容时，也可以直接用 dns.query 向权威服务器查询，不依赖文件读取权限。"
}

// 用于拼接 hints 的分隔，避免调用处各自写 \n\n 导致文案长度漂移（测试按块断言）。
const guideHintSeparator = "\n\n"

func appendGuide(hint, guide string) string {
	if strings.TrimSpace(hint) == "" {
		return guide
	}
	return hint + guideHintSeparator + guide
}
