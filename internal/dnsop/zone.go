package dnsop

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// zoneData 是内部区域数据：对外视图 + 记录集合。
type zoneData struct {
	entry   ZoneEntry
	records []Record
	total   int
}

// Zones 返回宿主全部可读区域的只读视图（bind9 + dnsmasq）。
//
// systemd-resolved / CoreDNS 不管理区域文件，因此不贡献区域；这不是错误，
// 由 hint 说明。全部区域都因权限读不到时给 E_NEED_ROOT + hint，不返回空列表冒充「没有区域」。
func (d Detector) Zones(ctx context.Context, preferred string) (ZonesResult, *pluginapi.Error) {
	paths := d.paths()
	status := d.Status(ctx, preferred)
	data, scanned, warnings, permissionBlocked := d.scanZones()
	result := ZonesResult{
		Engine:   status.Engine,
		Zones:    make([]ZoneEntry, 0, len(data)),
		Scanned:  scanned,
		Warnings: warnings,
	}
	for _, item := range data {
		result.Zones = append(result.Zones, item.entry)
	}
	sort.Slice(result.Zones, func(i, j int) bool {
		if result.Zones[i].Name != result.Zones[j].Name {
			return result.Zones[i].Name < result.Zones[j].Name
		}
		return result.Zones[i].File < result.Zones[j].File
	})
	result.Count = len(result.Zones)
	if result.Count > 0 {
		return result, nil
	}
	if permissionBlocked {
		result.ErrorCode = CodeNeedRoot
		result.Hint = "区域文件存在但当前用户读不到（需要 root）：请用 sudo 启动 kored，或把区域目录的只读权限授予 kore 运行用户。"
		return result, nil
	}
	if !status.Available {
		result.ErrorCode = CodeNoEngine
		result.Hint = status.Hint + "；区域列表只来自 bind9 与 dnsmasq 的配置，systemd-resolved 与 CoreDNS 不管理区域文件。"
		return result, nil
	}
	result.Hint = "未发现区域定义：bind9 读 " + paths.BindConf + "（含 named.conf 声明的 zone 块），" +
		"dnsmasq 读 " + paths.DnsmasqConf + " 与 " + paths.DnsmasqDir + "/ 下的 address=/server= 指令；" +
		"systemd-resolved 与 CoreDNS 不管理区域文件，因此没有区域列表。"
	return result, nil
}

// Records 返回指定区域的记录（最多 MaxRecords 条）。
func (d Detector) Records(ctx context.Context, zone string) (RecordsResult, *pluginapi.Error) {
	name := normalizeZoneName(zone)
	if name == "" {
		return RecordsResult{}, invalidParam("缺少必填字段 zone")
	}
	if perr := validateZoneNameParam(name); perr != nil {
		return RecordsResult{}, perr
	}
	data, _, warnings, permissionBlocked := d.scanZones()
	available := make([]string, 0, len(data))
	for _, item := range data {
		available = append(available, item.entry.Name)
		if item.entry.Name != name {
			continue
		}
		if !item.entry.Readable {
			if permissionBlocked {
				return RecordsResult{}, needRoot(item.entry.File)
			}
			return RecordsResult{}, &pluginapi.Error{
				Code:    pluginapi.E_NOTFOUND,
				Message: "区域 " + name + " 的数据文件不可读：" + item.entry.File,
				Detail:  encodeDetail(map[string]string{"hint": "检查该路径是否存在、是否为符号链接指向不可读位置。"}),
			}
		}
		records := item.records
		truncated := false
		if len(records) > MaxRecords {
			records = records[:MaxRecords]
			truncated = true
		}
		if records == nil {
			records = make([]Record, 0)
		}
		return RecordsResult{
			Zone:      name,
			Engine:    item.entry.Engine,
			File:      item.entry.File,
			Records:   records,
			Count:     len(records),
			Total:     item.total,
			Truncated: truncated,
		}, nil
	}
	sort.Strings(available)
	hint := "可选区域为空"
	if len(available) > 0 {
		limit := len(available)
		if limit > 10 {
			limit = 10
		}
		hint = "可用区域（前 " + strconv.Itoa(limit) + " 个）：" + strings.Join(available[:limit], "、")
	} else if len(warnings) > 0 {
		hint = warnings[0]
	}
	return RecordsResult{}, &pluginapi.Error{
		Code:    pluginapi.E_NOTFOUND,
		Message: "未知区域：" + name,
		Detail:  encodeDetail(map[string]string{"hint": hint}),
	}
}

// scanZones 扫描 bind9 与 dnsmasq 的区域定义，返回区域数据、扫描路径、告警与「是否被权限拦截」。
func (d Detector) scanZones() ([]zoneData, []string, []string, bool) {
	paths := d.paths()
	data := make([]zoneData, 0, 4)
	scanned := make([]string, 0, 8)
	warnings := make([]string, 0, 4)
	permissionBlocked := false

	bindData, bindScanned, bindWarnings, bindBlocked := d.scanBindZones(paths)
	data = append(data, bindData...)
	scanned = append(scanned, bindScanned...)
	warnings = append(warnings, bindWarnings...)
	permissionBlocked = permissionBlocked || bindBlocked

	dnsmasqData, dnsmasqScanned, dnsmasqWarnings, dnsmasqBlocked := d.scanDnsmasqZones(paths)
	data = append(data, dnsmasqData...)
	scanned = append(scanned, dnsmasqScanned...)
	warnings = append(warnings, dnsmasqWarnings...)
	permissionBlocked = permissionBlocked || dnsmasqBlocked

	if len(scanned) > maxScannedPaths {
		scanned = scanned[:maxScannedPaths]
	}
	return data, scanned, warnings, permissionBlocked
}

// scanBindZones 解析 named.conf.local 的 zone 块并读取对应区域文件。
func (d Detector) scanBindZones(paths Paths) ([]zoneData, []string, []string, bool) {
	scanned := []string{paths.BindConf}
	warnings := make([]string, 0, 2)
	data := make([]zoneData, 0, 4)
	permissionBlocked := false

	confText, err := d.Host.ReadFile(paths.BindConf)
	if err != nil {
		switch {
		case errorsIsNotExist(err):
			return data, scanned, warnings, false
		case errorsIsPermission(err):
			warnings = append(warnings, "需要 root 才能读取 "+paths.BindConf)
			return data, scanned, warnings, true
		default:
			warnings = append(warnings, "读取 "+paths.BindConf+" 失败："+err.Error())
			return data, scanned, warnings, false
		}
	}
	confDir := filepath.Dir(paths.BindConf)
	for _, decl := range ParseNamedConf(string(confText)) {
		if decl.Name == "" {
			continue
		}
		zoneType := decl.Type
		if zoneType == "" {
			zoneType = "master"
		}
		file := decl.File
		if file != "" && !strings.HasPrefix(file, "/") {
			file = filepath.Join(confDir, file)
		}
		entry := ZoneEntry{Name: decl.Name, Type: zoneType, File: file, Engine: EngineBind9}
		if file == "" {
			warnings = append(warnings, "区域 "+decl.Name+" 未声明 file，无法读取记录")
			data = append(data, zoneData{entry: entry})
			continue
		}
		if !WithinReadRoots(file) {
			warnings = append(warnings, "区域 "+decl.Name+" 的文件 "+file+" 不在只读白名单内，已跳过")
			data = append(data, zoneData{entry: entry})
			continue
		}
		body, readErr := d.Host.ReadFile(file)
		if readErr != nil {
			if errorsIsPermission(readErr) {
				warnings = append(warnings, "需要 root 才能读取 "+file)
				permissionBlocked = true
			} else if !errorsIsNotExist(readErr) {
				warnings = append(warnings, "读取区域文件 "+file+" 失败："+readErr.Error())
			}
			data = append(data, zoneData{entry: entry})
			continue
		}
		parsed := ParseZoneFile(string(body), decl.Name)
		entry.Readable = true
		entry.RecordsCount = parsed.Total
		data = append(data, zoneData{entry: entry, records: parsed.Records, total: parsed.Total})
	}
	return data, scanned, warnings, permissionBlocked
}

// scanDnsmasqZones 解析 dnsmasq 主配置与片段目录，把 address=/server=/local=/host-record
// 归一成「区域 + 记录」；host-record 与 addn-hosts 的记录按最长后缀归属到区域。
func (d Detector) scanDnsmasqZones(paths Paths) ([]zoneData, []string, []string, bool) {
	scanned := make([]string, 0, 4)
	warnings := make([]string, 0, 2)
	permissionBlocked := false
	confs := make([]string, 0, 4)

	scanned = append(scanned, paths.DnsmasqConf)
	if _, err := d.Host.ReadFile(paths.DnsmasqConf); err == nil {
		confs = append(confs, paths.DnsmasqConf)
	} else if errorsIsPermission(err) {
		warnings = append(warnings, "需要 root 才能读取 "+paths.DnsmasqConf)
		permissionBlocked = true
	}

	if names, err := d.Host.ListDir(paths.DnsmasqDir); err == nil {
		for _, name := range names {
			path := filepath.Join(paths.DnsmasqDir, name)
			scanned = append(scanned, path)
			if _, err := d.Host.ReadFile(path); err == nil {
				confs = append(confs, path)
			} else if errorsIsPermission(err) {
				warnings = append(warnings, "需要 root 才能读取 "+path)
				permissionBlocked = true
			}
		}
	} else if errorsIsPermission(err) {
		warnings = append(warnings, "需要 root 才能列出 "+paths.DnsmasqDir)
		permissionBlocked = true
	}

	type accumulator struct {
		entry   ZoneEntry
		records []Record
		order   []string
	}
	zones := make(map[string]*accumulator, 8)
	order := make([]string, 0, 8)
	ensure := func(name, zoneType, file string) *accumulator {
		if existing, ok := zones[name]; ok {
			return existing
		}
		item := &accumulator{entry: ZoneEntry{Name: name, Type: zoneType, File: file, Engine: EngineDnsmasq, Readable: true}}
		zones[name] = item
		order = append(order, name)
		return item
	}
	bestZone := func(name string) string {
		best := ""
		for _, zone := range order {
			if name == zone || strings.HasSuffix(name, "."+zone) {
				if len(zone) > len(best) {
					best = zone
				}
			}
		}
		return best
	}

	for _, conf := range confs {
		body, err := d.Host.ReadFile(conf)
		if err != nil {
			continue
		}
		for _, entry := range ParseDnsmasqConf(string(body)) {
			switch entry.Kind {
			case dnsmasqKindAddress:
				for _, domain := range entry.Domains {
					recordType := recordTypeForAddr(entry.Addr)
					if recordType == "" {
						continue
					}
					zone := ensure(domain, "static", conf)
					zone.records = append(zone.records, Record{Name: domain, Type: recordType, Value: entry.Addr, TTL: 0})
				}
			case dnsmasqKindServer:
				for _, domain := range entry.Domains {
					ensure(domain, "forward", conf)
				}
			case dnsmasqKindLocal:
				for _, domain := range entry.Domains {
					ensure(domain, "local", conf)
				}
			case dnsmasqKindHostRecord:
				for _, name := range entry.Names {
					zoneName := bestZone(name)
					if zoneName == "" {
						zoneName = parentDomain(name)
					}
					zone := ensure(zoneName, "static", conf)
					for _, addr := range entry.Addrs {
						recordType := recordTypeForAddr(addr)
						if recordType == "" {
							continue
						}
						zone.records = append(zone.records, Record{Name: name, Type: recordType, Value: addr, TTL: 0})
					}
				}
			case dnsmasqKindAddnHosts:
				if !WithinReadRoots(entry.Path) {
					warnings = append(warnings, "addn-hosts 指向的 "+entry.Path+" 不在只读白名单内，已跳过")
					continue
				}
				hostsBody, readErr := d.Host.ReadFile(entry.Path)
				if readErr != nil {
					if errorsIsPermission(readErr) {
						warnings = append(warnings, "需要 root 才能读取 "+entry.Path)
						permissionBlocked = true
						continue
					}
					warnings = append(warnings, "读取 "+entry.Path+" 失败："+readErr.Error())
					continue
				}
				for _, record := range ParseHostsFile(string(hostsBody)) {
					zoneName := bestZone(record.Name)
					if zoneName == "" {
						zoneName = parentDomain(record.Name)
					}
					zone := ensure(zoneName, "static", conf)
					zone.records = append(zone.records, record)
				}
			}
		}
	}

	data := make([]zoneData, 0, len(order))
	for _, name := range order {
		item := zones[name]
		item.entry.RecordsCount = len(item.records)
		data = append(data, zoneData{entry: item.entry, records: item.records, total: len(item.records)})
	}
	return data, scanned, warnings, permissionBlocked
}

// parentDomain 返回去掉首个标签的父域；单标签名返回自身。
func parentDomain(name string) string {
	if idx := strings.Index(name, "."); idx > 0 {
		return name[idx+1:]
	}
	return name
}

// validateZoneNameParam 校验 dns.records 的 zone 参数形状（允许单标签，dnsmasq 的 address=/kore/ 就是单标签）。
func validateZoneNameParam(name string) *pluginapi.Error {
	if len(name) > maxQueryNameLen {
		return invalidParam("zone 超过 253 字符")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return invalidParam("zone 非法：存在空标签")
		}
		if !queryLabelRE.MatchString(label) {
			return invalidParam("zone 非法：仅允许字母数字、连字符与下划线")
		}
	}
	return nil
}

// encodeDetail 把结构化 detail 编成 JSON；编码失败返回 nil（detail 可省略）。
func encodeDetail(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return encoded
}
