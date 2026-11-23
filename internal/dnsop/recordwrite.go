package dnsop

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// recordWriteSpec 是一次写入的完整已校验上下文（人工/机器均不可绕过校验直接构造）。
type recordWriteSpec struct {
	Operation string
	Zone      string
	Name      string
	Type      string
	Value     string
	Rendered  string
	OldValue  string
	TTL       int
	Server    string
	Port      int
	KeyFile   string
	Timeout   time.Duration
	Previous  []Record
}

// RecordAdd 新增一条记录（真实写入 bind9 动态更新）。
func (d Detector) RecordAdd(ctx context.Context, raw json.RawMessage) (RecordWriteResult, *pluginapi.Error) {
	return d.recordWrite(ctx, "add", raw)
}

// RecordUpdate 修改一条记录（同一 UPDATE 消息内先删后加，原子生效）。
func (d Detector) RecordUpdate(ctx context.Context, raw json.RawMessage) (RecordWriteResult, *pluginapi.Error) {
	return d.recordWrite(ctx, "update", raw)
}

// RecordDelete 删除一条记录（value 为空时删除该 name/type 的全部值）。
func (d Detector) RecordDelete(ctx context.Context, raw json.RawMessage) (RecordWriteResult, *pluginapi.Error) {
	return d.recordWrite(ctx, "delete", raw)
}

// recordWrite 是三种写方法的唯一实现：校验 → 快照 → 判定是否需改 → 审计 → 下发 → 生效校验 → 失败回滚。
func (d Detector) recordWrite(ctx context.Context, operation string, raw json.RawMessage) (RecordWriteResult, *pluginapi.Error) {
	var params RecordWriteParams
	if perr := decodeParams(raw, &params); perr != nil {
		return RecordWriteResult{}, perr
	}
	spec, perr := d.prepareWrite(operation, params)
	if perr != nil {
		return RecordWriteResult{}, perr
	}
	previous, perr := d.snapshotWrite(ctx, spec)
	if perr != nil {
		return RecordWriteResult{}, perr
	}
	spec.Previous = previous
	if spec.TTL == 0 {
		spec.TTL = DefaultWriteTTL
		if operation == "update" && len(previous) > 0 && previous[0].TTL > 0 {
			spec.TTL = previous[0].TTL
		}
	}
	changed, perr := decideWriteChange(operation, spec)
	if perr != nil {
		return RecordWriteResult{}, perr
	}

	result := RecordWriteResult{
		Operation: operation, Channel: WriteChannel, Zone: spec.Zone, Name: spec.Name,
		Type: spec.Type, Value: spec.Value, Previous: previousValues(previous),
		Server: spec.Server, Port: spec.Port, ReloadRequired: false, Changed: changed,
	}
	if !changed {
		// 幂等空操作：目标状态已达成，不发任何更新、不写 journal。
		result.Applied, result.Verified, result.VerifiedBy = true, true, "dig-direct"
		return result, nil
	}
	if operation == "delete" {
		result.Value = spec.OldValue
	} else if spec.TTL > 0 {
		result.TTL = spec.TTL
	}

	path, perr := d.journalWrite(JournalEntry{
		Phase: "intent", Operation: operation, Zone: spec.Zone, Name: spec.Name, Type: spec.Type,
		Value: spec.Value, Previous: result.Previous, TTL: result.TTL, Server: spec.Server, Port: spec.Port,
	})
	if perr != nil {
		return RecordWriteResult{}, perr
	}
	result.Journal = path

	script := buildUpdateScript(spec)
	output, runErr := d.Host.RunInput(ctx, "nsupdate", nsupdateArgv(spec), script)
	runErrText := ""
	if runErr != nil {
		runErrText = runErr.Error()
	}
	verified, verifyNote := d.verifyWrite(ctx, spec)
	if verified {
		result.Applied, result.Verified, result.VerifiedBy = true, true, "dig-direct"
		_, _ = d.journalWrite(JournalEntry{
			Phase: "result", Operation: operation, Zone: spec.Zone, Name: spec.Name, Type: spec.Type,
			Value: spec.Value, Previous: result.Previous, TTL: result.TTL, Server: spec.Server, Port: spec.Port,
			Result: "applied",
		})
		return result, nil
	}

	rolledBack, rollbackNote := d.rollbackWrite(ctx, spec)
	result.RolledBack = rolledBack
	_, _ = d.journalWrite(JournalEntry{
		Phase: "result", Operation: operation, Zone: spec.Zone, Name: spec.Name, Type: spec.Type,
		Value: spec.Value, Previous: result.Previous, TTL: result.TTL, Server: spec.Server, Port: spec.Port,
		Result: "verify_failed", Detail: "verified=false; rolled_back=" + strconv.FormatBool(rolledBack),
	})

	detail := map[string]string{
		"hint": "更新已下发但直连权威服务器校验未通过；" + rollbackHint(rolledBack) +
			"检查 nsupdate 输出与服务器 allow-update/update-policy 配置后重试。",
		"verify":       verifyNote,
		"rollback":     rollbackNote,
		"journal_path": path,
		"rolled_back":  strconv.FormatBool(rolledBack),
	}
	if snippet := strings.TrimSpace(strings.Join(strings.Fields(output), " ")); snippet != "" {
		detail["nsupdate_output"] = truncate(snippet, 2000)
	}
	if runErrText != "" {
		detail["exec_error"] = truncate(runErrText, 500)
	}
	return RecordWriteResult{}, &pluginapi.Error{
		Code:    pluginapi.E_UPSTREAM,
		Message: "DNS 记录" + operation + "已下发但生效校验失败",
		Detail:  encodeDetail(detail),
	}
}

// prepareWrite 校验入参、写通道与区域归属；任一不满足即返回可操作错误（不进入任何写动作）。
func (d Detector) prepareWrite(operation string, params RecordWriteParams) (recordWriteSpec, *pluginapi.Error) {
	switch operation {
	case "add", "update", "delete":
	default:
		return recordWriteSpec{}, invalidParam("未知写入操作 " + operation)
	}
	zone := normalizeZoneName(params.Zone)
	if zone == "" {
		return recordWriteSpec{}, invalidParam("缺少必填字段 zone")
	}
	if perr := validateZoneNameParam(zone); perr != nil {
		return recordWriteSpec{}, perr
	}
	name, perr := ValidateQueryName(params.Name)
	if perr != nil {
		return recordWriteSpec{}, perr
	}
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return recordWriteSpec{}, invalidParam("name=" + name + " 不在 zone=" + zone + " 内")
	}
	recordType, perr := validateWriteType(params.Type)
	if perr != nil {
		return recordWriteSpec{}, perr
	}
	spec := recordWriteSpec{Operation: operation, Zone: zone, Name: name, Type: recordType, TTL: params.TTL}
	if params.TTL < 0 || params.TTL > maxWriteTTL {
		return recordWriteSpec{}, invalidParam(fmt.Sprintf("ttl=%d 超出 [0, %d]", params.TTL, maxWriteTTL))
	}
	if operation != "delete" || strings.TrimSpace(params.Value) != "" {
		value, perr := normalizeWriteValue(recordType, params.Value)
		if perr != nil {
			return recordWriteSpec{}, perr
		}
		spec.Value, spec.Rendered = value, renderWriteValue(recordType, value)
	}
	if strings.TrimSpace(params.OldValue) != "" {
		oldValue, perr := normalizeWriteValue(recordType, params.OldValue)
		if perr != nil {
			return recordWriteSpec{}, perr
		}
		spec.OldValue = oldValue
	}
	if perr := d.resolveWriteZone(spec.Zone); perr != nil {
		return recordWriteSpec{}, perr
	}
	return spec, d.fillWriteChannel(&spec)
}

// resolveWriteZone 用既有区域扫描确认该区域确实由 bind9 声明（写入只支持 bind9 动态更新）。
func (d Detector) resolveWriteZone(zone string) *pluginapi.Error {
	zones, _, warnings, blocked := d.scanZones()
	available := make([]string, 0, len(zones))
	for _, item := range zones {
		available = append(available, item.entry.Name)
		if item.entry.Name != zone {
			continue
		}
		if item.entry.Engine != EngineBind9 {
			return &pluginapi.Error{
				Code:    pluginapi.E_UNSUPPORTED,
				Message: "区域 " + zone + " 由 " + item.entry.Engine + " 管理，写入只支持 bind9 动态更新",
				Detail: encodeDetail(map[string]string{"hint": "dnsmasq / systemd-resolved / CoreDNS 没有可用的动态更新接口；" +
					"改用 bind9（zone + allow-update + TSIG）后再试。"}),
			}
		}
		return nil
	}
	hint := "先把 zone 加入 bind_conf（" + d.paths().BindConf + "）并 reload bind9；写入只对 bind9 声明的区域生效。"
	if blocked {
		hint = "区域声明文件不可读（可能需要 root）：" + strings.Join(warnings, "；") + "；" + hint
	} else if len(available) > 0 {
		hint = "可用区域：" + strings.Join(available, "、") + "；" + hint
	}
	return &pluginapi.Error{
		Code:    pluginapi.E_NOTFOUND,
		Message: "区域 " + zone + " 不在 bind9 区域声明中",
		Detail:  encodeDetail(map[string]string{"hint": hint}),
	}
}

// fillWriteChannel 校验写入通道（服务器、端口、TSIG 密钥、nsupdate/dig 与 journal）。
func (d Detector) fillWriteChannel(spec *recordWriteSpec) *pluginapi.Error {
	write := d.Write
	if write.Journal == nil {
		return &pluginapi.Error{
			Code:    pluginapi.E_UNSUPPORTED,
			Message: "写通道未装配：缺少插件状态目录（KORE_STATE_DIR），无法保存写入审计",
			Detail:  encodeDetail(map[string]string{"hint": "设置 KORE_STATE_DIR 后重启插件；写操作必须先在 journal 留痕才会下发。"}),
		}
	}
	keyFile := strings.TrimSpace(write.KeyFile)
	if keyFile == "" {
		return &pluginapi.Error{
			Code:    pluginapi.E_UNSUPPORTED,
			Message: "未配置 update_key_file（TSIG 密钥），写入未启用",
			Detail: encodeDetail(map[string]string{"hint": "生成 TSIG 密钥（如 tsig-keygen kore-update）并在 bind9 zone 里配置 " +
				"allow-update { key \"kore-update\"; };，再把密钥文件路径写入 update_key_file。"}),
		}
	}
	cleaned, perr := validateWriteKeyPath(keyFile)
	if perr != nil {
		return perr
	}
	spec.KeyFile = cleaned
	if _, err := d.Host.ReadFile(cleaned); err != nil {
		return &pluginapi.Error{
			Code:    pluginapi.E_INVALID,
			Message: "update_key_file 不可读：" + cleaned,
			Detail:  encodeDetail(map[string]string{"hint": "kore 运行用户需要读该密钥（chgrp + 0640，或复制到 /var/lib/kore 下并授权）。"}),
		}
	}
	if _, err := d.Host.LookPath("nsupdate"); err != nil {
		return &pluginapi.Error{
			Code:    pluginapi.E_UPSTREAM,
			Message: "宿主缺少 nsupdate，无法执行动态更新",
			Detail:  encodeDetail(map[string]string{"hint": "安装 bind9-dnsutils（Debian/Ubuntu）或 bind-utils（RHEL 系）后重试。"}),
		}
	}
	if _, err := d.Host.LookPath("dig"); err != nil {
		return &pluginapi.Error{
			Code:    pluginapi.E_UPSTREAM,
			Message: "宿主缺少 dig，无法校验更新是否生效",
			Detail:  encodeDetail(map[string]string{"hint": "安装 bind9-dnsutils / bind-utils；写入必须校验生效，缺 dig 不放行。"}),
		}
	}
	server := strings.TrimSpace(write.Server)
	if server == "" {
		server = "127.0.0.1"
	}
	if net.ParseIP(server) == nil {
		if _, perr := ValidateQueryName(server); perr != nil {
			return invalidParam("update_server 非法：必须是 IP 或主机名")
		}
	}
	spec.Server = server
	spec.Port = write.Port
	if spec.Port == 0 {
		spec.Port = 53
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return invalidParam("update_port 必须在 1–65535")
	}
	spec.Timeout = write.Timeout
	if spec.Timeout <= 0 {
		spec.Timeout = 5 * time.Second
	}
	return nil
}

// snapshotWrite 写前直连权威服务器取旧值（回滚依据 + 冲突判定）。
func (d Detector) snapshotWrite(ctx context.Context, spec recordWriteSpec) ([]Record, *pluginapi.Error) {
	result, err := d.queryDirect(ctx, spec.Server, spec.Port, spec.Name, spec.Type, spec.Timeout)
	if err != nil {
		return nil, &pluginapi.Error{
			Code:    pluginapi.E_UPSTREAM,
			Message: "写入前无法读取当前记录（直连 " + spec.Server + "）",
			Detail:  encodeDetail(map[string]string{"hint": "确认 update_server/update_port 指向权威 bind9 实例，且该实例可应答查询。", "error": truncate(err.Error(), 500)}),
		}
	}
	return previousRecords(spec.Type, result.Answers), nil
}

// decideWriteChange 判定是否需要下发更新；冲突与不存在在这里就返回明确错误。
func decideWriteChange(operation string, spec recordWriteSpec) (bool, *pluginapi.Error) {
	contains := func(want string) bool {
		target := canonicalAnswerValue(spec.Type, want)
		for _, record := range spec.Previous {
			if canonicalAnswerValue(spec.Type, record.Value) == target {
				return true
			}
		}
		return false
	}
	switch operation {
	case "add":
		if contains(spec.Value) {
			return false, nil
		}
		if len(spec.Previous) > 0 {
			return false, &pluginapi.Error{
				Code:    pluginapi.E_CONFLICT,
				Message: spec.Name + " " + spec.Type + " 已存在且值不同",
				Detail: encodeDetail(map[string]string{
					"hint":     "用 record.update 覆盖旧值，或先 record.delete 再 add。",
					"existing": strings.Join(previousValues(spec.Previous), "；"),
				}),
			}
		}
		return true, nil
	case "update":
		if len(spec.Previous) == 0 {
			return false, &pluginapi.Error{
				Code:    pluginapi.E_NOTFOUND,
				Message: spec.Name + " " + spec.Type + " 不存在，无法 update",
				Detail:  encodeDetail(map[string]string{"hint": "用 record.add 新建该记录。"}),
			}
		}
		if spec.OldValue != "" && !contains(spec.OldValue) {
			return false, &pluginapi.Error{
				Code:    pluginapi.E_CONFLICT,
				Message: "old_value 与服务器当前值不一致",
				Detail: encodeDetail(map[string]string{
					"hint":     "先 record.list 复核当前值，再用最新 old_value 重试。",
					"existing": strings.Join(previousValues(spec.Previous), "；"),
				}),
			}
		}
		if len(spec.Previous) == 1 && contains(spec.Value) {
			return false, nil
		}
		return true, nil
	default: // delete
		if len(spec.Previous) == 0 {
			return false, nil
		}
		if spec.OldValue != "" && !contains(spec.OldValue) {
			return false, nil
		}
		return true, nil
	}
}

// verifyWrite 写后直连权威服务器校验新状态。
func (d Detector) verifyWrite(ctx context.Context, spec recordWriteSpec) (bool, string) {
	result, err := d.queryDirect(ctx, spec.Server, spec.Port, spec.Name, spec.Type, spec.Timeout)
	if err != nil {
		return false, "直连校验查询失败：" + truncate(err.Error(), 500)
	}
	switch spec.Operation {
	case "add", "update":
		if answersContain(spec.Type, result.Answers, spec.Value) {
			return true, ""
		}
		return false, "权威应答未包含新值；当前=[" + strings.Join(answerValues(spec.Type, result.Answers), "；") + "]"
	default:
		if spec.OldValue == "" {
			if len(answerValues(spec.Type, result.Answers)) == 0 {
				return true, ""
			}
			return false, "权威应答仍有该类型记录；当前=[" + strings.Join(answerValues(spec.Type, result.Answers), "；") + "]"
		}
		if answersContain(spec.Type, result.Answers, spec.OldValue) {
			return false, "权威应答仍包含待删除的值 " + spec.OldValue
		}
		return true, ""
	}
}

// rollbackWrite 逆操作恢复旧值并再次校验；返回是否恢复成功与说明。
func (d Detector) rollbackWrite(ctx context.Context, spec recordWriteSpec) (bool, string) {
	if len(spec.Previous) > maxPreviousRecords {
		return false, fmt.Sprintf("旧记录 %d 条超过回滚上限 %d，未自动回滚，请人工核对", len(spec.Previous), maxPreviousRecords)
	}
	output, err := d.Host.RunInput(ctx, "nsupdate", nsupdateArgv(spec), buildRollbackScript(spec))
	if err != nil {
		return false, "回滚命令执行失败：" + truncate(err.Error(), 500)
	}
	if nsupdateReportedFailure(output) {
		return false, "回滚被服务器拒绝：" + truncate(strings.Join(strings.Fields(output), " "), 1000)
	}
	result, queryErr := d.queryDirect(ctx, spec.Server, spec.Port, spec.Name, spec.Type, spec.Timeout)
	if queryErr != nil {
		return false, "回滚后校验查询失败：" + truncate(queryErr.Error(), 500)
	}
	switch spec.Operation {
	case "add":
		return !answersContain(spec.Type, result.Answers, spec.Value), ""
	case "update":
		for _, record := range spec.Previous {
			if !answersContain(spec.Type, result.Answers, record.Value) {
				return false, "回滚后仍缺旧值 " + record.Value
			}
		}
		return true, ""
	default:
		for _, record := range spec.Previous {
			if !answersContain(spec.Type, result.Answers, record.Value) {
				return false, "回滚后仍缺旧值 " + record.Value
			}
		}
		return true, ""
	}
}

// journalWrite 写一条审计记录；失败即 fail-closed（写操作不得在无留痕的情况下下发）。
func (d Detector) journalWrite(entry JournalEntry) (string, *pluginapi.Error) {
	path, err := d.Write.Journal.Append(entry)
	if err != nil {
		return "", &pluginapi.Error{
			Code:    pluginapi.E_INTERNAL,
			Message: "写入审计日志失败，已中止写操作",
			Detail:  encodeDetail(map[string]string{"hint": "检查 KORE_STATE_DIR 的磁盘空间与权限。", "error": truncate(err.Error(), 500)}),
		}
	}
	return path, nil
}

// previousValues 把快照拍平成结果字段。
func previousValues(records []Record) []string {
	values := make([]string, 0, len(records))
	for _, record := range records {
		values = append(values, record.Value)
	}
	if len(values) == 0 {
		return []string{}
	}
	return values
}

// rollbackHint 给出回滚结果的用户提示。
func rollbackHint(rolledBack bool) string {
	if rolledBack {
		return "已自动回滚到旧值。"
	}
	return "自动回滚未确认成功，请人工核对当前记录。"
}
