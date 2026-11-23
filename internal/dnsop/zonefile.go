package dnsop

import (
	"strconv"
	"strings"
)

// zoneParseResult 是一个 zone 文件的解析结果。
type zoneParseResult struct {
	// Origin 是最终生效的 $ORIGIN。
	Origin string
	// Records 是解析到的受支持类型记录（按出现顺序，未截断）。
	Records []Record
	// Total 是受支持类型记录总数（等于 len(Records)，保留字段便于将来分页）。
	Total int
}

// supportedRecordTypes 是 dns.records 支持的记录类型集合（与任务口径一致）。
var supportedRecordTypes = map[string]struct{}{
	"A": {}, "AAAA": {}, "CNAME": {}, "MX": {}, "TXT": {}, "NS": {},
}

// ParseZoneFile 解析 bind 风格 zone 文件文本。
//
// 支持：$ORIGIN / $TTL / 省略 owner 的续行 / 括号多行记录 / 行内与整行注释 /
// 任意顺序的 TTL 与 class / 引号包裹的 TXT。只解析、不执行；未知类型直接跳过。
// origin 是文件未声明 $ORIGIN 时的兜底区域名。
func ParseZoneFile(text, origin string) zoneParseResult {
	result := zoneParseResult{Origin: normalizeZoneName(origin)}
	defaultTTL := defaultZoneTTL
	lastOwner := ""
	for _, line := range splitZoneRecords(text) {
		tokens := tokenizeZoneRecord(line.text)
		if len(tokens) == 0 {
			continue
		}
		head := strings.ToUpper(tokens[0].text)
		if strings.HasPrefix(head, "$") {
			switch head {
			case "$ORIGIN":
				if len(tokens) >= 2 {
					result.Origin = normalizeZoneName(expandName(tokens[1].text, result.Origin))
				}
			case "$TTL":
				if len(tokens) >= 2 {
					if ttl, err := strconv.Atoi(tokens[1].text); err == nil && ttl >= 0 {
						defaultTTL = ttl
					}
				}
			}
			continue
		}
		record, owner, ok := parseZoneRecord(tokens, line.indented, result.Origin, defaultTTL, lastOwner)
		if owner != "" {
			// owner 必须继承下去：SOA 等未受支持类型也要更新 lastOwner，否则紧随其后的缩进行会丢。
			lastOwner = owner
		}
		if !ok {
			continue
		}
		result.Records = append(result.Records, record)
	}
	result.Total = len(result.Records)
	return result
}

// zoneToken 是 zone 文件的一个词法单元；quoted 表示原始形态带引号（TXT 需要）。
type zoneToken struct {
	text   string
	quoted bool
}

// zoneLine 是一条逻辑记录；indented 表示它在文件里以空白开头（owner 省略，继承上一行）。
type zoneLine struct {
	text     string
	indented bool
}

// splitZoneRecords 把 zone 文本切成逻辑记录：剔除注释、合并括号续行、记录是否缩进。
func splitZoneRecords(text string) []zoneLine {
	lines := make([]zoneLine, 0, 32)
	var current strings.Builder
	inQuote := false
	depth := 0
	indented := false
	lineStart := true
	flush := func() {
		body := strings.TrimSpace(current.String())
		if body != "" {
			lines = append(lines, zoneLine{text: body, indented: indented})
		}
		current.Reset()
		indented = false
		lineStart = true
	}
	for index := 0; index < len(text); index++ {
		char := text[index]
		if inQuote {
			current.WriteByte(char)
			if char == '\\' && index+1 < len(text) {
				index++
				current.WriteByte(text[index])
				continue
			}
			if char == '"' {
				inQuote = false
			}
			continue
		}
		switch char {
		case ';':
			// 行内注释：跳到行尾（括号续行里同样适用），但不吃掉换行——
			// 换行要留给外层判断 depth 后 flush，否则下一条记录会被并进当前逻辑记录。
			for index < len(text) && text[index] != '\n' {
				index++
			}
			if index > 0 {
				index--
			}
			current.WriteByte(' ')
		case '"':
			inQuote = true
			lineStart = false
			current.WriteByte(char)
		case '(':
			depth++
			current.WriteByte(' ')
		case ')':
			if depth > 0 {
				depth--
			}
			current.WriteByte(' ')
		case '\n', '\r':
			if depth == 0 {
				flush()
			} else {
				current.WriteByte(' ')
			}
		case ' ', '\t':
			if lineStart {
				indented = true
				continue
			}
			current.WriteByte(char)
		default:
			lineStart = false
			current.WriteByte(char)
		}
	}
	flush()
	return lines
}

// tokenizeZoneRecord 把一个逻辑记录切成 token；引号内的空白不切分。
func tokenizeZoneRecord(line string) []zoneToken {
	tokens := make([]zoneToken, 0, 8)
	index := 0
	for index < len(line) {
		for index < len(line) && (line[index] == ' ' || line[index] == '\t') {
			index++
		}
		if index >= len(line) {
			break
		}
		if line[index] == '"' {
			end := index + 1
			var value strings.Builder
			for end < len(line) && line[end] != '"' {
				if line[end] == '\\' && end+1 < len(line) {
					value.WriteByte(line[end+1])
					end += 2
					continue
				}
				value.WriteByte(line[end])
				end++
			}
			tokens = append(tokens, zoneToken{text: value.String(), quoted: true})
			index = end + 1
			continue
		}
		start := index
		for index < len(line) && line[index] != ' ' && line[index] != '\t' {
			index++
		}
		tokens = append(tokens, zoneToken{text: line[start:index]})
	}
	return tokens
}

// parseZoneRecord 解析一条记录；返回记录、本行 owner（供缩进续行继承）与是否受支持。
// indented 表示本行以空白开头，owner 继承上一行。
func parseZoneRecord(tokens []zoneToken, indented bool, origin string, defaultTTL int, lastOwner string) (Record, string, bool) {
	index := 0
	owner := tokens[0].text
	if indented {
		if lastOwner == "" {
			return Record{}, lastOwner, false
		}
		owner = lastOwner
	} else {
		index = 1
	}
	ttl := defaultTTL
	recordType := ""
	for ; index < len(tokens); index++ {
		tokenText := tokens[index].text
		if value, ok := parseTTLToken(tokenText); ok {
			ttl = value
			continue
		}
		upper := strings.ToUpper(tokenText)
		if upper == "IN" || upper == "CH" || upper == "HS" {
			continue
		}
		if _, ok := supportedRecordTypes[upper]; ok {
			recordType = upper
			index++
			break
		}
		// 未受支持类型（SOA / SRV / CAA / PTR / ...）：整行跳过，但 owner 要保留给缩进续行。
		return Record{}, owner, false
	}
	if recordType == "" || index > len(tokens) {
		return Record{}, owner, false
	}
	rdata := tokens[index:]
	name := expandName(owner, origin)
	if name == "" {
		return Record{}, owner, false
	}
	value, ok := formatRData(recordType, rdata, origin)
	if !ok {
		return Record{}, owner, false
	}
	return Record{Name: name, Type: recordType, Value: value, TTL: ttl}, owner, true
}

// parseTTLToken 判断 token 是否为纯数字 TTL。
func parseTTLToken(token string) (int, bool) {
	if token == "" {
		return 0, false
	}
	value, err := strconv.Atoi(token)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}

// formatRData 按类型格式化记录值：域名类目标展开为绝对名（无尾点），TXT 去引号。
func formatRData(recordType string, rdata []zoneToken, origin string) (string, bool) {
	if len(rdata) == 0 {
		return "", false
	}
	switch recordType {
	case "A", "AAAA":
		parts := make([]string, 0, len(rdata))
		for _, token := range rdata {
			parts = append(parts, token.text)
		}
		return strings.Join(parts, " "), true
	case "CNAME", "NS":
		return expandName(rdata[0].text, origin), true
	case "MX":
		if len(rdata) < 2 {
			return "", false
		}
		return rdata[0].text + " " + expandName(rdata[1].text, origin), true
	case "TXT":
		parts := make([]string, 0, len(rdata))
		for _, token := range rdata {
			parts = append(parts, strings.TrimSpace(token.text))
		}
		return strings.Join(parts, " "), true
	default:
		return "", false
	}
}

// expandName 把区域文件里的名字展开成绝对名（无尾点、小写）。
// "@" 与空名映射到 origin；以 "." 结尾视为绝对名；其余按 origin 相对展开。
func expandName(name, origin string) string {
	name = strings.TrimSpace(name)
	switch name {
	case "", "@":
		return normalizeZoneName(origin)
	}
	if strings.HasSuffix(name, ".") {
		return normalizeZoneName(name)
	}
	origin = normalizeZoneName(origin)
	if origin == "" {
		return normalizeZoneName(name)
	}
	return normalizeZoneName(name + "." + origin)
}
