package dnsop

import (
	"net"
	"strings"
)

// zoneDecl 是 named.conf 中的一个 zone 声明。
type zoneDecl struct {
	// Name 是区域名（无尾点、小写）。
	Name string
	// Type 是区域类型（master / slave / hint / forward / static-stub / ...）。
	Type string
	// File 是区域文件路径（相对路径按配置文件目录解析，由调用方处理）。
	File string
}

// bindToken 是 named.conf 的一个词法单元；quoted 表示它原本是带引号的字符串。
type bindToken struct {
	text   string
	quoted bool
}

// ParseNamedConf 解析 named.conf / named.conf.local，提取 zone 声明的 name / type / file。
//
// 只做文本解析：不展开 include、不执行任何脚本。注释支持 //、#、/* */。
func ParseNamedConf(text string) []zoneDecl {
	tokens := tokenizeNamed(text)
	decls := make([]zoneDecl, 0, 4)
	for index := 0; index < len(tokens); index++ {
		if !strings.EqualFold(tokens[index].text, "zone") {
			continue
		}
		decl, next, ok := parseZoneBlock(tokens, index)
		if !ok {
			continue
		}
		decls = append(decls, decl)
		index = next
	}
	return decls
}

// parseZoneBlock 从 zone 关键字的位置解析一个完整块；返回下一个待扫描下标。
func parseZoneBlock(tokens []bindToken, start int) (zoneDecl, int, bool) {
	// zone "name" { ... };
	if start+2 >= len(tokens) {
		return zoneDecl{}, start, false
	}
	name := strings.TrimSpace(tokens[start+1].text)
	if tokens[start+2].text != "{" {
		return zoneDecl{}, start, false
	}
	decl := zoneDecl{Name: normalizeZoneName(name)}
	depth := 0
	for index := start + 2; index < len(tokens); index++ {
		text := tokens[index].text
		switch text {
		case "{":
			depth++
			continue
		case "}":
			depth--
			if depth == 0 {
				return decl, index, true
			}
			continue
		}
		if depth != 1 {
			continue
		}
		switch strings.ToLower(text) {
		case "type":
			if index+1 < len(tokens) {
				decl.Type = strings.ToLower(strings.TrimSpace(tokens[index+1].text))
			}
		case "file":
			if index+1 < len(tokens) {
				decl.File = strings.TrimSpace(tokens[index+1].text)
			}
		}
	}
	return decl, start, false
}

// ParseNamedForwarders 提取 forwarders { ... }; 中的上游地址。
func ParseNamedForwarders(text string) []string {
	tokens := tokenizeNamed(text)
	out := make([]string, 0, 4)
	for index := 0; index < len(tokens); index++ {
		if !strings.EqualFold(tokens[index].text, "forwarders") {
			continue
		}
		if index+1 >= len(tokens) || tokens[index+1].text != "{" {
			continue
		}
		for cursor := index + 2; cursor < len(tokens); cursor++ {
			if tokens[cursor].text == "}" {
				index = cursor
				break
			}
			candidate := strings.TrimSpace(tokens[cursor].text)
			if candidate == ";" {
				continue
			}
			if ip := net.ParseIP(candidate); ip != nil {
				out = append(out, candidate)
				if len(out) >= maxUpstreams {
					return out
				}
			}
		}
	}
	return out
}

// tokenizeNamed 把 named.conf 文本切成词法单元：注释剔除、引号保留内容、
// `{` `}` `;` 各自成 token，其余按空白切分。
func tokenizeNamed(text string) []bindToken {
	tokens := make([]bindToken, 0, 128)
	var current strings.Builder
	flush := func() {
		if current.Len() == 0 {
			return
		}
		tokens = append(tokens, bindToken{text: current.String()})
		current.Reset()
	}
	for index := 0; index < len(text); index++ {
		char := text[index]
		switch {
		case char == '/' && index+1 < len(text) && text[index+1] == '/':
			flush()
			for index < len(text) && text[index] != '\n' {
				index++
			}
		case char == '#':
			flush()
			for index < len(text) && text[index] != '\n' {
				index++
			}
		case char == '/' && index+1 < len(text) && text[index+1] == '*':
			flush()
			index += 2
			for index+1 < len(text) && !(text[index] == '*' && text[index+1] == '/') {
				index++
			}
			index++
		case char == '"':
			flush()
			end := index + 1
			var quoted strings.Builder
			for end < len(text) && text[end] != '"' {
				if text[end] == '\\' && end+1 < len(text) {
					quoted.WriteByte(text[end+1])
					end += 2
					continue
				}
				quoted.WriteByte(text[end])
				end++
			}
			tokens = append(tokens, bindToken{text: quoted.String(), quoted: true})
			index = end
		case char == '{' || char == '}' || char == ';':
			flush()
			tokens = append(tokens, bindToken{text: string(char)})
		case char == ' ' || char == '\t' || char == '\r' || char == '\n':
			flush()
		default:
			current.WriteByte(char)
		}
	}
	flush()
	return tokens
}

// normalizeZoneName 归一区域名：去尾点、转小写。
func normalizeZoneName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
