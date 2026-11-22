package main

import (
	"encoding/json"
	"sync"
)

// zoneEntry 是 zone.list 返回的单条区域视图（骨架级：只含区域名与记录数）。
type zoneEntry struct {
	Name        string `json:"name"`
	RecordCount int    `json:"record_count"`
}

// recordEntry 是 record.add 登记的一条记录视图。
type recordEntry struct {
	Zone  string `json:"zone"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// zoneListResult 是 dns.zone.list 的结构化结果。
// applied=false 明确表示本插件不改动宿主 DNS 服务。
type zoneListResult struct {
	Zones   []zoneEntry `json:"zones"`
	Count   int         `json:"count"`
	Applied bool        `json:"applied"`
}

// recordAddResult 是 dns.record.add 的结构化结果。
// applied=false 表示只做语法校验与提案登记，未下发到真实 DNS 服务。
type recordAddResult struct {
	Zone    string `json:"zone"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	TTL     int    `json:"ttl"`
	Applied bool   `json:"applied"`
	Added   bool   `json:"added"`
}

// dnsStore 是进程内的提案注册表：仅用于让 zone.list 可见 record.add 的提案，
// 不写任何宿主文件、不下发任何 DNS 服务（基础级 0.1.0 口径）。
type dnsStore struct {
	mu      sync.Mutex
	records []recordEntry
}

// newDNSStore 构造空的提案注册表。
func newDNSStore() *dnsStore {
	return &dnsStore{}
}

// addRecord 登记一条提案记录；同 zone/name/type/value 视为已存在，不重复追加。
func (s *dnsStore) addRecord(r recordEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.records {
		if existing == r {
			return false
		}
	}
	s.records = append(s.records, r)
	return true
}

// zones 按 zone 聚合当前提案记录，返回按首次出现顺序排列的区域视图。
func (s *dnsStore) zones() []zoneEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []zoneEntry
	seen := make(map[string]int)
	for _, r := range s.records {
		idx, ok := seen[r.Zone]
		if !ok {
			seen[r.Zone] = len(out)
			idx = len(out)
			out = append(out, zoneEntry{Name: r.Zone})
		}
		out[idx].RecordCount++
	}
	return out
}

// encode 把结构化结果编成 response.result 的 JSON 载荷。
func encode[T any](v T) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{"error":"encode failed"}`)
	}
	return b
}
