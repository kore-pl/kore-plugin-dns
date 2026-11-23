package dnsop

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// JournalEntry 是一次写操作的审计记录与回滚依据。
//
// 每次真实写入写两条：phase=intent（下发前，失败即不执行）与 phase=result
// （下发后，带 applied/rolledback）。文件位于 <KORE_STATE_DIR>/dns-journal/updates.jsonl，
// 属主是插件运行用户、0600 追加写——这是"保留备份"的落点（服务器侧动态更新没有本地 zone 文件可备份）。
type JournalEntry struct {
	TS        string   `json:"ts"`
	Phase     string   `json:"phase"`
	Operation string   `json:"operation"`
	Zone      string   `json:"zone"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Value     string   `json:"value,omitempty"`
	Previous  []string `json:"previous,omitempty"`
	TTL       int      `json:"ttl,omitempty"`
	Server    string   `json:"server"`
	Port      int      `json:"port"`
	Result    string   `json:"result,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// Journal 持久化写操作记录；Append 返回落盘文件路径。
type Journal interface {
	Append(entry JournalEntry) (string, error)
}

// FileJournal 以 JSONL 追加写；目录 0700、文件 0600，每条写完 fsync（掉电也不丢审计）。
type FileJournal struct {
	Dir string
}

// Append 追加一条记录并返回文件路径。
func (j FileJournal) Append(entry JournalEntry) (string, error) {
	if j.Dir == "" {
		return "", fmt.Errorf("journal 目录未配置")
	}
	if err := os.MkdirAll(j.Dir, 0o700); err != nil {
		return "", fmt.Errorf("创建 journal 目录 %s: %w", j.Dir, err)
	}
	path := filepath.Join(j.Dir, "updates.jsonl")
	if entry.TS == "" {
		entry.TS = time.Now().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("序列化 journal 记录: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return "", fmt.Errorf("打开 journal %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return "", fmt.Errorf("写 journal %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("fsync journal %s: %w", path, err)
	}
	return path, nil
}
