package dnsop

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestWriteFragmentLinesConcurrentUniqueTemp 是 P2「固定临时名竞态」的并发边界用例。
//
// 场景：多个写者同秒并发写同一个 dnsmasq 片段，每个写者提交一份完整内容
// （200 行、每行都是自己的唯一标记）。正确行为有三条：
//  1. 每个写者都成功返回——不能因为争抢同一个临时文件而拿到 ENOENT / 半写错误；
//  2. 最终片段是某一写者的完整内容——行数不短、且不出现跨写者混合行；
//  3. 各写者临时文件互不干扰（这不是断言实现，而是 1+2 的唯一解释）。
//
// 旧实现 `tmp := path + ".tmp"` 下，N 个 os.WriteFile 互相截断同一临时文件，
// 第一次 os.Rename 成功后其余 rename 全部 ENOENT；即便侥幸无错也会留下半写/混合内容。
func TestWriteFragmentLinesConcurrentUniqueTemp(t *testing.T) {
	const (
		writers   = 32
		linesEach = 200
		rounds    = 8
	)

	for round := 0; round < rounds; round++ {
		dir := t.TempDir()
		path := filepath.Join(dir, hostsFragmentName)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errCh := make(chan string, writers)

		for w := 0; w < writers; w++ {
			marker := fmt.Sprintf("marker-%02d", w)
			lines := make([]string, linesEach)
			for i := range lines {
				lines[i] = marker
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if perr := writeFragmentLines(path, lines); perr != nil {
					errCh <- fmt.Sprintf("writer=%s err=%+v", marker, perr)
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errCh)

		var errs []string
		for msg := range errCh {
			errs = append(errs, msg)
		}
		if len(errs) > 0 {
			show := errs
			if len(show) > 3 {
				show = show[:3]
			}
			t.Fatalf("第 %d 轮：%d/%d 写者失败：%s", round, len(errs), writers, strings.Join(show, " | "))
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("第 %d 轮：片段未写入 %s: %v", round, path, err)
		}
		got := strings.TrimSuffix(string(data), "\n")
		if got == "" {
			t.Fatalf("第 %d 轮：片段为空", round)
		}
		gotLines := strings.Split(got, "\n")
		if len(gotLines) != linesEach {
			t.Fatalf("第 %d 轮：片段行数=%d，期望 %d（半写/截断）", round, len(gotLines), linesEach)
		}
		first := gotLines[0]
		for _, ln := range gotLines[1:] {
			if ln != first {
				t.Fatalf("第 %d 轮：片段出现跨写者混合行 %q 与 %q", round, first, ln)
			}
		}
	}
}

// TestConcurrentAddsKeepEveryRecord 锁定 lead 升级的验收口径：lost update 维度。
//
// N 个写者并发对**同一个 dnsmasq 片段**执行 record.add，各加一条不同记录；
// 最终文件必须逐条包含全部 N 条。只用唯一临时名挡不住这个坑——A/B 各读旧
// lines、各加自己的一条、各自 rename 到同一 path，后写覆盖前者。
// 正确实现必须用旁路锁把 read→apply→write 整段串行化（锁挂 .lock 旁路文件，
// 不挂片段本身：rename 后 inode 更替锁失效）。
func TestConcurrentAddsKeepEveryRecord(t *testing.T) {
	const writers = 16

	dir := t.TempDir()
	d := dnsmasqDetector(t, dir)
	start := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan string, writers)

	for i := 0; i < writers; i++ {
		name := fmt.Sprintf("h%02d.example.com", i)
		value := fmt.Sprintf("192.0.2.%d", i+1)
		params := RecordWriteParams{Zone: "example.com", Name: name, Type: "A", Value: value, TTL: 60}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, perr := d.writeWithEngine(context.Background(), EngineDnsmasq, "add", params); perr != nil {
				errCh <- fmt.Sprintf("add %s err=%+v", name, perr)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)

	for msg := range errCh {
		t.Errorf("并发 add 出错: %s", msg)
	}

	data, err := os.ReadFile(filepath.Join(dir, hostsFragmentName))
	if err != nil {
		t.Fatalf("读取片段失败: %v", err)
	}
	content := string(data)
	for i := 0; i < writers; i++ {
		name := fmt.Sprintf("h%02d.example.com", i)
		value := fmt.Sprintf("192.0.2.%d", i+1)
		want := fmt.Sprintf("host-record=%s,%s,60", name, value)
		if !strings.Contains(content, want) {
			t.Errorf("丢失记录 %s（lost update）：最终片段=\n%s", want, content)
		}
	}
}
