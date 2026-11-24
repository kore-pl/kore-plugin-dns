//go:build unix

package dnsop

import (
	"errors"
	"os"
	"syscall"
)

// lockFragment 对片段的**旁路 .lock 文件**加跨进程排他锁，返回释放函数。
//
// 为什么锁旁路文件而不是片段本身：writeFragmentLines 用 rename 换入新片段，
// 片段的 inode 每次都变；把 flock 挂在片段上，第二个进程 rename 后拿到的已经是
// 新 inode、锁随之失效（site 仓踩过这个坑）。旁路 .lock 文件的 inode 永不更替。
// 用阻塞 LOCK_EX 而非 LOCK_NB 轮询：临界区只有「读片段 → 改内存 → 原子写回」，
// 毫秒级；SIGKILL 时内核自动释放 flock，不会留下悬挂锁。
func lockFragment(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err == nil {
			break
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
