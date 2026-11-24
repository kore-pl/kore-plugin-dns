//go:build !unix && !windows

package dnsop

import "errors"

// errFragmentLockUnsupported 让不支持跨进程文件锁的平台**显式失败**，而不是
// 静默退化成进程内互斥——后者在多实例共享片段目录时依然会丢更新，且失败无声。
// kore 的目标平台是 linux / darwin / windows。
var errFragmentLockUnsupported = errors.New("当前平台不支持片段跨进程文件锁，拒绝在无互斥保护下写片段")

func lockFragment(string) (func(), error) {
	return nil, errFragmentLockUnsupported
}
