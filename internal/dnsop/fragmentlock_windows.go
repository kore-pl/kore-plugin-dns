//go:build windows

package dnsop

import (
	"os"
	"syscall"
	"unsafe"
)

// Go 标准库 syscall 在 Windows 上不导出 LockFileEx（它在 internal/syscall/windows），
// 直接按名称绑定 kernel32 过程——仍是标准库、零新增依赖。口径与 site 仓一致。
var (
	kernel32DNS         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileExDNS   = kernel32DNS.NewProc("LockFileEx")
	procUnlockFileExDNS = kernel32DNS.NewProc("UnlockFileEx")
)

// LOCKFILE_EXCLUSIVE_LOCK（winnt.h）。刻意不带 FAIL_IMMEDIATELY：与 unix 的
// 阻塞 LOCK_EX 语义一致，等待期间不忙轮询。
const lockfileExclusiveLockDNS = 0x00000002

func lockFragment(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped syscall.Overlapped
	ok, _, err := procLockFileExDNS.Call(
		f.Fd(), lockfileExclusiveLockDNS, 0,
		1, 0, // 锁 1 字节即可：只需「存在且唯一」
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if ok == 0 {
		_ = f.Close()
		return nil, err
	}
	return func() {
		var ov syscall.Overlapped
		_, _, _ = procUnlockFileExDNS.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
		_ = f.Close()
	}, nil
}
