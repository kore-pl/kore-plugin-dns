package dnsop

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"
)

// fakeHost 是 Host 的内存实现：命令输出、文件内容、目录清单与套接字全部由用例给定，
// 因此引擎检测与三种配置格式的解析可以完全离线覆盖。
type fakeHost struct {
	// cmds 是「命令 + 参数」到 stdout 的映射；key 形如 "resolvectl --version"。
	cmds map[string]string
	// cmdErrs 是「命令 + 参数」到错误的映射（模拟命令不存在或失败）。
	cmdErrs map[string]error
	// files 是路径到内容。
	files map[string]string
	// permission 标记读取被拒的路径。
	permission map[string]bool
	// dirs 是目录到条目名。
	dirs map[string][]string
	// binaries 是 LookPath 认为存在的命令。
	binaries map[string]bool
	// sockets 是 Sockets 的返回值。
	sockets []Listening
	// socketErr 是 Sockets 的错误。
	socketErr error
	// calls 记录实际执行过的命令（断言「只执行固定 argv」用）。
	calls []string
}

// newFakeHost 构造空假宿主。
func newFakeHost() *fakeHost {
	return &fakeHost{
		cmds:       map[string]string{},
		cmdErrs:    map[string]error{},
		files:      map[string]string{},
		permission: map[string]bool{},
		dirs:       map[string][]string{},
		binaries:   map[string]bool{},
	}
}

// key 把命令与参数拼成映射键。
func cmdKey(name string, args []string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

// Run 返回预置输出；未预置视为命令不可用。
func (f *fakeHost) Run(_ context.Context, name string, args ...string) (string, error) {
	key := cmdKey(name, args)
	f.calls = append(f.calls, key)
	if err, ok := f.cmdErrs[key]; ok {
		return "", err
	}
	if out, ok := f.cmds[key]; ok {
		return out, nil
	}
	return "", errors.New("fakeHost: 命令不可用: " + key)
}

// ReadFile 返回预置内容；permission 标记的路径返回权限错误。
func (f *fakeHost) ReadFile(path string) ([]byte, error) {
	if f.permission[path] {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	if content, ok := f.files[path]; ok {
		return []byte(content), nil
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

// ListDir 返回预置目录条目。
func (f *fakeHost) ListDir(path string) ([]string, error) {
	if f.permission[path] {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	if entries, ok := f.dirs[path]; ok {
		out := make([]string, len(entries))
		copy(out, entries)
		sort.Strings(out)
		return out, nil
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

// LookPath 返回预置命令是否存在。
func (f *fakeHost) LookPath(name string) (string, error) {
	if f.binaries[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("exec: \"" + name + "\": executable file not found in $PATH")
}

// Sockets 返回预置套接字。
func (f *fakeHost) Sockets(_ context.Context, _ int) ([]Listening, error) {
	return f.sockets, f.socketErr
}
