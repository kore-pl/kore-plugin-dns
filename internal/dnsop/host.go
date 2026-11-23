package dnsop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxCommandOutput 是单条命令 stdout 的保留上限（防止异常输出撑爆内存）。
const maxCommandOutput = 1 << 20

// maxFileSize 是单个配置/区域文件的读取上限（8 MiB，正常 zone 文件远小于此）。
const maxFileSize = 8 << 20

// ErrPermission / ErrNotExist 是 dnsop 对外暴露的错误分类，供上层映射 E_NEED_ROOT。
var (
	// ErrPermission 表示读取被权限拒绝（非 root 读 /etc/bind 等）。
	ErrPermission = fs.ErrPermission
	// ErrNotExist 表示路径不存在（不算错误，按「未安装」降级）。
	ErrNotExist = fs.ErrNotExist
)

// Host 抽象插件对宿主的全部只读访问：执行固定 argv 命令、读文件、列目录、探测监听套接字。
//
// 生产实现是 OSHost；单测用内存假实现，因此引擎检测与三种格式的解析都能离线覆盖，
// 不依赖机器上装了哪种 DNS 服务。
type Host interface {
	// Run 执行固定 argv 命令（不经 shell），返回 stdout；命令失败时同时返回已捕获的 stdout。
	Run(ctx context.Context, name string, args ...string) (string, error)
	// ReadFile 读取文件；不存在返回 ErrNotExist、被拒返回 ErrPermission（包装后可 errors.Is）。
	ReadFile(path string) ([]byte, error)
	// ListDir 列出目录下的条目名（不递归）；目录不存在返回 ErrNotExist。
	ListDir(path string) ([]string, error)
	// LookPath 判断命令是否在 PATH 内。
	LookPath(name string) (string, error)
	// Sockets 列出指定端口的监听套接字（TCP+UDP）。
	Sockets(ctx context.Context, port int) ([]Listening, error)
}

// OSHost 是 Host 的真实实现：所有命令都是固定 argv、带超时、只取 stdout。
type OSHost struct {
	// Timeout 是单条命令超时，缺省 5s。
	Timeout time.Duration
}

// Run 执行命令并返回 stdout；stderr 只用于错误文案，不参与解析。
func (h OSHost) Run(ctx context.Context, name string, args ...string) (string, error) {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	text := stdout.String()
	if len(text) > maxCommandOutput {
		text = text[:maxCommandOutput]
	}
	if err != nil {
		return text, fmt.Errorf("执行 %s: %w（stderr: %s）", name, err, truncate(strings.TrimSpace(stderr.String()), 200))
	}
	return text, nil
}

// ReadFile 读取文件（8 MiB 上限），权限/不存在错误原样返回供上层 errors.Is 分类。
func (h OSHost) ReadFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("文件 %s 超过 %d 字节上限", path, maxFileSize)
	}
	return data, nil
}

// ListDir 列出目录条目名（排序后返回，保证输出确定）。
func (h OSHost) ListDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

// LookPath 判断命令是否存在。
func (h OSHost) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// Sockets 列出 DNS 端口的监听套接字：优先 ss（能带属主进程），
// ss 不可用或没有结果时退回解析 /proc/net/{tcp,tcp6,udp,udp6}（无依赖、非 root 可读）。
func (h OSHost) Sockets(ctx context.Context, port int) ([]Listening, error) {
	var ssErr error
	if _, err := exec.LookPath("ss"); err == nil {
		filter := "sport = :" + strconv.Itoa(port)
		out, runErr := h.Run(ctx, "ss", "-lntup", filter)
		if runErr == nil {
			if items := parseSS(out, port); len(items) > 0 {
				return items, nil
			}
		} else {
			ssErr = runErr
		}
	}
	items, procErr := readProcNet(port)
	if len(items) > 0 {
		return items, nil
	}
	if ssErr != nil {
		return nil, fmt.Errorf("ss 不可用（%v）且 /proc/net 未列出端口 %d: %w", ssErr, port, procErr)
	}
	return nil, procErr
}

// truncate 截断字符串到 n 字节（仅用于错误文案）。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// parseSS 解析 `ss -lntup 'sport = :53'` 的输出。
//
// 输出列：Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]。
// 非 root 时 Process 列为空——此时只保留地址/协议，归属交给 assignListening 的地址启发式。
func parseSS(out string, port int) []Listening {
	items := make([]Listening, 0, 8)
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "Netid") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := fields[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		addr, gotPort, ok := splitAddrPort(fields[4])
		if !ok || gotPort != port {
			continue
		}
		item := Listening{Addr: addr, Port: gotPort, Proto: proto}
		for _, field := range fields[5:] {
			if name := ssProcessName(field); name != "" {
				item.Process = name
				break
			}
		}
		items = append(items, item)
	}
	return dedupeListening(items)
}

// ssProcessName 从 `users:(("dnsmasq",pid=2214,fd=5))` 中提取进程名。
func ssProcessName(field string) string {
	const marker = "(("
	idx := strings.Index(field, marker)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimPrefix(field[idx+len(marker):], "\"")
	end := strings.Index(rest, "\"")
	if end <= 0 {
		return ""
	}
	return rest[:end]
}

// splitAddrPort 拆 `127.0.0.53%lo:53` / `[::]:53` / `*:53`。
func splitAddrPort(raw string) (string, int, bool) {
	idx := strings.LastIndex(raw, ":")
	if idx <= 0 {
		return "", 0, false
	}
	addr := raw[:idx]
	port, err := strconv.Atoi(raw[idx+1:])
	if err != nil {
		return "", 0, false
	}
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	if at := strings.Index(addr, "%"); at >= 0 {
		addr = addr[:at]
	}
	switch addr {
	case "*", "":
		addr = "0.0.0.0"
	}
	return addr, port, true
}

// dedupeListening 去重（同一 addr/port/proto）并排序，保证输出稳定。
func dedupeListening(items []Listening) []Listening {
	seen := make(map[string]struct{}, len(items))
	out := make([]Listening, 0, len(items))
	for _, item := range items {
		key := item.Proto + "|" + item.Addr + "|" + strconv.Itoa(item.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// readProcNet 从 /proc/net 下四个文件解析指定端口的监听套接字（无外部命令依赖）。
func readProcNet(port int) ([]Listening, error) {
	sources := []struct {
		path  string
		proto string
		tcp   bool
	}{
		{"/proc/net/tcp", "tcp", true},
		{"/proc/net/tcp6", "tcp", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp", false},
	}
	items := make([]Listening, 0, 8)
	var lastErr error
	read := 0
	for _, source := range sources {
		data, err := os.ReadFile(source.path)
		if err != nil {
			lastErr = err
			continue
		}
		read++
		items = append(items, parseProcNet(string(data), source.proto, source.tcp, port)...)
	}
	if read == 0 {
		if lastErr == nil {
			lastErr = ErrNotExist
		}
		return nil, fmt.Errorf("读取 /proc/net: %w", lastErr)
	}
	return dedupeListening(items), nil
}

// parseProcNet 解析单个 /proc/net 文件：第 1 列是 local_address，第 3 列是状态。
// tcp 只要 LISTEN(0A)，udp 只要 CLOSE(07)（该状态下 socket 处于可收包监听）。
func parseProcNet(text, proto string, isTCP bool, port int) []Listening {
	items := make([]Listening, 0, 4)
	for index, raw := range strings.Split(text, "\n") {
		if index == 0 {
			continue // 表头
		}
		fields := strings.Fields(raw)
		if len(fields) < 4 {
			continue
		}
		if isTCP && fields[3] != "0A" {
			continue
		}
		if !isTCP && fields[3] != "07" {
			continue
		}
		addrHex, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		socketPort, err := strconv.ParseUint(portHex, 16, 32)
		if err != nil || int(socketPort) != port {
			continue
		}
		addr, ok := decodeProcNetAddr(addrHex)
		if !ok {
			continue
		}
		items = append(items, Listening{Addr: addr, Port: int(socketPort), Proto: proto})
	}
	return items
}

// decodeProcNetAddr 解码 /proc/net 的地址列：
// IPv4 是 8 位 hex（每组 4 字节小端），IPv6 是 32 位 hex（4 组 4 字节小端）。
func decodeProcNetAddr(raw string) (string, bool) {
	switch len(raw) {
	case 8:
		value, err := strconv.ParseUint(raw, 16, 32)
		if err != nil {
			return "", false
		}
		ip := net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
		return ip.String(), true
	case 32:
		buf := make([]byte, 0, 16)
		for group := 0; group < 4; group++ {
			value, err := strconv.ParseUint(raw[group*8:(group+1)*8], 16, 32)
			if err != nil {
				return "", false
			}
			buf = append(buf, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
		}
		return net.IP(buf).String(), true
	default:
		return "", false
	}
}

// errorsIsPermission 判断错误链是否属于权限拒绝。
func errorsIsPermission(err error) bool {
	return err != nil && (errors.Is(err, fs.ErrPermission) ||
		strings.Contains(strings.ToLower(err.Error()), "permission denied"))
}

// errorsIsNotExist 判断错误链是否属于路径不存在。
func errorsIsNotExist(err error) bool {
	return err != nil && errors.Is(err, fs.ErrNotExist)
}
