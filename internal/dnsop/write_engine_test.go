package dnsop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// armoredHost 是最小 Host 假实现：只回答 sockets 与「文件不存在」，用于引擎分派测试。
type armoredHost struct{ sockets []Listening }

func (h armoredHost) Run(context.Context, string, ...string) (string, error) { return "", nil }
func (h armoredHost) RunInput(context.Context, string, []string, string) (string, error) {
	return "", nil
}
func (h armoredHost) ReadFile(string) ([]byte, error)  { return nil, os.ErrNotExist }
func (h armoredHost) ListDir(string) ([]string, error) { return nil, os.ErrNotExist }
func (h armoredHost) LookPath(string) (string, error)  { return "", errors.New("not found") }
func (h armoredHost) Sockets(context.Context, int) ([]Listening, error) {
	return h.sockets, nil
}

func dnsmasqDetector(t *testing.T, dir string) Detector {
	t.Helper()
	return Detector{
		Host:          armoredHost{sockets: []Listening{{Addr: "127.0.0.1", Port: 53, Proto: "udp", Process: "dnsmasq"}}},
		Write:         WriteOptions{FragmentDir: dir},
		DefaultEngine: EngineDnsmasq,
	}
}

// TestWriteRecordDispatchesByEngine 覆盖引擎分派：dnsmasq 可写、systemd-resolved 不支持。
func TestWriteRecordDispatchesByEngine(t *testing.T) {
	ctx := context.Background()
	d := dnsmasqDetector(t, t.TempDir())
	raw := []byte(`{"zone":"example.com","name":"www.example.com","type":"A","value":"203.0.113.9","ttl":600}`)
	result, perr := d.WriteRecord(ctx, "add", raw)
	if perr != nil {
		t.Fatalf("dnsmasq add 失败: %+v", perr)
	}
	if result.Channel != DnsmasqChannel || !result.Changed || !result.Applied {
		t.Fatalf("dnsmasq add 结果不对: %+v", result)
	}

	// 探测不出引擎（stub 读不到配置）→ E_NO_ENGINE + hint，而不是静默失败。
	resolved := Detector{Host: armoredHost{sockets: []Listening{{Addr: "127.0.0.53", Port: 53, Proto: "udp", Process: "systemd-resolve"}}}}
	if _, perr = resolved.WriteRecord(ctx, "add", raw); perr == nil || perr.Code != CodeNoEngine {
		t.Fatalf("无引擎应返回 E_NO_ENGINE，实际 %+v", perr)
	}
	// 引擎不支持写（明确定位到 CoreDNS）→ E_UNSUPPORTED + hint。
	if _, perr = resolved.writeWithEngine(ctx, EngineCoreDNS, "add", RecordWriteParams{Zone: "example.com", Name: "a.example.com", Type: "A", Value: "192.0.2.1"}); perr == nil || perr.Code != pluginapi.E_UNSUPPORTED {
		t.Fatalf("CoreDNS 应返回 E_UNSUPPORTED，实际 %+v", perr)
	}
}

// TestDnsmasqWriteIsIdempotent 覆盖「重复加不重复写、重复删不报错」。
func TestDnsmasqWriteIsIdempotent(t *testing.T) {
	d := dnsmasqDetector(t, t.TempDir())
	params := RecordWriteParams{Zone: "example.com", Name: "a.example.com", Type: "A", Value: "192.0.2.10", TTL: 300}
	first, perr := d.writeWithEngine(context.Background(), EngineDnsmasq, "add", params)
	if perr != nil || !first.Changed {
		t.Fatalf("首次 add 应 changed=true: %+v %+v", first, perr)
	}
	second, perr := d.writeWithEngine(context.Background(), EngineDnsmasq, "add", params)
	if perr != nil || second.Changed || !second.Applied {
		t.Fatalf("重复 add 应幂等: %+v %+v", second, perr)
	}
	// 重复删：第一次 removed、第二次空操作。
	if del, perr := d.writeWithEngine(context.Background(), EngineDnsmasq, "delete", params); perr != nil || !del.Changed {
		t.Fatalf("首次 delete 应 changed=true: %+v %+v", del, perr)
	}
	again, perr := d.writeWithEngine(context.Background(), EngineDnsmasq, "delete", params)
	if perr != nil || again.Changed || !again.Applied {
		t.Fatalf("重复 delete 应幂等: %+v %+v", again, perr)
	}
}

// TestDnsmasqWriteParamValidation 覆盖非法 type / ttl / name / 值。
func TestDnsmasqWriteParamValidation(t *testing.T) {
	d := dnsmasqDetector(t, t.TempDir())
	cases := []struct {
		name   string
		params RecordWriteParams
		code   string
	}{
		{"mx 不支持", RecordWriteParams{Zone: "example.com", Name: "example.com", Type: "MX", Value: "10 mail.example.com"}, pluginapi.E_UNSUPPORTED},
		{"ttl 超限", RecordWriteParams{Zone: "example.com", Name: "a.example.com", Type: "A", Value: "192.0.2.1", TTL: 999999}, pluginapi.E_INVALID},
		{"name 越界", RecordWriteParams{Zone: "example.com", Name: "a.example.net", Type: "A", Value: "192.0.2.1"}, pluginapi.E_INVALID},
		{"A 用 v6", RecordWriteParams{Zone: "example.com", Name: "a.example.com", Type: "A", Value: "2001:db8::1"}, pluginapi.E_INVALID},
		{"缺值", RecordWriteParams{Zone: "example.com", Name: "a.example.com", Type: "A"}, pluginapi.E_INVALID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, perr := d.writeWithEngine(context.Background(), EngineDnsmasq, "add", tc.params)
			if perr == nil || perr.Code != tc.code {
				t.Fatalf("期望 %s，实际 %+v", tc.code, perr)
			}
		})
	}
	// 片段目录缺失 → E_UNSUPPORTED（明确告知未启用，而不是静默成功）。
	_, perr := Detector{}.writeWithEngine(context.Background(), EngineDnsmasq, "add",
		RecordWriteParams{Zone: "example.com", Name: "a.example.com", Type: "A", Value: "192.0.2.1"})
	if perr == nil || perr.Code != pluginapi.E_UNSUPPORTED {
		t.Fatalf("缺 FragmentDir 应 E_UNSUPPORTED，实际 %+v", perr)
	}
}

// TestDnsmasqFragmentOnlyUnderStateDir 证明写入只发生在状态目录内（零侵入）。
func TestDnsmasqFragmentOnlyUnderStateDir(t *testing.T) {
	dir := t.TempDir()
	d := dnsmasqDetector(t, dir)
	params := RecordWriteParams{Zone: "example.com", Name: "b.example.com", Type: "CNAME", Value: "target.example.com", TTL: 120}
	if _, perr := d.writeWithEngine(context.Background(), EngineDnsmasq, "add", params); perr != nil {
		t.Fatalf("add 失败: %+v", perr)
	}
	data, err := os.ReadFile(filepath.Join(dir, hostsFragmentName))
	if err != nil {
		t.Fatalf("片段未写入 state 目录: %v", err)
	}
	if got := string(data); got != "host-record=b.example.com,target.example.com,120\n" {
		t.Fatalf("片段内容不符: %q", got)
	}
}

// TestReloadByEngine 覆盖 reload 分派：dnsmasq 返回 restart hint，systemd-resolved 不支持。
func TestReloadByEngine(t *testing.T) {
	ctx := context.Background()
	d := dnsmasqDetector(t, t.TempDir())
	res, perr := d.Reload(ctx, "example.com")
	if perr != nil || !res.ReloadRequired || res.Reloaded {
		t.Fatalf("dnsmasq reload 应返回 reload_required: %+v %+v", res, perr)
	}
	// 无引擎时 reload 与写一致：E_NO_ENGINE + hint。
	resolved := Detector{Host: armoredHost{sockets: []Listening{{Addr: "127.0.0.53", Port: 53, Proto: "udp", Process: "systemd-resolve"}}}}
	if _, perr := resolved.Reload(ctx, ""); perr == nil || perr.Code != CodeNoEngine {
		t.Fatalf("无引擎 reload 应 E_NO_ENGINE，实际 %+v", perr)
	}
}
