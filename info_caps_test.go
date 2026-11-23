package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pengtang1024/kore-plugin-dns/internal/dnsop"
)

// TestMethodCapabilityConsistency 保证 info.json 的 method_capabilities 与代码方法表一致：
// 读方法 read、写方法 admin，且插件 capabilities 覆盖了两类。
func TestMethodCapabilityConsistency(t *testing.T) {
	var info struct {
		Capabilities       []string          `json:"capabilities"`
		MethodCapabilities map[string]string `json:"method_capabilities"`
	}
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读 info.json: %v", err)
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("解析 info.json: %v", err)
	}
	writes := map[string]bool{"dns.addRecord": true, "dns.updateRecord": true, "dns.deleteRecord": true, "dns.reload": true,
		"dns.record.add": true, "dns.record.update": true, "dns.record.delete": true}
	for _, m := range dnsop.Methods() {
		key := "dns." + m
		cap, ok := info.MethodCapabilities[key]
		if !ok {
			t.Fatalf("方法 %s 未在 info.json.method_capabilities 声明", key)
		}
		want := "system:read"
		if writes[key] {
			want = "system:admin"
		}
		if cap != want {
			t.Fatalf("%s 的 capability 应为 %s，实际 %s", key, want, cap)
		}
	}
	has := map[string]bool{}
	for _, c := range info.Capabilities {
		has[c] = true
	}
	if !has["system:read"] || !has["system:admin"] {
		t.Fatalf("capabilities 需同时声明 system:read 与 system:admin，实际 %v", info.Capabilities)
	}
}
