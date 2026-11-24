package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pengtang1024/kore-plugin-dns/internal/dnsop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
	"github.com/pengtang1024/kore/pkg/pluginapi/pluginapitest"
)

// declaredRootAction / declaredInfo 是 info.json 里本仓关心的声明字段（显式定形，G-24）。
type declaredRootAction struct {
	ID           string   `json:"id"`
	Argv         []string `json:"argv"`
	TimeoutS     int      `json:"timeout_s"`
	Description  string   `json:"description"`
	Irreversible bool     `json:"irreversible"`
}

type declaredInfo struct {
	ID           string               `json:"id"`
	Version      string               `json:"version"`
	RequiresRoot bool                 `json:"requires_root"`
	RootActions  []declaredRootAction `json:"root_actions"`
}

// loadDeclaredInfo 读取并解析仓根 info.json。
func loadDeclaredInfo(t *testing.T) declaredInfo {
	t.Helper()
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读取 info.json: %v", err)
	}
	var info declaredInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("解析 info.json: %v", err)
	}
	return info
}

// TestRootActionsMatchCode 锁定「声明 ↔ 代码」一一对应：
//
//   - 声明了 root_actions 就必须 requires_root=true（协议 §3.1.3）；
//   - 声明集合必须与代码常量集合双向相等（声明未使用 / 代码引用未声明都失败）；
//   - 每条 argv / timeout 必须与代码里的固定形状逐字一致，并通过 SDK 的
//     ValidateRootAction（ADR-0018 schema + ADR-0022 命令形状）。
//
// 反例自证：删掉 info.json 里任意一条 root_actions 后本用例立即失败（集合不等）；
// 改 argv（例如把 flush-caches 换成 reload）同样失败——声明的唯一真源在代码常量。
func TestRootActionsMatchCode(t *testing.T) {
	info := loadDeclaredInfo(t)
	// SDK 的整份 info.json 自检（root_actions schema + 形状、method_capabilities、
	// capabilities 与 requires_root 一致性）——与内核安装期使用的是同一实现。
	if err := pluginapitest.ValidateInfoFile("info.json"); err != nil {
		t.Fatalf("info.json 未通过 SDK 自检: %v", err)
	}
	if !info.RequiresRoot {
		t.Fatal("声明了 root_actions 时必须 requires_root=true")
	}
	codeIDs := map[string]bool{dnsop.RootActionResolvedFlush: true}
	if len(info.RootActions) != len(codeIDs) {
		t.Fatalf("info.json 声明 %d 条 root_actions，代码引用 %d 条（必须一一对应）",
			len(info.RootActions), len(codeIDs))
	}
	for _, action := range info.RootActions {
		if !codeIDs[action.ID] {
			t.Fatalf("声明 %q 在代码中没有对应常量/调用点（声明未使用）", action.ID)
		}
		if action.ID == dnsop.RootActionResolvedFlush {
			if len(action.Argv) != len(dnsop.ResolvedFlushArgv) {
				t.Fatalf("argv 长度=%d，代码常量=%d", len(action.Argv), len(dnsop.ResolvedFlushArgv))
			}
			for index := range action.Argv {
				if action.Argv[index] != dnsop.ResolvedFlushArgv[index] {
					t.Fatalf("argv[%d]=%q，代码常量=%q", index, action.Argv[index], dnsop.ResolvedFlushArgv[index])
				}
			}
		}
		if action.TimeoutS < 1 || action.TimeoutS > 300 {
			t.Fatalf("%s 的 timeout_s=%d 超出协议区间 1–300", action.ID, action.TimeoutS)
		}
		if action.Irreversible {
			t.Fatalf("%s 声明为不可逆：本插件只声明只读/可逆动作（刷新缓存可重复执行）", action.ID)
		}
		if action.Description == "" {
			t.Fatalf("%s 缺少 description（启用确认要展示给用户）", action.ID)
		}
		if err := pluginapi.ValidateRootAction(pluginapi.RootAction{
			ID:           action.ID,
			Argv:         action.Argv,
			TimeoutS:     action.TimeoutS,
			Description:  action.Description,
			Irreversible: action.Irreversible,
		}); err != nil {
			t.Fatalf("声明未通过 SDK 校验（schema + ADR-0022 形状）：%v", err)
		}
	}
	// 反向：代码常量必须都有声明。
	declared := make(map[string]bool, len(info.RootActions))
	for _, action := range info.RootActions {
		declared[action.ID] = true
	}
	if !declared[dnsop.RootActionResolvedFlush] {
		t.Fatalf("代码常量 %q 未在 info.json 声明", dnsop.RootActionResolvedFlush)
	}
}

// TestBlockedDNSActionsRejectedByPolicy 是「为什么只能声明一条」的可执行证据：
//
// 本轮真正想补的 bind9 重载与 zone 写入（rndc reload / rndc reconfig /
// named-checkzone / 写 zone 文件）在 ADR-0022 的受控形状表里**没有形状**，
// 声明出来会被内核在安装/启用期以 E_INVALID 拒绝（插件直接不可用）。
//
// 这不是本插件能绕过的：形状表在 kore/pkg/pluginapi（SDK），扩表属安全边界变更，
// 必须走 kore 侧 ADR + 新 SDK 版本。本用例把「不许偷偷声明」钉住——将来若 kore
// 扩了形状，这个用例会先失败，提醒同步 info.json 与代码，而不是静默漂移。
func TestBlockedDNSActionsRejectedByPolicy(t *testing.T) {
	blocked := []struct {
		name string
		argv []string
	}{
		{"rndc reload", []string{"/usr/sbin/rndc", "reload"}},
		{"rndc reconfig", []string{"/usr/sbin/rndc", "reconfig"}},
		{"named-checkzone", []string{"/usr/bin/named-checkzone", "example.com", "/var/lib/bind/db.example.com"}},
		{"写 zone 文件（tee）", []string{"/usr/bin/tee", "/etc/bind/zones/db.example.com"}},
	}
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			err := pluginapi.ValidateRootAction(pluginapi.RootAction{
				ID:       "blocked-probe",
				Argv:     tc.argv,
				TimeoutS: 15,
			})
			if err == nil {
				t.Fatalf("ADR-0022 形状表不应接受 %q——若已扩展，请同步 info.json 与 dnsop 常量并更新本用例", tc.argv)
			}
		})
	}
}
