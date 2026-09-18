package identity

import (
	"strings"
	"testing"

	"rmt.local/monitor/internal/domain"
)

func TestProcessKeySeparatesPIDReuseAndBootScope(t *testing.T) {
	scope := Scope{HostID: "host", BootID: "boot"}
	copy(scope.Salt[:], strings.Repeat("s", SaltBytes))
	first := ProcessIdentity{PID: 42, StartAbsolute: 100}
	reused := ProcessIdentity{PID: 42, StartAbsolute: 101}
	firstKey, err := ProcessKey(scope, first)
	if err != nil {
		t.Fatal(err)
	}
	reusedKey, err := ProcessKey(scope, reused)
	if err != nil {
		t.Fatal(err)
	}
	otherBoot := scope
	otherBoot.BootID = "next-boot"
	otherBootKey, err := ProcessKey(otherBoot, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstKey == reusedKey || firstKey == otherBootKey || len(firstKey) != 64 {
		t.Fatalf("keys do not fence identity: first=%s reused=%s boot=%s", firstKey, reusedKey, otherBootKey)
	}
}

func TestConsistencyRejectsExitRaceAndIdentityChange(t *testing.T) {
	before := ProcessIdentity{PID: 8, UID: 501, ParentPID: 1, StartAbsolute: 20, StartWallSec: 10, StartWallUsec: 5}
	if !Consistent(before, before) {
		t.Fatal("stable identity rejected")
	}
	after := before
	after.StartWallUsec++
	if Consistent(before, after) {
		t.Fatal("wall start identity race accepted")
	}
	after = before
	after.StartAbsolute++
	if Consistent(before, after) {
		t.Fatal("absolute start identity change accepted")
	}
}

func TestDisplayIdentityPersistsOnlyAllowlistedBasenames(t *testing.T) {
	if name, category := DisplayIdentity("/private/tmp/secret-worker", RoleNone); name != nil || category != domain.ProcessOtherSameUser {
		t.Fatalf("private process leaked: name=%v category=%s", name, category)
	}
	if name, category := DisplayIdentity("/usr/local/bin/ollama", RoleSelectedOllama); name == nil || *name != "ollama" || category != domain.ProcessSelectedOllama {
		t.Fatalf("selected Ollama not classified: name=%v category=%s", name, category)
	}
	if name, category := DisplayIdentity("llm-monitor-collector", RoleRMTCollector); name == nil || category != domain.ProcessRMT {
		t.Fatalf("RMT process not classified: name=%v category=%s", name, category)
	}
	if name, category := DisplayIdentity("llm-monitor", RoleNone); name != nil || category != domain.ProcessOtherSameUser {
		t.Fatalf("basename alone conferred RMT ownership: name=%v category=%s", name, category)
	}
}
