package notify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultImmutableRetryAndAuthenticatedCiphertext(t *testing.T) {
	dir := t.TempDir()
	v := Vault{Dir: filepath.Join(dir, "values"), KeyFile: filepath.Join(dir, "key")}
	ref, err := v.Put("generation/actor/exact-retry", "test-password-canary")
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := v.Put("generation/actor/exact-retry", "test-password-canary")
	if err != nil || repeated != ref {
		t.Fatalf("retry: %s %v", repeated, err)
	}
	value, err := v.Read(ref)
	if err != nil || value != "test-password-canary" {
		t.Fatalf("round trip: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(v.Dir, ref))
	if strings.Contains(string(raw), value) {
		t.Fatal("plaintext persisted")
	}
	other, _ := v.Put("generation/actor/another", value)
	if other == ref {
		t.Fatal("different request shares reference")
	}
	if err := os.WriteFile(filepath.Join(v.Dir, other), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Read(other); err == nil {
		t.Fatal("reference substitution accepted")
	}
	if _, err := v.Read("../key"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if err := os.Chmod(filepath.Join(v.Dir, ref), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Read(ref); err == nil {
		t.Fatal("public secret envelope accepted")
	}
}

func TestVaultMissingKeyNeverRecreatesOnRead(t *testing.T) {
	dir := t.TempDir()
	v := Vault{Dir: filepath.Join(dir, "values"), KeyFile: filepath.Join(dir, "key")}
	ref, err := v.Put("empty-secret", "")
	if err != nil {
		t.Fatal(err)
	}
	if value, err := v.Read(ref); err != nil || value != "" {
		t.Fatal("empty envelope unavailable")
	}
	if err := os.Remove(v.KeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Read(ref); err == nil {
		t.Fatal("missing key accepted")
	}
	if _, err := os.Stat(v.KeyFile); !os.IsNotExist(err) {
		t.Fatal("read recreated key")
	}
}
