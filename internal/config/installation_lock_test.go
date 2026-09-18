package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallationLeaseFencesRestoreAndKeepsStableInode(t *testing.T) {
	paths := ForHome(t.TempDir())
	if err := EnsurePrivateDir(paths.Support); err != nil {
		t.Fatal(err)
	}
	hub, err := AcquireInstallationLease(paths, false)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	admin, err := AcquireInstallationLease(paths, false)
	if err != nil {
		t.Fatal(err)
	}
	if restore, err := AcquireInstallationLease(paths, true); err == nil {
		restore.Close()
		t.Fatal("restore admitted beside a running hub")
	}
	before, err := os.Stat(filepath.Join(paths.Support, "installation.lock"))
	if err != nil {
		t.Fatal(err)
	}
	hub.Close()
	if restore, err := AcquireInstallationLease(paths, true); err == nil {
		restore.Close()
		t.Fatal("restore admitted beside administration")
	}
	admin.Close()
	restore, err := AcquireInstallationLease(paths, true)
	if err != nil {
		t.Fatal(err)
	}
	if hub, err := AcquireInstallationLease(paths, false); err == nil {
		hub.Close()
		t.Fatal("hub admitted during restore")
	}
	restore.Close()
	after, err := os.Stat(filepath.Join(paths.Support, "installation.lock"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lock inode changed or disappeared")
	}
}

func TestInstallationLeaseRejectsSymlinkAndPublicLock(t *testing.T) {
	paths := ForHome(t.TempDir())
	if err := EnsurePrivateDir(paths.Support); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(paths.Support, "installation.lock")
	out := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(out, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, lock); err != nil {
		t.Fatal(err)
	}
	if lease, err := AcquireInstallationLease(paths, true); err == nil {
		lease.Close()
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if lease, err := AcquireInstallationLease(paths, true); err == nil {
		lease.Close()
		t.Fatal("public lock accepted")
	}
	data, _ := os.ReadFile(out)
	if string(data) != "unchanged" {
		t.Fatal("symlink target changed")
	}
}
