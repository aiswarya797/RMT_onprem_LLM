package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateFilePreservesSharedParentMode(t *testing.T) {
	home := t.TempDir()
	paths := ForHome(home)
	if err := os.MkdirAll(paths.LaunchAgents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.LaunchAgents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(paths.HubPlist, []byte("plist")); err != nil {
		t.Fatal(err)
	}
	parent, _ := os.Stat(paths.LaunchAgents)
	if got := parent.Mode().Perm(); got != 0o755 {
		t.Fatalf("shared LaunchAgents mode changed to %o", got)
	}
	file, _ := os.Stat(paths.HubPlist)
	if got := file.Mode().Perm(); got != 0o600 {
		t.Fatalf("private file mode = %o", got)
	}
}

func TestPrivatePathsRejectSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(filepath.Join(link, "secret"), []byte("secret")); err == nil {
		t.Fatal("expected symlink component rejection")
	}
	if _, err := os.Stat(filepath.Join(realDir, "secret")); !os.IsNotExist(err) {
		t.Fatalf("write escaped through symlink: %v", err)
	}
}

func TestExtractRuntimeOptionsRequiresAbsolutePathsAndPreservesCommand(t *testing.T) {
	remaining, options, err := ExtractRuntimeOptions([]string{"--installation-root", "/tmp/rmt-home", "--runtime-dir", "/tmp/rmt-run", "--listen", "127.0.0.1:9555", "--local-probe-admission", "phase2-observation-v1", "hub", "serve"})
	if err != nil {
		t.Fatal(err)
	}
	if options.InstallationRoot != "/tmp/rmt-home" || options.RuntimeDir != "/tmp/rmt-run" || options.ListenAddress != "127.0.0.1:9555" || !options.ListenAddressSet || options.LocalProbeAdmission != "phase2-observation-v1" || len(remaining) != 2 || remaining[0] != "hub" || remaining[1] != "serve" {
		t.Fatalf("remaining=%v options=%#v", remaining, options)
	}
	_, omitted, err := ExtractRuntimeOptions([]string{"setup", "local"})
	if err != nil || omitted.ListenAddressSet {
		t.Fatalf("omitted listen was marked explicit: %#v err=%v", omitted, err)
	}
	if _, _, err := ExtractRuntimeOptions([]string{"--installation-root", "relative", "status"}); err == nil {
		t.Fatal("relative installation root accepted")
	}
}
