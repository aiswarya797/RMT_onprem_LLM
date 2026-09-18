package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rmt.local/monitor/internal/config"
)

func TestRunHubRejectsNonLoopbackBeforeOpeningStateOrListener(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".work", "u02-tests"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(root, "serve-home-")
	if err != nil {
		t.Fatal(err)
	}
	run, err := os.MkdirTemp(root, "serve-run-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(home)
		_ = os.RemoveAll(run)
	})
	paths := config.ForHome(home).WithRuntimeDir(run)
	err = runHub(context.Background(), paths, "0.0.0.0:9443", "")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback serve err=%v", err)
	}
	if _, err := os.Stat(paths.Database); !os.IsNotExist(err) {
		t.Fatalf("rejected serve opened state: %v", err)
	}
}
