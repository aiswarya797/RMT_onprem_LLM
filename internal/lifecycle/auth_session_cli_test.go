package lifecycle

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/httpapi"
	"rmt.local/monitor/internal/store"
)

func TestAuthLoginTokenAndLogoutUseRealAPIWithoutPrintingSecrets(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	clock := fixedClock{time.UnixMilli(1_800_000_000_000)}
	manager := NewManager(paths, newFakeRunner(), clock)
	setup, err := manager.SetupLocal(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenExisting(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := auth.NewService(st, paths, clock)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := os.ReadFile(paths.BootstrapToken)
	if err != nil {
		t.Fatal(err)
	}
	password := "stdin-secret-password-123"
	if _, _, err := service.CreateFirstAdmin(ctx, string(bootstrap), "owner", password, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager.ListenAddress, manager.ListenAddressExplicit = listener.Addr().String(), true
	server := &http.Server{Handler: httpapi.New(st, service, clock, listener.Addr().String(), http.NotFoundHandler())}
	go server.Serve(listener)
	defer server.Close()
	sessionPath := filepath.Join(paths.Support, "cli-session.json")
	tokenPath := filepath.Join(paths.Support, "cli-token")
	var stdout, stderr bytes.Buffer
	run := func(args ...string) int {
		stdout.Reset()
		stderr.Reset()
		return RunCLI(ctx, append(args, "--json"), &stdout, &stderr, manager)
	}
	manager.Input = strings.NewReader(password + "\n")
	if code := run("auth", "login", "--username", "owner", "--password-stdin", "--session-file", sessionPath); code != 0 {
		t.Fatalf("login code=%d output=%s", code, stdout.String())
	}
	saved, err := readCLISession(sessionPath, "http://"+listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String()+stderr.String(), password) || strings.Contains(stdout.String(), saved.Cookie) || strings.Contains(stdout.String(), saved.Session.CSRFToken) {
		t.Fatal("login output exposed credentials")
	}
	if _, err := service.Session(ctx, saved.Cookie); err != nil {
		t.Fatal("saved session was not authenticated")
	}
	if _, err := readCLIAuthentication("", sessionPath, "http://127.0.0.1:1", clock.Now().UnixMilli()); err == nil {
		t.Fatal("session accepted for another origin")
	}
	if err := os.Chmod(sessionPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCLIAuthentication("", sessionPath, saved.Origin, clock.Now().UnixMilli()); err == nil {
		t.Fatal("public session file accepted")
	}
	if err := os.Chmod(sessionPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run("auth", "login", "--username", "owner", "--password-stdin", "--session-file", sessionPath); code != 2 {
		t.Fatal("existing session file was not protected")
	}
	if code := run("auth", "login", "--password="+password, "--session-file", sessionPath); code != 2 || strings.Contains(stdout.String()+stderr.String(), password) {
		t.Fatal("password argument accepted or echoed")
	}
	if code := run("auth", "token", "create", "--session-file", sessionPath, "--output-token-file", tokenPath, "--name", "Automation", "--expires", "1h", "--deployment-generation", setup.DeploymentGeneration, "--idempotency-key", "00000000-0000-4000-8000-000000000201"); code != 0 {
		t.Fatalf("session token create code=%d output=%s", code, stdout.String())
	}
	bearer, err := readPrivateBearer(tokenPath)
	if err != nil || strings.Contains(stdout.String(), bearer) {
		t.Fatal("token was not stored privately")
	}
	if _, err := service.APISession(ctx, bearer); err != nil {
		t.Fatal("created bearer did not authenticate")
	}
	if code := run("auth", "logout", "--session-file", sessionPath); code != 0 {
		t.Fatalf("logout code=%d output=%s", code, stdout.String())
	}
	if _, err := os.Stat(sessionPath); !os.IsNotExist(err) {
		t.Fatal("logout retained the session file")
	}
	if _, err := service.Session(ctx, saved.Cookie); err == nil {
		t.Fatal("logged-out session still authenticates")
	}
	manager.Input = strings.NewReader("incorrect-password-123")
	if code := run("auth", "login", "--username", "owner", "--password-stdin", "--session-file", sessionPath); code != 4 || !strings.Contains(stdout.String(), "invalid_credentials") {
		t.Fatalf("bad password result=%d %s", code, stdout.String())
	}
	if _, err := os.Stat(sessionPath); !os.IsNotExist(err) {
		t.Fatal("failed sign-in wrote credentials")
	}
	if err := config.ValidatePrivateFile(tokenPath); err != nil {
		t.Fatal(err)
	}
}
