package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/store"
)

type mutableClock struct{ now time.Time }

func (c *mutableClock) Now() time.Time { return c.now }

func TestPasswordHashUsesExactBoundedProfile(t *testing.T) {
	hasher := NewPasswordHasher(1)
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded, "m=65536,t=3,p=1") {
		t.Fatalf("unexpected hash profile: %s", encoded)
	}
	ok, err := hasher.Verify(encoded, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("verify ok=%v err=%v", ok, err)
	}
	malicious := strings.Replace(encoded, "m=65536", "m=4294967295", 1)
	if _, _, _, err := parseHash(malicious); err == nil {
		t.Fatal("oversized memory profile accepted")
	}
}

func TestBootstrapLoginLogoutExpiryAndPersistence(t *testing.T) {
	ctx := context.Background()
	clock := &mutableClock{now: time.Unix(1_800_000_000, 0)}
	paths := config.ForHome(t.TempDir())
	st, err := store.Open(paths.Database, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, _, err := st.EnsureDeployment(ctx, "Test"); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(st, paths, clock)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = service.RenewBootstrap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expiredToken := readToken(t, paths.BootstrapToken)
	clock.now = clock.now.Add(31 * time.Minute)
	if _, _, err := service.CreateFirstAdmin(ctx, expiredToken, "admin", "a sufficiently long password", "127.0.0.1"); !errors.Is(err, store.ErrBootstrapExpired) {
		t.Fatalf("expired bootstrap err=%v", err)
	}
	if _, _, _, err := service.RenewBootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	validToken := readToken(t, paths.BootstrapToken)
	if _, _, err := service.CreateFirstAdmin(ctx, validToken+"x", "admin", "a sufficiently long password", "127.0.0.2"); !errors.Is(err, store.ErrBootstrapUnavailable) {
		t.Fatalf("invalid bootstrap err=%v", err)
	}
	session, rawSession, err := service.CreateFirstAdmin(ctx, validToken, "admin", "a sufficiently long password", "127.0.0.1")
	if err != nil || session.User.Role != "admin" || rawSession == "" {
		t.Fatalf("create admin session=%#v err=%v", session, err)
	}
	if _, err := os.Stat(paths.BootstrapToken); !os.IsNotExist(err) {
		t.Fatalf("consumed token file remains: %v", err)
	}
	if _, _, err := service.CreateFirstAdmin(ctx, validToken, "other", "another sufficiently long password", "127.0.0.3"); !errors.Is(err, store.ErrAdminExists) {
		t.Fatalf("one-use retry err=%v", err)
	}
	if _, _, err := service.Login(ctx, "admin", "wrong password", "127.0.0.1"); !errors.Is(err, store.ErrInvalidCredentials) {
		t.Fatalf("wrong login err=%v", err)
	}
	loggedIn, rawLogin, err := service.Login(ctx, "admin", "a sufficiently long password", "127.0.0.1")
	if err != nil || loggedIn.User.ID != session.User.ID {
		t.Fatalf("login=%#v err=%v", loggedIn, err)
	}
	if err := service.Logout(ctx, rawLogin); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Session(ctx, rawLogin); !errors.Is(err, store.ErrSessionExpired) {
		t.Fatalf("revoked session err=%v", err)
	}
	loggedIn, rawLogin, err = service.Login(ctx, "admin", "a sufficiently long password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	service, err = NewService(st, paths, clock)
	if err != nil {
		t.Fatal(err)
	}
	if persisted, err := service.Session(ctx, rawLogin); err != nil || persisted.User.ID != loggedIn.User.ID {
		t.Fatalf("persisted session=%#v err=%v", persisted, err)
	}
	clock.now = clock.now.Add(13 * time.Hour)
	if _, err := service.Session(ctx, rawLogin); !errors.Is(err, store.ErrSessionExpired) {
		t.Fatalf("idle expiry err=%v", err)
	}
}

func readToken(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}
