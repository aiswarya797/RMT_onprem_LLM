package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/store"
)

const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type Service struct {
	store            *store.Store
	hasher           *PasswordHasher
	clock            domain.Clock
	paths            config.Paths
	sessionSecret    []byte
	limiter          *loginLimiter
	bootstrapLimiter *loginLimiter
}

func NewService(st *store.Store, paths config.Paths, clock domain.Clock) (*Service, error) {
	if clock == nil {
		clock = domain.RealClock{}
	}
	secret, err := loadOrCreateSecret(paths.SessionSecret)
	if err != nil {
		return nil, err
	}
	return &Service{store: st, hasher: NewPasswordHasher(1), clock: clock, paths: paths, sessionSecret: secret, limiter: newLoginLimiter(512, 5), bootstrapLimiter: newLoginLimiter(256, 10)}, nil
}

func (s *Service) EnsureFirstBootstrap(ctx context.Context) (string, time.Time, bool, error) {
	state, err := s.store.BootstrapState(ctx)
	if err != nil {
		return "", time.Time{}, false, err
	}
	if state.State == "configured" {
		return "", time.Time{}, false, store.ErrAdminExists
	}
	if state.State == "required" {
		if info, err := os.Lstat(s.paths.BootstrapToken); err == nil && info.Mode().Perm() == 0o600 && info.Mode()&os.ModeSymlink == 0 {
			return s.paths.BootstrapToken, time.UnixMilli(*state.ExpiresMS), false, nil
		}
	}
	return s.RenewBootstrap(ctx)
}

func (s *Service) RenewBootstrap(ctx context.Context) (string, time.Time, bool, error) {
	count, err := s.store.AdminCount(ctx)
	if err != nil {
		return "", time.Time{}, false, err
	}
	if count > 0 {
		return "", time.Time{}, false, store.ErrAdminExists
	}
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, false, err
	}
	expires := s.clock.Now().Add(30 * time.Minute)
	if err := s.store.PutFirstAdminBootstrap(ctx, HashToken(token), expires); err != nil {
		return "", time.Time{}, false, err
	}
	if err := config.WritePrivateFile(s.paths.BootstrapToken, []byte(token+"\n")); err != nil {
		return "", time.Time{}, false, err
	}
	return s.paths.BootstrapToken, expires, true, nil
}

func (s *Service) BootstrapState(ctx context.Context) (store.BootstrapRecord, error) {
	return s.store.BootstrapState(ctx)
}

// LocalBootstrapToken is the browser-only handoff for first-admin setup. It
// is available only to the loopback HTTP server, validates the private file
// against the durable hash, and never exposes the file path to the caller.
func (s *Service) LocalBootstrapToken(ctx context.Context) (string, time.Time, error) {
	state, err := s.store.BootstrapState(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if state.State == "configured" {
		return "", time.Time{}, store.ErrAdminExists
	}
	if state.State != "required" || state.ExpiresMS == nil {
		return "", time.Time{}, store.ErrBootstrapUnavailable
	}
	expires := time.UnixMilli(*state.ExpiresMS)
	if !expires.After(s.clock.Now()) {
		return "", time.Time{}, store.ErrBootstrapExpired
	}
	if err := config.ValidatePrivateFile(s.paths.BootstrapToken); err != nil {
		return "", time.Time{}, store.ErrBootstrapUnavailable
	}
	info, err := os.Stat(s.paths.BootstrapToken)
	if err != nil || info.Size() > 1024 {
		return "", time.Time{}, store.ErrBootstrapUnavailable
	}
	data, err := os.ReadFile(s.paths.BootstrapToken)
	if err != nil {
		return "", time.Time{}, store.ErrBootstrapUnavailable
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, " \t\r\n") {
		return "", time.Time{}, store.ErrBootstrapUnavailable
	}
	if err := s.store.ValidateFirstAdminBootstrap(ctx, HashToken(token)); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

func (s *Service) CreateFirstAdmin(ctx context.Context, bootstrapToken, username, password, remoteIP string) (domain.Session, string, error) {
	limitKey := "bootstrap:" + remoteIP
	if !s.bootstrapLimiter.allow(limitKey, s.clock.Now()) {
		return domain.Session{}, "", ErrRateLimited
	}
	tokenHash := HashToken(strings.TrimSpace(bootstrapToken))
	if err := s.store.ValidateFirstAdminBootstrap(ctx, tokenHash); err != nil {
		s.bootstrapLimiter.fail(limitKey, s.clock.Now())
		return domain.Session{}, "", err
	}
	if err := validateUsername(username); err != nil {
		return domain.Session{}, "", err
	}
	passwordHash, err := s.hasher.Hash(password)
	if err != nil {
		return domain.Session{}, "", err
	}
	user, err := s.store.ConsumeBootstrapAndCreateAdmin(ctx, tokenHash, username, passwordHash)
	if err != nil {
		return domain.Session{}, "", err
	}
	s.bootstrapLimiter.success(limitKey)
	_ = os.Remove(s.paths.BootstrapToken)
	return s.newSession(ctx, user)
}

func (s *Service) Login(ctx context.Context, username, password, remoteIP string) (domain.Session, string, error) {
	accountKey := "account:" + strings.ToLower(username)
	ipKey := "ip:" + remoteIP
	if !s.limiter.allow(accountKey, s.clock.Now()) || !s.limiter.allow(ipKey, s.clock.Now()) {
		return domain.Session{}, "", ErrRateLimited
	}
	rec, err := s.store.LoginRecord(ctx, username)
	encoded := dummyPasswordHash
	if err == nil {
		encoded = rec.PasswordHash
	}
	valid, hashErr := s.hasher.Verify(encoded, password)
	if errors.Is(hashErr, ErrHashBusy) {
		return domain.Session{}, "", ErrHashBusy
	}
	if err != nil || hashErr != nil || !valid {
		s.limiter.fail(accountKey, s.clock.Now())
		s.limiter.fail(ipKey, s.clock.Now())
		return domain.Session{}, "", store.ErrInvalidCredentials
	}
	s.limiter.success(accountKey)
	s.limiter.success(ipKey)
	return s.newSession(ctx, rec.User)
}

func (s *Service) newSession(ctx context.Context, user domain.User) (domain.Session, string, error) {
	token, err := randomToken(32)
	if err != nil {
		return domain.Session{}, "", err
	}
	rec, err := s.store.CreateSession(ctx, HashToken(token), user.ID)
	if err != nil {
		return domain.Session{}, "", err
	}
	return domain.Session{User: rec.User, ExpiresMS: rec.ExpiresMS, CSRFToken: s.csrf(token)}, token, nil
}

func (s *Service) Session(ctx context.Context, rawToken string) (domain.Session, error) {
	if rawToken == "" {
		return domain.Session{}, store.ErrSessionExpired
	}
	rec, err := s.store.SessionByHash(ctx, HashToken(rawToken))
	if err != nil {
		return domain.Session{}, err
	}
	return domain.Session{User: rec.User, ExpiresMS: rec.ExpiresMS, CSRFToken: s.csrf(rawToken)}, nil
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return store.ErrSessionExpired
	}
	return s.store.RevokeSession(ctx, HashToken(rawToken))
}

func (s *Service) ValidCSRF(rawToken, candidate string) bool {
	if rawToken == "" || candidate == "" {
		return false
	}
	return hmac.Equal([]byte(s.csrf(rawToken)), []byte(candidate))
}

// EnrollmentToken derives the one-use bearer secret from the private session
// secret and the complete idempotency scope. The database stores only its
// SHA-256 hash, while an exact API retry can reproduce the same secret.
func (s *Service) EnrollmentToken(deploymentID, generation, actorID, idempotencyKey, requestHash string) (string, error) {
	if deploymentID == "" || generation == "" || actorID == "" || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || len(requestHash) != 64 {
		return "", errors.New("invalid enrollment token scope")
	}
	mac := hmac.New(sha256.New, s.sessionSecret)
	_, _ = mac.Write([]byte("collector-enrollment\x00" + deploymentID + "\x00" + generation + "\x00" + actorID + "\x00" + idempotencyKey + "\x00" + requestHash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// APIToken derives an API bearer from the private installation secret and the
// complete create request scope. Only its SHA-256 hash is persisted, while an
// exact idempotent retry can reproduce the same bearer for the caller.
func (s *Service) APIToken(deploymentID, generation, actorID, idempotencyKey, requestHash string) (string, error) {
	if deploymentID == "" || generation == "" || actorID == "" || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || len(requestHash) != 64 {
		return "", errors.New("invalid api token scope")
	}
	mac := hmac.New(sha256.New, s.sessionSecret)
	_, _ = mac.Write([]byte("api-token\x00" + deploymentID + "\x00" + generation + "\x00" + actorID + "\x00" + idempotencyKey + "\x00" + requestHash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) APISession(ctx context.Context, rawToken string) (domain.Session, error) {
	if len(rawToken) < 32 || len(rawToken) > 512 || strings.ContainsAny(rawToken, " \t\r\n") {
		return domain.Session{}, store.ErrAPITokenUnavailable
	}
	rec, err := s.store.AuthenticateAPIToken(ctx, HashToken(rawToken))
	if err != nil {
		return domain.Session{}, err
	}
	return domain.Session{User: rec.User, ExpiresMS: rec.ExpiresMS}, nil
}

func (s *Service) csrf(token string) string {
	mac := hmac.New(sha256.New, s.sessionSecret)
	_, _ = mac.Write([]byte("csrf:" + token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func HashToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func randomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func loadOrCreateSecret(path string) ([]byte, error) {
	if _, err := os.Lstat(path); err == nil {
		if err := config.ValidatePrivateFile(path); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(data) != 32 {
			return nil, errors.New("invalid session secret length")
		}
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := config.WritePrivateFile(path, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func validateUsername(name string) error {
	if len(name) < 1 || len(name) > 128 || strings.TrimSpace(name) != name {
		return errors.New("username must be 1 to 128 characters without surrounding whitespace")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("username contains a control character")
		}
	}
	return nil
}

var ErrRateLimited = errors.New("login temporarily rate limited")

type loginLimiter struct {
	mu          sync.Mutex
	entries     map[string]*loginEntry
	maxEntries  int
	maxFailures int
}

type loginEntry struct {
	windowStart time.Time
	failures    int
}

func newLoginLimiter(maxEntries, maxFailures int) *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginEntry), maxEntries: maxEntries, maxFailures: maxFailures}
}

func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil || now.Sub(e.windowStart) >= 15*time.Minute {
		return true
	}
	return e.failures < l.maxFailures
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= l.maxEntries {
		for k, v := range l.entries {
			if now.Sub(v.windowStart) >= 15*time.Minute {
				delete(l.entries, k)
			}
		}
	}
	if len(l.entries) >= l.maxEntries {
		var oldestKey string
		var oldest time.Time
		for k, v := range l.entries {
			if oldestKey == "" || v.windowStart.Before(oldest) {
				oldestKey, oldest = k, v.windowStart
			}
		}
		delete(l.entries, oldestKey)
	}
	e := l.entries[key]
	if e == nil || now.Sub(e.windowStart) >= 15*time.Minute {
		l.entries[key] = &loginEntry{windowStart: now, failures: 1}
		return
	}
	e.failures++
}

func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (s *Service) String() string { return fmt.Sprintf("auth service for %s", s.paths.Support) }
