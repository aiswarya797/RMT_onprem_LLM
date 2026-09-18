package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
)

// schemaSQL is an exact embedded copy of contracts/storage/v1/schema.sql.
// U02 tests guard that the two files stay byte-identical.
//
//go:embed schema.sql
var schemaSQL string

var (
	ErrNotConfigured        = errors.New("not configured")
	ErrBootstrapUnavailable = errors.New("bootstrap unavailable")
	ErrBootstrapExpired     = errors.New("bootstrap expired")
	ErrBootstrapConsumed    = errors.New("bootstrap consumed")
	ErrAdminExists          = errors.New("admin already exists")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrSessionExpired       = errors.New("session expired")
)

type Store struct {
	db                          *sql.DB
	clock                       domain.Clock
	writes                      chan struct{}
	ingest                      chan struct{}
	codec                       *FrameCodecV1
	capacityMeasurementCaptured func()
}

type BootstrapRecord struct {
	State     string
	ExpiresMS *int64
}

type LoginRecord struct {
	User         domain.User
	PasswordHash string
	DeploymentID string
	Generation   string
}

type SessionRecord struct {
	User         domain.User
	DeploymentID string
	Generation   string
	ExpiresMS    int64
}

type FoundationStatus struct {
	State       domain.DeploymentState
	HostCount   int
	TargetCount int
	SourceCount int
}

func Open(path string, clock domain.Clock) (*Store, error) {
	return open(path, clock, true, false)
}

func OpenExisting(path string, clock domain.Clock) (*Store, error) {
	return open(path, clock, false, false)
}

// OpenReadOnly opens an already configured database without migrating it,
// changing its mode, or asking SQLite to switch journal settings. It is the
// status-command boundary; callers must not use the returned store to mutate.
func OpenReadOnly(path string, clock domain.Clock) (*Store, error) {
	return open(path, clock, false, true)
}

func open(path string, clock domain.Clock, initialize, readOnly bool) (*Store, error) {
	if clock == nil {
		clock = domain.RealClock{}
	}
	if initialize {
		if err := config.EnsurePrivateDir(filepath.Dir(path)); err != nil {
			return nil, err
		}
	} else if err := config.RejectSymlinkTree(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refuse symlink database %s", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("database permissions are too broad: %o", info.Mode().Perm())
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if !initialize {
		return nil, ErrNotConfigured
	} else {
		file, createErr := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return nil, fmt.Errorf("create sqlite database: %w", createErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, closeErr
		}
	}
	dsnURL := &url.URL{Scheme: "file", Path: path}
	query := dsnURL.Query()
	query.Set("_foreign_keys", "on")
	query.Set("_busy_timeout", "2000")
	if readOnly {
		query.Set("mode", "ro")
		query.Set("_query_only", "on")
	} else {
		query.Set("_journal_mode", "WAL")
		query.Set("_synchronous", "FULL")
	}
	dsnURL.RawQuery = query.Encode()
	dsn := dsnURL.String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var dbstatEnabled int
	if err := db.QueryRow(`SELECT sqlite_compileoption_used('ENABLE_DBSTAT_VTAB')`).Scan(&dbstatEnabled); err != nil || dbstatEnabled != 1 {
		db.Close()
		return nil, errors.New("sqlite build lacks required ENABLE_DBSTAT_VTAB physical capacity accounting")
	}
	codec, err := NewFrameCodecV1()
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, clock: clock, writes: make(chan struct{}, 256), ingest: make(chan struct{}, 1), codec: codec}
	var sequence int
	var schemaName, actualPath string
	if err := db.QueryRow(`PRAGMA database_list`).Scan(&sequence, &schemaName, &actualPath); err != nil {
		db.Close()
		return nil, fmt.Errorf("verify sqlite path: %w", err)
	}
	wantPath, _ := filepath.Abs(path)
	gotPath, _ := filepath.Abs(actualPath)
	if strings.TrimSpace(gotPath) != strings.TrimSpace(wantPath) {
		db.Close()
		return nil, fmt.Errorf("sqlite opened unexpected path %q", actualPath)
	}
	if initialize {
		if err := s.initialize(); err != nil {
			db.Close()
			return nil, err
		}
	} else {
		var deployments int
		if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='deployments'`).Scan(&deployments); err != nil || deployments != 1 {
			db.Close()
			return nil, ErrNotConfigured
		}
	}
	if !readOnly {
		if err := s.ensureNotificationStorage(); err != nil {
			db.Close()
			return nil, err
		}
		if err := s.ensureComparisonStorage(); err != nil {
			db.Close()
			return nil, err
		}
	}
	if !readOnly {
		if err := os.Chmod(path, 0o600); err != nil {
			db.Close()
			return nil, fmt.Errorf("secure sqlite database: %w", err)
		}
	}
	return s, nil
}

func (s *Store) Close() error {
	s.codec.Close()
	return s.db.Close()
}

func (s *Store) initialize() error {
	var exists int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='deployments'`).Scan(&exists); err != nil {
		return fmt.Errorf("inspect sqlite schema: %w", err)
	}
	if exists == 0 {
		if _, err := s.db.Exec(schemaSQL); err != nil {
			return fmt.Errorf("install reviewed sqlite schema: %w", err)
		}
	}
	return nil
}

func (s *Store) EnsureDeployment(ctx context.Context, displayName string) (domain.DeploymentState, bool, error) {
	state, err := s.DeploymentState(ctx)
	if err == nil {
		return state, false, nil
	}
	if !errors.Is(err, ErrNotConfigured) {
		return domain.DeploymentState{}, false, err
	}
	deploymentID, err := domain.NewUUID()
	if err != nil {
		return domain.DeploymentState{}, false, err
	}
	installationID, err := domain.NewUUID()
	if err != nil {
		return domain.DeploymentState{}, false, err
	}
	generation, err := domain.NewUUID()
	if err != nil {
		return domain.DeploymentState{}, false, err
	}
	now := s.clock.Now().UnixMilli()
	_, err = s.db.ExecContext(ctx, `INSERT INTO deployments(id,display_name,schema_version,registry_revision,installation_uuid,deployment_generation,recovery_state,created_ms,updated_ms) VALUES(?,?,?,?,?,?,?,?,?)`, deploymentID, displayName, 1, domain.RegistryRevision, installationID, generation, "normal", now, now)
	if err != nil {
		// Another idempotent setup may have won the insert.
		state, stateErr := s.DeploymentState(ctx)
		if stateErr == nil {
			return state, false, nil
		}
		return domain.DeploymentState{}, false, fmt.Errorf("create deployment: %w", err)
	}
	state, err = s.DeploymentState(ctx)
	return state, true, err
}

func (s *Store) DeploymentState(ctx context.Context) (domain.DeploymentState, error) {
	var state domain.DeploymentState
	state.SchemaVersion = domain.SchemaVersion
	var created int64
	var recoveryPoint sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT d.id,d.deployment_generation,d.recovery_state,d.created_ms,
		CASE WHEN json_type(m.evaluator_cursor_json,'$.restore_recovery_point_ms')='integer' THEN json_extract(m.evaluator_cursor_json,'$.restore_recovery_point_ms') END
		FROM deployments d LEFT JOIN maintenance m ON m.deployment_id=d.id LIMIT 1`).Scan(&state.DeploymentID, &state.DeploymentGeneration, &state.RecoveryState, &created, &recoveryPoint)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.DeploymentState{}, ErrNotConfigured
	}
	if err != nil {
		return domain.DeploymentState{}, fmt.Errorf("read deployment state: %w", err)
	}
	if recoveryPoint.Valid && recoveryPoint.Int64 >= 0 {
		value := recoveryPoint.Int64
		state.RecoveryPointMS = &value
	}
	state.MutationsAllowed = state.RecoveryState == "normal"
	return state, nil
}

func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role='admin' AND disabled=0 AND historical_restored=0`).Scan(&count)
	return count, err
}

func (s *Store) PutFirstAdminBootstrap(ctx context.Context, tokenHash string, expires time.Time) error {
	state, err := s.DeploymentState(ctx)
	if err != nil {
		return err
	}
	count, err := s.AdminCount(ctx)
	if err != nil {
		return err
	}
	if count != 0 {
		return ErrAdminExists
	}
	now := s.clock.Now().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_bootstrap_tokens WHERE deployment_id=? AND purpose='first_admin'`, state.DeploymentID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_bootstrap_tokens(token_hash,deployment_id,deployment_generation,purpose,user_id,created_ms,expires_ms,consumed_ms) VALUES(?,?,?,'first_admin',NULL,?,?,NULL)`, tokenHash, state.DeploymentID, state.DeploymentGeneration, now, expires.UnixMilli()); err != nil {
		return err
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'auth.bootstrap.renew',NULL,?,'{}')`, auditID, state.DeploymentID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) BootstrapState(ctx context.Context) (BootstrapRecord, error) {
	count, err := s.AdminCount(ctx)
	if err != nil {
		return BootstrapRecord{}, err
	}
	if count > 0 {
		return BootstrapRecord{State: "configured"}, nil
	}
	var expires int64
	var consumed sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT expires_ms,consumed_ms FROM auth_bootstrap_tokens WHERE purpose='first_admin' ORDER BY created_ms DESC LIMIT 1`).Scan(&expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return BootstrapRecord{State: "expired"}, nil
	}
	if err != nil {
		return BootstrapRecord{}, err
	}
	if consumed.Valid || s.clock.Now().UnixMilli() >= expires {
		return BootstrapRecord{State: "expired", ExpiresMS: &expires}, nil
	}
	return BootstrapRecord{State: "required", ExpiresMS: &expires}, nil
}

func (s *Store) ValidateFirstAdminBootstrap(ctx context.Context, tokenHash string) error {
	count, err := s.AdminCount(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrAdminExists
	}
	state, err := s.DeploymentState(ctx)
	if err != nil {
		return err
	}
	var expires int64
	var consumed sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT expires_ms,consumed_ms FROM auth_bootstrap_tokens WHERE token_hash=? AND deployment_id=? AND deployment_generation=? AND purpose='first_admin'`, tokenHash, state.DeploymentID, state.DeploymentGeneration).Scan(&expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBootstrapUnavailable
	}
	if err != nil {
		return err
	}
	if consumed.Valid {
		return ErrBootstrapConsumed
	}
	if s.clock.Now().UnixMilli() >= expires {
		return ErrBootstrapExpired
	}
	return nil
}

func (s *Store) ConsumeBootstrapAndCreateAdmin(ctx context.Context, tokenHash, username, passwordHash string) (domain.User, error) {
	state, err := s.DeploymentState(ctx)
	if err != nil {
		return domain.User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.User{}, err
	}
	defer tx.Rollback()
	var expires int64
	var consumed sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT expires_ms,consumed_ms FROM auth_bootstrap_tokens WHERE token_hash=? AND deployment_id=? AND deployment_generation=? AND purpose='first_admin'`, tokenHash, state.DeploymentID, state.DeploymentGeneration).Scan(&expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, ErrBootstrapUnavailable
	}
	if err != nil {
		return domain.User{}, err
	}
	if consumed.Valid {
		return domain.User{}, ErrBootstrapConsumed
	}
	now := s.clock.Now().UnixMilli()
	if now >= expires {
		return domain.User{}, ErrBootstrapExpired
	}
	var admins int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE deployment_id=? AND role='admin' AND disabled=0 AND historical_restored=0`, state.DeploymentID).Scan(&admins); err != nil {
		return domain.User{}, err
	}
	if admins > 0 {
		return domain.User{}, ErrAdminExists
	}
	userID, err := domain.NewUUID()
	if err != nil {
		return domain.User{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,?,'admin',0,?,0,1,?,?)`, userID, state.DeploymentID, username, passwordHash, state.DeploymentGeneration, now, now); err != nil {
		return domain.User{}, fmt.Errorf("create first admin: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth_bootstrap_tokens SET consumed_ms=? WHERE token_hash=? AND consumed_ms IS NULL`, now, tokenHash)
	if err != nil {
		return domain.User{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return domain.User{}, ErrBootstrapConsumed
	}
	if state.RecoveryState == "restore_requires_bootstrap" {
		var archivedUsers int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE deployment_id=? AND historical_restored=1`, state.DeploymentID).Scan(&archivedUsers); err != nil {
			return domain.User{}, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE restore_bootstrap_transitions SET state='bootstrap_complete',archived_user_count=?,completed_ms=? WHERE deployment_id=? AND deployment_generation=? AND state='archiving_restored_users'`, archivedUsers, now, state.DeploymentID, state.DeploymentGeneration)
		if err != nil {
			return domain.User{}, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return domain.User{}, ErrGenerationConflict
		}
		result, err = tx.ExecContext(ctx, `UPDATE deployments SET recovery_state='normal',updated_ms=? WHERE id=? AND deployment_generation=? AND recovery_state='restore_requires_bootstrap'`, now, state.DeploymentID, state.DeploymentGeneration)
		if err != nil {
			return domain.User{}, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return domain.User{}, ErrGenerationConflict
		}
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return domain.User{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'auth.bootstrap.complete',?,?, '{}')`, auditID, state.DeploymentID, userID, userID, now); err != nil {
		return domain.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.User{}, err
	}
	return domain.User{ID: userID, Revision: 1, Name: username, Role: "admin", TrustGeneration: state.DeploymentGeneration}, nil
}

func (s *Store) LoginRecord(ctx context.Context, username string) (LoginRecord, error) {
	var rec LoginRecord
	var disabled, historical int
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.version,u.name,u.role,u.disabled,u.trust_generation,u.historical_restored,u.argon2_hash,u.deployment_id,d.deployment_generation FROM users u JOIN deployments d ON d.id=u.deployment_id WHERE u.name=? LIMIT 1`, username).Scan(&rec.User.ID, &rec.User.Revision, &rec.User.Name, &rec.User.Role, &disabled, &rec.User.TrustGeneration, &historical, &rec.PasswordHash, &rec.DeploymentID, &rec.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginRecord{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginRecord{}, err
	}
	rec.User.Disabled = disabled != 0
	rec.User.HistoricalRestored = historical != 0
	if rec.User.Disabled || rec.User.HistoricalRestored || rec.User.TrustGeneration != rec.Generation {
		return LoginRecord{}, ErrInvalidCredentials
	}
	return rec, nil
}

func (s *Store) CreateSession(ctx context.Context, tokenHash, userID string) (SessionRecord, error) {
	state, err := s.DeploymentState(ctx)
	if err != nil {
		return SessionRecord{}, err
	}
	now := s.clock.Now().UnixMilli()
	idle := now + int64((12*time.Hour)/time.Millisecond)
	abs := now + int64((7*24*time.Hour)/time.Millisecond)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SessionRecord{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_sessions(token_hash,deployment_id,deployment_generation,user_id,created_ms,expires_ms,absolute_expires_ms,last_seen_ms,revoked_ms) VALUES(?,?,?,?,?,?,?,?,NULL)`, tokenHash, state.DeploymentID, state.DeploymentGeneration, userID, now, idle, abs, now); err != nil {
		return SessionRecord{}, err
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return SessionRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'auth.login',NULL,?,'{}')`, auditID, state.DeploymentID, userID, now); err != nil {
		return SessionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return SessionRecord{}, err
	}
	rec, err := s.SessionByHash(ctx, tokenHash)
	return rec, err
}

func (s *Store) SessionByHash(ctx context.Context, tokenHash string) (SessionRecord, error) {
	now := s.clock.Now().UnixMilli()
	var rec SessionRecord
	var disabled, historical int
	var absolute int64
	var revoked sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.version,u.name,u.role,u.disabled,u.trust_generation,u.historical_restored,s.deployment_id,s.deployment_generation,s.expires_ms,s.absolute_expires_ms,s.revoked_ms FROM user_sessions s JOIN users u ON u.deployment_id=s.deployment_id AND u.id=s.user_id JOIN deployments d ON d.id=s.deployment_id WHERE s.token_hash=? AND s.deployment_generation=d.deployment_generation AND u.trust_generation=d.deployment_generation`, tokenHash).Scan(&rec.User.ID, &rec.User.Revision, &rec.User.Name, &rec.User.Role, &disabled, &rec.User.TrustGeneration, &historical, &rec.DeploymentID, &rec.Generation, &rec.ExpiresMS, &absolute, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionRecord{}, ErrSessionExpired
	}
	if err != nil {
		return SessionRecord{}, err
	}
	rec.User.Disabled = disabled != 0
	rec.User.HistoricalRestored = historical != 0
	if revoked.Valid || rec.User.Disabled || rec.User.HistoricalRestored || now >= rec.ExpiresMS || now >= absolute {
		return SessionRecord{}, ErrSessionExpired
	}
	refreshed := now + int64((12*time.Hour)/time.Millisecond)
	if refreshed > absolute {
		refreshed = absolute
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE user_sessions SET last_seen_ms=?,expires_ms=? WHERE token_hash=? AND revoked_ms IS NULL`, now, refreshed, tokenHash); err != nil {
		return SessionRecord{}, err
	}
	rec.ExpiresMS = refreshed
	return rec, nil
}

func (s *Store) RevokeSession(ctx context.Context, tokenHash string) error {
	now := s.clock.Now().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var deploymentID, userID string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id,user_id FROM user_sessions WHERE token_hash=? AND revoked_ms IS NULL`, tokenHash).Scan(&deploymentID, &userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSessionExpired
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_sessions SET revoked_ms=? WHERE token_hash=? AND revoked_ms IS NULL`, now, tokenHash); err != nil {
		return err
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'auth.logout',NULL,?,'{}')`, auditID, deploymentID, userID, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	now := s.clock.Now().UnixMilli()
	_, err := s.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_ms=? WHERE user_id=? AND revoked_ms IS NULL`, now, userID)
	return err
}

func (s *Store) FoundationStatus(ctx context.Context) (FoundationStatus, error) {
	state, err := s.DeploymentState(ctx)
	if err != nil {
		return FoundationStatus{}, err
	}
	status := FoundationStatus{State: state}
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM hosts WHERE retired_ms IS NULL),(SELECT count(*) FROM targets WHERE retired_ms IS NULL),(SELECT count(*) FROM sources WHERE retired_ms IS NULL)`).Scan(&status.HostCount, &status.TargetCount, &status.SourceCount); err != nil {
		return FoundationStatus{}, err
	}
	return status, nil
}

// HasDirectProbe reports whether this deployment has retained a submitted
// direct local request. Blocked admission receipts deliberately do not count.
func (s *Store) HasDirectProbe(ctx context.Context, deploymentID string) (bool, error) {
	if !validUUIDText(deploymentID) {
		return false, ErrOwnershipMismatch
	}
	var observed int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM request_samples s JOIN request_runs r ON r.deployment_id=s.deployment_id AND r.host_id=s.host_id AND r.id=s.run_id WHERE s.deployment_id=? AND r.source_kind='deliberate_probe')`, deploymentID).Scan(&observed)
	return observed == 1, err
}
