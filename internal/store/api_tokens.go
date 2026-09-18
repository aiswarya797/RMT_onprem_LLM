package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
)

const (
	APITokenMaxValidity = 90 * 24 * time.Hour
	apiTokenPerUserCap  = 10
)

var (
	ErrAPITokenUnavailable = errors.New("api token unavailable")
	ErrAPITokenLimit       = errors.New("api token limit reached")
	ErrAPITokenConflict    = errors.New("api token request conflict")
)

// APITokenRecord is safe to retain and display. ID is the one-way token hash;
// the bearer secret itself is returned only by the create response.
type APITokenRecord struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Scope       string `json:"scope"`
	CreatedMS   int64  `json:"created_ms"`
	ExpiresMS   int64  `json:"expires_ms"`
	RevokedMS   *int64 `json:"revoked_ms"`
}

type APITokenOnce struct {
	Token  string         `json:"token"`
	Record APITokenRecord `json:"record"`
}

type apiTokenReceipt struct {
	TokenHash string         `json:"token_hash"`
	Record    APITokenRecord `json:"record"`
}

type apiTokenRevocationReceipt struct {
	TokenID   string `json:"token_id"`
	RevokedMS int64  `json:"revoked_ms"`
}

func (s *Store) CreateAPIToken(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash, token, displayName string, expiresMS int64) (APITokenOnce, error) {
	displayName = strings.TrimSpace(displayName)
	tokenHash := hashSecret(token)
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !sha256HexPattern.MatchString(requestHash) || len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") || len(displayName) < 1 || len(displayName) > 128 {
		return APITokenOnce{}, ErrAPITokenConflict
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return APITokenOnce{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return APITokenOnce{}, err
	}
	defer tx.Rollback()
	role, username, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return APITokenOnce{}, err
	}
	now := s.clock.Now().UnixMilli()
	if expiresMS <= now || expiresMS > now+int64(APITokenMaxValidity/time.Millisecond) {
		return APITokenOnce{}, ErrAPITokenConflict
	}
	var storedHash, storedJSON string
	var receiptExpires int64
	err = tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey).Scan(&storedHash, &storedJSON, &receiptExpires)
	if err == nil && now < receiptExpires {
		if storedHash != requestHash {
			return APITokenOnce{}, ErrAPITokenConflict
		}
		var receipt apiTokenReceipt
		if json.Unmarshal([]byte(storedJSON), &receipt) != nil || receipt.TokenHash != tokenHash {
			return APITokenOnce{}, ErrAPITokenConflict
		}
		return APITokenOnce{Token: token, Record: receipt.Record}, nil
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=? AND expires_ms<=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, now); err != nil {
			return APITokenOnce{}, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return APITokenOnce{}, err
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM api_tokens WHERE deployment_id=? AND user_id=? AND revoked_ms IS NULL AND expires_ms>?`, actor.DeploymentID, actor.User.ID, now).Scan(&active); err != nil {
		return APITokenOnce{}, err
	}
	if active >= apiTokenPerUserCap {
		return APITokenOnce{}, ErrAPITokenLimit
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens(token_hash,deployment_id,deployment_generation,user_id,display_name,scope,created_ms,expires_ms,revoked_ms) VALUES(?,?,?,?,?,?,?,?,NULL)`, tokenHash, actor.DeploymentID, actor.Generation, actor.User.ID, displayName, role, now, expiresMS); err != nil {
		return APITokenOnce{}, err
	}
	record := APITokenRecord{ID: tokenHash, UserID: actor.User.ID, Username: username, DisplayName: displayName, Scope: role, CreatedMS: now, ExpiresMS: expiresMS}
	detail, _ := json.Marshal(struct {
		DisplayName string `json:"display_name"`
		Scope       string `json:"scope"`
	}{displayName, role})
	auditID, err := domain.NewUUID()
	if err != nil {
		return APITokenOnce{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'auth.token.create',?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, tokenHash, now, string(detail)); err != nil {
		return APITokenOnce{}, err
	}
	receiptJSON, _ := json.Marshal(apiTokenReceipt{TokenHash: tokenHash, Record: record})
	if len(receiptJSON) > 65536 {
		return APITokenOnce{}, errors.New("api token receipt exceeds bound")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,201,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, string(receiptJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return APITokenOnce{}, err
	}
	if err := tx.Commit(); err != nil {
		return APITokenOnce{}, err
	}
	return APITokenOnce{Token: token, Record: record}, nil
}

func (s *Store) AuthenticateAPIToken(ctx context.Context, tokenHash string) (SessionRecord, error) {
	if !sha256HexPattern.MatchString(tokenHash) {
		return SessionRecord{}, ErrAPITokenUnavailable
	}
	var result SessionRecord
	var tokenScope string
	var disabled, historical int
	now := s.clock.Now().UnixMilli()
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.version,u.name,u.role,u.disabled,u.trust_generation,u.historical_restored,t.deployment_id,t.deployment_generation,t.scope,t.expires_ms FROM api_tokens t JOIN users u ON u.deployment_id=t.deployment_id AND u.id=t.user_id JOIN deployments d ON d.id=t.deployment_id WHERE t.token_hash=? AND t.revoked_ms IS NULL AND t.expires_ms>? AND t.deployment_generation=d.deployment_generation AND u.trust_generation=d.deployment_generation AND d.recovery_state='normal'`, tokenHash, now).Scan(&result.User.ID, &result.User.Revision, &result.User.Name, &result.User.Role, &disabled, &result.User.TrustGeneration, &historical, &result.DeploymentID, &result.Generation, &tokenScope, &result.ExpiresMS)
	if err != nil || disabled != 0 || historical != 0 {
		return SessionRecord{}, ErrAPITokenUnavailable
	}
	result.User.Disabled = disabled != 0
	result.User.HistoricalRestored = historical != 0
	if tokenScope == "viewer" {
		result.User.Role = "viewer"
	}
	return result, nil
}

func (s *Store) ListAPITokens(ctx context.Context, actor SessionRecord) ([]APITokenRecord, error) {
	role, _, err := s.validateAPITokenActorRead(ctx, actor)
	if err != nil {
		return nil, err
	}
	// Active credentials always fit the per-user/deployment caps. Fill any
	// remaining list slots with recent inactive history so token churn cannot
	// hide an older usable credential from discovery and revocation.
	query := `SELECT t.token_hash,t.user_id,u.name,t.display_name,t.scope,t.created_ms,t.expires_ms,t.revoked_ms FROM api_tokens t JOIN users u ON u.deployment_id=t.deployment_id AND u.id=t.user_id WHERE t.deployment_id=? AND t.user_id=? ORDER BY (t.revoked_ms IS NULL AND t.expires_ms>? AND t.deployment_generation=? AND u.historical_restored=0) DESC,t.created_ms DESC,t.token_hash LIMIT 10`
	arguments := []any{actor.DeploymentID, actor.User.ID, s.clock.Now().UnixMilli(), actor.Generation}
	if role == "admin" {
		query = `SELECT t.token_hash,t.user_id,u.name,t.display_name,t.scope,t.created_ms,t.expires_ms,t.revoked_ms FROM api_tokens t JOIN users u ON u.deployment_id=t.deployment_id AND u.id=t.user_id WHERE t.deployment_id=? ORDER BY (t.revoked_ms IS NULL AND t.expires_ms>? AND t.deployment_generation=? AND u.historical_restored=0) DESC,t.created_ms DESC,t.token_hash LIMIT 100`
		arguments = []any{actor.DeploymentID, s.clock.Now().UnixMilli(), actor.Generation}
	}
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []APITokenRecord{}
	for rows.Next() {
		var item APITokenRecord
		var revoked sql.NullInt64
		if err := rows.Scan(&item.ID, &item.UserID, &item.Username, &item.DisplayName, &item.Scope, &item.CreatedMS, &item.ExpiresMS, &revoked); err != nil {
			return nil, err
		}
		item.RevokedMS = nullableInt64Pointer(revoked)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeAPIToken(ctx context.Context, actor SessionRecord, tokenID, idempotencyKey, requestHash string) (int64, error) {
	if !sha256HexPattern.MatchString(tokenID) || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !sha256HexPattern.MatchString(requestHash) {
		return 0, ErrAPITokenConflict
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return 0, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return 0, err
	}
	now := s.clock.Now().UnixMilli()
	var storedHash, storedJSON string
	var receiptExpires int64
	err = tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey).Scan(&storedHash, &storedJSON, &receiptExpires)
	if err == nil && now < receiptExpires {
		if storedHash != requestHash {
			return 0, ErrAPITokenConflict
		}
		var receipt apiTokenRevocationReceipt
		if json.Unmarshal([]byte(storedJSON), &receipt) != nil || receipt.TokenID != tokenID {
			return 0, ErrAPITokenConflict
		}
		return receipt.RevokedMS, nil
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=? AND expires_ms<=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, now); err != nil {
			return 0, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	var ownerID string
	var revoked sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT user_id,revoked_ms FROM api_tokens WHERE deployment_id=? AND token_hash=?`, actor.DeploymentID, tokenID).Scan(&ownerID, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrAPITokenUnavailable
		}
		return 0, err
	}
	if ownerID != actor.User.ID && role != "admin" {
		return 0, ErrOwnershipMismatch
	}
	revokedMS := now
	if revoked.Valid {
		revokedMS = revoked.Int64
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_ms=? WHERE deployment_id=? AND token_hash=? AND revoked_ms IS NULL`, now, actor.DeploymentID, tokenID); err != nil {
			return 0, err
		}
		auditID, err := domain.NewUUID()
		if err != nil {
			return 0, err
		}
		detail, _ := json.Marshal(struct {
			OwnerUserID string `json:"owner_user_id"`
		}{ownerID})
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'auth.token.revoke',?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, tokenID, now, string(detail)); err != nil {
			return 0, err
		}
	}
	receiptJSON, _ := json.Marshal(apiTokenRevocationReceipt{TokenID: tokenID, RevokedMS: revokedMS})
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, string(receiptJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return revokedMS, nil
}

func validateAPITokenActor(ctx context.Context, tx *sql.Tx, actor SessionRecord) (string, string, error) {
	if actor.DeploymentID == "" || actor.Generation == "" || actor.User.ID == "" || actor.User.Disabled || actor.User.HistoricalRestored {
		return "", "", ErrOwnershipMismatch
	}
	var role, username, generation, recovery string
	var disabled, historical int
	err := tx.QueryRowContext(ctx, `SELECT u.role,u.name,u.disabled,u.historical_restored,d.deployment_generation,d.recovery_state FROM users u JOIN deployments d ON d.id=u.deployment_id WHERE u.deployment_id=? AND u.id=? AND u.trust_generation=d.deployment_generation`, actor.DeploymentID, actor.User.ID).Scan(&role, &username, &disabled, &historical, &generation, &recovery)
	if err != nil {
		return "", "", ErrOwnershipMismatch
	}
	if disabled != 0 || historical != 0 || generation != actor.Generation || recovery != "normal" || (role != "admin" && role != "viewer") {
		return "", "", ErrAdmissionFenced
	}
	return role, username, nil
}

func (s *Store) validateAPITokenActorRead(ctx context.Context, actor SessionRecord) (string, string, error) {
	var role, username, generation, recovery string
	var disabled, historical int
	err := s.db.QueryRowContext(ctx, `SELECT u.role,u.name,u.disabled,u.historical_restored,d.deployment_generation,d.recovery_state FROM users u JOIN deployments d ON d.id=u.deployment_id WHERE u.deployment_id=? AND u.id=? AND u.trust_generation=d.deployment_generation`, actor.DeploymentID, actor.User.ID).Scan(&role, &username, &disabled, &historical, &generation, &recovery)
	if err != nil || disabled != 0 || historical != 0 || generation != actor.Generation || recovery != "normal" {
		return "", "", ErrOwnershipMismatch
	}
	return role, username, nil
}

func hashSecret(value string) string {
	// enrollment.HashToken and auth.HashToken intentionally share this SHA-256
	// representation; keeping it local avoids a store-to-auth import cycle.
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
