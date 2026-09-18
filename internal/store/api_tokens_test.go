package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAPITokenCreateAuthenticateListAndRevoke(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	raw := strings.Repeat("t", 43)
	requestHash := strings.Repeat("1", 64)
	idempotencyKey := "00000000-0000-4000-8000-000000000091"
	expires := clock.Now().Add(time.Hour).UnixMilli()
	created, err := st.CreateAPIToken(context.Background(), admin, idempotencyKey, requestHash, raw, "Automation", expires)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := st.CreateAPIToken(context.Background(), admin, idempotencyKey, requestHash, raw, "Automation", expires)
	if err != nil || retried != created {
		t.Fatalf("exact retry changed result: first=%#v retry=%#v err=%v", created, retried, err)
	}
	if _, err := st.CreateAPIToken(context.Background(), admin, idempotencyKey, strings.Repeat("2", 64), raw, "Changed", expires); !errors.Is(err, ErrAPITokenConflict) {
		t.Fatalf("changed idempotency input err=%v", err)
	}
	authenticated, err := st.AuthenticateAPIToken(context.Background(), hashSecret(raw))
	if err != nil || authenticated.User.ID != admin.User.ID || authenticated.User.Role != "admin" || authenticated.ExpiresMS != expires {
		t.Fatalf("authenticated=%#v err=%v", authenticated, err)
	}
	items, err := st.ListAPITokens(context.Background(), admin)
	if err != nil || len(items) != 1 || items[0].ID != created.Record.ID || items[0].RevokedMS != nil {
		t.Fatalf("tokens=%#v err=%v", items, err)
	}
	var secretRows int
	if err := st.db.QueryRow(`SELECT count(*) FROM api_tokens WHERE token_hash=? AND token_hash<>?`, hashSecret(raw), raw).Scan(&secretRows); err != nil || secretRows != 1 {
		t.Fatalf("token hash persistence rows=%d err=%v", secretRows, err)
	}
	var receipt, audit string
	if err := st.db.QueryRow(`SELECT result_json FROM idempotency_receipts WHERE deployment_id=? AND actor_user_id=? AND idempotency_key=?`, admin.DeploymentID, admin.User.ID, idempotencyKey).Scan(&receipt); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT allowlisted_detail_json FROM audit WHERE deployment_id=? AND action='auth.token.create' AND resource_id=?`, admin.DeploymentID, created.Record.ID).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(receipt, raw) || strings.Contains(audit, raw) {
		t.Fatal("raw API bearer persisted in receipt or audit")
	}
	revocationHash := strings.Repeat("3", 64)
	revokedMS, err := st.RevokeAPIToken(context.Background(), admin, created.Record.ID, "00000000-0000-4000-8000-000000000092", revocationHash)
	if err != nil || revokedMS != clock.Now().UnixMilli() {
		t.Fatalf("revoke ms=%d err=%v", revokedMS, err)
	}
	retryMS, err := st.RevokeAPIToken(context.Background(), admin, created.Record.ID, "00000000-0000-4000-8000-000000000092", revocationHash)
	if err != nil || retryMS != revokedMS {
		t.Fatalf("revoke retry ms=%d err=%v", retryMS, err)
	}
	if _, err := st.AuthenticateAPIToken(context.Background(), hashSecret(raw)); !errors.Is(err, ErrAPITokenUnavailable) {
		t.Fatalf("revoked bearer authentication err=%v", err)
	}
}

func TestAPITokenRoleScopeAndAdminRevocationAuthority(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	viewerID := "00000000-0000-4000-8000-000000000099"
	now := clock.Now().UnixMilli()
	if _, err := st.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','viewer',0,?,0,1,?,?)`, viewerID, admin.DeploymentID, "viewer", admin.Generation, now, now); err != nil {
		t.Fatal(err)
	}
	viewer := SessionRecord{User: admin.User, DeploymentID: admin.DeploymentID, Generation: admin.Generation, ExpiresMS: admin.ExpiresMS}
	viewer.User.ID, viewer.User.Name, viewer.User.Role = viewerID, "viewer", "viewer"
	raw := strings.Repeat("v", 43)
	created, err := st.CreateAPIToken(context.Background(), viewer, "00000000-0000-4000-8000-000000000093", strings.Repeat("4", 64), raw, "Viewer automation", clock.Now().Add(time.Hour).UnixMilli())
	if err != nil || created.Record.Scope != "viewer" {
		t.Fatalf("viewer token=%#v err=%v", created, err)
	}
	adminItems, err := st.ListAPITokens(context.Background(), admin)
	if err != nil || len(adminItems) != 1 || adminItems[0].UserID != viewerID {
		t.Fatalf("admin token list=%#v err=%v", adminItems, err)
	}
	if _, err := st.RevokeAPIToken(context.Background(), admin, created.Record.ID, "00000000-0000-4000-8000-000000000094", strings.Repeat("5", 64)); err != nil {
		t.Fatal(err)
	}
}

func TestAPITokenListKeepsActiveCredentialsVisibleAfterChurn(t *testing.T) {
	for _, role := range []string{"admin", "viewer"} {
		t.Run(role, func(t *testing.T) {
			st, clock, actor := newEnrollmentStore(t)
			if role == "viewer" {
				viewerID := "00000000-0000-4000-8000-000000000119"
				now := clock.Now().UnixMilli()
				if _, err := st.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','viewer',0,?,0,1,?,?)`, viewerID, actor.DeploymentID, "churn-viewer", actor.Generation, now, now); err != nil {
					t.Fatal(err)
				}
				actor.User.ID, actor.User.Name, actor.User.Role = viewerID, "churn-viewer", role
			}
			ctx := context.Background()
			created, err := st.CreateAPIToken(ctx, actor, "token-list-active-regression", strings.Repeat("8", 64), strings.Repeat("a", 43), "Retained active credential", clock.Now().Add(time.Hour).UnixMilli())
			if err != nil {
				t.Fatal(err)
			}
			now := clock.Now().UnixMilli()
			// A mix of newer expired and revoked records exceeds both list limits.
			for index := 0; index < 101; index++ {
				var revoked any
				expiry := now + 2000
				if index%2 == 0 {
					revoked = now
					expiry = now + 3600000
				}
				if _, err := st.db.Exec(`INSERT INTO api_tokens(token_hash,deployment_id,deployment_generation,user_id,display_name,scope,created_ms,expires_ms,revoked_ms) VALUES(?,?,?,?,?,?,?,?,?)`, fmt.Sprintf("%064x", index+1), actor.DeploymentID, actor.Generation, actor.User.ID, "Inactive", role, now+int64(index+1), expiry, revoked); err != nil {
					t.Fatal(err)
				}
			}
			clock.now = clock.now.Add(10 * time.Second)
			items, err := st.ListAPITokens(ctx, actor)
			limit := 100
			if role == "viewer" {
				limit = 10
			}
			if err != nil || len(items) != limit || items[0].ID != created.Record.ID {
				t.Fatalf("active credential hidden: count=%d err=%v", len(items), err)
			}
			if _, err := st.RevokeAPIToken(ctx, actor, items[0].ID, "token-list-revoke-regression", strings.Repeat("9", 64)); err != nil {
				t.Fatal(err)
			}
			if _, err := st.AuthenticateAPIToken(ctx, created.Record.ID); !errors.Is(err, ErrAPITokenUnavailable) {
				t.Fatalf("discovered credential remained usable: %v", err)
			}
		})
	}
}
