package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

var (
	ErrRecoveryConflict     = errors.New("recovery scope conflicts with retained identity")
	ErrRecoveryGrantExpired = errors.New("recovery grant expired or inactive")
	ErrRecoveryCapacityBusy = errors.New("recovery receipt capacity unavailable")
	ErrRecoveryDefinition   = errors.New("recovery definition is incompatible")
)

// The reservation envelope is pinned to the SQLite build and schema measured
// by TestRecoveryReceiptReservationMatchesPinnedDBStatFixture. It includes the
// grant, tombstone, idempotency and audit rows plus every receipt table/index
// page. Keep the generous page-rounded margin: payload bytes are admitted by
// the bulk lane separately and must never be hidden inside this estimate.
const (
	recoveryReceiptReservationFixed    int64 = 256 << 10
	recoveryReceiptReservationPerFrame int64 = 4096
	recoveryPendingCapacityKey               = "capacity_pending_recovery_bytes"
)

type recoveryGrantScanner interface {
	Scan(dest ...any) error
}

type recoveryEncodedFrame struct {
	original protocol.RecoveryFrame
	payload  []byte
	hash     string
}

func RecoveryReceiptReservationBytes(frames int) (int64, error) {
	if frames < 1 || frames > 1_000_000 || int64(frames) > (math.MaxInt64-recoveryReceiptReservationFixed)/recoveryReceiptReservationPerFrame {
		return 0, ErrRecoveryCapacityBusy
	}
	return recoveryReceiptReservationFixed + int64(frames)*recoveryReceiptReservationPerFrame, nil
}

func scanRecoveryGrant(row recoveryGrantScanner) (protocol.RecoveryGrant, int64, sql.NullInt64, sql.NullInt64, error) {
	var grant protocol.RecoveryGrant
	var allowlist string
	var reservation int64
	var revoked, completed sql.NullInt64
	err := row.Scan(&grant.GrantID, &grant.DeploymentID, &grant.CurrentSecurityGeneration, &grant.HostID, &grant.OriginalSecurityGeneration, &grant.OriginalCollectorBootID, &grant.ManifestSHA256, &allowlist, &grant.GrantSHA256, &grant.MaxBytes, &grant.MaxFrames, &reservation, &grant.IssuedMS, &grant.ExpiresMS, &revoked, &completed)
	if err != nil {
		return protocol.RecoveryGrant{}, 0, revoked, completed, err
	}
	var manifest protocol.RecoveryManifest
	if json.Unmarshal([]byte(allowlist), &manifest) != nil || manifest.Validate() != nil {
		return protocol.RecoveryGrant{}, 0, revoked, completed, ErrRecoveryConflict
	}
	grant.SchemaVersion = domain.SchemaVersion
	grant.ApprovedSegments = make([]protocol.ApprovedRecoverySegment, 0, len(manifest.Segments))
	for _, segment := range manifest.Segments {
		grant.ApprovedSegments = append(grant.ApprovedSegments, protocol.ApprovedRecoverySegment{SourceID: segment.SourceID, FromSequence: segment.FromSequence, ToSequence: segment.ToSequence, SegmentSHA256: segment.SegmentSHA256})
	}
	if grant.Validate() != nil {
		return protocol.RecoveryGrant{}, 0, revoked, completed, ErrRecoveryConflict
	}
	return grant, reservation, revoked, completed, nil
}

const recoveryGrantSelect = `SELECT id,deployment_id,deployment_generation,host_id,original_security_generation,original_collector_boot_id,manifest_hash,allowlist_json,grant_sha256,max_bytes,max_frames,reserved_receipt_bytes,issued_ms,expires_ms,revoked_ms,completed_ms FROM recovery_grants`

func (s *Store) ListRecoveryGrants(ctx context.Context, actor SessionRecord) ([]protocol.RecoveryGrant, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil || role != "admin" {
		return nil, ErrOwnershipMismatch
	}
	rows, err := tx.QueryContext(ctx, recoveryGrantSelect+` WHERE deployment_id=? AND deployment_generation=? AND revoked_ms IS NULL AND completed_ms IS NULL AND expires_ms>=? ORDER BY issued_ms,id LIMIT 4`, actor.DeploymentID, actor.Generation, s.clock.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]protocol.RecoveryGrant, 0, 4)
	for rows.Next() {
		grant, _, _, _, err := scanRecoveryGrant(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, grant)
	}
	return result, rows.Err()
}

func (s *Store) ReadRecoveryGrant(ctx context.Context, actor SessionRecord, grantID string) (protocol.RecoveryGrant, error) {
	if len(grantID) != 36 {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil || role != "admin" {
		return protocol.RecoveryGrant{}, ErrOwnershipMismatch
	}
	grant, _, _, _, err := scanRecoveryGrant(tx.QueryRowContext(ctx, recoveryGrantSelect+` WHERE deployment_id=? AND deployment_generation=? AND id=?`, actor.DeploymentID, actor.Generation, grantID))
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	return grant, err
}

func (s *Store) RevokeRecoveryGrant(ctx context.Context, actor SessionRecord, grantID, idempotencyKey, requestHash string) (protocol.RecoveryGrant, error) {
	if len(grantID) != 36 || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !sha256HexPattern.MatchString(requestHash) {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil || role != "admin" {
		return protocol.RecoveryGrant{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	var storedHash, storedJSON string
	var receiptExpires int64
	err = tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey).Scan(&storedHash, &storedJSON, &receiptExpires)
	if err == nil && now < receiptExpires {
		var grant protocol.RecoveryGrant
		if storedHash != requestHash || json.Unmarshal([]byte(storedJSON), &grant) != nil || grant.Validate() != nil {
			return protocol.RecoveryGrant{}, ErrRecoveryConflict
		}
		return grant, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return protocol.RecoveryGrant{}, err
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=? AND expires_ms<=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, now); err != nil {
			return protocol.RecoveryGrant{}, err
		}
	}
	grant, reservation, revoked, completed, err := scanRecoveryGrant(tx.QueryRowContext(ctx, recoveryGrantSelect+` WHERE deployment_id=? AND deployment_generation=? AND id=?`, actor.DeploymentID, actor.Generation, grantID))
	if err != nil || revoked.Valid || completed.Valid {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	updated, err := tx.ExecContext(ctx, `UPDATE recovery_grants SET revoked_ms=? WHERE deployment_id=? AND host_id=? AND id=? AND revoked_ms IS NULL AND completed_ms IS NULL`, now, actor.DeploymentID, grant.HostID, grant.GrantID)
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	if err := releaseRecoveryCapacity(ctx, tx, actor.DeploymentID, reservation, now); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'recovery.grant.revoke',?,?,'{}')`, auditID, actor.DeploymentID, actor.User.ID, grant.GrantID, now); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	resultJSON, _ := json.Marshal(grant)
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, string(resultJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	return grant, nil
}

func (s *Store) CreateRecoveryGrant(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash string, manifest protocol.RecoveryManifest) (protocol.RecoveryGrant, error) {
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !sha256HexPattern.MatchString(requestHash) || manifest.Validate() != nil {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil || role != "admin" || manifest.DeploymentID != actor.DeploymentID {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	now := s.clock.Now().UnixMilli()
	var storedHash, storedJSON string
	var receiptExpires int64
	err = tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey).Scan(&storedHash, &storedJSON, &receiptExpires)
	if err == nil && now < receiptExpires {
		var grant protocol.RecoveryGrant
		if storedHash != requestHash || json.Unmarshal([]byte(storedJSON), &grant) != nil || grant.Validate() != nil {
			return protocol.RecoveryGrant{}, ErrRecoveryConflict
		}
		return grant, nil
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=? AND expires_ms<=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, now); err != nil {
			return protocol.RecoveryGrant{}, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return protocol.RecoveryGrant{}, err
	}
	if err := expireRecoveryGrantsTx(ctx, tx, actor.DeploymentID, now); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	var generation, recovery string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, actor.DeploymentID).Scan(&generation, &recovery); err != nil || generation != actor.Generation || recovery != "normal" {
		return protocol.RecoveryGrant{}, ErrAdmissionFenced
	}
	var hostActive, oldGeneration int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE deployment_id=? AND id=? AND retired_ms IS NULL`, actor.DeploymentID, manifest.HostID).Scan(&hostActive); err != nil || hostActive != 1 {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM deployment_generations WHERE deployment_id=? AND generation=? AND generation<>?`, actor.DeploymentID, manifest.OriginalSecurityGeneration, actor.Generation).Scan(&oldGeneration); err != nil || oldGeneration != 1 {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	var reenrolled int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit WHERE deployment_id=? AND resource_id=? AND action IN ('collector.local_host.reenroll','collector.reenrollment.redeem')`, actor.DeploymentID, manifest.HostID).Scan(&reenrolled); err != nil || reenrolled < 1 {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	oldestEligible := now - int64(24*time.Hour/time.Millisecond)
	if manifest.CreatedMS > now+60_000 {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	for _, segment := range manifest.Segments {
		if segment.FirstMS < oldestEligible || segment.LastMS > now+60_000 {
			return protocol.RecoveryGrant{}, ErrRecoveryConflict
		}
	}
	if err := admitHistoricalDefinitions(ctx, tx, manifest, now); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	approved := make([]protocol.ApprovedRecoverySegment, 0, len(manifest.Segments))
	for _, segment := range manifest.Segments {
		approved = append(approved, protocol.ApprovedRecoverySegment{SourceID: segment.SourceID, FromSequence: segment.FromSequence, ToSequence: segment.ToSequence, SegmentSHA256: segment.SegmentSHA256})
	}
	approvedJSON, err := json.Marshal(approved)
	if err != nil || len(approvedJSON) > 65536 {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	scopeSum := sha256.Sum256(approvedJSON)
	scopeHash := hex.EncodeToString(scopeSum[:])
	grantID, err := domain.NewUUID()
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	grant := protocol.RecoveryGrant{SchemaVersion: domain.SchemaVersion, GrantID: grantID, DeploymentID: actor.DeploymentID, HostID: manifest.HostID, CurrentSecurityGeneration: actor.Generation, OriginalSecurityGeneration: manifest.OriginalSecurityGeneration, OriginalCollectorBootID: manifest.OriginalCollectorBootID, ManifestSHA256: manifest.ManifestSHA256, ApprovedSegments: approved, MaxBytes: manifest.TotalBytes, MaxFrames: manifest.TotalFrames, IssuedMS: now, ExpiresMS: now + int64(time.Hour/time.Millisecond)}
	grant.GrantSHA256, err = protocol.CanonicalRecoveryGrantHash(grant)
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	reservation, err := RecoveryReceiptReservationBytes(grant.MaxFrames)
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	if err := reserveRecoveryCapacity(ctx, tx, actor.DeploymentID, reservation, now); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil || len(manifestJSON) > 65536 {
		return protocol.RecoveryGrant{}, ErrRecoveryConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO recovery_grants(id,deployment_id,deployment_generation,host_id,original_security_generation,original_collector_boot_id,manifest_hash,allowlist_json,approved_scope_sha256,grant_sha256,max_bytes,max_frames,reserved_receipt_bytes,issued_by,issued_ms,expires_ms,receipt_detail_expires_ms,revoked_ms,completed_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)`, grant.GrantID, grant.DeploymentID, grant.CurrentSecurityGeneration, grant.HostID, grant.OriginalSecurityGeneration, grant.OriginalCollectorBootID, grant.ManifestSHA256, string(manifestJSON), scopeHash, grant.GrantSHA256, grant.MaxBytes, grant.MaxFrames, reservation, actor.User.ID, grant.IssuedMS, grant.ExpiresMS, grant.ExpiresMS+int64(24*time.Hour/time.Millisecond))
	if err != nil {
		if strings.Contains(err.Error(), "active_recovery_grant_cap_4") || strings.Contains(err.Error(), "recovery_one_active_host") || strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return protocol.RecoveryGrant{}, ErrRecoveryConflict
		}
		return protocol.RecoveryGrant{}, fmt.Errorf("create recovery grant: %w", err)
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return protocol.RecoveryGrant{}, err
	}
	detail, _ := json.Marshal(map[string]any{"manifest_sha256": grant.ManifestSHA256, "max_bytes": grant.MaxBytes, "max_frames": grant.MaxFrames})
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'recovery.grant.create',?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, grant.GrantID, now, string(detail)); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	resultJSON, _ := json.Marshal(grant)
	if _, err = tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,201,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, string(resultJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return protocol.RecoveryGrant{}, err
	}
	return grant, nil
}

func admitHistoricalDefinitions(ctx context.Context, tx *sql.Tx, manifest protocol.RecoveryManifest, now int64) error {
	defs := manifest.HistoricalDefinitions
	for _, target := range defs.Targets {
		var dep, host, adapter, selector string
		err := tx.QueryRowContext(ctx, `SELECT deployment_id,host_id,adapter_id,local_selector_hash FROM targets WHERE id=?`, target.TargetID).Scan(&dep, &host, &adapter, &selector)
		if err == nil {
			if dep != manifest.DeploymentID || host != manifest.HostID || adapter != target.AdapterID || selector != target.LocalSelectorSHA256 {
				return ErrRecoveryDefinition
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO targets(id,deployment_id,host_id,adapter_id,local_selector_hash,display_name,endpoint_alias,retired_ms,created_ms,updated_ms) VALUES(?,?,?,?,?,'Historical recovered target','Historical recovery manifest',?,?,?)`, target.TargetID, manifest.DeploymentID, manifest.HostID, target.AdapterID, target.LocalSelectorSHA256, now, now, now); err != nil {
			return ErrRecoveryDefinition
		}
	}
	for _, source := range defs.Sources {
		var dep, host, kind, capability string
		var target sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT deployment_id,host_id,kind,target_id,admitted_capability_revision FROM sources WHERE id=?`, source.SourceID).Scan(&dep, &host, &kind, &target, &capability)
		if err == nil {
			if dep != manifest.DeploymentID || host != manifest.HostID || kind != source.Kind || !nullableEqual(target, source.TargetID) || capability != source.CapabilityRevision {
				return ErrRecoveryDefinition
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO sources(id,deployment_id,host_id,kind,target_id,admitted_capability_revision,retired_ms,created_ms,updated_ms) VALUES(?,?,?,?,?,?,?,?,?)`, source.SourceID, manifest.DeploymentID, manifest.HostID, source.Kind, source.TargetID, source.CapabilityRevision, now, now, now); err != nil {
			return ErrRecoveryDefinition
		}
	}
	for _, model := range defs.Models {
		var dep, host, target, alias string
		var digest sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT deployment_id,host_id,target_id,served_alias,digest FROM model_revisions WHERE id=?`, model.ModelID).Scan(&dep, &host, &target, &alias, &digest)
		if err == nil {
			if dep != manifest.DeploymentID || host != manifest.HostID || target != model.TargetID || alias != model.Alias || !nullableEqual(digest, model.Digest) {
				return ErrRecoveryDefinition
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO model_revisions(id,deployment_id,host_id,target_id,served_alias,digest,format,family,quantization,context_length,config_hash,created_ms) VALUES(?,?,?,?,?,?,NULL,NULL,NULL,NULL,?,?)`, model.ModelID, manifest.DeploymentID, manifest.HostID, model.TargetID, model.Alias, model.Digest, inventoryModelConfigHash(model), now); err != nil {
			return ErrRecoveryDefinition
		}
	}
	return nil
}

func reserveRecoveryCapacity(ctx context.Context, tx *sql.Tx, deploymentID string, bytes, now int64) error {
	var state, cursorJSON string
	if err := tx.QueryRowContext(ctx, `SELECT storage_state,evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&state, &cursorJSON); err != nil {
		return ErrRecoveryCapacityBusy
	}
	if state == StorageReadOnlyENOSPC {
		return ErrRecoveryCapacityBusy
	}
	observedMS, _, pendingBulk, err := readCapacityCursor(cursorJSON)
	if err != nil || observedMS > now+5000 || now-observedMS > CapacityMeasurementMaxAge.Milliseconds() {
		return ErrRecoveryCapacityBusy
	}
	pendingRecovery, err := readPendingRecoveryCapacity(cursorJSON)
	if err != nil {
		return ErrRecoveryCapacityBusy
	}
	for _, class := range []string{"metadata", "live_total"} {
		additionalPending := pendingRecovery
		if class == "live_total" {
			if pendingBulk > math.MaxInt64-additionalPending {
				return ErrRecoveryCapacityBusy
			}
			additionalPending += pendingBulk
		}
		res, err := tx.ExecContext(ctx, `UPDATE quota_classes SET reserved_physical_bytes=reserved_physical_bytes+?,updated_ms=? WHERE deployment_id=? AND class=? AND current_physical_bytes+reserved_physical_bytes+?+?<=byte_limit`, bytes, now, deploymentID, class, additionalPending, bytes)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrRecoveryCapacityBusy
		}
	}
	return nil
}

func releaseRecoveryCapacity(ctx context.Context, tx *sql.Tx, deploymentID string, bytes, now int64) error {
	var cursorJSON string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&cursorJSON); err != nil {
		return err
	}
	pending, err := readPendingRecoveryCapacity(cursorJSON)
	if err != nil || pending > math.MaxInt64-bytes {
		return ErrRecoveryConflict
	}
	if err := writePendingRecoveryCapacity(ctx, tx, deploymentID, pending+bytes); err != nil {
		return err
	}
	for _, class := range []string{"metadata", "live_total"} {
		res, err := tx.ExecContext(ctx, `UPDATE quota_classes SET reserved_physical_bytes=reserved_physical_bytes-?,updated_ms=? WHERE deployment_id=? AND class=? AND reserved_physical_bytes>=?`, bytes, now, deploymentID, class, bytes)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrRecoveryConflict
		}
	}
	return nil
}

func readPendingRecoveryCapacity(encoded string) (int64, error) {
	var cursor map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &cursor) != nil {
		return 0, ErrRecoveryCapacityBusy
	}
	raw, ok := cursor[recoveryPendingCapacityKey]
	if !ok {
		return 0, nil
	}
	var pending int64
	if json.Unmarshal(raw, &pending) != nil || pending < 0 {
		return 0, ErrRecoveryCapacityBusy
	}
	return pending, nil
}

func writePendingRecoveryCapacity(ctx context.Context, tx *sql.Tx, deploymentID string, pending int64) error {
	if pending < 0 {
		return ErrRecoveryConflict
	}
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&encoded); err != nil {
		return err
	}
	var cursor map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &cursor) != nil {
		return ErrRecoveryCapacityBusy
	}
	if cursor == nil {
		cursor = make(map[string]json.RawMessage)
	}
	cursor[recoveryPendingCapacityKey], _ = json.Marshal(pending)
	updated, err := json.Marshal(cursor)
	if err != nil || len(updated) > 65536 {
		return ErrRecoveryCapacityBusy
	}
	_, err = tx.ExecContext(ctx, `UPDATE maintenance SET evaluator_cursor_json=? WHERE deployment_id=?`, string(updated), deploymentID)
	return err
}

func expireRecoveryGrantsTx(ctx context.Context, tx *sql.Tx, deploymentID string, now int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,reserved_receipt_bytes,expires_ms FROM recovery_grants WHERE deployment_id=? AND revoked_ms IS NULL AND completed_ms IS NULL AND expires_ms<? ORDER BY expires_ms,id`, deploymentID, now)
	if err != nil {
		return err
	}
	type expiredGrant struct {
		reservation, expires int64
		grantID              string
	}
	expired := make([]expiredGrant, 0, 4)
	for rows.Next() {
		var grantID string
		var reservation, expires int64
		if err := rows.Scan(&grantID, &reservation, &expires); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, expiredGrant{grantID: grantID, reservation: reservation, expires: expires})
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, grant := range expired {
		result, err := tx.ExecContext(ctx, `UPDATE recovery_grants SET revoked_ms=? WHERE deployment_id=? AND id=? AND revoked_ms IS NULL AND completed_ms IS NULL`, grant.expires, deploymentID, grant.grantID)
		if err != nil {
			return err
		}
		if count, _ := result.RowsAffected(); count == 1 {
			if err := releaseRecoveryCapacity(ctx, tx, deploymentID, grant.reservation, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) IngestRecoveryReplay(ctx context.Context, replay protocol.RecoveryReplay) (protocol.RecoveryACK, error) {
	if err := replay.Validate(); err != nil {
		return protocol.RecoveryACK{}, err
	}
	select {
	case s.ingest <- struct{}{}:
		defer func() { <-s.ingest }()
	default:
		return protocol.RecoveryACK{}, ErrWriterBackpressure
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return protocol.RecoveryACK{}, err
	}
	defer release()
	encoded := make([]recoveryEncodedFrame, 0, len(replay.Frames))
	totalEncodedBytes := int64(0)
	for _, frame := range replay.Frames {
		payload, hash, err := s.codec.Encode(frame.Frame)
		if err != nil {
			return protocol.RecoveryACK{}, err
		}
		if hash != frame.OriginalPayloadSHA256 {
			return protocol.RecoveryACK{}, ErrRecoveryConflict
		}
		encoded = append(encoded, recoveryEncodedFrame{frame, payload, hash})
		totalEncodedBytes += int64(len(payload))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.RecoveryACK{}, err
	}
	defer tx.Rollback()
	current, err := validateCurrentSession(ctx, tx, replay.DeploymentID, replay.HostID, replay.AdmittingSecurityGeneration, replay.AdmittingSessionGeneration, replay.AdmittingCollectorBootID)
	if err != nil || !current {
		return protocol.RecoveryACK{}, ErrGenerationConflict
	}
	var generation, host, originalGeneration, originalBoot, grantHash, allowlistJSON string
	var maxBytes int64
	var maxFrames int
	var expires int64
	var revoked, completed sql.NullInt64
	var reservation int64
	err = tx.QueryRowContext(ctx, `SELECT deployment_generation,host_id,original_security_generation,original_collector_boot_id,grant_sha256,allowlist_json,max_bytes,max_frames,expires_ms,revoked_ms,completed_ms,reserved_receipt_bytes FROM recovery_grants WHERE deployment_id=? AND id=?`, replay.DeploymentID, replay.GrantID).Scan(&generation, &host, &originalGeneration, &originalBoot, &grantHash, &allowlistJSON, &maxBytes, &maxFrames, &expires, &revoked, &completed, &reservation)
	if err != nil || generation != replay.AdmittingSecurityGeneration || host != replay.HostID || originalGeneration != replay.OriginalSecurityGeneration || originalBoot != replay.OriginalCollectorBootID || grantHash != replay.GrantSHA256 || revoked.Valid {
		return protocol.RecoveryACK{}, ErrRecoveryConflict
	}
	if totalEncodedBytes > maxBytes {
		return protocol.RecoveryACK{}, ErrRecoveryConflict
	}
	now := s.clock.Now().UnixMilli()
	if now > expires {
		return protocol.RecoveryACK{}, ErrRecoveryGrantExpired
	}
	var manifest protocol.RecoveryManifest
	if json.Unmarshal([]byte(allowlistJSON), &manifest) != nil || manifest.Validate() != nil {
		return protocol.RecoveryACK{}, ErrRecoveryConflict
	}
	if !recoverySegmentsApproved(manifest, encoded) {
		return protocol.RecoveryACK{}, ErrRecoveryConflict
	}
	var priorScope string
	requestSeen := false
	err = tx.QueryRowContext(ctx, `SELECT json_extract(allowlisted_detail_json,'$.scope_sha256') FROM audit WHERE deployment_id=? AND action='recovery.grant.use' AND resource_id=? AND json_extract(allowlisted_detail_json,'$.replay_request_id')=? ORDER BY id LIMIT 1`, replay.DeploymentID, replay.GrantID, replay.ReplayRequestID).Scan(&priorScope)
	if err == nil {
		if priorScope != replay.ScopeSHA256 {
			return protocol.RecoveryACK{}, ErrRecoveryConflict
		}
		requestSeen = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return protocol.RecoveryACK{}, err
	}
	var retainedPayloadBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(sum(length(payload)),0) FROM source_frames WHERE deployment_id=? AND host_id=? AND recovery_grant_id=?`, replay.DeploymentID, replay.HostID, replay.GrantID).Scan(&retainedPayloadBytes); err != nil {
		return protocol.RecoveryACK{}, err
	}
	batch := protocol.CollectorBatch{Protocol: domain.ProtocolVersion, DeliveryMode: "restored_replay", SecurityGeneration: replay.AdmittingSecurityGeneration, SessionGeneration: replay.AdmittingSessionGeneration, DeploymentID: replay.DeploymentID, HostID: replay.HostID, CollectorBootID: replay.AdmittingCollectorBootID, BatchID: replay.ReplayRequestID}
	receipts := make([]protocol.RecoveryReceipt, 0, len(encoded))
	accepted, duplicates, payloadBytes, newFrames, newReceipts := 0, 0, 0, 0, 0
	for _, item := range encoded {
		if replay.OriginalCollectorBootID != manifest.OriginalCollectorBootID || now-item.original.OriginalObservedMS > int64(24*time.Hour/time.Millisecond) || item.original.OriginalObservedMS > now+60000 {
			return protocol.RecoveryACK{}, ErrRecoveryConflict
		}
		batch.Frames = []protocol.CollectorFrame{item.original.Frame}
		if err := validateFrameOwnership(ctx, tx, batch, item.original.Frame); err != nil {
			return protocol.RecoveryACK{}, err
		}
		var receiptHash, disposition string
		err := tx.QueryRowContext(ctx, `SELECT original_payload_sha256,disposition FROM recovery_grant_receipts WHERE deployment_id=? AND host_id=? AND grant_id=? AND original_collector_boot_id=? AND original_source_id=? AND original_sequence=?`, replay.DeploymentID, replay.HostID, replay.GrantID, replay.OriginalCollectorBootID, item.original.OriginalSourceID, item.original.OriginalSequence).Scan(&receiptHash, &disposition)
		if err == nil {
			if receiptHash != item.hash {
				return protocol.RecoveryACK{}, ErrRecoveryConflict
			}
			if disposition == "recovered" {
				accepted++
			} else if disposition == "duplicate" {
				duplicates++
			}
			receipts = append(receipts, protocol.RecoveryReceipt{OriginalCollectorBootID: replay.OriginalCollectorBootID, OriginalSourceID: item.original.OriginalSourceID, OriginalSequence: item.original.OriginalSequence, OriginalPayloadSHA256: item.hash, Disposition: disposition})
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return protocol.RecoveryACK{}, err
		}
		var existing string
		err = tx.QueryRowContext(ctx, `SELECT original_payload_sha256 FROM source_frames WHERE deployment_id=? AND host_id=? AND original_collector_boot_id=? AND original_source_id=? AND original_sequence=?`, replay.DeploymentID, replay.HostID, replay.OriginalCollectorBootID, item.original.OriginalSourceID, item.original.OriginalSequence).Scan(&existing)
		disposition = "recovered"
		if err == nil {
			if existing != item.hash {
				return protocol.RecoveryACK{}, ErrRecoveryConflict
			}
			disposition = "duplicate"
			duplicates++
		} else if !errors.Is(err, sql.ErrNoRows) {
			return protocol.RecoveryACK{}, err
		} else {
			accepted++
			payloadBytes += len(item.payload)
			newFrames++
		}
		newReceipts++
		receipts = append(receipts, protocol.RecoveryReceipt{OriginalCollectorBootID: replay.OriginalCollectorBootID, OriginalSourceID: item.original.OriginalSourceID, OriginalSequence: item.original.OriginalSequence, OriginalPayloadSHA256: item.hash, Disposition: disposition})
	}
	if !requestSeen && newReceipts == 0 {
		return protocol.RecoveryACK{}, ErrRecoveryConflict
	}
	if retainedPayloadBytes+int64(payloadBytes) > maxBytes {
		return protocol.RecoveryACK{}, ErrRecoveryConflict
	}
	if payloadBytes > 0 {
		requested, err := batchCapacityBytes(payloadBytes, newFrames)
		if err != nil {
			return protocol.RecoveryACK{}, err
		}
		if err := s.capacityAdmissionTx(ctx, tx, replay.DeploymentID, now, requested); err != nil {
			return protocol.RecoveryACK{}, err
		}
	}
	for index, item := range encoded {
		receipt := receipts[index]
		if receipt.Disposition == "recovered" {
			frame := item.original.Frame
			inserted, insertErr := tx.ExecContext(ctx, `INSERT OR IGNORE INTO source_frames(deployment_id,host_id,security_generation,session_generation,collector_boot_id,source_id,sequence,delivery_mode,incarnation_id,original_wall_ms,aligned_ms,uncertainty_ms,duration_ms,quality,definition_revision,codec,payload,payload_sha256,original_security_generation,original_collector_boot_id,original_source_id,original_sequence,original_payload_sha256,recovery_grant_id,recovery_grant_hash,admitted_ms) VALUES(?,?,?,?,?,?,?,'restored_replay',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, replay.DeploymentID, replay.HostID, replay.AdmittingSecurityGeneration, replay.AdmittingSessionGeneration, replay.AdmittingCollectorBootID, frame.SourceID, frame.Sequence, frame.IncarnationID, frame.ObservedWallMS, frame.EstimatedUTCMS, frame.UncertaintyMS, frame.DurationMS, string(frame.Quality), frame.DefinitionRevision, FrameCodec, item.payload, item.hash, replay.OriginalSecurityGeneration, replay.OriginalCollectorBootID, item.original.OriginalSourceID, item.original.OriginalSequence, item.hash, replay.GrantID, replay.GrantSHA256, now)
			if insertErr != nil {
				return protocol.RecoveryACK{}, insertErr
			}
			if rows, _ := inserted.RowsAffected(); rows == 1 {
				batch.Frames = []protocol.CollectorFrame{frame}
				if err := persistProcessObservations(ctx, tx, batch, frame, now); err != nil {
					return protocol.RecoveryACK{}, err
				}
				if err := persistModelObservations(ctx, tx, batch, frame); err != nil {
					return protocol.RecoveryACK{}, err
				}
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO recovery_grant_receipts(deployment_id,host_id,grant_id,original_collector_boot_id,original_source_id,original_sequence,original_payload_sha256,disposition,accepted_ms) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, replay.DeploymentID, replay.HostID, replay.GrantID, replay.OriginalCollectorBootID, receipt.OriginalSourceID, receipt.OriginalSequence, receipt.OriginalPayloadSHA256, receipt.Disposition, now); err != nil {
			return protocol.RecoveryACK{}, err
		}
	}
	var receiptCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM recovery_grant_receipts WHERE deployment_id=? AND host_id=? AND grant_id=?`, replay.DeploymentID, replay.HostID, replay.GrantID).Scan(&receiptCount); err != nil {
		return protocol.RecoveryACK{}, err
	}
	complete := receiptCount == maxFrames
	if complete && !completed.Valid {
		res, err := tx.ExecContext(ctx, `UPDATE recovery_grants SET completed_ms=? WHERE deployment_id=? AND host_id=? AND id=? AND completed_ms IS NULL`, now, replay.DeploymentID, replay.HostID, replay.GrantID)
		if err != nil {
			return protocol.RecoveryACK{}, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			if err := releaseRecoveryCapacity(ctx, tx, replay.DeploymentID, reservation, now); err != nil {
				return protocol.RecoveryACK{}, err
			}
		}
	}
	if !requestSeen {
		auditID, err := domain.NewUUID()
		if err != nil {
			return protocol.RecoveryACK{}, err
		}
		detail, _ := json.Marshal(map[string]any{"replay_request_id": replay.ReplayRequestID, "scope_sha256": replay.ScopeSHA256, "accepted": accepted, "duplicate": duplicates})
		if _, err = tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'recovery.grant.use',?,?,?)`, auditID, replay.DeploymentID, replay.GrantID, now, string(detail)); err != nil {
			return protocol.RecoveryACK{}, err
		}
	}
	ack := protocol.RecoveryACK{GrantID: replay.GrantID, GrantSHA256: replay.GrantSHA256, ReplayRequestID: replay.ReplayRequestID, ScopeSHA256: replay.ScopeSHA256, Durable: true, Accepted: accepted, Duplicate: duplicates, Rejected: 0, Receipts: receipts, Complete: complete, HubTimeMS: now}
	if err := ack.Validate(replay); err != nil {
		return protocol.RecoveryACK{}, err
	}
	if err := tx.Commit(); err != nil {
		return protocol.RecoveryACK{}, err
	}
	return ack, nil
}

func recoverySegmentsApproved(manifest protocol.RecoveryManifest, frames []recoveryEncodedFrame) bool {
	for index := 0; index < len(frames); {
		first := frames[index]
		var approved *protocol.RecoverySegment
		for segmentIndex := range manifest.Segments {
			candidate := &manifest.Segments[segmentIndex]
			if candidate.SourceID == first.original.OriginalSourceID && candidate.FromSequence == first.original.OriginalSequence {
				approved = candidate
				break
			}
		}
		if approved == nil || approved.FrameCount > len(frames)-index {
			return false
		}
		hasher := sha256.New()
		bytesInSegment := int64(0)
		firstMS, lastMS := first.original.OriginalObservedMS, first.original.OriginalObservedMS
		for offset := 0; offset < approved.FrameCount; offset++ {
			frame := frames[index+offset]
			if frame.original.OriginalSourceID != approved.SourceID || frame.original.OriginalSequence != approved.FromSequence+int64(offset) {
				return false
			}
			if err := protocol.WriteRecoveryDescriptor(hasher, protocol.RecoveryDescriptor{SourceID: frame.original.OriginalSourceID, Sequence: frame.original.OriginalSequence, ObservedMS: frame.original.OriginalObservedMS, PayloadSHA256: frame.original.OriginalPayloadSHA256}); err != nil {
				return false
			}
			bytesInSegment += int64(len(frame.payload))
			if frame.original.OriginalObservedMS < firstMS {
				firstMS = frame.original.OriginalObservedMS
			}
			if frame.original.OriginalObservedMS > lastMS {
				lastMS = frame.original.OriginalObservedMS
			}
		}
		if approved.ToSequence != approved.FromSequence+int64(approved.FrameCount)-1 || approved.Bytes != bytesInSegment || approved.FirstMS != firstMS || approved.LastMS != lastMS || approved.SegmentSHA256 != hex.EncodeToString(hasher.Sum(nil)) {
			return false
		}
		index += approved.FrameCount
	}
	return len(frames) > 0
}
