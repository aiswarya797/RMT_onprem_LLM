package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
)

const (
	destinationActiveLimit = 16
	destinationListMaximum = 100
)

var (
	ErrDestinationNotFound = errors.New("notification destination not found")
	ErrDestinationConflict = errors.New("notification destination request conflict")
	ErrDestinationRevision = errors.New("notification destination revision conflict")
	ErrDestinationLimit    = errors.New("notification destination limit reached")
	ErrDestinationInvalid  = errors.New("invalid notification destination")
)

type DestinationDefinition struct {
	ExpectedVersion *int64                    `json:"expected_version"`
	Kind            string                    `json:"kind"`
	DisplayName     string                    `json:"display_name"`
	Config          domain.NotificationConfig `json:"config"`
	SecretRef       string                    `json:"-"`
}

type DestinationRecord struct {
	ID               string                    `json:"id"`
	Version          int64                     `json:"version"`
	Kind             string                    `json:"kind"`
	DisplayName      string                    `json:"display_name"`
	Config           domain.NotificationConfig `json:"config"`
	SecretConfigured bool                      `json:"secret_configured"`
	LastTestMS       *int64                    `json:"last_test_ms"`
	LastTestResult   *string                   `json:"last_test_result"`
	LastTestJobID    *string                   `json:"last_test_job_id"`
	DisabledMS       *int64                    `json:"disabled_ms"`
	CreatedMS        int64                     `json:"created_ms"`
	UpdatedMS        int64                     `json:"updated_ms"`
}

// DestinationListOptions keeps settings reads bounded. IDs are opaque UUIDs;
// callers pass the last ID from the prior page as AfterID.
type DestinationListOptions struct {
	IncludeDisabled bool
	AfterID         string
	Limit           int
}

type destinationReceipt struct {
	Operation string            `json:"operation"`
	Record    DestinationRecord `json:"record"`
}

func (s *Store) CreateDestination(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash string, definition DestinationDefinition) (DestinationRecord, error) {
	if definition.ExpectedVersion != nil || definition.SecretRef == "" && definition.Config.NeedsSecret() || definition.SecretRef != "" && !validNotificationSecretRef(definition.SecretRef) {
		return DestinationRecord{}, ErrDestinationInvalid
	}
	return s.mutateDestination(ctx, actor, "", idempotencyKey, requestHash, definition, "create")
}

func (s *Store) UpdateDestination(ctx context.Context, actor SessionRecord, destinationID, idempotencyKey, requestHash string, definition DestinationDefinition) (DestinationRecord, error) {
	if !validUUIDText(destinationID) || definition.ExpectedVersion == nil || *definition.ExpectedVersion < 1 {
		return DestinationRecord{}, ErrDestinationInvalid
	}
	return s.mutateDestination(ctx, actor, destinationID, idempotencyKey, requestHash, definition, "update")
}

func (s *Store) DisableDestination(ctx context.Context, actor SessionRecord, destinationID, idempotencyKey, requestHash string, expectedVersion int64) (DestinationRecord, error) {
	if !validUUIDText(destinationID) || expectedVersion < 1 || !validMutationReceipt(idempotencyKey, requestHash) {
		return DestinationRecord{}, ErrDestinationInvalid
	}
	definition := DestinationDefinition{ExpectedVersion: &expectedVersion}
	return s.mutateDestination(ctx, actor, destinationID, idempotencyKey, requestHash, definition, "disable")
}

// RemoveDestination is the API-facing name for a recoverable soft removal.
func (s *Store) RemoveDestination(ctx context.Context, actor SessionRecord, destinationID, idempotencyKey, requestHash string, expectedVersion int64) (DestinationRecord, error) {
	return s.DisableDestination(ctx, actor, destinationID, idempotencyKey, requestHash, expectedVersion)
}

func (s *Store) mutateDestination(ctx context.Context, actor SessionRecord, destinationID, idempotencyKey, requestHash string, definition DestinationDefinition, operation string) (DestinationRecord, error) {
	if !validMutationReceipt(idempotencyKey, requestHash) || operation != "disable" && !validDestinationDefinition(definition) {
		return DestinationRecord{}, ErrDestinationInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return DestinationRecord{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DestinationRecord{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return DestinationRecord{}, err
	}
	if role != "admin" {
		return DestinationRecord{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if record, found, err := readDestinationReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, operation, now); err != nil {
		return DestinationRecord{}, err
	} else if found {
		return record, nil
	}
	status := 200
	switch operation {
	case "create":
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM destinations WHERE deployment_id=? AND disabled_ms IS NULL`, actor.DeploymentID).Scan(&active); err != nil {
			return DestinationRecord{}, err
		}
		if active >= destinationActiveLimit {
			return DestinationRecord{}, ErrDestinationLimit
		}
		destinationID, err = domain.NewUUID()
		if err != nil {
			return DestinationRecord{}, err
		}
		configJSON, _ := json.Marshal(definition.Config)
		if _, err := tx.ExecContext(ctx, `INSERT INTO destinations(id,deployment_id,type,display_name,secret_ref,configuration_json,version,created_ms,updated_ms) VALUES(?,?,?,?,?,?,1,?,?)`, destinationID, actor.DeploymentID, definition.Kind, strings.TrimSpace(definition.DisplayName), nullableSecretRefValue(definition.SecretRef), string(configJSON), now, now); err != nil {
			return DestinationRecord{}, err
		}
		status = 201
	case "update":
		current, err := readDestinationTx(ctx, tx, actor.DeploymentID, destinationID, true)
		if err != nil {
			return DestinationRecord{}, err
		}
		if current.DisabledMS != nil || current.Version != *definition.ExpectedVersion {
			return DestinationRecord{}, ErrDestinationRevision
		}
		configJSON, _ := json.Marshal(definition.Config)
		secretRefSQL := `secret_ref`
		args := []any{definition.Kind, strings.TrimSpace(definition.DisplayName), string(configJSON)}
		if definition.SecretRef != "" {
			secretRefSQL = `?`
			args = append(args, definition.SecretRef)
		}
		args = append(args, now, actor.DeploymentID, destinationID, *definition.ExpectedVersion)
		result, err := tx.ExecContext(ctx, `UPDATE destinations SET type=?,display_name=?,configuration_json=?,secret_ref=`+secretRefSQL+`,version=version+1,last_test_ms=NULL,last_test_result=NULL,last_test_job_id=NULL,updated_ms=? WHERE deployment_id=? AND id=? AND version=? AND disabled_ms IS NULL`, args...)
		if err != nil {
			return DestinationRecord{}, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return DestinationRecord{}, ErrDestinationRevision
		}
		if err := invalidateDestinationOutboxTx(ctx, tx, actor.DeploymentID, destinationID, *definition.ExpectedVersion, "destination_revised", now); err != nil {
			return DestinationRecord{}, err
		}
	case "disable":
		current, err := readDestinationTx(ctx, tx, actor.DeploymentID, destinationID, true)
		if err != nil {
			return DestinationRecord{}, err
		}
		if current.DisabledMS != nil || current.Version != *definition.ExpectedVersion {
			return DestinationRecord{}, ErrDestinationRevision
		}
		result, err := tx.ExecContext(ctx, `UPDATE destinations SET version=version+1,disabled_ms=?,updated_ms=? WHERE deployment_id=? AND id=? AND version=? AND disabled_ms IS NULL`, now, now, actor.DeploymentID, destinationID, *definition.ExpectedVersion)
		if err != nil {
			return DestinationRecord{}, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return DestinationRecord{}, ErrDestinationRevision
		}
		if err := invalidateDestinationOutboxTx(ctx, tx, actor.DeploymentID, destinationID, *definition.ExpectedVersion, "destination_disabled", now); err != nil {
			return DestinationRecord{}, err
		}
	default:
		return DestinationRecord{}, ErrDestinationInvalid
	}
	record, err := readDestinationTx(ctx, tx, actor.DeploymentID, destinationID, true)
	if err != nil {
		return DestinationRecord{}, err
	}
	if err := persistDestinationMutationTx(ctx, tx, actor, idempotencyKey, requestHash, operation, status, record, now); err != nil {
		return DestinationRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DestinationRecord{}, err
	}
	return record, nil
}

func (s *Store) ReadDestination(ctx context.Context, actor SessionRecord, destinationID string) (DestinationRecord, error) {
	if !validUUIDText(destinationID) {
		return DestinationRecord{}, ErrDestinationInvalid
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return DestinationRecord{}, err
	}
	return readDestinationQuery(ctx, s.db, actor.DeploymentID, destinationID, true)
}

func (s *Store) ListDestinations(ctx context.Context, actor SessionRecord, options DestinationListOptions) ([]DestinationRecord, error) {
	if options.Limit < 1 || options.Limit > destinationListMaximum || options.AfterID != "" && !validUUIDText(options.AfterID) {
		return nil, ErrDestinationInvalid
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return nil, err
	}
	disabled := "AND disabled_ms IS NULL"
	if options.IncludeDisabled {
		disabled = ""
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM destinations WHERE deployment_id=? AND id>? `+disabled+` ORDER BY id LIMIT ?`, actor.DeploymentID, options.AfterID, options.Limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, options.Limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) > options.Limit {
		ids = ids[:options.Limit]
	}
	records := make([]DestinationRecord, 0, len(ids))
	for _, id := range ids {
		record, err := readDestinationQuery(ctx, s.db, actor.DeploymentID, id, true)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// ReferencedNotificationSecrets returns the complete, bounded vault retention
// set for the current generation. Disabled destinations remain references until
// they are physically removed, and an in-flight old revision retains the exact
// secret envelope it claimed with.
func (s *Store) ReferencedNotificationSecrets(ctx context.Context) ([]string, error) {
	state, err := s.DeploymentState(ctx)
	if err != nil || state.RecoveryState != "normal" {
		return nil, ErrAdmissionFenced
	}
	rows, err := s.db.QueryContext(ctx, `SELECT secret_ref FROM destinations WHERE deployment_id=? AND secret_ref IS NOT NULL AND secret_ref!=''
		UNION SELECT destination_secret_ref FROM outbox WHERE deployment_id=? AND state='leased' AND destination_secret_ref IS NOT NULL AND destination_secret_ref!=''
		ORDER BY 1 LIMIT 117`, state.DeploymentID, state.DeploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make([]string, 0, destinationActiveLimit)
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		if !validNotificationSecretRef(ref) {
			return nil, ErrDestinationInvalid
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(refs) > 116 { // 100 retained settings rows plus 16 bounded leases.
		return nil, ErrDestinationLimit
	}
	return refs, nil
}

func validDestinationDefinition(definition DestinationDefinition) bool {
	name := strings.TrimSpace(definition.DisplayName)
	if name != definition.DisplayName || !safeRuleString(name, 128) || domain.ValidateNotificationConfig(definition.Kind, definition.Config) != nil {
		return false
	}
	return definition.SecretRef == "" || validNotificationSecretRef(definition.SecretRef)
}

func nullableSecretRefValue(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func validNotificationSecretRef(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func readDestinationTx(ctx context.Context, tx *sql.Tx, deploymentID, destinationID string, includeDisabled bool) (DestinationRecord, error) {
	return readDestinationQuery(ctx, tx, deploymentID, destinationID, includeDisabled)
}

func readDestinationQuery(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, deploymentID, destinationID string, includeDisabled bool) (DestinationRecord, error) {
	var record DestinationRecord
	var configJSON string
	var secretRef, lastResult, lastJob sql.NullString
	var lastTest, disabled sql.NullInt64
	extra := ""
	if !includeDisabled {
		extra = " AND disabled_ms IS NULL"
	}
	err := query.QueryRowContext(ctx, `SELECT id,version,type,display_name,configuration_json,secret_ref,last_test_ms,last_test_result,last_test_job_id,disabled_ms,created_ms,updated_ms FROM destinations WHERE deployment_id=? AND id=?`+extra, deploymentID, destinationID).Scan(&record.ID, &record.Version, &record.Kind, &record.DisplayName, &configJSON, &secretRef, &lastTest, &lastResult, &lastJob, &disabled, &record.CreatedMS, &record.UpdatedMS)
	if errors.Is(err, sql.ErrNoRows) {
		return DestinationRecord{}, ErrDestinationNotFound
	}
	if err != nil {
		return DestinationRecord{}, err
	}
	if json.Unmarshal([]byte(configJSON), &record.Config) != nil || domain.ValidateNotificationConfig(record.Kind, record.Config) != nil {
		return DestinationRecord{}, ErrDestinationInvalid
	}
	record.SecretConfigured = secretRef.Valid && secretRef.String != ""
	record.LastTestMS = nullableInt64Pointer(lastTest)
	record.LastTestResult = nullableStringPointer(lastResult)
	record.LastTestJobID = nullableStringPointer(lastJob)
	record.DisabledMS = nullableInt64Pointer(disabled)
	return record, nil
}

func readDestinationReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash, operation string, now int64) (DestinationRecord, bool, error) {
	var storedHash, encoded string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &encoded, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return DestinationRecord{}, false, nil
	}
	if err != nil {
		return DestinationRecord{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return DestinationRecord{}, false, err
		}
		return DestinationRecord{}, false, nil
	}
	var receipt destinationReceipt
	if storedHash != requestHash || json.Unmarshal([]byte(encoded), &receipt) != nil || receipt.Operation != operation || !validUUIDText(receipt.Record.ID) {
		return DestinationRecord{}, false, ErrDestinationConflict
	}
	return receipt.Record, true, nil
}

func persistDestinationMutationTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash, operation string, status int, record DestinationRecord, now int64) error {
	receiptJSON, err := json.Marshal(destinationReceipt{Operation: operation, Record: record})
	if err != nil || len(receiptJSON) > 64<<10 {
		return ErrDestinationInvalid
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	detail, _ := json.Marshal(struct {
		Kind             string `json:"kind"`
		Version          int64  `json:"version"`
		SecretConfigured bool   `json:"secret_configured"`
	}{record.Kind, record.Version, record.SecretConfigured})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,?,?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, "notification.destination."+operation, record.ID, now, string(detail)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,?,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, key, requestHash, status, string(receiptJSON), now, now+int64(24*time.Hour/time.Millisecond))
	return err
}

func invalidateDestinationOutboxTx(ctx context.Context, tx *sql.Tx, deploymentID, destinationID string, priorVersion int64, code string, now int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE outbox SET state='superseded_before_delivery',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code=?,completed_ms=? WHERE deployment_id=? AND destination_id=? AND destination_revision=? AND state IN ('pending','failed','muted')`, code, now, deploymentID, destinationID, priorVersion)
	return err
}
