package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
)

const (
	deliveryLeaseDuration = 30 * time.Second
	deliveryListMaximum   = 100
	deliveryScanMaximum   = 32
)

var (
	ErrDeliveryNotFound = errors.New("notification delivery not found")
	ErrDeliveryConflict = errors.New("notification delivery request conflict")
	ErrDeliveryStale    = errors.New("notification delivery is stale")
	ErrDeliveryExpired  = errors.New("notification delivery expired")
	ErrDeliveryInvalid  = errors.New("invalid notification delivery")
)

type DeliveryRecord struct {
	ID                  string  `json:"id"`
	InstanceID          *string `json:"instance_id"`
	TransitionSequence  *int64  `json:"transition_sequence"`
	DestinationID       string  `json:"destination_id"`
	DestinationRevision int64   `json:"destination_revision"`
	RuleRevision        *int64  `json:"rule_revision"`
	IncidentGeneration  int64   `json:"incident_generation"`
	IdempotencyKey      string  `json:"idempotency_key"`
	State               string  `json:"state"`
	Status              string  `json:"status"`
	Attempts            int     `json:"attempts"`
	LeaseUntilMS        *int64  `json:"lease_until_ms"`
	NextAttemptMS       *int64  `json:"next_attempt_ms"`
	LastErrorCode       *string `json:"last_error_code"`
	SendStartedMS       *int64  `json:"send_started_ms"`
	SentMS              *int64  `json:"sent_ms"`
	ReceiverACKMS       *int64  `json:"receiver_ack_ms"`
	CompletedMS         *int64  `json:"completed_ms"`
	AcceptedUnknown     bool    `json:"accepted_unknown"`
	JobID               *string `json:"job_id"`
	ExpiresMS           int64   `json:"expires_ms"`
	CreatedMS           int64   `json:"created_ms"`
}

type DeliveryLease struct {
	DeliveryRecord
	LeaseToken string                    `json:"lease_token"`
	Kind       string                    `json:"kind"`
	Config     domain.NotificationConfig `json:"config"`
	SecretRef  string                    `json:"-"`
	Payload    json.RawMessage           `json:"payload"`
}

type DeliveryCompletion struct {
	ID              string
	ExpectedAttempt int
	LeaseToken      string
	Succeeded       bool
	Permanent       bool
	SafeCode        string
	RetryAfter      time.Duration
	ReceiverACKMS   *int64
}

type DeliveryListOptions struct {
	DestinationID string
	AfterID       string
	Limit         int
}

type deliveryRetryReceipt struct {
	Delivery DeliveryRecord `json:"delivery"`
}

func (s *Store) ClaimNotificationDelivery(ctx context.Context, deploymentID, deploymentGeneration string) (*DeliveryLease, error) {
	if !validUUIDText(deploymentID) || !validUUIDText(deploymentGeneration) {
		return nil, ErrDeliveryInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := s.clock.Now().UnixMilli()
	var currentGeneration, recoveryState string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, deploymentID).Scan(&currentGeneration, &recoveryState); err != nil || currentGeneration != deploymentGeneration || recoveryState != "normal" {
		return nil, ErrAdmissionFenced
	}
	if err := reconcileDeliveryLeasesTx(ctx, tx, deploymentID, now); err != nil {
		return nil, err
	}
	for scanned := 0; scanned < deliveryScanMaximum; scanned++ {
		var deliveryID string
		err := tx.QueryRowContext(ctx, `SELECT id FROM outbox WHERE deployment_id=? AND state IN ('pending','failed','muted') AND next_attempt_ms IS NOT NULL AND next_attempt_ms<=? ORDER BY next_attempt_ms,created_ms,id LIMIT 1`, deploymentID, now).Scan(&deliveryID)
		if errors.Is(err, sql.ErrNoRows) {
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		lease, ready, err := reconcileDeliveryCandidateTx(ctx, tx, deploymentID, deliveryID, now)
		if err != nil {
			return nil, err
		}
		if !ready {
			continue
		}
		contended, err := deferContendedDeliveryTx(ctx, tx, deploymentID, deliveryID, now)
		if err != nil {
			return nil, err
		}
		if contended {
			continue
		}
		leaseToken, err := domain.NewUUID()
		if err != nil {
			return nil, err
		}
		leaseUntil := now + deliveryLeaseDuration.Milliseconds()
		result, err := tx.ExecContext(ctx, `UPDATE outbox SET state='leased',attempts=attempts+1,lease_token=?,lease_until_ms=?,next_attempt_ms=NULL,last_error_code=NULL,send_started_ms=? WHERE deployment_id=? AND id=? AND state IN ('pending','failed','muted')`, leaseToken, leaseUntil, now, deploymentID, deliveryID)
		if err != nil {
			if isDeliveryLeaseConstraint(err) {
				if _, deferErr := deferContendedDeliveryTx(ctx, tx, deploymentID, deliveryID, now); deferErr != nil {
					return nil, deferErr
				}
				continue
			}
			return nil, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			continue
		}
		claimed, err := readDeliveryTx(ctx, tx, deploymentID, deliveryID)
		if err != nil {
			return nil, err
		}
		lease.DeliveryRecord = claimed
		lease.LeaseToken = leaseToken
		if claimed.JobID != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE jobs SET state='running',progress=0.5,lease_until_ms=?,updated_ms=? WHERE deployment_id=? AND id=? AND type='destination_test' AND state IN ('queued','running')`, leaseUntil, now, deploymentID, *claimed.JobID); err != nil {
				return nil, err
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return lease, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return nil, nil
}

func reconcileDeliveryLeasesTx(ctx context.Context, tx *sql.Tx, deploymentID string, now int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='expired',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code='delivery_expired',completed_ms=?,accepted_unknown=CASE WHEN state='leased' THEN 1 ELSE accepted_unknown END WHERE deployment_id=? AND state IN ('pending','failed','muted','leased') AND expires_ms<=?`, now, deploymentID, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET state='failed',progress=1,error_code='delivery_expired',lease_until_ms=NULL,updated_ms=? WHERE deployment_id=? AND type='destination_test' AND state IN ('queued','running') AND EXISTS (SELECT 1 FROM outbox WHERE outbox.deployment_id=jobs.deployment_id AND outbox.job_id=jobs.id AND outbox.state='expired')`, now, deploymentID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE outbox SET state='failed',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=?,last_error_code='receiver_ack_unknown',accepted_unknown=1 WHERE deployment_id=? AND state='leased' AND lease_until_ms<=? AND expires_ms>?`, now, deploymentID, now, now)
	return err
}

func reconcileDeliveryCandidateTx(ctx context.Context, tx *sql.Tx, deploymentID, deliveryID string, now int64) (*DeliveryLease, bool, error) {
	var instanceID sql.NullString
	var transition, ruleRevision sql.NullInt64
	var destinationID, storedSecretRef, payloadJSON string
	var destinationRevision, incidentGeneration int64
	err := tx.QueryRowContext(ctx, `SELECT instance_id,transition_seq,destination_id,destination_revision,COALESCE(destination_secret_ref,''),rule_revision,incident_generation,payload_json FROM outbox WHERE deployment_id=? AND id=?`, deploymentID, deliveryID).Scan(&instanceID, &transition, &destinationID, &destinationRevision, &storedSecretRef, &ruleRevision, &incidentGeneration, &payloadJSON)
	if err != nil {
		return nil, false, err
	}
	var kind, configJSON, currentSecretRef string
	var currentRevision int64
	var disabled sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT type,configuration_json,COALESCE(secret_ref,''),version,disabled_ms FROM destinations WHERE deployment_id=? AND id=?`, deploymentID, destinationID).Scan(&kind, &configJSON, &currentSecretRef, &currentRevision, &disabled)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (disabled.Valid || currentRevision != destinationRevision) {
		return nil, false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "destination_superseded", now)
	}
	if err != nil {
		return nil, false, err
	}
	var config domain.NotificationConfig
	if json.Unmarshal([]byte(configJSON), &config) != nil || domain.ValidateNotificationConfig(kind, config) != nil || !json.Valid([]byte(payloadJSON)) {
		return nil, false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "destination_invalid", now)
	}
	if !notificationSecretReferencesMatch(storedSecretRef, currentSecretRef, config) {
		return nil, false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "destination_secret_superseded", now)
	}
	lease := &DeliveryLease{Kind: kind, Config: config, SecretRef: storedSecretRef, Payload: json.RawMessage(payloadJSON)}
	if !instanceID.Valid { // Explicit destination test; job/generation checks are below.
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM jobs j JOIN deployments d ON d.id=j.deployment_id WHERE j.deployment_id=? AND j.id=(SELECT job_id FROM outbox WHERE deployment_id=? AND id=?) AND j.type='destination_test' AND j.state IN ('queued','running') AND j.deployment_generation=d.deployment_generation`, deploymentID, deploymentID, deliveryID).Scan(&active); err != nil {
			return nil, false, err
		}
		if active != 1 {
			return nil, false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "destination_test_stale", now)
		}
		return lease, true, nil
	}
	if !transition.Valid || !ruleRevision.Valid {
		return nil, false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "alert_identity_invalid", now)
	}
	var currentGeneration, currentTransition, currentRuleRevision int64
	var condition string
	var mutedUntil sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT active_generation,transition_seq,rule_version,state,muted_until_ms FROM alert_instances WHERE deployment_id=? AND id=?`, deploymentID, instanceID.String).Scan(&currentGeneration, &currentTransition, &currentRuleRevision, &condition, &mutedUntil)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (currentGeneration != incidentGeneration || currentTransition != transition.Int64 || currentRuleRevision != ruleRevision.Int64 || condition == string(alerts.StateSuperseded)) {
		return nil, false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "newer_alert_state", now)
	}
	if err != nil {
		return nil, false, err
	}
	var currentRuleVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT current_version FROM rules WHERE deployment_id=? AND id=(SELECT rule_id FROM alert_instances WHERE deployment_id=? AND id=?)`, deploymentID, deploymentID, instanceID.String).Scan(&currentRuleVersion); err != nil || currentRuleVersion != ruleRevision.Int64 {
		return nil, false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "rule_superseded", now)
	}
	if mutedUntil.Valid && mutedUntil.Int64 > now {
		_, err := tx.ExecContext(ctx, `UPDATE outbox SET state='muted',next_attempt_ms=?,last_error_code='operator_muted' WHERE deployment_id=? AND id=?`, mutedUntil.Int64, deploymentID, deliveryID)
		return nil, false, err
	}
	maintenanceUntil, err := deliveryMaintenanceUntilTx(ctx, tx, deploymentID, instanceID.String, now)
	if err != nil {
		return nil, false, err
	}
	if maintenanceUntil > now {
		_, err := tx.ExecContext(ctx, `UPDATE outbox SET state='muted',next_attempt_ms=?,last_error_code='maintenance_suppressed' WHERE deployment_id=? AND id=?`, maintenanceUntil, deploymentID, deliveryID)
		return nil, false, err
	}
	parentSuppressed, err := deliveryParentSuppressedTx(ctx, tx, deploymentID, instanceID.String)
	if err != nil {
		return nil, false, err
	}
	if parentSuppressed {
		_, err := tx.ExecContext(ctx, `UPDATE outbox SET state='muted',next_attempt_ms=?,last_error_code='parent_host_disconnected' WHERE deployment_id=? AND id=?`, now+deliveryLeaseDuration.Milliseconds(), deploymentID, deliveryID)
		return nil, false, err
	}
	if err := coalesceObsoleteDeliveriesTx(ctx, tx, deploymentID, instanceID.String, destinationID, transition.Int64, deliveryID, now); err != nil {
		return nil, false, err
	}
	updatedPayload, err := currentSummaryPayloadTx(ctx, tx, deploymentID, instanceID.String, destinationID, transition.Int64, payloadJSON)
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='pending',payload_json=?,next_attempt_ms=?,last_error_code=NULL WHERE deployment_id=? AND id=?`, updatedPayload, now, deploymentID, deliveryID); err != nil {
		return nil, false, err
	}
	lease.Payload = json.RawMessage(updatedPayload)
	return lease, true, nil
}

func (s *Store) CompleteNotificationDelivery(ctx context.Context, completion DeliveryCompletion) (DeliveryRecord, error) {
	if !validUUIDText(completion.ID) || completion.ExpectedAttempt < 1 || !validUUIDText(completion.LeaseToken) || completion.RetryAfter < 0 || completion.RetryAfter > 30*time.Minute || completion.Succeeded && (completion.Permanent || completion.SafeCode != "") || !completion.Succeeded && !safeDeliveryCode(completion.SafeCode) {
		return DeliveryRecord{}, ErrDeliveryInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return DeliveryRecord{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeliveryRecord{}, err
	}
	defer tx.Rollback()
	now := s.clock.Now().UnixMilli()
	var deploymentID, state string
	var attempts int
	var leaseToken sql.NullString
	var leaseUntil, expires sql.NullInt64
	var jobID sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id,state,attempts,lease_token,lease_until_ms,expires_ms,job_id FROM outbox WHERE id=?`, completion.ID).Scan(&deploymentID, &state, &attempts, &leaseToken, &leaseUntil, &expires, &jobID); errors.Is(err, sql.ErrNoRows) {
		return DeliveryRecord{}, ErrDeliveryNotFound
	} else if err != nil {
		return DeliveryRecord{}, err
	}
	if state != "leased" || attempts != completion.ExpectedAttempt || !leaseToken.Valid || leaseToken.String != completion.LeaseToken || !leaseUntil.Valid || leaseUntil.Int64 <= now {
		return DeliveryRecord{}, ErrDeliveryConflict
	}
	if completion.Succeeded {
		if completion.ReceiverACKMS != nil && (*completion.ReceiverACKMS < 0 || *completion.ReceiverACKMS > now) {
			return DeliveryRecord{}, ErrDeliveryInvalid
		}
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='sent',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code=NULL,sent_ms=?,receiver_ack_ms=?,completed_ms=? WHERE id=? AND state='leased' AND attempts=? AND lease_token=?`, now, completion.ReceiverACKMS, now, completion.ID, completion.ExpectedAttempt, completion.LeaseToken); err != nil {
			return DeliveryRecord{}, err
		}
		if jobID.Valid {
			if err := completeDestinationTestJobTx(ctx, tx, deploymentID, jobID.String, completion.ID, true, "", now); err != nil {
				return DeliveryRecord{}, err
			}
		}
	} else if completion.Permanent || jobID.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='failed',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code=?,completed_ms=? WHERE id=? AND state='leased' AND attempts=? AND lease_token=?`, completion.SafeCode, now, completion.ID, completion.ExpectedAttempt, completion.LeaseToken); err != nil {
			return DeliveryRecord{}, err
		}
		if jobID.Valid {
			if err := completeDestinationTestJobTx(ctx, tx, deploymentID, jobID.String, completion.ID, false, completion.SafeCode, now); err != nil {
				return DeliveryRecord{}, err
			}
		}
	} else {
		retryAllowed, err := revalidateDeliveryForRetryTx(ctx, tx, deploymentID, completion.ID, now)
		if err != nil {
			return DeliveryRecord{}, err
		}
		if !retryAllowed {
			record, err := readDeliveryTx(ctx, tx, deploymentID, completion.ID)
			if err != nil {
				return DeliveryRecord{}, err
			}
			if err := tx.Commit(); err != nil {
				return DeliveryRecord{}, err
			}
			return record, nil
		}
		next := now + deliveryRetryDelay(completion.ExpectedAttempt, completion.RetryAfter).Milliseconds()
		if next >= expires.Int64 {
			if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='expired',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code='delivery_expired',completed_ms=? WHERE id=? AND state='leased' AND attempts=? AND lease_token=?`, now, completion.ID, completion.ExpectedAttempt, completion.LeaseToken); err != nil {
				return DeliveryRecord{}, err
			}
			if jobID.Valid {
				if err := completeDestinationTestJobTx(ctx, tx, deploymentID, jobID.String, completion.ID, false, "delivery_expired", now); err != nil {
					return DeliveryRecord{}, err
				}
			}
		} else {
			if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='failed',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=?,last_error_code=?,accepted_unknown=CASE WHEN ? IN ('notification_connection_failed','notification_timeout_or_cancelled') THEN 1 ELSE accepted_unknown END WHERE id=? AND state='leased' AND attempts=? AND lease_token=?`, next, completion.SafeCode, completion.SafeCode, completion.ID, completion.ExpectedAttempt, completion.LeaseToken); err != nil {
				return DeliveryRecord{}, err
			}
		}
	}
	record, err := readDeliveryTx(ctx, tx, deploymentID, completion.ID)
	if err != nil {
		return DeliveryRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeliveryRecord{}, err
	}
	return record, nil
}

func (s *Store) RetryNotificationDelivery(ctx context.Context, actor SessionRecord, deliveryID, idempotencyKey, requestHash string) (DeliveryRecord, error) {
	if !validUUIDText(deliveryID) || !validMutationReceipt(idempotencyKey, requestHash) {
		return DeliveryRecord{}, ErrDeliveryInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return DeliveryRecord{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeliveryRecord{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return DeliveryRecord{}, err
	}
	if role != "admin" {
		return DeliveryRecord{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if record, found, err := readDeliveryRetryReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, deliveryID, now); err != nil {
		return DeliveryRecord{}, err
	} else if found {
		return record, nil
	}
	record, err := readDeliveryTx(ctx, tx, actor.DeploymentID, deliveryID)
	if err != nil {
		return DeliveryRecord{}, err
	}
	if record.ExpiresMS <= now || record.State == "expired" {
		return DeliveryRecord{}, ErrDeliveryExpired
	}
	if record.State != "failed" {
		return DeliveryRecord{}, ErrDeliveryConflict
	}
	_, ready, err := reconcileDeliveryCandidateTx(ctx, tx, actor.DeploymentID, deliveryID, now)
	if err != nil {
		return DeliveryRecord{}, err
	}
	if !ready {
		return DeliveryRecord{}, ErrDeliveryStale
	}
	if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='pending',next_attempt_ms=?,last_error_code=NULL,completed_ms=NULL WHERE deployment_id=? AND id=? AND state IN ('pending','failed','muted')`, now, actor.DeploymentID, deliveryID); err != nil {
		return DeliveryRecord{}, err
	}
	record, err = readDeliveryTx(ctx, tx, actor.DeploymentID, deliveryID)
	if err != nil {
		return DeliveryRecord{}, err
	}
	if err := persistDeliveryRetryTx(ctx, tx, actor, idempotencyKey, requestHash, record, now); err != nil {
		return DeliveryRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeliveryRecord{}, err
	}
	return record, nil
}

func (s *Store) ReadNotificationDelivery(ctx context.Context, actor SessionRecord, deliveryID string) (DeliveryRecord, error) {
	if !validUUIDText(deliveryID) {
		return DeliveryRecord{}, ErrDeliveryInvalid
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return DeliveryRecord{}, err
	}
	return readDeliveryQuery(ctx, s.db, actor.DeploymentID, deliveryID)
}

func (s *Store) ListNotificationDeliveries(ctx context.Context, actor SessionRecord, options DeliveryListOptions) ([]DeliveryRecord, error) {
	if options.Limit < 1 || options.Limit > deliveryListMaximum || options.AfterID != "" && !validUUIDText(options.AfterID) || options.DestinationID != "" && !validUUIDText(options.DestinationID) {
		return nil, ErrDeliveryInvalid
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return nil, err
	}
	query := `SELECT id FROM outbox WHERE deployment_id=? AND id>?`
	args := []any{actor.DeploymentID, options.AfterID}
	if options.DestinationID != "" {
		query += ` AND destination_id=?`
		args = append(args, options.DestinationID)
	}
	query += ` ORDER BY id LIMIT ?`
	args = append(args, options.Limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
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
	records := make([]DeliveryRecord, 0, len(ids))
	for _, id := range ids {
		record, err := readDeliveryQuery(ctx, s.db, actor.DeploymentID, id)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func readDeliveryTx(ctx context.Context, tx *sql.Tx, deploymentID, deliveryID string) (DeliveryRecord, error) {
	return readDeliveryQuery(ctx, tx, deploymentID, deliveryID)
}

func readDeliveryQuery(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, deploymentID, deliveryID string) (DeliveryRecord, error) {
	var record DeliveryRecord
	var instance, lastError, job sql.NullString
	var transition, ruleRevision, leaseUntil, nextAttempt, sendStarted, sent, receiverACK, completed sql.NullInt64
	var acceptedUnknown int
	err := query.QueryRowContext(ctx, `SELECT id,instance_id,transition_seq,destination_id,destination_revision,rule_revision,incident_generation,idempotency_key,state,attempts,lease_until_ms,next_attempt_ms,last_error_code,send_started_ms,sent_ms,receiver_ack_ms,completed_ms,accepted_unknown,job_id,expires_ms,created_ms FROM outbox WHERE deployment_id=? AND id=?`, deploymentID, deliveryID).Scan(&record.ID, &instance, &transition, &record.DestinationID, &record.DestinationRevision, &ruleRevision, &record.IncidentGeneration, &record.IdempotencyKey, &record.State, &record.Attempts, &leaseUntil, &nextAttempt, &lastError, &sendStarted, &sent, &receiverACK, &completed, &acceptedUnknown, &job, &record.ExpiresMS, &record.CreatedMS)
	if errors.Is(err, sql.ErrNoRows) {
		return DeliveryRecord{}, ErrDeliveryNotFound
	}
	if err != nil {
		return DeliveryRecord{}, err
	}
	record.InstanceID, record.TransitionSequence, record.RuleRevision = nullableStringPointer(instance), nullableInt64Pointer(transition), nullableInt64Pointer(ruleRevision)
	record.LeaseUntilMS, record.NextAttemptMS, record.LastErrorCode = nullableInt64Pointer(leaseUntil), nullableInt64Pointer(nextAttempt), nullableStringPointer(lastError)
	record.SendStartedMS, record.SentMS, record.ReceiverACKMS, record.CompletedMS = nullableInt64Pointer(sendStarted), nullableInt64Pointer(sent), nullableInt64Pointer(receiverACK), nullableInt64Pointer(completed)
	record.AcceptedUnknown, record.JobID = acceptedUnknown == 1, nullableStringPointer(job)
	record.Status = deliveryStatus(record)
	return record, nil
}

func deliveryStatus(record DeliveryRecord) string {
	switch record.State {
	case "pending":
		if record.NextAttemptMS != nil && record.Attempts > 0 && record.LastErrorCode != nil {
			return "retrying"
		}
		return "queued"
	case "leased":
		return "attempted"
	case "sent":
		if record.ReceiverACKMS != nil {
			return "acknowledged"
		}
		return "attempted"
	case "failed":
		if record.NextAttemptMS != nil {
			return "retrying"
		}
		return "terminal_failure"
	case "muted", "superseded_before_delivery":
		return "suppressed"
	case "expired":
		return "terminal_failure"
	default:
		return "terminal_failure"
	}
}

func deliveryRetryDelay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if retryAfter > 30*time.Minute {
			return 30 * time.Minute
		}
		return retryAfter
	}
	delays := []time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute}
	if attempt <= 0 {
		return delays[0]
	}
	if attempt > len(delays) {
		return 30 * time.Minute
	}
	return delays[attempt-1]
}

func safeDeliveryCode(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_') {
			return false
		}
	}
	return true
}

func notificationSecretReferencesMatch(stored, current string, config domain.NotificationConfig) bool {
	if stored != "" && !validNotificationSecretRef(stored) || current != "" && !validNotificationSecretRef(current) {
		return false
	}
	if config.NeedsSecret() {
		return stored != "" && current != "" && stored == current
	}
	return stored == current
}

func supersedeDeliveryTx(ctx context.Context, tx *sql.Tx, deploymentID, deliveryID, code string, now int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE outbox SET state='superseded_before_delivery',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code=?,completed_ms=?,accepted_unknown=CASE WHEN state='leased' THEN 1 ELSE accepted_unknown END WHERE deployment_id=? AND id=? AND state IN ('pending','failed','muted','leased')`, code, now, deploymentID, deliveryID)
	return err
}

func deferContendedDeliveryTx(ctx context.Context, tx *sql.Tx, deploymentID, deliveryID string, now int64) (bool, error) {
	var leaseUntil sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT leased.lease_until_ms FROM outbox candidate JOIN outbox leased ON leased.deployment_id=candidate.deployment_id AND leased.instance_id=candidate.instance_id AND leased.destination_id=candidate.destination_id AND leased.id!=candidate.id AND leased.state='leased' WHERE candidate.deployment_id=? AND candidate.id=? AND candidate.instance_id IS NOT NULL LIMIT 1`, deploymentID, deliveryID).Scan(&leaseUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	next := now + deliveryLeaseDuration.Milliseconds()
	if leaseUntil.Valid && leaseUntil.Int64 > next {
		next = leaseUntil.Int64
	}
	_, err = tx.ExecContext(ctx, `UPDATE outbox SET next_attempt_ms=?,last_error_code='delivery_in_flight' WHERE deployment_id=? AND id=? AND state IN ('pending','failed','muted')`, next, deploymentID, deliveryID)
	return true, err
}

func isDeliveryLeaseConstraint(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "outbox_one_inflight") || strings.Contains(message, "outbox.deployment_id, outbox.instance_id, outbox.destination_id")
}

func revalidateDeliveryForRetryTx(ctx context.Context, tx *sql.Tx, deploymentID, deliveryID string, now int64) (bool, error) {
	var instanceID sql.NullString
	var transition, ruleRevision sql.NullInt64
	var destinationID, storedSecretRef, payloadJSON string
	var destinationRevision, incidentGeneration int64
	if err := tx.QueryRowContext(ctx, `SELECT instance_id,transition_seq,destination_id,destination_revision,COALESCE(destination_secret_ref,''),rule_revision,incident_generation,payload_json FROM outbox WHERE deployment_id=? AND id=?`, deploymentID, deliveryID).Scan(&instanceID, &transition, &destinationID, &destinationRevision, &storedSecretRef, &ruleRevision, &incidentGeneration, &payloadJSON); err != nil {
		return false, err
	}
	var kind, configJSON, currentSecretRef string
	var currentRevision int64
	var disabled sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT type,configuration_json,COALESCE(secret_ref,''),version,disabled_ms FROM destinations WHERE deployment_id=? AND id=?`, deploymentID, destinationID).Scan(&kind, &configJSON, &currentSecretRef, &currentRevision, &disabled)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (disabled.Valid || currentRevision != destinationRevision) {
		return false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "destination_superseded", now)
	}
	if err != nil {
		return false, err
	}
	var config domain.NotificationConfig
	if json.Unmarshal([]byte(configJSON), &config) != nil || domain.ValidateNotificationConfig(kind, config) != nil || !json.Valid([]byte(payloadJSON)) {
		return false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "destination_invalid", now)
	}
	if !notificationSecretReferencesMatch(storedSecretRef, currentSecretRef, config) {
		return false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "destination_secret_superseded", now)
	}
	if !instanceID.Valid {
		return true, nil
	}
	if !transition.Valid || !ruleRevision.Valid {
		return false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "alert_identity_invalid", now)
	}
	var currentGeneration, currentTransition, currentRuleRevision int64
	var condition string
	var mutedUntil sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT active_generation,transition_seq,rule_version,state,muted_until_ms FROM alert_instances WHERE deployment_id=? AND id=?`, deploymentID, instanceID.String).Scan(&currentGeneration, &currentTransition, &currentRuleRevision, &condition, &mutedUntil)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (currentGeneration != incidentGeneration || currentTransition != transition.Int64 || currentRuleRevision != ruleRevision.Int64 || condition == string(alerts.StateSuperseded)) {
		return false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "newer_alert_state", now)
	}
	if err != nil {
		return false, err
	}
	var currentRuleVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT current_version FROM rules WHERE deployment_id=? AND id=(SELECT rule_id FROM alert_instances WHERE deployment_id=? AND id=?)`, deploymentID, deploymentID, instanceID.String).Scan(&currentRuleVersion); err != nil || currentRuleVersion != ruleRevision.Int64 {
		return false, supersedeDeliveryTx(ctx, tx, deploymentID, deliveryID, "rule_superseded", now)
	}
	if mutedUntil.Valid && mutedUntil.Int64 > now {
		return false, suppressInFlightDeliveryTx(ctx, tx, deploymentID, deliveryID, mutedUntil.Int64, "operator_muted")
	}
	maintenanceUntil, err := deliveryMaintenanceUntilTx(ctx, tx, deploymentID, instanceID.String, now)
	if err != nil {
		return false, err
	}
	if maintenanceUntil > now {
		return false, suppressInFlightDeliveryTx(ctx, tx, deploymentID, deliveryID, maintenanceUntil, "maintenance_suppressed")
	}
	parentSuppressed, err := deliveryParentSuppressedTx(ctx, tx, deploymentID, instanceID.String)
	if err != nil {
		return false, err
	}
	if parentSuppressed {
		return false, suppressInFlightDeliveryTx(ctx, tx, deploymentID, deliveryID, now+deliveryLeaseDuration.Milliseconds(), "parent_host_disconnected")
	}
	return true, nil
}

func suppressInFlightDeliveryTx(ctx context.Context, tx *sql.Tx, deploymentID, deliveryID string, next int64, code string) error {
	_, err := tx.ExecContext(ctx, `UPDATE outbox SET state='muted',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=?,last_error_code=?,completed_ms=NULL,accepted_unknown=1 WHERE deployment_id=? AND id=? AND state='leased'`, next, code, deploymentID, deliveryID)
	if err != nil {
		return err
	}
	return nil
}

func coalesceObsoleteDeliveriesTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID, destinationID string, transition int64, keepID string, now int64) error {
	result, err := tx.ExecContext(ctx, `UPDATE outbox SET state='superseded_before_delivery',lease_token=NULL,lease_until_ms=NULL,next_attempt_ms=NULL,last_error_code='newer_alert_state',completed_ms=? WHERE deployment_id=? AND instance_id=? AND destination_id=? AND id!=? AND transition_seq!=? AND state IN ('pending','failed','muted')`, now, deploymentID, instanceID, destinationID, keepID, transition)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return nil
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	detail, _ := json.Marshal(map[string]any{"destination_id": destinationID, "current_transition_sequence": transition, "superseded_count": count})
	_, err = tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'notification.delivery.superseded_before_delivery',?,?,?)`, auditID, deploymentID, instanceID, now, string(detail))
	return err
}

func currentSummaryPayloadTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID, destinationID string, transition int64, encoded string) (string, error) {
	var payload map[string]any
	if json.Unmarshal([]byte(encoded), &payload) != nil {
		return "", ErrDeliveryInvalid
	}
	var state string
	var startMS int64
	var endMS sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT a.state,i.start_ms,i.end_ms FROM alert_instances a JOIN incidents i ON i.deployment_id=a.deployment_id AND i.alert_instance_id=a.id WHERE a.deployment_id=? AND a.id=? ORDER BY i.created_ms DESC LIMIT 1`, deploymentID, instanceID).Scan(&state, &startMS, &endMS); err != nil {
		return "", err
	}
	var firingSent, acceptedUnknown int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM outbox o JOIN alert_transitions t ON t.deployment_id=o.deployment_id AND t.instance_id=o.instance_id AND t.transition_seq=o.transition_seq WHERE o.deployment_id=? AND o.instance_id=? AND o.destination_id=? AND o.state='sent' AND t.new_state='FIRING'), EXISTS(SELECT 1 FROM outbox WHERE deployment_id=? AND instance_id=? AND destination_id=? AND transition_seq<? AND accepted_unknown=1)`, deploymentID, instanceID, destinationID, deploymentID, instanceID, destinationID, transition).Scan(&firingSent, &acceptedUnknown); err != nil {
		return "", err
	}
	payload["onset_ms"] = startMS
	if endMS.Valid {
		payload["recovery_ms"] = endMS.Int64
	}
	if state == string(alerts.StateResolved) && firingSent == 0 {
		payload["summary_kind"] = "occurred_and_recovered"
	} else {
		payload["summary_kind"] = "current_state"
	}
	payload["accepted_unknown"] = acceptedUnknown == 1
	result, err := json.Marshal(payload)
	if err != nil || len(result) > alertNotificationPayloadMax {
		return "", ErrDeliveryInvalid
	}
	return string(result), nil
}

func deliveryMaintenanceUntilTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID string, now int64) (int64, error) {
	var scopeJSON string
	if err := tx.QueryRowContext(ctx, `SELECT rr.scope_json FROM alert_instances a JOIN rule_revisions rr ON rr.deployment_id=a.deployment_id AND rr.rule_id=a.rule_id AND rr.version=a.rule_version WHERE a.deployment_id=? AND a.id=?`, deploymentID, instanceID).Scan(&scopeJSON); err != nil {
		return 0, err
	}
	var scope ruleScope
	if json.Unmarshal([]byte(scopeJSON), &scope) != nil {
		return 0, ErrDeliveryInvalid
	}
	rows, err := tx.QueryContext(ctx, `SELECT scope_json,expires_ms FROM maintenance_windows WHERE deployment_id=? AND starts_ms<=? AND expires_ms>? AND cancelled_ms IS NULL ORDER BY expires_ms LIMIT 65`, deploymentID, now, now)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var maximum int64
	count := 0
	for rows.Next() {
		count++
		var encoded string
		var expires int64
		if err := rows.Scan(&encoded, &expires); err != nil {
			return 0, err
		}
		if maintenanceScopeMatchesTx(ctx, tx, deploymentID, scope, encoded) && expires > maximum {
			maximum = expires
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if count > 64 {
		return 0, ErrDeliveryConflict
	}
	return maximum, nil
}

func maintenanceScopeMatchesTx(ctx context.Context, tx *sql.Tx, deploymentID string, alertScope ruleScope, encoded string) bool {
	var value struct {
		ScopeKind string `json:"scope_kind"`
		ScopeID   string `json:"scope_id"`
		Kind      string `json:"kind"`
		ID        string `json:"id"`
	}
	if json.Unmarshal([]byte(encoded), &value) != nil {
		return true // fail closed: an admitted but unreadable active window suppresses sends.
	}
	if value.ScopeKind == "" {
		value.ScopeKind = value.Kind
	}
	if value.ScopeID == "" {
		value.ScopeID = value.ID
	}
	if value.ScopeKind == "deployment" || value.ScopeKind == "" && value.ScopeID == "" {
		return value.ScopeID == "" || value.ScopeID == deploymentID
	}
	if value.ScopeKind == alertScope.ScopeKind && value.ScopeID == alertScope.ScopeID {
		return true
	}
	if value.ScopeKind == "host" && alertScope.ScopeKind == "target" {
		var hostID string
		return tx.QueryRowContext(ctx, `SELECT host_id FROM targets WHERE deployment_id=? AND id=?`, deploymentID, alertScope.ScopeID).Scan(&hostID) == nil && hostID == value.ScopeID
	}
	return false
}

func deliveryParentSuppressedTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID string) (bool, error) {
	var evaluator, scopeJSON string
	if err := tx.QueryRowContext(ctx, `SELECT rr.evaluator_type,rr.scope_json FROM alert_instances a JOIN rule_revisions rr ON rr.deployment_id=a.deployment_id AND rr.rule_id=a.rule_id AND rr.version=a.rule_version WHERE a.deployment_id=? AND a.id=?`, deploymentID, instanceID).Scan(&evaluator, &scopeJSON); err != nil {
		return false, err
	}
	if evaluator == string(alerts.RuleHostNotReporting) {
		return false, nil
	}
	var scope ruleScope
	if json.Unmarshal([]byte(scopeJSON), &scope) != nil {
		return false, ErrDeliveryInvalid
	}
	hostID := ""
	switch scope.ScopeKind {
	case "host":
		hostID = scope.ScopeID
	case "target":
		if err := tx.QueryRowContext(ctx, `SELECT host_id FROM targets WHERE deployment_id=? AND id=?`, deploymentID, scope.ScopeID).Scan(&hostID); err != nil {
			return false, err
		}
	default:
		return false, nil
	}
	var count int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM alert_instances a JOIN rules r ON r.deployment_id=a.deployment_id AND r.id=a.rule_id AND r.current_version=a.rule_version JOIN rule_revisions rr ON rr.deployment_id=a.deployment_id AND rr.rule_id=a.rule_id AND rr.version=a.rule_version WHERE a.deployment_id=? AND rr.evaluator_type=? AND json_extract(rr.scope_json,'$.scope_id')=? AND a.state IN ('FIRING','RECOVERING')`, deploymentID, string(alerts.RuleHostNotReporting), hostID).Scan(&count)
	return count > 0, err
}

func readDeliveryRetryReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash, deliveryID string, now int64) (DeliveryRecord, bool, error) {
	var storedHash, encoded string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &encoded, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return DeliveryRecord{}, false, nil
	}
	if err != nil {
		return DeliveryRecord{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return DeliveryRecord{}, false, err
		}
		return DeliveryRecord{}, false, nil
	}
	var receipt deliveryRetryReceipt
	if storedHash != requestHash || json.Unmarshal([]byte(encoded), &receipt) != nil || receipt.Delivery.ID != deliveryID {
		return DeliveryRecord{}, false, ErrDeliveryConflict
	}
	receipt.Delivery.Status = deliveryStatus(receipt.Delivery)
	return receipt.Delivery, true, nil
}

func persistDeliveryRetryTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, record DeliveryRecord, now int64) error {
	encoded, err := json.Marshal(deliveryRetryReceipt{Delivery: record})
	if err != nil || len(encoded) > 64<<10 {
		return ErrDeliveryInvalid
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'notification.delivery.retry',?,?,'{}')`, auditID, actor.DeploymentID, actor.User.ID, record.ID, now); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, key, requestHash, string(encoded), now, now+int64(24*time.Hour/time.Millisecond))
	return err
}
