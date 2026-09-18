package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"rmt.local/monitor/internal/domain"
)

const destinationTestActivePerActor = 4

var ErrDestinationTestBusy = errors.New("notification destination test busy")

type NotificationTestJob struct {
	ID                  string  `json:"id"`
	DestinationID       string  `json:"destination_id"`
	DestinationRevision int64   `json:"destination_revision"`
	DeliveryID          string  `json:"delivery_id"`
	State               string  `json:"state"`
	ErrorCode           *string `json:"error_code"`
	ReceiverACKMS       *int64  `json:"receiver_ack_ms"`
	CreatedMS           int64   `json:"created_ms"`
	UpdatedMS           int64   `json:"updated_ms"`
	ExpiresMS           int64   `json:"expires_ms"`
}

type notificationTestReceipt struct {
	Job NotificationTestJob `json:"job"`
}

func (s *Store) EnqueueDestinationTest(ctx context.Context, actor SessionRecord, destinationID, idempotencyKey, requestHash string, expectedVersion int64) (NotificationTestJob, error) {
	if !validUUIDText(destinationID) || expectedVersion < 1 || !validMutationReceipt(idempotencyKey, requestHash) {
		return NotificationTestJob{}, ErrDestinationInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return NotificationTestJob{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NotificationTestJob{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return NotificationTestJob{}, err
	}
	if role != "admin" {
		return NotificationTestJob{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if job, found, err := readNotificationTestReceiptTx(ctx, tx, actor, idempotencyKey, requestHash, destinationID, now); err != nil {
		return NotificationTestJob{}, err
	} else if found {
		return job, nil
	}
	destination, err := readDestinationTx(ctx, tx, actor.DeploymentID, destinationID, false)
	if err != nil {
		return NotificationTestJob{}, err
	}
	if destination.Version != expectedVersion {
		return NotificationTestJob{}, ErrDestinationRevision
	}
	var secretRef string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(secret_ref,'') FROM destinations WHERE deployment_id=? AND id=? AND version=? AND disabled_ms IS NULL`, actor.DeploymentID, destinationID, expectedVersion).Scan(&secretRef); err != nil || secretRef == "" && destination.Config.NeedsSecret() || secretRef != "" && !validNotificationSecretRef(secretRef) {
		return NotificationTestJob{}, ErrDestinationInvalid
	}
	var actorActive, destinationActive int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE deployment_id=? AND actor_user_id=? AND type='destination_test' AND state IN ('queued','running')`, actor.DeploymentID, actor.User.ID).Scan(&actorActive); err != nil {
		return NotificationTestJob{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE deployment_id=? AND type='destination_test' AND state IN ('queued','running') AND json_extract(request_json,'$.destination_id')=?`, actor.DeploymentID, destinationID).Scan(&destinationActive); err != nil {
		return NotificationTestJob{}, err
	}
	if actorActive >= destinationTestActivePerActor || destinationActive != 0 {
		return NotificationTestJob{}, ErrDestinationTestBusy
	}
	jobID, err := domain.NewUUID()
	if err != nil {
		return NotificationTestJob{}, err
	}
	deliveryID, err := domain.NewUUID()
	if err != nil {
		return NotificationTestJob{}, err
	}
	expires := now + int64(24*time.Hour/time.Millisecond)
	requestJSON, _ := json.Marshal(map[string]any{"destination_id": destinationID, "destination_revision": expectedVersion, "delivery_id": deliveryID})
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id,deployment_id,deployment_generation,type,state,progress,request_json,actor_user_id,created_ms,updated_ms,expires_ms) VALUES(?,?,?,'destination_test','queued',0,?,?,?,?,?)`, jobID, actor.DeploymentID, actor.Generation, string(requestJSON), actor.User.ID, now, now, expires); err != nil {
		return NotificationTestJob{}, err
	}
	idempotencyKeyDelivery := "destination-test:" + jobID
	payloadJSON, _ := json.Marshal(map[string]any{
		"schema_version":  "notification-test-1",
		"event_id":        deliveryID,
		"idempotency_key": idempotencyKeyDelivery,
		"test":            true,
		"destination_id":  destinationID,
		"created_ms":      now,
	})
	if _, err := tx.ExecContext(ctx, `INSERT INTO outbox(id,deployment_id,instance_id,transition_seq,destination_id,destination_revision,destination_secret_ref,rule_revision,incident_generation,idempotency_key,payload_json,state,attempts,next_attempt_ms,expires_ms,created_ms,job_id) VALUES(?,?,NULL,NULL,?,?,?,?,1,?,?,'pending',0,?,?,?,?)`, deliveryID, actor.DeploymentID, destinationID, expectedVersion, nullableSecretRefValue(secretRef), nil, idempotencyKeyDelivery, string(payloadJSON), now, expires, now, jobID); err != nil {
		return NotificationTestJob{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE destinations SET last_test_job_id=?,updated_ms=? WHERE deployment_id=? AND id=? AND version=?`, jobID, now, actor.DeploymentID, destinationID, expectedVersion); err != nil {
		return NotificationTestJob{}, err
	}
	job := NotificationTestJob{ID: jobID, DestinationID: destinationID, DestinationRevision: expectedVersion, DeliveryID: deliveryID, State: "queued", CreatedMS: now, UpdatedMS: now, ExpiresMS: expires}
	if err := persistNotificationTestEnqueueTx(ctx, tx, actor, idempotencyKey, requestHash, job, now); err != nil {
		return NotificationTestJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return NotificationTestJob{}, err
	}
	return job, nil
}

func (s *Store) ReadDestinationTest(ctx context.Context, actor SessionRecord, jobID string) (NotificationTestJob, error) {
	if !validUUIDText(jobID) {
		return NotificationTestJob{}, ErrDestinationInvalid
	}
	if _, _, err := s.validateAPITokenActorRead(ctx, actor); err != nil {
		return NotificationTestJob{}, err
	}
	return readNotificationTestQuery(ctx, s.db, actor.DeploymentID, jobID)
}

func readNotificationTestQuery(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, deploymentID, jobID string) (NotificationTestJob, error) {
	var job NotificationTestJob
	var requestJSON string
	var errorCode sql.NullString
	var receiverACK sql.NullInt64
	err := query.QueryRowContext(ctx, `SELECT j.id,j.state,j.request_json,j.error_code,j.created_ms,j.updated_ms,j.expires_ms,o.receiver_ack_ms FROM jobs j LEFT JOIN outbox o ON o.deployment_id=j.deployment_id AND o.job_id=j.id WHERE j.deployment_id=? AND j.id=? AND j.type='destination_test'`, deploymentID, jobID).Scan(&job.ID, &job.State, &requestJSON, &errorCode, &job.CreatedMS, &job.UpdatedMS, &job.ExpiresMS, &receiverACK)
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationTestJob{}, ErrDeliveryNotFound
	}
	if err != nil {
		return NotificationTestJob{}, err
	}
	var request struct {
		DestinationID       string `json:"destination_id"`
		DestinationRevision int64  `json:"destination_revision"`
		DeliveryID          string `json:"delivery_id"`
	}
	if json.Unmarshal([]byte(requestJSON), &request) != nil || !validUUIDText(request.DestinationID) || !validUUIDText(request.DeliveryID) || request.DestinationRevision < 1 {
		return NotificationTestJob{}, ErrDeliveryInvalid
	}
	job.DestinationID, job.DestinationRevision, job.DeliveryID, job.ErrorCode, job.ReceiverACKMS = request.DestinationID, request.DestinationRevision, request.DeliveryID, nullableStringPointer(errorCode), nullableInt64Pointer(receiverACK)
	return job, nil
}

func completeDestinationTestJobTx(ctx context.Context, tx *sql.Tx, deploymentID, jobID, deliveryID string, succeeded bool, errorCode string, now int64) error {
	state, result, progress := "failed", "failed", 1.0
	var safeError any = errorCode
	if succeeded {
		state, result, safeError = "succeeded", "succeeded", nil
	}
	update, err := tx.ExecContext(ctx, `UPDATE jobs SET state=?,progress=?,error_code=?,lease_until_ms=NULL,updated_ms=? WHERE deployment_id=? AND id=? AND type='destination_test' AND state IN ('queued','running') AND json_extract(request_json,'$.delivery_id')=?`, state, progress, safeError, now, deploymentID, jobID, deliveryID)
	if err != nil {
		return err
	}
	if changed, _ := update.RowsAffected(); changed != 1 {
		return ErrDeliveryConflict
	}
	_, err = tx.ExecContext(ctx, `UPDATE destinations SET last_test_ms=?,last_test_result=?,updated_ms=? WHERE deployment_id=? AND id=json_extract((SELECT request_json FROM jobs WHERE deployment_id=? AND id=?),'$.destination_id') AND version=json_extract((SELECT request_json FROM jobs WHERE deployment_id=? AND id=?),'$.destination_revision')`, now, result, now, deploymentID, deploymentID, jobID, deploymentID, jobID)
	return err
}

func readNotificationTestReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash, destinationID string, now int64) (NotificationTestJob, bool, error) {
	var storedHash, encoded string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &encoded, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationTestJob{}, false, nil
	}
	if err != nil {
		return NotificationTestJob{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return NotificationTestJob{}, false, err
		}
		return NotificationTestJob{}, false, nil
	}
	var receipt notificationTestReceipt
	if storedHash != requestHash || json.Unmarshal([]byte(encoded), &receipt) != nil || receipt.Job.DestinationID != destinationID {
		return NotificationTestJob{}, false, ErrDestinationConflict
	}
	return receipt.Job, true, nil
}

func persistNotificationTestEnqueueTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, job NotificationTestJob, now int64) error {
	encoded, err := json.Marshal(notificationTestReceipt{Job: job})
	if err != nil || len(encoded) > 64<<10 {
		return ErrDestinationInvalid
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	detail, _ := json.Marshal(map[string]any{"destination_revision": job.DestinationRevision, "delivery_id": job.DeliveryID})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'notification.destination.test.enqueue',?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, job.DestinationID, now, string(detail)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,202,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, key, requestHash, string(encoded), now, now+int64(24*time.Hour/time.Millisecond))
	return err
}
