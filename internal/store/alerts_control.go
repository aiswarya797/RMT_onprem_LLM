package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
)

const alertMuteMaximum = 24 * time.Hour

type AlertControlResult struct {
	AlertState                AlertIncidentState `json:"alert_state"`
	NotificationMayBeInFlight bool               `json:"notification_may_be_in_flight"`
}

type alertControlReceipt struct {
	Action string             `json:"action"`
	Result AlertControlResult `json:"result"`
}

func (s *Store) AcknowledgeAlertIncident(ctx context.Context, actor SessionRecord, incidentID, idempotencyKey, requestHash string, observedTransitionSeq int64) (AlertControlResult, error) {
	if !validUUIDText(incidentID) || observedTransitionSeq < 1 || !validMutationReceipt(idempotencyKey, requestHash) {
		return AlertControlResult{}, ErrAlertInvalid
	}
	return s.mutateAlertControl(ctx, actor, incidentID, idempotencyKey, requestHash, "alert.acknowledge", nil, func(ctx context.Context, tx *sql.Tx, state AlertIncidentState, now int64) (bool, error) {
		if state.TransitionSeq != observedTransitionSeq || state.AcknowledgedMS != nil {
			return false, ErrAlertCursorConflict
		}
		result, err := tx.ExecContext(ctx, `UPDATE alert_instances SET acknowledged_by=?,acknowledged_ms=? WHERE deployment_id=? AND id=? AND transition_seq=? AND acknowledged_ms IS NULL`, actor.User.ID, now, actor.DeploymentID, state.InstanceID, observedTransitionSeq)
		if err != nil {
			return false, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return false, ErrAlertCursorConflict
		}
		return alertNotificationInFlightTx(ctx, tx, actor.DeploymentID, state.InstanceID)
	})
}

func (s *Store) MuteAlertIncident(ctx context.Context, actor SessionRecord, incidentID, idempotencyKey, requestHash, reason string, expiresMS int64) (AlertControlResult, error) {
	if !validUUIDText(incidentID) || !validMutationReceipt(idempotencyKey, requestHash) || !safeRuleString(reason, 256) {
		return AlertControlResult{}, ErrAlertInvalid
	}
	return s.mutateAlertControl(ctx, actor, incidentID, idempotencyKey, requestHash, "alert.mute", &reason, func(ctx context.Context, tx *sql.Tx, state AlertIncidentState, now int64) (bool, error) {
		if expiresMS <= now || expiresMS > now+alertMuteMaximum.Milliseconds() || state.Condition == alerts.StateResolved || state.Condition == alerts.StateSuperseded {
			return false, ErrAlertInvalid
		}
		if _, err := tx.ExecContext(ctx, `UPDATE alert_instances SET muted_until_ms=? WHERE deployment_id=? AND id=?`, expiresMS, actor.DeploymentID, state.InstanceID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='muted',next_attempt_ms=NULL,last_error_code='operator_muted' WHERE deployment_id=? AND instance_id=? AND state IN ('pending','failed')`, actor.DeploymentID, state.InstanceID); err != nil {
			return false, err
		}
		return alertNotificationInFlightTx(ctx, tx, actor.DeploymentID, state.InstanceID)
	})
}

func (s *Store) UnmuteAlertIncident(ctx context.Context, actor SessionRecord, incidentID, idempotencyKey, requestHash string) (AlertControlResult, error) {
	if !validUUIDText(incidentID) || !validMutationReceipt(idempotencyKey, requestHash) {
		return AlertControlResult{}, ErrAlertInvalid
	}
	return s.mutateAlertControl(ctx, actor, incidentID, idempotencyKey, requestHash, "alert.unmute", nil, func(ctx context.Context, tx *sql.Tx, state AlertIncidentState, now int64) (bool, error) {
		if state.MutedUntilMS == nil {
			return false, ErrAlertCursorConflict
		}
		inFlight, err := alertNotificationInFlightTx(ctx, tx, actor.DeploymentID, state.InstanceID)
		if err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE alert_instances SET muted_until_ms=NULL WHERE deployment_id=? AND id=?`, actor.DeploymentID, state.InstanceID); err != nil {
			return false, err
		}
		if state.Condition == alerts.StateResolved || state.Condition == alerts.StateSuperseded {
			if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='superseded_before_delivery',next_attempt_ms=NULL,last_error_code='alert_terminal' WHERE deployment_id=? AND instance_id=? AND state='muted'`, actor.DeploymentID, state.InstanceID); err != nil {
				return false, err
			}
			return inFlight, nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='superseded_before_delivery',last_error_code='newer_alert_state' WHERE deployment_id=? AND instance_id=? AND state='muted' AND (transition_seq!=? OR NOT EXISTS (SELECT 1 FROM destinations d WHERE d.deployment_id=outbox.deployment_id AND d.id=outbox.destination_id AND d.version=outbox.destination_revision AND d.disabled_ms IS NULL))`, actor.DeploymentID, state.InstanceID, state.TransitionSeq); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE outbox SET state='pending',next_attempt_ms=?,last_error_code=NULL WHERE deployment_id=? AND instance_id=? AND transition_seq=? AND state='muted'`, now, actor.DeploymentID, state.InstanceID, state.TransitionSeq); err != nil {
			return false, err
		}
		if state.Condition == alerts.StateFiring || state.Condition == alerts.StateRecovering {
			if err := createAlertCurrentSummaryTx(ctx, tx, actor.DeploymentID, state, idempotencyKey, now); err != nil {
				return false, err
			}
		}
		return inFlight, nil
	})
}

type alertControlMutation func(context.Context, *sql.Tx, AlertIncidentState, int64) (bool, error)

func (s *Store) mutateAlertControl(ctx context.Context, actor SessionRecord, incidentID, idempotencyKey, requestHash, action string, auditReason *string, mutation alertControlMutation) (AlertControlResult, error) {
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return AlertControlResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertControlResult{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return AlertControlResult{}, err
	}
	if role != "admin" {
		return AlertControlResult{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if result, found, err := readAlertControlReceiptTx(ctx, tx, actor, incidentID, idempotencyKey, requestHash, action, now); err != nil {
		return AlertControlResult{}, err
	} else if found {
		return result, nil
	}
	state, err := readAlertIncidentStateTx(ctx, tx, actor.DeploymentID, incidentID)
	if err != nil {
		return AlertControlResult{}, err
	}
	// The measured 16-destination resolution envelope is a conservative bound
	// for one control mutation, receipt, audit row and any current-state summary.
	if err := admitAlertEnvelopeTx(ctx, tx, actor.DeploymentID, alertEnvelopeResolution, now); err != nil {
		return AlertControlResult{}, err
	}
	inFlight, err := mutation(ctx, tx, state, now)
	if err != nil {
		return AlertControlResult{}, err
	}
	updated, err := readAlertIncidentStateTx(ctx, tx, actor.DeploymentID, incidentID)
	if err != nil {
		return AlertControlResult{}, err
	}
	result := AlertControlResult{AlertState: updated, NotificationMayBeInFlight: inFlight}
	if err := persistAlertControlReceiptTx(ctx, tx, actor, incidentID, idempotencyKey, requestHash, action, auditReason, result, now); err != nil {
		return AlertControlResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return AlertControlResult{}, err
	}
	return result, nil
}

func readAlertControlReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, incidentID, key, requestHash, action string, now int64) (AlertControlResult, bool, error) {
	var storedHash, encoded string
	var expiresMS int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &encoded, &expiresMS)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertControlResult{}, false, nil
	}
	if err != nil {
		return AlertControlResult{}, false, err
	}
	if expiresMS <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return AlertControlResult{}, false, err
		}
		return AlertControlResult{}, false, nil
	}
	var receipt alertControlReceipt
	if storedHash != requestHash || json.Unmarshal([]byte(encoded), &receipt) != nil || receipt.Action != action || receipt.Result.AlertState.IncidentID != incidentID {
		return AlertControlResult{}, false, ErrAlertCursorConflict
	}
	return receipt.Result, true, nil
}

func persistAlertControlReceiptTx(ctx context.Context, tx *sql.Tx, actor SessionRecord, incidentID, key, requestHash, action string, auditReason *string, result AlertControlResult, now int64) error {
	receipt, err := json.Marshal(alertControlReceipt{Action: action, Result: result})
	if err != nil || len(receipt) > 64<<10 {
		return ErrAlertInvalid
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	detail, _ := json.Marshal(struct {
		TransitionSeq int64   `json:"transition_seq"`
		MutedUntilMS  *int64  `json:"muted_until_ms"`
		Reason        *string `json:"reason"`
	}{result.AlertState.TransitionSeq, result.AlertState.MutedUntilMS, auditReason})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,?,?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, action, incidentID, now, string(detail)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, key, requestHash, string(receipt), now, now+int64(24*time.Hour/time.Millisecond))
	return err
}

func alertNotificationInFlightTx(ctx context.Context, tx *sql.Tx, deploymentID, instanceID string) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE deployment_id=? AND instance_id=? AND state='leased'`, deploymentID, instanceID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func createAlertCurrentSummaryTx(ctx context.Context, tx *sql.Tx, deploymentID string, state AlertIncidentState, controlKey string, now int64) error {
	var eventMS int64
	var evidenceHash string
	if err := tx.QueryRowContext(ctx, `SELECT event_ms,evidence_hash FROM alert_transitions WHERE deployment_id=? AND instance_id=? AND transition_seq=?`, deploymentID, state.InstanceID, state.TransitionSeq).Scan(&eventMS, &evidenceHash); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,version,COALESCE(secret_ref,'') FROM destinations WHERE deployment_id=? AND disabled_ms IS NULL ORDER BY id LIMIT ?`, deploymentID, alertDestinationLimit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	destinations := []alertDestination{}
	for rows.Next() {
		var destination alertDestination
		if err := rows.Scan(&destination.ID, &destination.Revision, &destination.SecretRef); err != nil {
			return err
		}
		destinations = append(destinations, destination)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(destinations) > alertDestinationLimit {
		return ErrAlertDestinationLimit
	}
	for _, destination := range destinations {
		var existing int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE deployment_id=? AND instance_id=? AND transition_seq=? AND destination_id=? AND destination_revision=? AND state IN ('pending','leased','muted')`, deploymentID, state.InstanceID, state.TransitionSeq, destination.ID, destination.Revision).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			continue
		}
		idempotencyKey := "alert-summary:" + sha256Hex([]byte(controlKey+"/"+state.InstanceID+"/"+destination.ID))
		if err := insertAlertOutboxIntentTx(ctx, tx, deploymentID, state.RuleID, state.RuleVersion, state.InstanceID, state.IncidentID, destination, state.TransitionSeq, state.ActiveGeneration, state.Condition, state.DataState, eventMS, now, evidenceHash, idempotencyKey, "pending"); err != nil {
			return err
		}
	}
	return nil
}
