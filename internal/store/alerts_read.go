package store

import (
	"context"
	"database/sql"
	"errors"

	"rmt.local/monitor/internal/alerts"
)

type AlertDeliveryAggregate struct {
	Total                    int `json:"total"`
	Pending                  int `json:"pending"`
	Leased                   int `json:"leased"`
	Sent                     int `json:"sent"`
	Failed                   int `json:"failed"`
	Expired                  int `json:"expired"`
	SupersededBeforeDelivery int `json:"superseded_before_delivery"`
	Muted                    int `json:"muted"`
}

type AlertDeliveryStatus struct {
	ID                  string  `json:"id"`
	DestinationID       string  `json:"destination_id"`
	DestinationRevision int64   `json:"destination_revision"`
	State               string  `json:"state"`
	Status              string  `json:"status"`
	Attempts            int     `json:"attempts"`
	NextAttemptMS       *int64  `json:"next_attempt_ms"`
	SafeErrorCode       *string `json:"safe_error_code"`
	ReceiverACKMS       *int64  `json:"receiver_ack_ms"`
	AcceptedUnknown     bool    `json:"accepted_unknown"`
}

type AlertIncidentState struct {
	IncidentID       string                 `json:"incident_id"`
	InstanceID       string                 `json:"instance_id"`
	RuleID           string                 `json:"rule_id"`
	RuleVersion      int64                  `json:"rule_version"`
	Condition        alerts.State           `json:"condition"`
	DataState        alerts.DataState       `json:"data_state"`
	AcknowledgedBy   *string                `json:"acknowledged_by"`
	AcknowledgedMS   *int64                 `json:"acknowledged_ms"`
	MutedUntilMS     *int64                 `json:"muted_until_ms"`
	Delivery         AlertDeliveryAggregate `json:"delivery"`
	Deliveries       []AlertDeliveryStatus  `json:"deliveries"`
	TransitionSeq    int64                  `json:"transition_seq"`
	ActiveGeneration int64                  `json:"active_generation"`
}

// ReadAlertIncidentState exposes the mutable alert condition and delivery
// state separately from the immutable trigger capsule. Authorization belongs
// to the authenticated HTTP adapter; this store boundary remains deployment
// scoped and never accepts an alert instance without its incident join.
func (s *Store) ReadAlertIncidentState(ctx context.Context, deploymentID, incidentID string) (AlertIncidentState, error) {
	if !validUUIDText(deploymentID) || !validUUIDText(incidentID) {
		return AlertIncidentState{}, ErrIncidentNotFound
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AlertIncidentState{}, err
	}
	defer tx.Rollback()
	result, err := readAlertIncidentStateTx(ctx, tx, deploymentID, incidentID)
	if err != nil {
		return AlertIncidentState{}, err
	}
	if err := tx.Commit(); err != nil {
		return AlertIncidentState{}, err
	}
	return result, nil
}

func readAlertIncidentStateTx(ctx context.Context, tx *sql.Tx, deploymentID, incidentID string) (AlertIncidentState, error) {
	var result AlertIncidentState
	var acknowledgedBy sql.NullString
	var acknowledgedMS, mutedUntilMS sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT i.id,a.id,a.rule_id,a.rule_version,a.state,a.data_state,a.acknowledged_by,a.acknowledged_ms,a.muted_until_ms,a.transition_seq,a.active_generation FROM incidents i JOIN alert_instances a ON a.deployment_id=i.deployment_id AND a.id=i.alert_instance_id WHERE i.deployment_id=? AND i.id=? AND i.origin='alert'`, deploymentID, incidentID).Scan(&result.IncidentID, &result.InstanceID, &result.RuleID, &result.RuleVersion, &result.Condition, &result.DataState, &acknowledgedBy, &acknowledgedMS, &mutedUntilMS, &result.TransitionSeq, &result.ActiveGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return AlertIncidentState{}, ErrIncidentNotFound
	}
	if err != nil {
		return AlertIncidentState{}, err
	}
	result.AcknowledgedBy = nullableStringPointer(acknowledgedBy)
	result.AcknowledgedMS = nullableInt64Pointer(acknowledgedMS)
	result.MutedUntilMS = nullableInt64Pointer(mutedUntilMS)
	result.Deliveries = []AlertDeliveryStatus{}
	if err := tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(state='pending'),0),COALESCE(sum(state='leased'),0),COALESCE(sum(state='sent'),0),COALESCE(sum(state='failed'),0),COALESCE(sum(state='expired'),0),COALESCE(sum(state='superseded_before_delivery'),0),COALESCE(sum(state='muted'),0) FROM outbox WHERE deployment_id=? AND instance_id=?`, deploymentID, result.InstanceID).Scan(&result.Delivery.Total, &result.Delivery.Pending, &result.Delivery.Leased, &result.Delivery.Sent, &result.Delivery.Failed, &result.Delivery.Expired, &result.Delivery.SupersededBeforeDelivery, &result.Delivery.Muted); err != nil {
		return AlertIncidentState{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM outbox WHERE deployment_id=? AND instance_id=? ORDER BY created_ms DESC,id DESC LIMIT ?`, deploymentID, result.InstanceID, deliveryListMaximum)
	if err != nil {
		return AlertIncidentState{}, err
	}
	deliveryIDs := make([]string, 0, deliveryListMaximum)
	for rows.Next() {
		var deliveryID string
		if err := rows.Scan(&deliveryID); err != nil {
			rows.Close()
			return AlertIncidentState{}, err
		}
		deliveryIDs = append(deliveryIDs, deliveryID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return AlertIncidentState{}, err
	}
	if err := rows.Close(); err != nil {
		return AlertIncidentState{}, err
	}
	for _, deliveryID := range deliveryIDs {
		delivery, err := readDeliveryTx(ctx, tx, deploymentID, deliveryID)
		if err != nil {
			return AlertIncidentState{}, err
		}
		result.Deliveries = append(result.Deliveries, AlertDeliveryStatus{
			ID: delivery.ID, DestinationID: delivery.DestinationID, DestinationRevision: delivery.DestinationRevision,
			State: delivery.State, Status: delivery.Status, Attempts: delivery.Attempts, NextAttemptMS: delivery.NextAttemptMS,
			SafeErrorCode: delivery.LastErrorCode, ReceiverACKMS: delivery.ReceiverACKMS, AcceptedUnknown: delivery.AcceptedUnknown,
		})
	}
	return result, nil
}
