package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"rmt.local/monitor/internal/protocol"
)

var (
	ErrWriterBackpressure = errors.New("bounded writer queue full")
	ErrAdmissionFenced    = errors.New("collector admission fenced")
	ErrOwnershipMismatch  = errors.New("collector ownership mismatch")
	ErrGenerationConflict = errors.New("collector generation conflict")
)

func (s *Store) acquireWrite(ctx context.Context) (func(), error) {
	select {
	case s.writes <- struct{}{}:
		return func() { <-s.writes }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrWriterBackpressure
	}
}

func (s *Store) ActivateCollectorSession(ctx context.Context, request protocol.SessionActivation) (protocol.SessionResult, error) {
	if err := request.Validate(); err != nil {
		return protocol.SessionResult{}, err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return protocol.SessionResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.SessionResult{}, err
	}
	defer tx.Rollback()

	var generation, recovery string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, request.DeploymentID).Scan(&generation, &recovery); err != nil {
		return protocol.SessionResult{}, ownershipError(err)
	}
	if recovery != "normal" || generation != request.SecurityGeneration {
		return protocol.SessionResult{}, ErrAdmissionFenced
	}
	var retired sql.NullInt64
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT retired_ms,current_session_generation FROM hosts WHERE deployment_id=? AND id=?`, request.DeploymentID, request.HostID).Scan(&retired, &current); err != nil {
		return protocol.SessionResult{}, ownershipError(err)
	}
	if retired.Valid {
		return protocol.SessionResult{}, ErrAdmissionFenced
	}

	var existing protocol.SessionResult
	var existingJSON string
	var existingPredecessor int64
	err = tx.QueryRowContext(ctx, `SELECT activation_result_json,predecessor_generation FROM collector_sessions WHERE deployment_id=? AND host_id=? AND activation_request_id=?`, request.DeploymentID, request.HostID, request.ActivationRequestID).Scan(&existingJSON, &existingPredecessor)
	if err == nil {
		if json.Unmarshal([]byte(existingJSON), &existing) != nil || existing.CollectorBootID != request.CollectorBootID || existing.SecurityGeneration != request.SecurityGeneration || existingPredecessor != request.ExpectedPreviousGeneration || existing.SessionGeneration != current {
			return protocol.SessionResult{}, ErrGenerationConflict
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return protocol.SessionResult{}, err
	}
	if current != request.ExpectedPreviousGeneration {
		return protocol.SessionResult{}, ErrGenerationConflict
	}
	// Restore deliberately resets the host's current-session pointer to zero,
	// but retained historical sessions keep their immutable generation numbers.
	// Allocate above that retained high-water mark while the CAS still compares
	// the collector's expected predecessor with the current host pointer.
	var highest int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(session_generation),0) FROM collector_sessions WHERE deployment_id=? AND host_id=?`, request.DeploymentID, request.HostID).Scan(&highest); err != nil {
		return protocol.SessionResult{}, err
	}
	if highest >= protocol.MaxUint53 {
		return protocol.SessionResult{}, ErrGenerationConflict
	}
	now := s.clock.Now().UnixMilli()
	next := highest + 1
	result := protocol.NewSessionResult(request, next, now)
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return protocol.SessionResult{}, err
	}
	if current > 0 {
		res, err := tx.ExecContext(ctx, `UPDATE collector_sessions SET superseded_ms=? WHERE deployment_id=? AND host_id=? AND session_generation=? AND superseded_ms IS NULL`, now, request.DeploymentID, request.HostID, current)
		if err != nil {
			return protocol.SessionResult{}, err
		}
		if rows, _ := res.RowsAffected(); rows != 1 {
			return protocol.SessionResult{}, ErrGenerationConflict
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO collector_sessions(deployment_id,host_id,session_generation,security_generation,activation_request_id,collector_boot_id,predecessor_generation,activated_ms,superseded_ms,activation_result_json) VALUES(?,?,?,?,?,?,?,?,NULL,?)`, request.DeploymentID, request.HostID, next, request.SecurityGeneration, request.ActivationRequestID, request.CollectorBootID, current, now, string(resultJSON))
	if err != nil {
		return protocol.SessionResult{}, fmt.Errorf("insert collector session: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE hosts SET current_session_generation=?,last_boot_id=?,updated_ms=? WHERE deployment_id=? AND id=? AND current_session_generation=?`, next, request.CollectorBootID, now, request.DeploymentID, request.HostID, current)
	if err != nil {
		return protocol.SessionResult{}, err
	}
	if rows, _ := res.RowsAffected(); rows != 1 {
		return protocol.SessionResult{}, ErrGenerationConflict
	}
	if err := tx.Commit(); err != nil {
		return protocol.SessionResult{}, err
	}
	return result, nil
}

func ownershipError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrOwnershipMismatch
	}
	return err
}
