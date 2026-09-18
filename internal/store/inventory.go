package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

type TrustedOwnerContext struct {
	DeploymentID       string
	SecurityGeneration string
	InstallingUID      uint32
	VerifiedOSOwner    bool
}
type LocalHostRegistration struct {
	HostID, InstallationUUID, DisplayName, CollectorVersion string
	Capabilities                                            map[string]bool
}

func (s *Store) RegisterLocalHost(ctx context.Context, owner TrustedOwnerContext, request LocalHostRegistration) error {
	if !owner.VerifiedOSOwner || owner.DeploymentID == "" || owner.SecurityGeneration == "" || request.HostID == "" || request.InstallationUUID == "" || request.DisplayName == "" {
		return ErrOwnershipMismatch
	}
	capabilities, err := json.Marshal(request.Capabilities)
	if err != nil || len(capabilities) > 65536 {
		return errors.New("invalid host capabilities")
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var generation, recovery string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, owner.DeploymentID).Scan(&generation, &recovery); err != nil {
		return ownershipError(err)
	}
	if recovery != "normal" || generation != owner.SecurityGeneration {
		return ErrAdmissionFenced
	}
	now := s.clock.Now().UnixMilli()
	// Avoid INSERT ... ON CONFLICT here: the active-host BEFORE INSERT cap runs
	// before conflict resolution and would reject an idempotent refresh once a
	// deployment legitimately has two active hosts.
	res, err := tx.ExecContext(ctx, `UPDATE hosts SET display_name=?,collector_version=?,capabilities_json=?,updated_ms=? WHERE id=? AND deployment_id=? AND installation_uuid=? AND retired_ms IS NULL`, request.DisplayName, nullableText(request.CollectorVersion), string(capabilities), now, request.HostID, owner.DeploymentID, request.InstallationUUID)
	if err != nil {
		return fmt.Errorf("register local host: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		var existing int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE id=? OR (deployment_id=? AND installation_uuid=?)`, request.HostID, owner.DeploymentID, request.InstallationUUID).Scan(&existing); err != nil {
			return err
		}
		if existing != 0 {
			return ErrOwnershipMismatch
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO hosts(id,deployment_id,display_name,installation_uuid,current_session_generation,last_boot_id,collector_version,capabilities_json,retired_ms,created_ms,updated_ms) VALUES(?,?,?,?,0,NULL,?,?,NULL,?,?)`, request.HostID, owner.DeploymentID, request.DisplayName, request.InstallationUUID, nullableText(request.CollectorVersion), string(capabilities), now, now); err != nil {
			return fmt.Errorf("register local host: %w", err)
		}
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	detailJSON, _ := json.Marshal(struct {
		InstallingUID uint32 `json:"installing_uid"`
		Authority     string `json:"authority"`
	}{owner.InstallingUID, "verified_owner_socket"})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'collector.local_host.register',?,?,?)`, auditID, owner.DeploymentID, request.HostID, now, string(detailJSON)); err != nil {
		return err
	}
	return tx.Commit()
}

// ReEnrollLocalHost reactivates the exact same-user host retained by a
// trust-reset restore. It never creates a host or converts a remotely enrolled
// host into a local one.
func (s *Store) ReEnrollLocalHost(ctx context.Context, owner TrustedOwnerContext, request LocalHostRegistration, previousGeneration string) error {
	if !owner.VerifiedOSOwner || owner.DeploymentID == "" || owner.SecurityGeneration == "" || previousGeneration == "" || previousGeneration == owner.SecurityGeneration || !validUUIDText(request.HostID) || !validUUIDText(request.InstallationUUID) || request.DisplayName == "" {
		return ErrOwnershipMismatch
	}
	capabilities, err := json.Marshal(request.Capabilities)
	if err != nil || len(capabilities) > 65536 {
		return errors.New("invalid host capabilities")
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var generation, recovery, reason string
	if err := tx.QueryRowContext(ctx, `SELECT d.deployment_generation,d.recovery_state,g.reason FROM deployments d JOIN deployment_generations g ON g.deployment_id=d.id AND g.generation=d.deployment_generation WHERE d.id=?`, owner.DeploymentID).Scan(&generation, &recovery, &reason); err != nil {
		return ownershipError(err)
	}
	if recovery != "normal" || generation != owner.SecurityGeneration || reason != "restore_bootstrap" {
		return ErrAdmissionFenced
	}
	var previousKnown int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM deployment_generations WHERE deployment_id=? AND generation=? AND generation<>?`, owner.DeploymentID, previousGeneration, generation).Scan(&previousKnown); err != nil || previousKnown != 1 {
		return ErrReEnrollmentDenied
	}
	now := s.clock.Now().UnixMilli()
	var installation string
	var retired sql.NullInt64
	var currentSession int64
	var lastBoot sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT installation_uuid,retired_ms,current_session_generation,last_boot_id FROM hosts WHERE deployment_id=? AND id=?`, owner.DeploymentID, request.HostID).Scan(&installation, &retired, &currentSession, &lastBoot); err != nil || installation != request.InstallationUUID || currentSession != 0 || lastBoot.Valid {
		return ErrReEnrollmentDenied
	}
	var remoteEnrollments, liveSessions int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_enrollments WHERE deployment_id=? AND result_host_id=? AND consumed_ms IS NOT NULL`, owner.DeploymentID, request.HostID).Scan(&remoteEnrollments); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_sessions WHERE deployment_id=? AND host_id=? AND superseded_ms IS NULL`, owner.DeploymentID, request.HostID).Scan(&liveSessions); err != nil {
		return err
	}
	if remoteEnrollments != 0 || liveSessions != 0 {
		return ErrReEnrollmentDenied
	}
	if !retired.Valid {
		var prior int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit WHERE deployment_id=? AND action='collector.local_host.reenroll' AND resource_id=? AND json_extract(allowlisted_detail_json,'$.security_generation')=? AND json_extract(allowlisted_detail_json,'$.previous_generation')=?`, owner.DeploymentID, request.HostID, generation, previousGeneration).Scan(&prior); err != nil || prior != 1 {
			return ErrReEnrollmentDenied
		}
		return tx.Commit()
	}
	updated, err := tx.ExecContext(ctx, `UPDATE hosts SET display_name=?,collector_version=?,capabilities_json=?,retired_ms=NULL,current_session_generation=0,last_boot_id=NULL,updated_ms=? WHERE deployment_id=? AND id=? AND installation_uuid=? AND retired_ms IS NOT NULL`, request.DisplayName, nullableText(request.CollectorVersion), string(capabilities), now, owner.DeploymentID, request.HostID, request.InstallationUUID)
	if err != nil {
		return err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return ErrReEnrollmentDenied
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	detailJSON, _ := json.Marshal(struct {
		InstallingUID      uint32 `json:"installing_uid"`
		Authority          string `json:"authority"`
		PreviousGeneration string `json:"previous_generation"`
		SecurityGeneration string `json:"security_generation"`
	}{owner.InstallingUID, "verified_owner_socket", previousGeneration, generation})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'collector.local_host.reenroll',?,?,?)`, auditID, owner.DeploymentID, request.HostID, now, string(detailJSON)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RegisterCollectorInventory(ctx context.Context, inventory protocol.CollectorInventory) (protocol.InventoryResult, error) {
	if err := inventory.Validate(); err != nil {
		return protocol.InventoryResult{}, err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return protocol.InventoryResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.InventoryResult{}, err
	}
	defer tx.Rollback()
	current, err := validateCurrentSession(ctx, tx, inventory.DeploymentID, inventory.HostID, inventory.SecurityGeneration, inventory.SessionGeneration, inventory.CollectorBootID)
	if err != nil {
		return protocol.InventoryResult{}, err
	}
	now := s.clock.Now().UnixMilli()
	// Retire prior sources before admitting replacements. An endpoint edit is
	// represented by one inventory containing an inactive old source and an
	// active new source. SQLite INSERT triggers run before conflict resolution,
	// so admitting the replacement first can trip the two-passive-source cap.
	admitSource := func(source protocol.InventorySource) error {
		var retired any = now
		if source.Active {
			retired = nil
		}
		// Update known identities before considering an insert. SQLite BEFORE
		// INSERT cap triggers run before ON CONFLICT, so an upsert of an already
		// admitted host/runtime source can otherwise count itself and reject an
		// idempotent inventory refresh at the two-source limit.
		res, err := tx.ExecContext(ctx, `UPDATE sources SET retired_ms=?,updated_ms=? WHERE id=? AND deployment_id=? AND host_id=? AND kind=? AND target_id IS ? AND admitted_capability_revision=?`, retired, now, source.SourceID, inventory.DeploymentID, inventory.HostID, source.Kind, source.TargetID, source.CapabilityRevision)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			var existing int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sources WHERE id=?`, source.SourceID).Scan(&existing); err != nil {
				return err
			}
			if existing != 0 {
				return ErrOwnershipMismatch
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO sources(id,deployment_id,host_id,kind,target_id,admitted_capability_revision,retired_ms,created_ms,updated_ms) VALUES(?,?,?,?,?,?,?,?,?)`, source.SourceID, inventory.DeploymentID, inventory.HostID, source.Kind, source.TargetID, source.CapabilityRevision, retired, now, now); err != nil {
				return err
			}
		}
		return nil
	}
	for _, source := range inventory.Sources {
		if source.Active {
			continue
		}
		known, err := validateRetirementIdentity(ctx, tx, inventory, source)
		if err != nil {
			return protocol.InventoryResult{}, err
		}
		if !known {
			// A locally persisted possibly-sent identity whose original inventory
			// never committed is an idempotent retirement no-op. Never create it.
			continue
		}
		if err := admitSource(source); err != nil {
			return protocol.InventoryResult{}, err
		}
	}
	// An explicitly inactive target-bound source authorizes retirement of its
	// already-owned target once no active source still refers to it. History is
	// retained under the immutable target/source identities.
	for _, source := range inventory.Sources {
		if source.Active || source.TargetID == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE targets SET retired_ms=?,updated_ms=? WHERE deployment_id=? AND host_id=? AND id=? AND retired_ms IS NULL AND NOT EXISTS (SELECT 1 FROM sources WHERE deployment_id=? AND host_id=? AND target_id=? AND retired_ms IS NULL)`, now, now, inventory.DeploymentID, inventory.HostID, *source.TargetID, inventory.DeploymentID, inventory.HostID, *source.TargetID); err != nil {
			return protocol.InventoryResult{}, err
		}
	}
	for _, target := range inventory.Targets {
		res, err := tx.ExecContext(ctx, `INSERT INTO targets(id,deployment_id,host_id,adapter_id,local_selector_hash,display_name,endpoint_alias,retired_ms,created_ms,updated_ms) VALUES(?,?,?,?,?,'Ollama target','Configured local endpoint',NULL,?,?) ON CONFLICT(id) DO UPDATE SET retired_ms=NULL,updated_ms=excluded.updated_ms WHERE targets.deployment_id=excluded.deployment_id AND targets.host_id=excluded.host_id AND targets.local_selector_hash=excluded.local_selector_hash`, target.TargetID, inventory.DeploymentID, inventory.HostID, target.AdapterID, target.LocalSelectorSHA256, now, now)
		if err != nil {
			return protocol.InventoryResult{}, err
		}
		if rows, _ := res.RowsAffected(); rows != 1 {
			return protocol.InventoryResult{}, ErrOwnershipMismatch
		}
	}
	for _, source := range inventory.Sources {
		if !source.Active {
			continue
		}
		if err := admitSource(source); err != nil {
			return protocol.InventoryResult{}, err
		}
	}
	for _, model := range inventory.Models {
		configHash := inventoryModelConfigHash(model)
		res, err := tx.ExecContext(ctx, `INSERT INTO model_revisions(id,deployment_id,host_id,target_id,served_alias,digest,format,family,quantization,context_length,config_hash,created_ms) VALUES(?,?,?,?,?,?,NULL,NULL,NULL,NULL,?,?) ON CONFLICT(id) DO NOTHING`, model.ModelID, inventory.DeploymentID, inventory.HostID, model.TargetID, model.Alias, model.Digest, configHash, now)
		if err != nil {
			return protocol.InventoryResult{}, err
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			var alias string
			var digest sql.NullString
			if err := tx.QueryRowContext(ctx, `SELECT served_alias,digest FROM model_revisions WHERE deployment_id=? AND host_id=? AND target_id=? AND id=?`, inventory.DeploymentID, inventory.HostID, model.TargetID, model.ModelID).Scan(&alias, &digest); err != nil || alias != model.Alias || nullableEqual(digest, model.Digest) == false {
				return protocol.InventoryResult{}, ErrOwnershipMismatch
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return protocol.InventoryResult{}, err
	}
	return protocol.InventoryResult{InventoryRevision: inventory.InventoryRevision, Durable: true, Current: current, HubTimeMS: now, ControlRequests: []protocol.ControlRequest{}}, nil
}

func validateRetirementIdentity(ctx context.Context, tx *sql.Tx, inventory protocol.CollectorInventory, source protocol.InventorySource) (bool, error) {
	var deploymentID, hostID, kind string
	var targetID sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT deployment_id,host_id,kind,target_id FROM sources WHERE id=?`, source.SourceID).Scan(&deploymentID, &hostID, &kind, &targetID)
	if err == nil {
		if deploymentID != inventory.DeploymentID || hostID != inventory.HostID || kind != source.Kind || !nullableEqual(targetID, source.TargetID) {
			return false, ErrOwnershipMismatch
		}
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if source.TargetID == nil {
		return false, nil
	}
	var targetDeployment, targetHost string
	err = tx.QueryRowContext(ctx, `SELECT deployment_id,host_id FROM targets WHERE id=?`, *source.TargetID).Scan(&targetDeployment, &targetHost)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if targetDeployment != inventory.DeploymentID || targetHost != inventory.HostID {
		return false, ErrOwnershipMismatch
	}
	// The target exists but this source was never admitted. Preserve the target
	// and do not invent a historical source record during retirement.
	return false, nil
}

func validateCurrentSession(ctx context.Context, tx *sql.Tx, deploymentID, hostID, security string, session int64, boot string) (bool, error) {
	var recovery, generation string
	var current int64
	var currentBoot sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT d.recovery_state,d.deployment_generation,h.current_session_generation,h.last_boot_id FROM deployments d JOIN hosts h ON h.deployment_id=d.id WHERE d.id=? AND h.id=? AND h.retired_ms IS NULL`, deploymentID, hostID).Scan(&recovery, &generation, &current, &currentBoot)
	if err != nil {
		return false, ownershipError(err)
	}
	if recovery != "normal" || generation != security {
		return false, ErrAdmissionFenced
	}
	if current != session || !currentBoot.Valid || currentBoot.String != boot {
		return false, ErrGenerationConflict
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_sessions WHERE deployment_id=? AND host_id=? AND security_generation=? AND session_generation=? AND collector_boot_id=? AND superseded_ms IS NULL`, deploymentID, hostID, security, session, boot).Scan(&exists); err != nil || exists != 1 {
		return false, ErrGenerationConflict
	}
	return true, nil
}
func inventoryModelConfigHash(model protocol.InventoryModel) string {
	value, _ := json.Marshal(struct {
		Alias  string  `json:"alias"`
		Digest *string `json:"digest"`
	}{model.Alias, model.Digest})
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func nullableEqual(existing sql.NullString, want *string) bool {
	if want == nil {
		return !existing.Valid
	}
	return existing.Valid && existing.String == *want
}
