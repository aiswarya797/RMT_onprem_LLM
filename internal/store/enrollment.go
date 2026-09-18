package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
)

var (
	ErrEnrollmentUnavailable   = errors.New("collector enrollment unavailable")
	ErrEnrollmentExpired       = errors.New("collector enrollment expired")
	ErrEnrollmentConsumed      = errors.New("collector enrollment consumed")
	ErrEnrollmentConflict      = errors.New("collector enrollment request conflict")
	ErrReEnrollmentDenied      = errors.New("collector re-enrollment is not allowed")
	ErrHostLimit               = errors.New("two-host limit reached")
	ErrCredentialRevoked       = errors.New("collector credential revoked")
	ErrCredentialRenewalNotDue = errors.New("collector credential renewal not due")
	sha256HexPattern           = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type EnrollmentReservation struct {
	TokenHash              string
	DeploymentID           string
	SecurityGeneration     string
	ReservedHostID         string
	CreatedBy              string
	HostDisplayName        string
	HubURL                 string
	HubCAFingerprintSHA256 string
	CreatedMS              int64
	ExpiresMS              int64
	ReEnrollment           bool
	RetainedInstallationID string
}

type EnrollmentToken struct {
	HostID                 string `json:"host_id"`
	Token                  string `json:"token"`
	ExpiresMS              int64  `json:"expires_ms"`
	HubURL                 string `json:"hub_url"`
	HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
}

type EnrollmentStatus struct {
	SchemaVersion string `json:"schema_version"`
	HostID        string `json:"host_id"`
	DisplayName   string `json:"display_name"`
	State         string `json:"state"`
	CreatedMS     int64  `json:"created_ms"`
	ExpiresMS     int64  `json:"expires_ms"`
	ConnectedMS   *int64 `json:"connected_ms,omitempty"`
}

type enrollmentIssueReceipt struct {
	HostID                 string `json:"host_id"`
	TokenHash              string `json:"token_hash"`
	ExpiresMS              int64  `json:"expires_ms"`
	HubURL                 string `json:"hub_url"`
	HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
	ReEnrollment           bool   `json:"re_enrollment"`
}

// IssueCollectorEnrollment atomically reserves a host slot and persists the
// 24-hour API idempotency receipt. The short-lived token is returned only in
// this result (and an exact receipt retry); audit records retain its hash.
func (s *Store) IssueCollectorEnrollment(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash, token, displayName, hubURL, hubCAFingerprint string, replacementHostIDs ...string) (EnrollmentToken, error) {
	displayName = strings.TrimSpace(displayName)
	tokenHash := enrollment.HashToken(token)
	if len(replacementHostIDs) > 1 {
		return EnrollmentToken{}, ErrEnrollmentConflict
	}
	replacementHostID := ""
	if len(replacementHostIDs) == 1 {
		replacementHostID = replacementHostIDs[0]
	}
	if actor.User.Role != "admin" || actor.User.Disabled || actor.User.HistoricalRestored || actor.DeploymentID == "" || actor.Generation == "" || actor.User.ID == "" || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !sha256HexPattern.MatchString(requestHash) || len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, " \t\r\n") || len(displayName) < 1 || len(displayName) > 128 || len(hubURL) < 1 || len(hubURL) > 2048 || !sha256HexPattern.MatchString(hubCAFingerprint) || (replacementHostID != "" && !validUUIDText(replacementHostID)) {
		return EnrollmentToken{}, ErrEnrollmentConflict
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return EnrollmentToken{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EnrollmentToken{}, err
	}
	defer tx.Rollback()
	now := s.clock.Now().UnixMilli()
	var generation, recovery string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, actor.DeploymentID).Scan(&generation, &recovery); err != nil {
		return EnrollmentToken{}, ownershipError(err)
	}
	if recovery != "normal" || generation != actor.Generation || actor.User.TrustGeneration != generation {
		return EnrollmentToken{}, ErrAdmissionFenced
	}
	var role string
	var disabled, historical int
	if err := tx.QueryRowContext(ctx, `SELECT role,disabled,historical_restored FROM users WHERE deployment_id=? AND id=? AND trust_generation=?`, actor.DeploymentID, actor.User.ID, generation).Scan(&role, &disabled, &historical); err != nil || role != "admin" || disabled != 0 || historical != 0 {
		return EnrollmentToken{}, ErrOwnershipMismatch
	}
	var storedHash, storedJSON string
	var receiptExpires int64
	receiptErr := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, generation, actor.User.ID, idempotencyKey).Scan(&storedHash, &storedJSON, &receiptExpires)
	if receiptErr == nil && now < receiptExpires {
		if storedHash != requestHash {
			return EnrollmentToken{}, ErrEnrollmentConflict
		}
		var receipt enrollmentIssueReceipt
		if err := json.Unmarshal([]byte(storedJSON), &receipt); err != nil {
			return EnrollmentToken{}, fmt.Errorf("decode enrollment issue receipt: %w", err)
		}
		if receipt.TokenHash != tokenHash || receipt.ReEnrollment != (replacementHostID != "") || (replacementHostID != "" && receipt.HostID != replacementHostID) {
			return EnrollmentToken{}, ErrEnrollmentConflict
		}
		return EnrollmentToken{HostID: receipt.HostID, Token: token, ExpiresMS: receipt.ExpiresMS, HubURL: receipt.HubURL, HubCAFingerprintSHA256: receipt.HubCAFingerprintSHA256}, nil
	}
	if receiptErr == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=? AND expires_ms<=?`, actor.DeploymentID, generation, actor.User.ID, idempotencyKey, now); err != nil {
			return EnrollmentToken{}, err
		}
	} else if !errors.Is(receiptErr, sql.ErrNoRows) {
		return EnrollmentToken{}, receiptErr
	}
	var activeHosts, activeReservations int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE deployment_id=? AND retired_ms IS NULL`, actor.DeploymentID).Scan(&activeHosts); err != nil {
		return EnrollmentToken{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_enrollments WHERE deployment_id=? AND deployment_generation=? AND consumed_ms IS NULL AND expires_ms>?`, actor.DeploymentID, generation, now).Scan(&activeReservations); err != nil {
		return EnrollmentToken{}, err
	}
	if activeHosts+activeReservations >= 2 {
		return EnrollmentToken{}, ErrHostLimit
	}
	hostID := replacementHostID
	reEnrollment := hostID != ""
	retainedInstallationID := ""
	if reEnrollment {
		if err := validateRetainedHostForReEnrollment(ctx, tx, actor.DeploymentID, generation, hostID, now, &retainedInstallationID); err != nil {
			return EnrollmentToken{}, err
		}
	} else {
		var err error
		hostID, err = domain.NewUUID()
		if err != nil {
			return EnrollmentToken{}, err
		}
	}
	expires := now + int64(enrollment.TokenValidity/time.Millisecond)
	if _, err := tx.ExecContext(ctx, `INSERT INTO collector_enrollments(token_hash,deployment_id,deployment_generation,reserved_host_id,created_by,created_ms,expires_ms,consumed_ms,result_host_id,result_cert_fingerprint_sha256) VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL)`, tokenHash, actor.DeploymentID, generation, hostID, actor.User.ID, now, expires); err != nil {
		return EnrollmentToken{}, fmt.Errorf("reserve collector enrollment: %w", err)
	}
	detail, _ := json.Marshal(struct {
		HostDisplayName        string `json:"host_display_name"`
		HubURL                 string `json:"hub_url"`
		HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
		IssuerUserID           string `json:"issuer_user_id"`
		TokenHash              string `json:"token_hash"`
		ReEnrollment           bool   `json:"re_enrollment"`
		RetainedInstallationID string `json:"retained_installation_id,omitempty"`
	}{displayName, hubURL, hubCAFingerprint, actor.User.ID, tokenHash, reEnrollment, retainedInstallationID})
	auditID, err := domain.NewUUID()
	if err != nil {
		return EnrollmentToken{}, err
	}
	action := "collector.enrollment.issue"
	if reEnrollment {
		action = "collector.reenrollment.issue"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,?,?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, action, hostID, now, string(detail)); err != nil {
		return EnrollmentToken{}, err
	}
	result := EnrollmentToken{HostID: hostID, Token: token, ExpiresMS: expires, HubURL: hubURL, HubCAFingerprintSHA256: hubCAFingerprint}
	receipt := enrollmentIssueReceipt{HostID: hostID, TokenHash: tokenHash, ExpiresMS: expires, HubURL: hubURL, HubCAFingerprintSHA256: hubCAFingerprint, ReEnrollment: reEnrollment}
	resultJSON, err := json.Marshal(receipt)
	if err != nil || len(resultJSON) > 65536 {
		return EnrollmentToken{}, errors.New("enrollment issue receipt exceeds bound")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, generation, actor.User.ID, idempotencyKey, requestHash, string(resultJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return EnrollmentToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentToken{}, err
	}
	return result, nil
}

func validateRetainedHostForReEnrollment(ctx context.Context, tx *sql.Tx, deploymentID, generation, hostID string, now int64, installationID *string) error {
	var retainedInstallation, reason string
	var currentSession int64
	var lastBoot sql.NullString
	var retired sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT h.installation_uuid,h.current_session_generation,h.last_boot_id,h.retired_ms,g.reason FROM hosts h JOIN deployment_generations g ON g.deployment_id=h.deployment_id AND g.generation=? WHERE h.deployment_id=? AND h.id=?`, generation, deploymentID, hostID).Scan(&retainedInstallation, &currentSession, &lastBoot, &retired, &reason); err != nil {
		return ErrReEnrollmentDenied
	}
	if reason != "restore_bootstrap" || !retired.Valid || currentSession != 0 || lastBoot.Valid || !validUUIDText(retainedInstallation) {
		return ErrReEnrollmentDenied
	}
	var priorEnrollments, liveCredentials, liveSessions, pendingReservations int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_enrollments WHERE deployment_id=? AND result_host_id=? AND consumed_ms IS NOT NULL AND deployment_generation<>?`, deploymentID, hostID, generation).Scan(&priorEnrollments); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_credentials WHERE deployment_id=? AND host_id=? AND (revoked_ms IS NULL OR revoked_ms>?)`, deploymentID, hostID, now).Scan(&liveCredentials); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_sessions WHERE deployment_id=? AND host_id=? AND superseded_ms IS NULL`, deploymentID, hostID).Scan(&liveSessions); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_enrollments WHERE deployment_id=? AND deployment_generation=? AND reserved_host_id=? AND consumed_ms IS NULL AND expires_ms>?`, deploymentID, generation, hostID, now).Scan(&pendingReservations); err != nil {
		return err
	}
	if priorEnrollments == 0 || liveCredentials != 0 || liveSessions != 0 || pendingReservations != 0 {
		return ErrReEnrollmentDenied
	}
	*installationID = retainedInstallation
	return nil
}

type CredentialIdentity struct {
	Serial             string
	FingerprintSHA256  string
	DeploymentID       string
	HostID             string
	SecurityGeneration string
	ExpiresMS          int64
}

type CertificateIssue func(enrollment.Identity, string) (enrollment.ExchangeResult, string, string, error)

func (s *Store) ReserveCollectorEnrollment(ctx context.Context, actor SessionRecord, tokenHash, reservedHostID, displayName, hubURL, hubCAFingerprint string) (EnrollmentReservation, error) {
	if actor.User.Role != "admin" || actor.User.Disabled || actor.User.HistoricalRestored || actor.DeploymentID == "" || actor.Generation == "" || actor.User.ID == "" {
		return EnrollmentReservation{}, ErrOwnershipMismatch
	}
	displayName = strings.TrimSpace(displayName)
	if !validUUIDText(reservedHostID) || !sha256HexPattern.MatchString(tokenHash) || !sha256HexPattern.MatchString(hubCAFingerprint) || len(displayName) < 1 || len(displayName) > 128 || len(hubURL) < 1 || len(hubURL) > 2048 {
		return EnrollmentReservation{}, ErrEnrollmentConflict
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return EnrollmentReservation{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EnrollmentReservation{}, err
	}
	defer tx.Rollback()
	var generation, recovery string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, actor.DeploymentID).Scan(&generation, &recovery); err != nil {
		return EnrollmentReservation{}, ownershipError(err)
	}
	if recovery != "normal" || generation != actor.Generation || actor.User.TrustGeneration != generation {
		return EnrollmentReservation{}, ErrAdmissionFenced
	}
	var role string
	var disabled, historical int
	if err := tx.QueryRowContext(ctx, `SELECT role,disabled,historical_restored FROM users WHERE deployment_id=? AND id=? AND trust_generation=?`, actor.DeploymentID, actor.User.ID, generation).Scan(&role, &disabled, &historical); err != nil || role != "admin" || disabled != 0 || historical != 0 {
		return EnrollmentReservation{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	var activeHosts, activeReservations int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE deployment_id=? AND retired_ms IS NULL`, actor.DeploymentID).Scan(&activeHosts); err != nil {
		return EnrollmentReservation{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM collector_enrollments WHERE deployment_id=? AND deployment_generation=? AND consumed_ms IS NULL AND expires_ms>?`, actor.DeploymentID, generation, now).Scan(&activeReservations); err != nil {
		return EnrollmentReservation{}, err
	}
	if activeHosts+activeReservations >= 2 {
		return EnrollmentReservation{}, ErrHostLimit
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO collector_enrollments(token_hash,deployment_id,deployment_generation,reserved_host_id,created_by,created_ms,expires_ms,consumed_ms,result_host_id,result_cert_fingerprint_sha256) VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL)`, tokenHash, actor.DeploymentID, generation, reservedHostID, actor.User.ID, now, now+int64(enrollment.TokenValidity/time.Millisecond)); err != nil {
		return EnrollmentReservation{}, fmt.Errorf("reserve collector enrollment: %w", err)
	}
	detail, _ := json.Marshal(struct {
		HostDisplayName        string `json:"host_display_name"`
		HubURL                 string `json:"hub_url"`
		HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
		IssuerUserID           string `json:"issuer_user_id"`
		TokenHash              string `json:"token_hash"`
	}{displayName, hubURL, hubCAFingerprint, actor.User.ID, tokenHash})
	auditID, err := domain.NewUUID()
	if err != nil {
		return EnrollmentReservation{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'collector.enrollment.issue',?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, reservedHostID, now, string(detail)); err != nil {
		return EnrollmentReservation{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentReservation{}, err
	}
	return EnrollmentReservation{TokenHash: tokenHash, DeploymentID: actor.DeploymentID, SecurityGeneration: generation, ReservedHostID: reservedHostID, CreatedBy: actor.User.ID, HostDisplayName: displayName, HubURL: hubURL, HubCAFingerprintSHA256: hubCAFingerprint, CreatedMS: now, ExpiresMS: now + int64(enrollment.TokenValidity/time.Millisecond)}, nil
}

// AuthenticateCollectorEnrollment performs the cheap token lookup used before a
// request body is decoded. A consumed token remains recognizable so an exact
// lost-response retry can resolve its 24-hour public receipt.
func (s *Store) AuthenticateCollectorEnrollment(ctx context.Context, tokenHash string) (EnrollmentReservation, error) {
	if !sha256HexPattern.MatchString(tokenHash) {
		return EnrollmentReservation{}, ErrEnrollmentUnavailable
	}
	var value EnrollmentReservation
	var detailJSON string
	var consumed sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT e.token_hash,e.deployment_id,e.deployment_generation,e.reserved_host_id,e.created_by,e.created_ms,e.expires_ms,e.consumed_ms,a.allowlisted_detail_json FROM collector_enrollments e JOIN audit a ON a.deployment_id=e.deployment_id AND a.action IN ('collector.enrollment.issue','collector.reenrollment.issue') AND a.resource_id=e.reserved_host_id AND a.time_ms=e.created_ms AND json_extract(a.allowlisted_detail_json,'$.token_hash')=e.token_hash WHERE e.token_hash=? ORDER BY a.id LIMIT 1`, tokenHash).Scan(&value.TokenHash, &value.DeploymentID, &value.SecurityGeneration, &value.ReservedHostID, &value.CreatedBy, &value.CreatedMS, &value.ExpiresMS, &consumed, &detailJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentReservation{}, ErrEnrollmentUnavailable
	}
	if err != nil {
		return EnrollmentReservation{}, err
	}
	var detail struct {
		HostDisplayName        string `json:"host_display_name"`
		HubURL                 string `json:"hub_url"`
		HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
		ReEnrollment           bool   `json:"re_enrollment"`
		RetainedInstallationID string `json:"retained_installation_id"`
	}
	if json.Unmarshal([]byte(detailJSON), &detail) != nil || detail.HostDisplayName == "" || !sha256HexPattern.MatchString(detail.HubCAFingerprintSHA256) {
		return EnrollmentReservation{}, ErrEnrollmentUnavailable
	}
	value.HostDisplayName, value.HubURL, value.HubCAFingerprintSHA256 = detail.HostDisplayName, detail.HubURL, detail.HubCAFingerprintSHA256
	value.ReEnrollment, value.RetainedInstallationID = detail.ReEnrollment, detail.RetainedInstallationID
	if value.ReEnrollment && !validUUIDText(value.RetainedInstallationID) {
		return EnrollmentReservation{}, ErrEnrollmentUnavailable
	}
	if !consumed.Valid && s.clock.Now().UnixMilli() >= value.ExpiresMS {
		return EnrollmentReservation{}, ErrEnrollmentExpired
	}
	return value, nil
}

// CollectorEnrollmentStatus exposes only the lifecycle of the latest
// reservation for an administrator. It never returns the bearer, its hash or
// certificate material.
func (s *Store) CollectorEnrollmentStatus(ctx context.Context, deploymentID, hostID string) (EnrollmentStatus, error) {
	if !validUUIDText(deploymentID) || !validUUIDText(hostID) {
		return EnrollmentStatus{}, ErrEnrollmentUnavailable
	}
	var result EnrollmentStatus
	var consumed sql.NullInt64
	var detailJSON string
	err := s.db.QueryRowContext(ctx, `SELECT e.reserved_host_id,e.created_ms,e.expires_ms,e.consumed_ms,a.allowlisted_detail_json FROM collector_enrollments e JOIN audit a ON a.deployment_id=e.deployment_id AND a.action IN ('collector.enrollment.issue','collector.reenrollment.issue') AND a.resource_id=e.reserved_host_id AND a.time_ms=e.created_ms WHERE e.deployment_id=? AND e.reserved_host_id=? ORDER BY e.created_ms DESC,a.id DESC LIMIT 1`, deploymentID, hostID).Scan(&result.HostID, &result.CreatedMS, &result.ExpiresMS, &consumed, &detailJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentStatus{}, ErrEnrollmentUnavailable
	}
	if err != nil {
		return EnrollmentStatus{}, err
	}
	var detail struct {
		HostDisplayName string `json:"host_display_name"`
	}
	if json.Unmarshal([]byte(detailJSON), &detail) != nil || strings.TrimSpace(detail.HostDisplayName) == "" {
		return EnrollmentStatus{}, ErrEnrollmentUnavailable
	}
	result.SchemaVersion = domain.SchemaVersion
	result.DisplayName = detail.HostDisplayName
	if consumed.Valid {
		result.State = "connected"
		result.ConnectedMS = nullableInt64Pointer(consumed)
	} else if s.clock.Now().UnixMilli() >= result.ExpiresMS {
		result.State = "expired"
	} else {
		result.State = "waiting"
	}
	return result, nil
}

func CanonicalEnrollmentRequestHash(request enrollment.ExchangeRequest) (string, error) {
	canonical, err := json.Marshal(struct {
		Protocol               string `json:"protocol"`
		DeploymentID           string `json:"deployment_id"`
		HostID                 string `json:"host_id"`
		InstallationID         string `json:"installation_id"`
		CSRPEM                 string `json:"csr_pem"`
		HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
	}{request.Protocol, request.DeploymentID, request.HostID, request.InstallationID, request.CSRPEM, request.HubCAFingerprintSHA256})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Store) RedeemCollectorEnrollment(ctx context.Context, authorization EnrollmentReservation, idempotencyKey, requestHash string, request enrollment.ExchangeRequest, issue CertificateIssue) (enrollment.ExchangeResult, error) {
	if authorization.TokenHash == "" || issue == nil || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !sha256HexPattern.MatchString(requestHash) {
		return enrollment.ExchangeResult{}, ErrEnrollmentConflict
	}
	receiptKey := "collector-enrollment:" + authorization.TokenHash
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	defer tx.Rollback()
	now := s.clock.Now().UnixMilli()
	var deploymentID, generation, hostID, createdBy string
	var expires int64
	var consumed sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id,deployment_generation,reserved_host_id,created_by,expires_ms,consumed_ms FROM collector_enrollments WHERE token_hash=?`, authorization.TokenHash).Scan(&deploymentID, &generation, &hostID, &createdBy, &expires, &consumed); err != nil {
		return enrollment.ExchangeResult{}, ownershipError(err)
	}
	if deploymentID != authorization.DeploymentID || generation != authorization.SecurityGeneration || hostID != authorization.ReservedHostID || createdBy != authorization.CreatedBy {
		return enrollment.ExchangeResult{}, ErrOwnershipMismatch
	}
	var storedHash, storedJSON string
	var receiptExpires int64
	receiptErr := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, deploymentID, generation, createdBy, receiptKey).Scan(&storedHash, &storedJSON, &receiptExpires)
	if receiptErr == nil {
		if storedHash != requestHash {
			return enrollment.ExchangeResult{}, ErrEnrollmentConflict
		}
		if now >= receiptExpires {
			return enrollment.ExchangeResult{}, ErrEnrollmentConsumed
		}
		var result enrollment.ExchangeResult
		if err := json.Unmarshal([]byte(storedJSON), &result); err != nil {
			return enrollment.ExchangeResult{}, fmt.Errorf("decode enrollment receipt: %w", err)
		}
		return result, nil
	}
	if !errors.Is(receiptErr, sql.ErrNoRows) {
		return enrollment.ExchangeResult{}, receiptErr
	}
	if consumed.Valid {
		return enrollment.ExchangeResult{}, ErrEnrollmentConsumed
	}
	if now >= expires {
		return enrollment.ExchangeResult{}, ErrEnrollmentExpired
	}
	if request.Protocol != domain.ProtocolVersion || request.DeploymentID != deploymentID || request.HostID != hostID || request.HubCAFingerprintSHA256 != authorization.HubCAFingerprintSHA256 || !validUUIDText(request.InstallationID) || len(request.CSRPEM) < 64 || len(request.CSRPEM) > 16384 || (authorization.ReEnrollment && request.InstallationID != authorization.RetainedInstallationID) {
		return enrollment.ExchangeResult{}, ErrEnrollmentConflict
	}
	var currentGeneration, recovery string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_generation,recovery_state FROM deployments WHERE id=?`, deploymentID).Scan(&currentGeneration, &recovery); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	if recovery != "normal" || currentGeneration != generation {
		return enrollment.ExchangeResult{}, ErrAdmissionFenced
	}
	result, serial, fingerprint, err := issue(enrollment.Identity{DeploymentID: deploymentID, HostID: hostID, SecurityGeneration: generation}, request.CSRPEM)
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	if serial == "" || len(serial) > 128 || !sha256HexPattern.MatchString(fingerprint) || result.Protocol != domain.ProtocolVersion || result.DeploymentID != deploymentID || result.HostID != hostID || result.SecurityGeneration != generation || result.HubCAFingerprintSHA256 != authorization.HubCAFingerprintSHA256 || result.ExpiresMS <= now {
		return enrollment.ExchangeResult{}, ErrEnrollmentConflict
	}
	if authorization.ReEnrollment {
		updated, err := tx.ExecContext(ctx, `UPDATE hosts SET display_name=?,current_session_generation=0,last_boot_id=NULL,collector_version=NULL,capabilities_json='{}',retired_ms=NULL,updated_ms=? WHERE id=? AND deployment_id=? AND installation_uuid=? AND retired_ms IS NOT NULL AND current_session_generation=0 AND last_boot_id IS NULL`, authorization.HostDisplayName, now, hostID, deploymentID, request.InstallationID)
		if err != nil {
			return enrollment.ExchangeResult{}, fmt.Errorf("reactivate retained enrolled host: %w", err)
		}
		if count, _ := updated.RowsAffected(); count != 1 {
			return enrollment.ExchangeResult{}, ErrReEnrollmentDenied
		}
	} else if _, err := tx.ExecContext(ctx, `INSERT INTO hosts(id,deployment_id,display_name,installation_uuid,current_session_generation,last_boot_id,collector_version,capabilities_json,retired_ms,created_ms,updated_ms) VALUES(?,?,?,?,0,NULL,NULL,'{}',NULL,?,?)`, hostID, deploymentID, authorization.HostDisplayName, request.InstallationID, now, now); err != nil {
		return enrollment.ExchangeResult{}, fmt.Errorf("create enrolled host: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO collector_credentials(serial,deployment_id,host_id,cert_fingerprint_sha256,issued_ms,expires_ms,revoked_ms) VALUES(?,?,?,?,?,?,NULL)`, serial, deploymentID, hostID, fingerprint, now, result.ExpiresMS); err != nil {
		return enrollment.ExchangeResult{}, fmt.Errorf("record collector credential: %w", err)
	}
	updated, err := tx.ExecContext(ctx, `UPDATE collector_enrollments SET consumed_ms=?,result_host_id=?,result_cert_fingerprint_sha256=? WHERE token_hash=? AND consumed_ms IS NULL`, now, hostID, fingerprint, authorization.TokenHash)
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return enrollment.ExchangeResult{}, ErrEnrollmentConsumed
	}
	resultJSON, err := json.Marshal(result)
	if err != nil || len(resultJSON) > 65536 {
		return enrollment.ExchangeResult{}, errors.New("public enrollment result exceeds receipt bound")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, deploymentID, generation, createdBy, receiptKey, requestHash, string(resultJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	detail, _ := json.Marshal(struct {
		IssuerUserID           string `json:"issuer_user_id"`
		CredentialSerial       string `json:"credential_serial"`
		CertificateFingerprint string `json:"certificate_fingerprint_sha256"`
	}{createdBy, serial, fingerprint})
	auditID, err := domain.NewUUID()
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	action := "collector.enrollment.redeem"
	if authorization.ReEnrollment {
		action = "collector.reenrollment.redeem"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,?,?,?,?)`, auditID, deploymentID, action, hostID, now, string(detail)); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	return result, nil
}

func (s *Store) AuthenticateCollectorCredential(ctx context.Context, credential CredentialIdentity) error {
	if credential.Serial == "" || !sha256HexPattern.MatchString(credential.FingerprintSHA256) || !validUUIDText(credential.DeploymentID) || !validUUIDText(credential.HostID) || !validUUIDText(credential.SecurityGeneration) {
		return ErrCredentialRevoked
	}
	now := s.clock.Now().UnixMilli()
	var expires int64
	var revoked sql.NullInt64
	var generation, recovery string
	err := s.db.QueryRowContext(ctx, `SELECT c.expires_ms,c.revoked_ms,d.deployment_generation,d.recovery_state FROM collector_credentials c JOIN hosts h ON h.deployment_id=c.deployment_id AND h.id=c.host_id JOIN deployments d ON d.id=c.deployment_id WHERE c.serial=? AND c.cert_fingerprint_sha256=? AND c.deployment_id=? AND c.host_id=? AND h.retired_ms IS NULL`, credential.Serial, credential.FingerprintSHA256, credential.DeploymentID, credential.HostID).Scan(&expires, &revoked, &generation, &recovery)
	if err != nil || expires <= now || (revoked.Valid && revoked.Int64 <= now) || generation != credential.SecurityGeneration || recovery != "normal" {
		return ErrCredentialRevoked
	}
	return nil
}

// RenewCollectorCredential issues one replacement certificate for the same
// deployment/host/generation and keeps the authenticated predecessor valid
// for the seven-day overlap. The receipt contains public certificate material
// only, so a lost response can be retried without retaining collector keys.
func (s *Store) RenewCollectorCredential(ctx context.Context, current CredentialIdentity, idempotencyKey, requestHash string, request enrollment.ExchangeRequest, issue CertificateIssue) (enrollment.ExchangeResult, error) {
	if current.Serial == "" || !sha256HexPattern.MatchString(current.FingerprintSHA256) || !validUUIDText(current.DeploymentID) || !validUUIDText(current.HostID) || !validUUIDText(current.SecurityGeneration) || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !sha256HexPattern.MatchString(requestHash) || issue == nil {
		return enrollment.ExchangeResult{}, ErrEnrollmentConflict
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	defer tx.Rollback()
	now := s.clock.Now().UnixMilli()
	var expires int64
	var revoked sql.NullInt64
	var installationID, generation, recovery, issuerUserID string
	err = tx.QueryRowContext(ctx, `SELECT c.expires_ms,c.revoked_ms,h.installation_uuid,d.deployment_generation,d.recovery_state,(SELECT e.created_by FROM collector_enrollments e WHERE e.deployment_id=c.deployment_id AND e.result_host_id=c.host_id AND e.consumed_ms IS NOT NULL ORDER BY e.consumed_ms LIMIT 1) FROM collector_credentials c JOIN hosts h ON h.deployment_id=c.deployment_id AND h.id=c.host_id JOIN deployments d ON d.id=c.deployment_id WHERE c.serial=? AND c.cert_fingerprint_sha256=? AND c.deployment_id=? AND c.host_id=? AND h.retired_ms IS NULL`, current.Serial, current.FingerprintSHA256, current.DeploymentID, current.HostID).Scan(&expires, &revoked, &installationID, &generation, &recovery, &issuerUserID)
	if err != nil || expires <= now || (revoked.Valid && revoked.Int64 <= now) {
		return enrollment.ExchangeResult{}, ErrCredentialRevoked
	}
	if current.ExpiresMS != 0 && current.ExpiresMS != expires {
		return enrollment.ExchangeResult{}, ErrCredentialRevoked
	}
	if generation != current.SecurityGeneration || recovery != "normal" {
		return enrollment.ExchangeResult{}, ErrAdmissionFenced
	}
	receiptKey := "collector-renewal:" + current.Serial + ":" + idempotencyKey
	if len(receiptKey) > 128 {
		return enrollment.ExchangeResult{}, ErrEnrollmentConflict
	}
	var storedHash, storedJSON string
	var receiptExpires int64
	receiptErr := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, current.DeploymentID, generation, issuerUserID, receiptKey).Scan(&storedHash, &storedJSON, &receiptExpires)
	if receiptErr == nil && now < receiptExpires {
		if storedHash != requestHash {
			return enrollment.ExchangeResult{}, ErrEnrollmentConflict
		}
		var result enrollment.ExchangeResult
		if json.Unmarshal([]byte(storedJSON), &result) != nil {
			return enrollment.ExchangeResult{}, ErrEnrollmentConflict
		}
		return result, nil
	}
	if receiptErr == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=? AND expires_ms<=?`, current.DeploymentID, generation, issuerUserID, receiptKey, now); err != nil {
			return enrollment.ExchangeResult{}, err
		}
	} else if !errors.Is(receiptErr, sql.ErrNoRows) {
		return enrollment.ExchangeResult{}, receiptErr
	}
	if expires-now > int64(enrollment.RenewBefore/time.Millisecond) {
		return enrollment.ExchangeResult{}, ErrCredentialRenewalNotDue
	}
	if request.Protocol != domain.ProtocolVersion || request.DeploymentID != current.DeploymentID || request.HostID != current.HostID || request.InstallationID != installationID || !validUUIDText(request.InstallationID) || !sha256HexPattern.MatchString(request.HubCAFingerprintSHA256) || len(request.CSRPEM) < 64 || len(request.CSRPEM) > 16384 {
		return enrollment.ExchangeResult{}, ErrEnrollmentConflict
	}
	result, serial, fingerprint, err := issue(enrollment.Identity{DeploymentID: current.DeploymentID, HostID: current.HostID, SecurityGeneration: generation}, request.CSRPEM)
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	if serial == "" || serial == current.Serial || len(serial) > 128 || !sha256HexPattern.MatchString(fingerprint) || result.Protocol != domain.ProtocolVersion || result.DeploymentID != current.DeploymentID || result.HostID != current.HostID || result.SecurityGeneration != generation || result.HubCAFingerprintSHA256 != request.HubCAFingerprintSHA256 || result.ExpiresMS <= now {
		return enrollment.ExchangeResult{}, ErrEnrollmentConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO collector_credentials(serial,deployment_id,host_id,cert_fingerprint_sha256,issued_ms,expires_ms,revoked_ms) VALUES(?,?,?,?,?,?,NULL)`, serial, current.DeploymentID, current.HostID, fingerprint, now, result.ExpiresMS); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	overlapEnd := now + int64(enrollment.RotationOverlap/time.Millisecond)
	if _, err := tx.ExecContext(ctx, `UPDATE collector_credentials SET revoked_ms=CASE WHEN revoked_ms IS NULL OR revoked_ms>? THEN ? ELSE revoked_ms END WHERE serial=? AND deployment_id=? AND host_id=?`, overlapEnd, overlapEnd, current.Serial, current.DeploymentID, current.HostID); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil || len(resultJSON) > 65536 {
		return enrollment.ExchangeResult{}, errors.New("public renewal result exceeds receipt bound")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, current.DeploymentID, generation, issuerUserID, receiptKey, requestHash, string(resultJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	detail, _ := json.Marshal(struct {
		PreviousSerial string `json:"previous_serial"`
		NewSerial      string `json:"new_serial"`
		OverlapEndsMS  int64  `json:"overlap_ends_ms"`
	}{current.Serial, serial, overlapEnd})
	auditID, err := domain.NewUUID()
	if err != nil {
		return enrollment.ExchangeResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,NULL,'collector.credential.renew',?,?,?)`, auditID, current.DeploymentID, current.HostID, now, string(detail)); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return enrollment.ExchangeResult{}, err
	}
	return result, nil
}

func (s *Store) RevokeCollectorCredentials(ctx context.Context, actor SessionRecord, hostID string) error {
	if actor.User.Role != "admin" || !validUUIDText(hostID) {
		return ErrOwnershipMismatch
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
	now := s.clock.Now().UnixMilli()
	result, err := tx.ExecContext(ctx, `UPDATE collector_credentials SET revoked_ms=? WHERE deployment_id=? AND host_id=? AND (revoked_ms IS NULL OR revoked_ms>?)`, now, actor.DeploymentID, hostID, now)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrCredentialRevoked
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'collector.credential.revoke',?,?,'{}')`, auditID, actor.DeploymentID, actor.User.ID, hostID, now); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeCollectorCredentialsIdempotent is the API mutation boundary. It
// fences the current generation and persists a 24-hour receipt before ACK.
func (s *Store) RevokeCollectorCredentialsIdempotent(ctx context.Context, actor SessionRecord, hostID, idempotencyKey, requestHash string) (int64, error) {
	if actor.User.Role != "admin" || !validUUIDText(hostID) || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !sha256HexPattern.MatchString(requestHash) {
		return 0, ErrOwnershipMismatch
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
	if err != nil || role != "admin" {
		return 0, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	var storedHash, storedJSON string
	var receiptExpires int64
	err = tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey).Scan(&storedHash, &storedJSON, &receiptExpires)
	if err == nil && now < receiptExpires {
		if storedHash != requestHash {
			return 0, ErrEnrollmentConflict
		}
		var receipt struct {
			HostID    string `json:"host_id"`
			RevokedMS int64  `json:"revoked_ms"`
		}
		if json.Unmarshal([]byte(storedJSON), &receipt) != nil || receipt.HostID != hostID {
			return 0, ErrEnrollmentConflict
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
	var known int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE deployment_id=? AND id=? AND retired_ms IS NULL`, actor.DeploymentID, hostID).Scan(&known); err != nil || known != 1 {
		return 0, ErrOwnershipMismatch
	}
	result, err := tx.ExecContext(ctx, `UPDATE collector_credentials SET revoked_ms=? WHERE deployment_id=? AND host_id=? AND (revoked_ms IS NULL OR revoked_ms>?)`, now, actor.DeploymentID, hostID, now)
	if err != nil {
		return 0, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return 0, ErrCredentialRevoked
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'collector.credential.revoke',?,?,'{}')`, auditID, actor.DeploymentID, actor.User.ID, hostID, now); err != nil {
		return 0, err
	}
	receiptJSON, _ := json.Marshal(struct {
		HostID    string `json:"host_id"`
		RevokedMS int64  `json:"revoked_ms"`
	}{hostID, now})
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, string(receiptJSON), now, now+int64(24*time.Hour/time.Millisecond)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return now, nil
}

func validUUIDText(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, r := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if r != '-' {
				return false
			}
		} else if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return value[14] >= '1' && value[14] <= '5' && strings.ContainsRune("89abAB", rune(value[19]))
}
