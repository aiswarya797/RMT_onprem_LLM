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
	"unicode"
	"unicode/utf8"

	"rmt.local/monitor/internal/domain"
)

const (
	incidentCapsulePayloadLimitBytes int64 = 64 << 10
	// The row field reserves the maximum immutable payload only. Measured
	// SQLite state/index overhead is charged by the separate manual-admission
	// value. The opt-in dbstat witness measured 132,953 bytes per worst-case
	// manual capsule; admission rounds that result to the next 4 KiB page.
	incidentCapsulePayloadReservationBytes               = incidentCapsulePayloadLimitBytes
	incidentManualCapsuleAdmissionReservationBytes       = 135168
	incidentResolvedRetention                            = 90 * 24 * time.Hour
	incidentOpenLimit                              int64 = 1000
	incidentResolvedCapsuleLimit                   int64 = 2000
	incidentRetainedCapsuleLimit                   int64 = 3000
	incidentPageLimit                                    = 100
	annotationPageLimit                                  = 100
)

var (
	ErrIncidentNotFound   = errors.New("incident not found")
	ErrIncidentConflict   = errors.New("incident request conflict")
	ErrIncidentRevision   = errors.New("incident revision conflict")
	ErrIncidentLimit      = errors.New("open incident limit reached")
	ErrIncidentCapacity   = errors.New("incident evidence capacity exhausted")
	ErrIncidentInvalid    = errors.New("invalid incident input")
	ErrIncidentState      = errors.New("incident workflow state conflict")
	ErrAnnotationNotFound = errors.New("annotation not found")
	ErrAnnotationLimit    = errors.New("annotation limit reached")
)

type IncidentRecord struct {
	ID                    string             `json:"id"`
	Revision              int64              `json:"revision"`
	Title                 string             `json:"title"`
	ScopeJSON             string             `json:"-"`
	Origin                string             `json:"origin"`
	StartMS               int64              `json:"start_ms"`
	EndMS                 int64              `json:"end_ms"`
	EndMSValid            bool               `json:"-"`
	WorkflowState         string             `json:"workflow_state"`
	OwnerUserID           *string            `json:"owner_user_id"`
	EvidenceState         string             `json:"evidence_state"`
	EvidenceExpiryReason  *string            `json:"evidence_expiry_reason"`
	CapsuleSchemaRevision string             `json:"capsule_schema_revision"`
	CardRevision          string             `json:"card_revision"`
	CapsulePayload        []byte             `json:"-"`
	CapsuleSHA256         string             `json:"capsule_sha256"`
	CreatedMS             int64              `json:"created_ms"`
	UpdatedMS             int64              `json:"updated_ms"`
	Annotations           []AnnotationRecord `json:"annotations"`
	AnnotationsNextCursor *string            `json:"annotations_next_cursor"`
}

type IncidentPage struct {
	Items      []IncidentRecord
	NextCursor *string
}

type AnnotationPage struct {
	Items      []AnnotationRecord
	NextCursor *string
}

type ManualIncidentInput struct {
	Title                 string
	ScopeJSON             []byte
	StartMS               int64
	EndMS                 int64
	CapsuleSchemaRevision string
	CardRevision          string
	CapsulePayload        []byte
	EvidenceState         string
}

type ManualIncidentUpdate struct {
	ExpectedRevision int64
	Title            *string
	WorkflowState    *string
}

// IncidentSummaryResult is the bounded, immutable wire result retained for an
// idempotent create or metadata mutation. It intentionally excludes the
// capsule and annotations so a retry remains exact after later mutations.
type IncidentSummaryResult struct {
	ID                   string  `json:"id"`
	Revision             int64   `json:"revision"`
	Title                string  `json:"title"`
	ScopeJSON            string  `json:"scope_json"`
	Origin               string  `json:"origin"`
	StartMS              int64   `json:"start_ms"`
	EndMS                int64   `json:"end_ms"`
	WorkflowState        string  `json:"workflow_state"`
	OwnerUserID          *string `json:"owner_user_id"`
	EvidenceState        string  `json:"evidence_state"`
	EvidenceExpiryReason *string `json:"evidence_expiry_reason"`
	CapsuleSHA256        string  `json:"capsule_sha256"`
	CreatedMS            int64   `json:"created_ms"`
	UpdatedMS            int64   `json:"updated_ms"`
}

type AnnotationRecord struct {
	ID             string `json:"id"`
	Revision       int64  `json:"revision"`
	IncidentID     string `json:"incident_id"`
	DeclaredTimeMS int64  `json:"declared_time_ms"`
	Text           string `json:"text"`
	AuthorUserID   string `json:"author_user_id"`
	EditedMS       *int64 `json:"edited_ms"`
	CreatedMS      int64  `json:"created_ms"`
}

// ReadManualIncidentRetry authenticates the actor and resolves an unexpired
// create receipt before any historical evidence is queried again. This keeps
// an exact retry stable when the immutable capsule outlives its source rows.
func (s *Store) ReadManualIncidentRetry(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash string) (IncidentSummaryResult, bool, error) {
	if !validMutationReceipt(idempotencyKey, requestHash) {
		return IncidentSummaryResult{}, false, ErrIncidentInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return IncidentSummaryResult{}, false, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IncidentSummaryResult{}, false, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return IncidentSummaryResult{}, false, err
	}
	if role != "admin" {
		return IncidentSummaryResult{}, false, ErrOwnershipMismatch
	}
	record, found, err := readIncidentReceipt(ctx, tx, actor, idempotencyKey, requestHash, s.clock.Now().UnixMilli())
	if err != nil {
		return IncidentSummaryResult{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return IncidentSummaryResult{}, false, err
	}
	return record, found, nil
}

func (s *Store) CreateManualIncident(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash string, input ManualIncidentInput) (IncidentSummaryResult, error) {
	if err := validateManualIncidentInput(input, idempotencyKey, requestHash); err != nil {
		return IncidentSummaryResult{}, err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	if role != "admin" {
		return IncidentSummaryResult{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if record, found, err := readIncidentReceipt(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return IncidentSummaryResult{}, err
	} else if found {
		return record, nil
	}
	if err := admitIncidentCapsuleTx(ctx, tx, actor.DeploymentID, actor.User.ID, incidentManualCapsuleAdmissionReservationBytes, now); err != nil {
		return IncidentSummaryResult{}, err
	}
	incidentID, err := domain.NewUUID()
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	payloadHash := sha256.Sum256(input.CapsulePayload)
	payloadSHA256 := hex.EncodeToString(payloadHash[:])
	if _, err := tx.ExecContext(ctx, `INSERT INTO incidents(id,deployment_id,target_scope_json,title,origin,start_ms,end_ms,alert_instance_id,workflow_state,owner_user_id,snapshot_id,evidence_expiry_reason,version,created_ms,updated_ms) VALUES(?,?,?,?, 'manual',?,?,NULL,'open',NULL,NULL,NULL,1,?,?)`, incidentID, actor.DeploymentID, string(input.ScopeJSON), input.Title, input.StartMS, input.EndMS, now, now); err != nil {
		return IncidentSummaryResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO incident_capsules(deployment_id,incident_id,schema_revision,card_revision,rule_revision,payload,payload_sha256,physical_reservation_bytes,evidence_state,expires_ms,resolved_ms) VALUES(?,?,?,?,NULL,?,?,?,?,NULL,NULL)`, actor.DeploymentID, incidentID, input.CapsuleSchemaRevision, input.CardRevision, input.CapsulePayload, payloadSHA256, incidentCapsulePayloadReservationBytes, input.EvidenceState); err != nil {
		return IncidentSummaryResult{}, err
	}
	auditID, err := domain.NewUUID()
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	detail, _ := json.Marshal(struct {
		Origin       string `json:"origin"`
		EvidenceHash string `json:"evidence_sha256"`
		StartMS      int64  `json:"start_ms"`
		EndMS        int64  `json:"end_ms"`
	}{"manual", payloadSHA256, input.StartMS, input.EndMS})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'incident.manual.create',?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, incidentID, now, string(detail)); err != nil {
		return IncidentSummaryResult{}, err
	}
	record, err := readIncidentTx(ctx, tx, actor.DeploymentID, incidentID, false)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	result := incidentSummaryResultFromRecord(record)
	receiptJSON, _ := json.Marshal(result)
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,201,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, string(receiptJSON), now, now+86400000); err != nil {
		return IncidentSummaryResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return IncidentSummaryResult{}, err
	}
	return result, nil
}

func (s *Store) ListIncidents(ctx context.Context, deploymentID, cursor string, limit int) (IncidentPage, error) {
	if !validUUIDText(deploymentID) || (cursor != "" && !validUUIDText(cursor)) || limit < 1 || limit > incidentPageLimit {
		return IncidentPage{}, ErrIncidentInvalid
	}
	query := `SELECT i.id,i.version,i.title,i.target_scope_json,i.origin,i.start_ms,i.end_ms,i.workflow_state,i.owner_user_id,i.evidence_expiry_reason,c.evidence_state,c.schema_revision,c.card_revision,c.payload_sha256,i.created_ms,i.updated_ms FROM incidents i LEFT JOIN incident_capsules c ON c.deployment_id=i.deployment_id AND c.incident_id=i.id WHERE i.deployment_id=?`
	arguments := []any{deploymentID}
	if cursor != "" {
		var cursorStart int64
		if err := s.db.QueryRowContext(ctx, `SELECT start_ms FROM incidents WHERE deployment_id=? AND id=?`, deploymentID, cursor).Scan(&cursorStart); err != nil {
			return IncidentPage{}, ErrIncidentInvalid
		}
		query += ` AND (i.start_ms<? OR (i.start_ms=? AND i.id>?))`
		arguments = append(arguments, cursorStart, cursorStart, cursor)
	}
	query += ` ORDER BY i.start_ms DESC,i.id LIMIT ?`
	arguments = append(arguments, limit+1)
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return IncidentPage{}, err
	}
	defer rows.Close()
	items := []IncidentRecord{}
	for rows.Next() {
		record, err := scanIncident(rows, false)
		if err != nil {
			return IncidentPage{}, err
		}
		items = append(items, record)
	}
	if err := rows.Err(); err != nil {
		return IncidentPage{}, err
	}
	page := IncidentPage{Items: items}
	if len(page.Items) > limit {
		cursor := page.Items[limit-1].ID
		page.Items, page.NextCursor = page.Items[:limit], &cursor
	}
	return page, nil
}

func (s *Store) ReadIncident(ctx context.Context, deploymentID, incidentID string) (IncidentRecord, error) {
	if !validUUIDText(deploymentID) || !validUUIDText(incidentID) {
		return IncidentRecord{}, ErrIncidentNotFound
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return IncidentRecord{}, err
	}
	defer tx.Rollback()
	record, err := readIncidentTx(ctx, tx, deploymentID, incidentID, true)
	if err != nil {
		return IncidentRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return IncidentRecord{}, err
	}
	return record, nil
}

// UpdateManualIncident changes only operator-owned workflow metadata. The
// immutable evidence capsule, focus window and capsule hash are never rewritten.
func (s *Store) UpdateManualIncident(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash, incidentID string, input ManualIncidentUpdate) (IncidentSummaryResult, error) {
	if !validUUIDText(incidentID) || input.ExpectedRevision < 1 || !validMutationReceipt(idempotencyKey, requestHash) || !validManualIncidentUpdate(input) {
		return IncidentSummaryResult{}, ErrIncidentInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	if role != "admin" {
		return IncidentSummaryResult{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if record, found, err := readIncidentMutationReceipt(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return IncidentSummaryResult{}, err
	} else if found {
		return record, nil
	}
	record, err := readIncidentTx(ctx, tx, actor.DeploymentID, incidentID, true)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	if record.Origin != "manual" {
		return IncidentSummaryResult{}, ErrIncidentState
	}
	if record.Revision != input.ExpectedRevision {
		return IncidentSummaryResult{}, ErrIncidentRevision
	}
	nextTitle, nextState := record.Title, record.WorkflowState
	if input.Title != nil {
		nextTitle = *input.Title
	}
	if input.WorkflowState != nil {
		nextState = *input.WorkflowState
	}
	if nextTitle == record.Title && nextState == record.WorkflowState {
		return IncidentSummaryResult{}, ErrIncidentInvalid
	}
	if record.WorkflowState == "closed" && nextState == "open" {
		var openCount int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE deployment_id=? AND workflow_state='open'`, actor.DeploymentID).Scan(&openCount); err != nil {
			return IncidentSummaryResult{}, err
		}
		if openCount >= 1000 {
			return IncidentSummaryResult{}, ErrIncidentLimit
		}
		if err := validateIncidentReopenTx(ctx, tx, actor.DeploymentID, incidentID, record.EvidenceExpiryReason); err != nil {
			return IncidentSummaryResult{}, err
		}
	}
	nextRevision := input.ExpectedRevision + 1
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET title=?,workflow_state=?,version=?,updated_ms=? WHERE deployment_id=? AND id=? AND version=? AND origin='manual'`, nextTitle, nextState, nextRevision, now, actor.DeploymentID, incidentID, input.ExpectedRevision)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return IncidentSummaryResult{}, ErrIncidentRevision
	}
	if nextState != record.WorkflowState {
		resolvedMS := any(nil)
		expiresMS := any(nil)
		if nextState == "closed" {
			resolvedMS = now
			expiresMS = now + incidentResolvedRetention.Milliseconds()
		}
		if _, err := tx.ExecContext(ctx, `UPDATE incident_capsules SET resolved_ms=?,expires_ms=? WHERE deployment_id=? AND incident_id=?`, resolvedMS, expiresMS, actor.DeploymentID, incidentID); err != nil {
			return IncidentSummaryResult{}, err
		}
		if nextState == "closed" {
			if err := pruneResolvedIncidentCapsulesTx(ctx, tx, actor.DeploymentID, actor.User.ID, now, 0, false); err != nil {
				return IncidentSummaryResult{}, err
			}
		}
	}
	previousTitle, previousState := record.Title, record.WorkflowState
	record.Title, record.WorkflowState, record.Revision, record.UpdatedMS = nextTitle, nextState, nextRevision, now
	auditID, err := domain.NewUUID()
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	detail, _ := json.Marshal(struct {
		Revision            int64  `json:"revision"`
		PreviousTitleSHA256 string `json:"previous_title_sha256"`
		TitleSHA256         string `json:"title_sha256"`
		PreviousState       string `json:"previous_workflow_state"`
		WorkflowState       string `json:"workflow_state"`
	}{nextRevision, sha256Text(previousTitle), sha256Text(nextTitle), previousState, nextState})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'incident.manual.update',?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, incidentID, now, string(detail)); err != nil {
		return IncidentSummaryResult{}, err
	}
	record, err = readIncidentTx(ctx, tx, actor.DeploymentID, incidentID, false)
	if err != nil {
		return IncidentSummaryResult{}, err
	}
	mutationResult := incidentSummaryResultFromRecord(record)
	receiptJSON, _ := json.Marshal(mutationResult)
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,200,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, idempotencyKey, requestHash, string(receiptJSON), now, now+86400000); err != nil {
		return IncidentSummaryResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return IncidentSummaryResult{}, err
	}
	return mutationResult, nil
}

func (s *Store) ListIncidentAnnotations(ctx context.Context, deploymentID, incidentID, cursor string, limit int) (AnnotationPage, error) {
	if !validUUIDText(deploymentID) || !validUUIDText(incidentID) || (cursor != "" && !validUUIDText(cursor)) || limit < 1 || limit > annotationPageLimit {
		return AnnotationPage{}, ErrIncidentInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AnnotationPage{}, err
	}
	defer tx.Rollback()
	page, err := readAnnotationPageTx(ctx, tx, deploymentID, incidentID, cursor, limit)
	if err != nil {
		return AnnotationPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return AnnotationPage{}, err
	}
	return page, nil
}

func (s *Store) CreateIncidentAnnotation(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash, incidentID string, declaredTimeMS int64, text string) (AnnotationRecord, error) {
	text = strings.TrimSpace(text)
	if !validUUIDText(incidentID) || declaredTimeMS < 0 || !validAnnotationText(text) || !validMutationReceipt(idempotencyKey, requestHash) {
		return AnnotationRecord{}, ErrIncidentInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return AnnotationRecord{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AnnotationRecord{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return AnnotationRecord{}, err
	}
	if role != "admin" {
		return AnnotationRecord{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if record, found, err := readAnnotationReceipt(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return AnnotationRecord{}, err
	} else if found {
		return record, nil
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE deployment_id=? AND id=?`, actor.DeploymentID, incidentID).Scan(&exists); err != nil {
		return AnnotationRecord{}, err
	}
	if exists != 1 {
		return AnnotationRecord{}, ErrIncidentNotFound
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM annotations WHERE deployment_id=?`, actor.DeploymentID).Scan(&count); err != nil {
		return AnnotationRecord{}, err
	}
	if count >= 20000 {
		return AnnotationRecord{}, ErrAnnotationLimit
	}
	annotationID, err := domain.NewUUID()
	if err != nil {
		return AnnotationRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO annotations(id,deployment_id,incident_id,host_id,target_id,declared_time_ms,text,author_user_id,version,edited_ms,created_ms) VALUES(?,?,?,NULL,NULL,?,?,?,1,NULL,?)`, annotationID, actor.DeploymentID, incidentID, declaredTimeMS, text, actor.User.ID, now); err != nil {
		return AnnotationRecord{}, err
	}
	record := AnnotationRecord{ID: annotationID, Revision: 1, IncidentID: incidentID, DeclaredTimeMS: declaredTimeMS, Text: text, AuthorUserID: actor.User.ID, CreatedMS: now}
	if err := writeAnnotationAuditAndReceipt(ctx, tx, actor, idempotencyKey, requestHash, record, "", "annotation.create", now, 201); err != nil {
		return AnnotationRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return AnnotationRecord{}, err
	}
	return record, nil
}

func (s *Store) EditIncidentAnnotation(ctx context.Context, actor SessionRecord, idempotencyKey, requestHash, annotationID string, expectedRevision int64, text string) (AnnotationRecord, error) {
	text = strings.TrimSpace(text)
	if !validUUIDText(annotationID) || expectedRevision < 1 || !validAnnotationText(text) || !validMutationReceipt(idempotencyKey, requestHash) {
		return AnnotationRecord{}, ErrIncidentInvalid
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return AnnotationRecord{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AnnotationRecord{}, err
	}
	defer tx.Rollback()
	role, _, err := validateAPITokenActor(ctx, tx, actor)
	if err != nil {
		return AnnotationRecord{}, err
	}
	if role != "admin" {
		return AnnotationRecord{}, ErrOwnershipMismatch
	}
	now := s.clock.Now().UnixMilli()
	if record, found, err := readAnnotationReceipt(ctx, tx, actor, idempotencyKey, requestHash, now); err != nil {
		return AnnotationRecord{}, err
	} else if found {
		return record, nil
	}
	record, err := readAnnotationTx(ctx, tx, actor.DeploymentID, annotationID)
	if err != nil {
		return AnnotationRecord{}, err
	}
	if record.Revision != expectedRevision {
		return AnnotationRecord{}, ErrIncidentRevision
	}
	previousText := record.Text
	nextRevision := expectedRevision + 1
	result, err := tx.ExecContext(ctx, `UPDATE annotations SET text=?,version=?,edited_ms=? WHERE deployment_id=? AND id=? AND version=?`, text, nextRevision, now, actor.DeploymentID, annotationID, expectedRevision)
	if err != nil {
		return AnnotationRecord{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return AnnotationRecord{}, ErrIncidentRevision
	}
	record.Text, record.Revision, record.EditedMS = text, nextRevision, &now
	if err := writeAnnotationAuditAndReceipt(ctx, tx, actor, idempotencyKey, requestHash, record, previousText, "annotation.edit", now, 200); err != nil {
		return AnnotationRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return AnnotationRecord{}, err
	}
	return record, nil
}

func validateManualIncidentInput(input ManualIncidentInput, idempotencyKey, requestHash string) error {
	title := strings.TrimSpace(input.Title)
	if title != input.Title || title == "" || utf8.RuneCountInString(title) > 160 || invalidManualIncidentTitle(title) || input.StartMS < 0 || input.EndMS <= input.StartMS || input.EndMS-input.StartMS < 5*60*1000 || input.EndMS-input.StartMS > 24*60*60*1000 || len(input.ScopeJSON) == 0 || len(input.ScopeJSON) > 65536 || !json.Valid(input.ScopeJSON) || input.CapsuleSchemaRevision == "" || len(input.CapsuleSchemaRevision) > 32 || input.CardRevision == "" || len(input.CardRevision) > 32 || len(input.CapsulePayload) == 0 || len(input.CapsulePayload) > int(incidentCapsulePayloadLimitBytes) || !json.Valid(input.CapsulePayload) || (input.EvidenceState != "complete" && input.EvidenceState != "partial") || !validMutationReceipt(idempotencyKey, requestHash) {
		return ErrIncidentInvalid
	}
	return nil
}

func validManualIncidentUpdate(input ManualIncidentUpdate) bool {
	if input.Title == nil && input.WorkflowState == nil {
		return false
	}
	if input.Title != nil {
		title := strings.TrimSpace(*input.Title)
		if title != *input.Title || title == "" || utf8.RuneCountInString(title) > 160 || invalidManualIncidentTitle(title) {
			return false
		}
	}
	return input.WorkflowState == nil || *input.WorkflowState == "open" || *input.WorkflowState == "closed"
}

func invalidManualIncidentTitle(value string) bool {
	return strings.ContainsAny(value, "<>") || strings.IndexFunc(value, unicode.IsControl) >= 0
}

func validMutationReceipt(idempotencyKey, requestHash string) bool {
	return len(idempotencyKey) >= 16 && len(idempotencyKey) <= 128 && sha256HexPattern.MatchString(requestHash)
}

func validAnnotationText(value string) bool {
	if value == "" || len([]byte(value)) > 2048 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\t' && character != '\n' && character != '\r' {
			return false
		}
	}
	return true
}

func admitIncidentCapsuleTx(ctx context.Context, tx *sql.Tx, deploymentID, actorUserID string, requested, now int64) error {
	var openCount int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE deployment_id=? AND workflow_state='open'`, deploymentID).Scan(&openCount); err != nil {
		return err
	}
	if openCount >= incidentOpenLimit {
		return ErrIncidentLimit
	}
	if err := pruneResolvedIncidentCapsulesTx(ctx, tx, deploymentID, actorUserID, now, requested, true); err != nil {
		return err
	}
	return reserveManualIncidentLiveCapacityTx(ctx, tx, deploymentID, requested, now)
}

type incidentCapsuleUsage struct {
	Retained, Resolved, Reservations int64
	Limit, ConfiguredCount           int64
	Current, ExternalReservations    int64
	PendingWrites                    int64
}

type incidentLossBatch struct {
	Reason      string
	Count       int64
	FirstMS     int64
	LastMS      int64
	Initialized bool
}

func pruneResolvedIncidentCapsulesTx(ctx context.Context, tx *sql.Tx, deploymentID, actorUserID string, now, requestedReservation int64, admitting bool) error {
	baselineReusable, err := incidentReusableBytesTx(ctx, tx)
	if err != nil {
		return err
	}
	losses := map[string]*incidentLossBatch{
		"evidence_expired_age":   {Reason: "evidence_expired_age"},
		"evidence_expired_quota": {Reason: "evidence_expired_quota"},
	}
	cutoff := now - incidentResolvedRetention.Milliseconds()
	rows, err := tx.QueryContext(ctx, `SELECT i.id,i.start_ms FROM incidents i JOIN incident_capsules c ON c.deployment_id=i.deployment_id AND c.incident_id=i.id WHERE i.deployment_id=? AND i.workflow_state='closed' AND c.payload IS NOT NULL AND (c.expires_ms<=? OR (c.expires_ms IS NULL AND COALESCE(c.resolved_ms,i.updated_ms)<=?)) ORDER BY COALESCE(c.resolved_ms,i.updated_ms),i.id LIMIT ?`, deploymentID, now, cutoff, incidentRetainedCapsuleLimit+1)
	if err != nil {
		return err
	}
	type expiredCandidate struct {
		ID      string
		StartMS int64
	}
	ageExpired := []expiredCandidate{}
	for rows.Next() {
		var candidate expiredCandidate
		if err := rows.Scan(&candidate.ID, &candidate.StartMS); err != nil {
			rows.Close()
			return err
		}
		ageExpired = append(ageExpired, candidate)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, candidate := range ageExpired {
		if err := expireIncidentCapsuleTx(ctx, tx, deploymentID, candidate.ID, candidate.StartMS, losses["evidence_expired_age"], now); err != nil {
			return err
		}
	}
	pruned := int64(len(ageExpired))

	for expired := int64(0); ; expired++ {
		if expired > incidentRetainedCapsuleLimit {
			return errors.New("incident retention pruning exceeded bound")
		}
		usage, err := readIncidentCapsuleUsageTx(ctx, tx, deploymentID)
		if err != nil {
			return err
		}
		if pruned > 0 {
			currentReusable, err := incidentReusableBytesTx(ctx, tx)
			if err != nil {
				return err
			}
			if freed := currentReusable - baselineReusable; freed > 0 {
				if freed >= usage.Current {
					usage.Current = 0
				} else {
					usage.Current -= freed
				}
			}
		}
		countLimit := incidentRetainedCapsuleLimit
		if usage.ConfiguredCount > 0 && usage.ConfiguredCount < countLimit {
			countLimit = usage.ConfiguredCount
		}
		projectedCount := usage.Retained
		if admitting {
			projectedCount++
		}
		projectedReservations := usage.Reservations + requestedReservation
		capacityFits := projectedReservations <= usage.Limit && usage.ExternalReservations <= usage.Limit-projectedReservations
		if admitting {
			// The last physical observation already includes prior incident
			// rows. PendingWrites covers committed alert/manual rows after that
			// snapshot. Reservations independently bound retained capsules, so
			// admission uses the larger bound rather than double-counting them.
			accounted := usage.Current
			if usage.PendingWrites > usage.Limit-accounted {
				capacityFits = false
				accounted = usage.Limit
			} else {
				accounted += usage.PendingWrites
			}
			if requestedReservation > usage.Limit-accounted {
				capacityFits = false
				accounted = usage.Limit
			} else {
				accounted += requestedReservation
			}
			if projectedReservations > accounted {
				accounted = projectedReservations
			}
			capacityFits = capacityFits && accounted <= usage.Limit && usage.ExternalReservations <= usage.Limit-accounted
		}
		if usage.Resolved <= incidentResolvedCapsuleLimit && projectedCount <= countLimit && capacityFits {
			break
		}
		// A measured allocation plus independent reservations cannot be made
		// smaller safely from payload arithmetic. Refuse admission before
		// evicting unrelated evidence when pruning cannot prove it creates room.
		if admitting && usage.Current > usage.Limit-usage.ExternalReservations {
			return ErrIncidentCapacity
		}
		var incidentID string
		var startMS int64
		err = tx.QueryRowContext(ctx, `SELECT i.id,i.start_ms FROM incidents i JOIN incident_capsules c ON c.deployment_id=i.deployment_id AND c.incident_id=i.id WHERE i.deployment_id=? AND i.workflow_state='closed' AND c.payload IS NOT NULL ORDER BY COALESCE(c.resolved_ms,i.updated_ms),i.id LIMIT 1`, deploymentID).Scan(&incidentID, &startMS)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIncidentCapacity
		}
		if err != nil {
			return err
		}
		if err := expireIncidentCapsuleTx(ctx, tx, deploymentID, incidentID, startMS, losses["evidence_expired_quota"], now); err != nil {
			return err
		}
		pruned++
	}
	return recordIncidentLossesTx(ctx, tx, deploymentID, actorUserID, losses, now)
}

// incidentReusableBytesTx measures reusable allocation from the incident
// b-trees plus the database freelist. The write gate makes a positive delta
// across an incident prune attributable to that prune. Crediting only that
// delta preserves any external/stale component in the quota observation.
func incidentReusableBytesTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.unused,COALESCE(m.tbl_name,d.name) FROM dbstat AS d LEFT JOIN sqlite_schema AS m ON m.name=d.name WHERE d.aggregate=TRUE ORDER BY d.name`)
	if err != nil {
		return 0, fmt.Errorf("measure incident sqlite reuse: %w", err)
	}
	defer rows.Close()
	var reusable int64
	for rows.Next() {
		var unused int64
		var table string
		if err := rows.Scan(&unused, &table); err != nil {
			return 0, err
		}
		if unused < 0 {
			return 0, errors.New("negative incident sqlite reuse")
		}
		if sqliteTableCapacityClass(table) == "incident_ledger" {
			if unused > math.MaxInt64-reusable {
				return 0, errors.New("incident sqlite reuse overflow")
			}
			reusable += unused
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var freePages, pageSize int64
	if err := tx.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&freePages); err != nil {
		return 0, err
	}
	if err := tx.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	if freePages < 0 || pageSize <= 0 || (freePages > 0 && pageSize > math.MaxInt64/freePages) || freePages*pageSize > math.MaxInt64-reusable {
		return 0, errors.New("sqlite freelist reuse overflow")
	}
	return reusable + freePages*pageSize, nil
}

func readIncidentCapsuleUsageTx(ctx context.Context, tx *sql.Tx, deploymentID string) (incidentCapsuleUsage, error) {
	var usage incidentCapsuleUsage
	var countLimit sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT byte_limit,count_limit,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='incident_ledger'`, deploymentID).Scan(&usage.Limit, &countLimit, &usage.Current, &usage.ExternalReservations); err != nil {
		return incidentCapsuleUsage{}, err
	}
	if countLimit.Valid {
		usage.ConfiguredCount = countLimit.Int64
	}
	var manual, alert int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(CASE WHEN i.workflow_state='closed' THEN 1 ELSE 0 END),0),COALESCE(sum(i.origin='manual'),0),COALESCE(sum(i.origin='alert'),0) FROM incident_capsules c JOIN incidents i ON i.deployment_id=c.deployment_id AND i.id=c.incident_id WHERE c.deployment_id=? AND c.payload IS NOT NULL`, deploymentID).Scan(&usage.Retained, &usage.Resolved, &manual, &alert); err != nil {
		return incidentCapsuleUsage{}, err
	}
	if manual > math.MaxInt64/incidentManualCapsuleAdmissionReservationBytes || alert > math.MaxInt64/alertFiringIncidentReservationBytes {
		return incidentCapsuleUsage{}, errors.New("incident capsule reservation overflow")
	}
	manualBytes := manual * incidentManualCapsuleAdmissionReservationBytes
	alertBytes := alert * alertFiringIncidentReservationBytes
	if alertBytes > math.MaxInt64-manualBytes {
		return incidentCapsuleUsage{}, errors.New("incident capsule reservation overflow")
	}
	usage.Reservations = manualBytes + alertBytes
	var cursorJSON string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&cursorJSON); err != nil {
		return incidentCapsuleUsage{}, err
	}
	pendingAlert, _, _, err := readPendingAlertCapacity(cursorJSON)
	if err != nil {
		return incidentCapsuleUsage{}, err
	}
	pendingManual, err := readPendingManualIncidentCapacity(cursorJSON)
	if err != nil || pendingManual > math.MaxInt64-pendingAlert {
		return incidentCapsuleUsage{}, ErrIncidentCapacity
	}
	usage.PendingWrites = pendingAlert + pendingManual
	return usage, nil
}

const manualIncidentPendingCapacityKey = "capacity_pending_manual_incident_bytes"

func readPendingManualIncidentCapacity(encoded string) (int64, error) {
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &root) != nil {
		return 0, ErrIncidentCapacity
	}
	raw, ok := root[manualIncidentPendingCapacityKey]
	if !ok {
		return 0, nil
	}
	var pending int64
	if json.Unmarshal(raw, &pending) != nil || pending < 0 {
		return 0, ErrIncidentCapacity
	}
	return pending, nil
}

func writePendingManualIncidentCapacity(ctx context.Context, tx *sql.Tx, deploymentID string, pending int64) error {
	if pending < 0 {
		return ErrIncidentCapacity
	}
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&encoded); err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &root) != nil || root == nil {
		return ErrIncidentCapacity
	}
	root[manualIncidentPendingCapacityKey], _ = json.Marshal(pending)
	updated, err := json.Marshal(root)
	if err != nil || len(updated) > 65536 {
		return ErrIncidentCapacity
	}
	_, err = tx.ExecContext(ctx, `UPDATE maintenance SET evaluator_cursor_json=? WHERE deployment_id=?`, string(updated), deploymentID)
	return err
}

func reserveManualIncidentLiveCapacityTx(ctx context.Context, tx *sql.Tx, deploymentID string, requested, now int64) error {
	var state, cursorJSON string
	if err := tx.QueryRowContext(ctx, `SELECT storage_state,evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&state, &cursorJSON); err != nil || state == StorageReadOnlyENOSPC {
		return ErrIncidentCapacity
	}
	observedMS, _, pendingBulk, err := readCapacityCursor(cursorJSON)
	if err != nil || observedMS > now+5000 || now-observedMS > CapacityMeasurementMaxAge.Milliseconds() {
		return ErrIncidentCapacity
	}
	pendingRecovery, err := readPendingRecoveryCapacity(cursorJSON)
	if err != nil {
		return ErrIncidentCapacity
	}
	_, _, pendingAlertLive, err := readPendingAlertCapacity(cursorJSON)
	if err != nil {
		return ErrIncidentCapacity
	}
	pendingManual, err := readPendingManualIncidentCapacity(cursorJSON)
	if err != nil {
		return ErrIncidentCapacity
	}
	pending := int64(0)
	for _, value := range []int64{pendingBulk, pendingRecovery, pendingAlertLive, pendingManual} {
		if value > math.MaxInt64-pending {
			return ErrIncidentCapacity
		}
		pending += value
	}
	var limit, current, reserved int64
	if err := tx.QueryRowContext(ctx, `SELECT byte_limit,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='live_total'`, deploymentID).Scan(&limit, &current, &reserved); err != nil {
		return ErrIncidentCapacity
	}
	if requested > limit || current > math.MaxInt64-reserved || current+reserved > math.MaxInt64-pending || current+reserved+pending > limit-requested || requested > math.MaxInt64-pendingManual {
		return ErrIncidentCapacity
	}
	return writePendingManualIncidentCapacity(ctx, tx, deploymentID, pendingManual+requested)
}

func expireIncidentCapsuleTx(ctx context.Context, tx *sql.Tx, deploymentID, incidentID string, startMS int64, loss *incidentLossBatch, now int64) error {
	result, err := tx.ExecContext(ctx, `UPDATE incident_capsules SET payload=NULL,physical_reservation_bytes=0,evidence_state=? WHERE deployment_id=? AND incident_id=? AND payload IS NOT NULL`, loss.Reason, deploymentID, incidentID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("incident capsule changed during retention")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE incidents SET evidence_expiry_reason=?,version=version+1,updated_ms=? WHERE deployment_id=? AND id=?`, loss.Reason, now, deploymentID, incidentID); err != nil {
		return err
	}
	if !loss.Initialized || startMS < loss.FirstMS {
		loss.FirstMS = startMS
	}
	if !loss.Initialized || startMS > loss.LastMS {
		loss.LastMS = startMS
	}
	loss.Initialized, loss.Count = true, loss.Count+1
	return nil
}

func recordIncidentLossesTx(ctx context.Context, tx *sql.Tx, deploymentID, actorUserID string, losses map[string]*incidentLossBatch, now int64) error {
	var earliest sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT min(i.start_ms) FROM incidents i JOIN incident_capsules c ON c.deployment_id=i.deployment_id AND c.incident_id=i.id WHERE i.deployment_id=? AND c.payload IS NOT NULL`, deploymentID).Scan(&earliest); err != nil {
		return err
	}
	for _, reason := range []string{"evidence_expired_age", "evidence_expired_quota"} {
		loss := losses[reason]
		if loss == nil || loss.Count == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO retention_loss_ledger(deployment_id,class,reason,first_ms,last_ms,loss_count,earliest_retained_ms,updated_ms) VALUES(?,'incident_capsule',?,?,?,?,?,?) ON CONFLICT(deployment_id,class,reason) DO UPDATE SET first_ms=min(retention_loss_ledger.first_ms,excluded.first_ms),last_ms=max(retention_loss_ledger.last_ms,excluded.last_ms),loss_count=retention_loss_ledger.loss_count+excluded.loss_count,earliest_retained_ms=excluded.earliest_retained_ms,updated_ms=excluded.updated_ms`, deploymentID, loss.Reason, loss.FirstMS, loss.LastMS, loss.Count, nullableInt64SQLValue(earliest), now); err != nil {
			return err
		}
		auditID, err := domain.NewUUID()
		if err != nil {
			return err
		}
		detail, _ := json.Marshal(struct {
			Reason             string `json:"reason"`
			LossCount          int64  `json:"loss_count"`
			FirstIncidentMS    int64  `json:"first_incident_ms"`
			LastIncidentMS     int64  `json:"last_incident_ms"`
			EarliestRetainedMS *int64 `json:"earliest_retained_ms"`
		}{loss.Reason, loss.Count, loss.FirstMS, loss.LastMS, nullableInt64Pointer(earliest)})
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,'incident.evidence.expire',?,?,?)`, auditID, deploymentID, actorUserID, deploymentID, now, string(detail)); err != nil {
			return err
		}
	}
	return nil
}

func nullableInt64SQLValue(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func validateIncidentReopenTx(ctx context.Context, tx *sql.Tx, deploymentID, incidentID string, expiryReason *string) error {
	if expiryReason != nil {
		return ErrIncidentState
	}
	var payloadBytes, capsuleReservation int64
	var evidenceState string
	if err := tx.QueryRowContext(ctx, `SELECT length(payload),physical_reservation_bytes,evidence_state FROM incident_capsules WHERE deployment_id=? AND incident_id=?`, deploymentID, incidentID).Scan(&payloadBytes, &capsuleReservation, &evidenceState); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIncidentState
		}
		return err
	}
	if payloadBytes <= 0 || capsuleReservation < incidentCapsulePayloadReservationBytes || (evidenceState != "complete" && evidenceState != "partial") {
		return ErrIncidentState
	}
	var limit, current, externallyReserved int64
	var countLimit sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT byte_limit,count_limit,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='incident_ledger'`, deploymentID).Scan(&limit, &countLimit, &current, &externallyReserved); err != nil {
		return err
	}
	var capsuleCount int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incident_capsules WHERE deployment_id=? AND payload IS NOT NULL`, deploymentID).Scan(&capsuleCount); err != nil {
		return err
	}
	if capsuleCount > math.MaxInt64/incidentManualCapsuleAdmissionReservationBytes {
		return ErrIncidentCapacity
	}
	capsuleReservations := capsuleCount * incidentManualCapsuleAdmissionReservationBytes
	accounted := current
	if capsuleReservations > accounted {
		accounted = capsuleReservations
	}
	if (countLimit.Valid && capsuleCount > countLimit.Int64) || accounted > limit || externallyReserved > limit-accounted {
		return ErrIncidentCapacity
	}
	return nil
}

func readIncidentReceipt(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, now int64) (IncidentSummaryResult, bool, error) {
	var storedHash, resultJSON string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &resultJSON, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return IncidentSummaryResult{}, false, nil
	}
	if err != nil {
		return IncidentSummaryResult{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return IncidentSummaryResult{}, false, err
		}
		return IncidentSummaryResult{}, false, nil
	}
	if storedHash != requestHash {
		return IncidentSummaryResult{}, false, ErrIncidentConflict
	}
	var result IncidentSummaryResult
	if json.Unmarshal([]byte(resultJSON), &result) != nil || !validIncidentSummaryResult(result, 1) {
		return IncidentSummaryResult{}, false, ErrIncidentConflict
	}
	var deploymentID string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id FROM incidents WHERE id=?`, result.ID).Scan(&deploymentID); err != nil || deploymentID != actor.DeploymentID {
		return IncidentSummaryResult{}, false, ErrIncidentConflict
	}
	return result, true, nil
}

func readIncidentMutationReceipt(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, now int64) (IncidentSummaryResult, bool, error) {
	var storedHash, resultJSON string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &resultJSON, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return IncidentSummaryResult{}, false, nil
	}
	if err != nil {
		return IncidentSummaryResult{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return IncidentSummaryResult{}, false, err
		}
		return IncidentSummaryResult{}, false, nil
	}
	if storedHash != requestHash {
		return IncidentSummaryResult{}, false, ErrIncidentConflict
	}
	var result IncidentSummaryResult
	if json.Unmarshal([]byte(resultJSON), &result) != nil || !validIncidentSummaryResult(result, 2) {
		return IncidentSummaryResult{}, false, ErrIncidentConflict
	}
	var deploymentID string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id FROM incidents WHERE id=?`, result.ID).Scan(&deploymentID); err != nil || deploymentID != actor.DeploymentID {
		return IncidentSummaryResult{}, false, ErrIncidentConflict
	}
	return result, true, nil
}

func incidentSummaryResultFromRecord(record IncidentRecord) IncidentSummaryResult {
	return IncidentSummaryResult{
		ID:                   record.ID,
		Revision:             record.Revision,
		Title:                record.Title,
		ScopeJSON:            record.ScopeJSON,
		Origin:               record.Origin,
		StartMS:              record.StartMS,
		EndMS:                record.EndMS,
		WorkflowState:        record.WorkflowState,
		OwnerUserID:          record.OwnerUserID,
		EvidenceState:        record.EvidenceState,
		EvidenceExpiryReason: record.EvidenceExpiryReason,
		CapsuleSHA256:        record.CapsuleSHA256,
		CreatedMS:            record.CreatedMS,
		UpdatedMS:            record.UpdatedMS,
	}
}

func validIncidentSummaryResult(result IncidentSummaryResult, minimumRevision int64) bool {
	return validUUIDText(result.ID) && result.Revision >= minimumRevision && result.Title != "" && utf8.RuneCountInString(result.Title) <= 160 && !invalidManualIncidentTitle(result.Title) && result.Origin == "manual" && result.StartMS >= 0 && result.EndMS > result.StartMS && json.Valid([]byte(result.ScopeJSON)) && (result.WorkflowState == "open" || result.WorkflowState == "closed") && sha256HexPattern.MatchString(result.CapsuleSHA256) && result.CreatedMS >= 0 && result.UpdatedMS >= result.CreatedMS
}

type rowScanner interface{ Scan(...any) error }

func scanIncident(row rowScanner, includePayload bool) (IncidentRecord, error) {
	var record IncidentRecord
	var endMS sql.NullInt64
	var owner, expiry, capsuleSchema, cardRevision, capsuleHash, evidence sql.NullString
	values := []any{&record.ID, &record.Revision, &record.Title, &record.ScopeJSON, &record.Origin, &record.StartMS, &endMS, &record.WorkflowState, &owner, &expiry, &evidence, &capsuleSchema, &cardRevision}
	if includePayload {
		values = append(values, &record.CapsulePayload)
	}
	values = append(values, &capsuleHash, &record.CreatedMS, &record.UpdatedMS)
	if err := row.Scan(values...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IncidentRecord{}, ErrIncidentNotFound
		}
		return IncidentRecord{}, err
	}
	record.OwnerUserID = nullableStringPointer(owner)
	record.EndMS, record.EndMSValid = endMS.Int64, endMS.Valid
	record.EvidenceExpiryReason = nullableStringPointer(expiry)
	record.EvidenceState, record.CapsuleSchemaRevision, record.CardRevision, record.CapsuleSHA256 = evidence.String, capsuleSchema.String, cardRevision.String, capsuleHash.String
	record.Annotations = []AnnotationRecord{}
	return record, nil
}

func readIncidentTx(ctx context.Context, tx *sql.Tx, deploymentID, incidentID string, includePayload bool) (IncidentRecord, error) {
	columns := `i.id,i.version,i.title,i.target_scope_json,i.origin,i.start_ms,i.end_ms,i.workflow_state,i.owner_user_id,i.evidence_expiry_reason,c.evidence_state,c.schema_revision,c.card_revision`
	if includePayload {
		columns += `,c.payload`
	}
	columns += `,c.payload_sha256,i.created_ms,i.updated_ms`
	record, err := scanIncident(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM incidents i LEFT JOIN incident_capsules c ON c.deployment_id=i.deployment_id AND c.incident_id=i.id WHERE i.deployment_id=? AND i.id=?`, deploymentID, incidentID), includePayload)
	if err != nil {
		return IncidentRecord{}, err
	}
	page, err := readAnnotationPageTx(ctx, tx, deploymentID, incidentID, "", annotationPageLimit)
	if err != nil {
		return IncidentRecord{}, err
	}
	record.Annotations, record.AnnotationsNextCursor = page.Items, page.NextCursor
	return record, nil
}

func readAnnotationPageTx(ctx context.Context, tx *sql.Tx, deploymentID, incidentID, cursor string, limit int) (AnnotationPage, error) {
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE deployment_id=? AND id=?`, deploymentID, incidentID).Scan(&exists); err != nil {
		return AnnotationPage{}, err
	}
	if exists != 1 {
		return AnnotationPage{}, ErrIncidentNotFound
	}
	query := `SELECT id,version,incident_id,declared_time_ms,text,author_user_id,edited_ms,created_ms FROM annotations WHERE deployment_id=? AND incident_id=?`
	arguments := []any{deploymentID, incidentID}
	if cursor != "" {
		var createdMS int64
		if err := tx.QueryRowContext(ctx, `SELECT created_ms FROM annotations WHERE deployment_id=? AND incident_id=? AND id=?`, deploymentID, incidentID, cursor).Scan(&createdMS); err != nil {
			return AnnotationPage{}, ErrIncidentInvalid
		}
		query += ` AND (created_ms>? OR (created_ms=? AND id>?))`
		arguments = append(arguments, createdMS, createdMS, cursor)
	}
	query += ` ORDER BY created_ms,id LIMIT ?`
	arguments = append(arguments, limit+1)
	rows, err := tx.QueryContext(ctx, query, arguments...)
	if err != nil {
		return AnnotationPage{}, err
	}
	defer rows.Close()
	page := AnnotationPage{Items: []AnnotationRecord{}}
	for rows.Next() {
		var annotation AnnotationRecord
		var edited sql.NullInt64
		if err := rows.Scan(&annotation.ID, &annotation.Revision, &annotation.IncidentID, &annotation.DeclaredTimeMS, &annotation.Text, &annotation.AuthorUserID, &edited, &annotation.CreatedMS); err != nil {
			return AnnotationPage{}, err
		}
		annotation.EditedMS = nullableInt64Pointer(edited)
		page.Items = append(page.Items, annotation)
	}
	if err := rows.Err(); err != nil {
		return AnnotationPage{}, err
	}
	if len(page.Items) > limit {
		cursor := page.Items[limit-1].ID
		page.Items, page.NextCursor = page.Items[:limit], &cursor
	}
	return page, nil
}

func readAnnotationTx(ctx context.Context, tx *sql.Tx, deploymentID, annotationID string) (AnnotationRecord, error) {
	var record AnnotationRecord
	var edited sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id,version,incident_id,declared_time_ms,text,author_user_id,edited_ms,created_ms FROM annotations WHERE deployment_id=? AND id=? AND incident_id IS NOT NULL`, deploymentID, annotationID).Scan(&record.ID, &record.Revision, &record.IncidentID, &record.DeclaredTimeMS, &record.Text, &record.AuthorUserID, &edited, &record.CreatedMS)
	if errors.Is(err, sql.ErrNoRows) {
		return AnnotationRecord{}, ErrAnnotationNotFound
	}
	if err != nil {
		return AnnotationRecord{}, err
	}
	record.EditedMS = nullableInt64Pointer(edited)
	return record, nil
}

func readAnnotationReceipt(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, now int64) (AnnotationRecord, bool, error) {
	var storedHash, resultJSON string
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT request_body_sha256,result_json,expires_ms FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key).Scan(&storedHash, &resultJSON, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return AnnotationRecord{}, false, nil
	}
	if err != nil {
		return AnnotationRecord{}, false, err
	}
	if expires <= now {
		if _, err := tx.ExecContext(ctx, `DELETE FROM idempotency_receipts WHERE deployment_id=? AND deployment_generation=? AND actor_user_id=? AND idempotency_key=?`, actor.DeploymentID, actor.Generation, actor.User.ID, key); err != nil {
			return AnnotationRecord{}, false, err
		}
		return AnnotationRecord{}, false, nil
	}
	if storedHash != requestHash {
		return AnnotationRecord{}, false, ErrIncidentConflict
	}
	var record AnnotationRecord
	if json.Unmarshal([]byte(resultJSON), &record) != nil || !validAnnotationReceiptResult(record) {
		return AnnotationRecord{}, false, ErrIncidentConflict
	}
	var deploymentID string
	if err := tx.QueryRowContext(ctx, `SELECT deployment_id FROM annotations WHERE id=?`, record.ID).Scan(&deploymentID); err != nil || deploymentID != actor.DeploymentID {
		return AnnotationRecord{}, false, ErrIncidentConflict
	}
	return record, true, nil
}

func validAnnotationReceiptResult(record AnnotationRecord) bool {
	return validUUIDText(record.ID) && record.Revision >= 1 && validUUIDText(record.IncidentID) && record.DeclaredTimeMS >= 0 && validAnnotationText(record.Text) && validUUIDText(record.AuthorUserID) && record.CreatedMS >= 0 && (record.EditedMS == nil || *record.EditedMS >= record.CreatedMS)
}

func writeAnnotationAuditAndReceipt(ctx context.Context, tx *sql.Tx, actor SessionRecord, key, requestHash string, record AnnotationRecord, previousText, action string, now int64, status int) error {
	auditID, err := domain.NewUUID()
	if err != nil {
		return err
	}
	detail, _ := json.Marshal(struct {
		IncidentID         string  `json:"incident_id"`
		Revision           int64   `json:"revision"`
		TextSHA256         string  `json:"text_sha256"`
		PreviousTextSHA256 *string `json:"previous_text_sha256"`
	}{record.IncidentID, record.Revision, sha256Text(record.Text), optionalSHA256Text(previousText)})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id,deployment_id,actor_user_id,action,resource_id,time_ms,allowlisted_detail_json) VALUES(?,?,?,?,?,?,?)`, auditID, actor.DeploymentID, actor.User.ID, action, record.ID, now, string(detail)); err != nil {
		return err
	}
	receiptJSON, _ := json.Marshal(record)
	_, err = tx.ExecContext(ctx, `INSERT INTO idempotency_receipts(deployment_id,deployment_generation,actor_user_id,idempotency_key,request_body_sha256,result_status,result_json,created_ms,expires_ms) VALUES(?,?,?,?,?,?,?,?,?)`, actor.DeploymentID, actor.Generation, actor.User.ID, key, requestHash, status, string(receiptJSON), now, now+86400000)
	return err
}

func sha256Text(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func optionalSHA256Text(value string) *string {
	if value == "" {
		return nil
	}
	hash := sha256Text(value)
	return &hash
}
