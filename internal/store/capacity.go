package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"time"
)

const (
	LiveDataLimitBytes             int64 = 16 << 30
	EmergencyReserveBytes          int64 = 128 << 20
	MaximumFleetRecommendedBytes   int64 = 96 << 30
	MaintenanceFixedAllowanceBytes int64 = 4 << 30
	CapacityMeasurementMaxAge            = 30 * time.Second
	capacityFrameSafetyBytes       int64 = 64 << 10

	capacityWarningFreeBytes int64 = 2 << 30
	capacityStopFreeBytes    int64 = 1 << 30
	capacityPauseFreeBytes   int64 = 512 << 20
)

var (
	ErrCapacityMeasurementUnavailable = errors.New("capacity measurement unavailable")
	ErrBulkIngestPaused               = errors.New("bulk ingest paused")
)

const (
	StorageNormal              = "normal"
	StorageWarning             = "warning"
	StorageOptionalJobsStopped = "optional_jobs_stopped"
	StorageBulkIngestPaused    = "bulk_ingest_paused"
	StorageReadOnlyENOSPC      = "read_only_enospc"
)

var quotaClasses = map[string]bool{
	"live_total": true, "bulk_database": true, "detailed_snapshots": true,
	"incident_ledger": true, "control_ledger": true, "metadata": true,
	"saved_comparisons": true, "completed_exports": true, "transient": true,
	"live_headroom": true, "emergency_outside_live": true,
	"request_samples": true, "attachment_staging": true,
}

var optionalCapacityClasses = map[string]bool{
	"detailed_snapshots": true,
	"saved_comparisons":  true,
	"completed_exports":  true,
	"transient":          true,
	"attachment_staging": true,
}

var bulkCapacityClasses = map[string]bool{
	"bulk_database":   true,
	"request_samples": true,
}

type QuotaUsage struct {
	Class         string
	PhysicalBytes int64
}

type CapacityObservation struct {
	Usage      []QuotaUsage
	FreeBytes  int64
	ObservedMS int64
	ENOSPC     bool
}

type CapacityState struct {
	State                string
	FreeBytes            int64
	LivePhysicalBytes    int64
	LiveReservedBytes    int64
	LiveLimitBytes       int64
	Reasons              []string
	BulkIngestAllowed    bool
	OptionalJobsAllowed  bool
	ControlWritesAllowed bool
	MeasurementMS        *int64
	MeasurementFresh     bool
}

type CapacityAdmission struct {
	Allowed        bool
	State          string
	SafeCode       string
	AvailableBytes int64
}

type BackupSpaceForecast struct {
	MeasuredLiveBytes            int64
	TwoVerifiedBackupsBytes      int64
	RotationStagingBytes         int64
	UpgradeSnapshotBytes         int64
	FixedReserveAndPackageBytes  int64
	PeakInstallationBytes        int64
	MaximumFleetRecommendedBytes int64
}

type PhysicalDatabaseUsage struct {
	MainBytes  int64
	WALBytes   int64
	SHMBytes   int64
	TotalBytes int64
}

type ExternalCapacityUsage struct {
	DetailedSnapshotsBytes int64
	IncidentLedgerBytes    int64
	MetadataBytes          int64
	SavedComparisonsBytes  int64
	CompletedExportsBytes  int64
	TransientBytes         int64
	AttachmentStagingBytes int64
}

// RecordCapacityObservation persists bounded physical-usage observations and
// derives the documented pressure state. Callers measure external blobs and
// temporary files and include them in the relevant class and live_total; this
// method never substitutes payload-length arithmetic for physical allocation.
func (s *Store) RecordCapacityObservation(ctx context.Context, deploymentID string, observation CapacityObservation) (CapacityState, error) {
	if err := validateCapacityObservation(deploymentID, observation); err != nil {
		return CapacityState{}, err
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return CapacityState{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CapacityState{}, err
	}
	defer tx.Rollback()
	state, err := recordCapacityObservationTx(ctx, tx, deploymentID, observation, false)
	if err != nil {
		return CapacityState{}, err
	}
	if err := tx.Commit(); err != nil {
		return CapacityState{}, err
	}
	return state, nil
}

func validateCapacityObservation(deploymentID string, observation CapacityObservation) error {
	if deploymentID == "" || observation.ObservedMS < 0 || observation.FreeBytes < 0 || len(observation.Usage) == 0 || len(observation.Usage) > len(quotaClasses) {
		return errors.New("invalid capacity observation")
	}
	seen := make(map[string]bool, len(observation.Usage))
	for _, usage := range observation.Usage {
		if !quotaClasses[usage.Class] || seen[usage.Class] || usage.PhysicalBytes < 0 {
			return errors.New("invalid capacity class observation")
		}
		seen[usage.Class] = true
	}
	return nil
}

func recordCapacityObservationTx(ctx context.Context, tx *sql.Tx, deploymentID string, observation CapacityObservation, resetPending bool) (CapacityState, error) {
	seen := make(map[string]bool, len(observation.Usage))
	for _, usage := range observation.Usage {
		seen[usage.Class] = true
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO maintenance(deployment_id,retention_revision,rollup_watermark_ms,last_backup_ms,storage_state,recovery_journal_cursor,evaluator_cursor_json,updated_ms) VALUES(?,1,0,NULL,'normal',NULL,'{}',?) ON CONFLICT(deployment_id) DO NOTHING`, deploymentID, observation.ObservedMS); err != nil {
		return CapacityState{}, err
	}
	for _, usage := range observation.Usage {
		result, err := tx.ExecContext(ctx, `UPDATE quota_classes SET current_physical_bytes=?,updated_ms=? WHERE deployment_id=? AND class=?`, usage.PhysicalBytes, observation.ObservedMS, deploymentID, usage.Class)
		if err != nil {
			return CapacityState{}, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return CapacityState{}, fmt.Errorf("capacity class %s is not configured", usage.Class)
		}
	}
	if seen["live_total"] && seen["bulk_database"] {
		pending := int64(0)
		if !resetPending {
			var err error
			pending, err = readPendingBulkBytes(ctx, tx, deploymentID)
			if err != nil {
				return CapacityState{}, err
			}
		}
		if err := writeCapacityCursor(ctx, tx, deploymentID, observation.ObservedMS, observation.FreeBytes, pending); err != nil {
			return CapacityState{}, err
		}
	}
	state, err := readCapacityState(ctx, tx, deploymentID, observation.FreeBytes, observation.ENOSPC)
	if err != nil {
		return CapacityState{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE maintenance SET storage_state=?,updated_ms=? WHERE deployment_id=?`, state.State, observation.ObservedMS, deploymentID); err != nil {
		return CapacityState{}, err
	}
	return state, nil
}

func readPendingBulkBytes(ctx context.Context, tx *sql.Tx, deploymentID string) (int64, error) {
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&encoded); err != nil {
		return 0, err
	}
	var cursor map[string]json.RawMessage
	if err := json.Unmarshal([]byte(encoded), &cursor); err != nil {
		return 0, errors.New("invalid maintenance cursor")
	}
	raw, ok := cursor["capacity_pending_bulk_bytes"]
	if !ok {
		return 0, nil
	}
	var pending int64
	if json.Unmarshal(raw, &pending) != nil || pending < 0 {
		return 0, errors.New("invalid pending bulk capacity")
	}
	return pending, nil
}

func writeCapacityCursor(ctx context.Context, tx *sql.Tx, deploymentID string, observedMS, freeBytes, pendingBulkBytes int64) error {
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&encoded); err != nil {
		return err
	}
	var cursor map[string]json.RawMessage
	if err := json.Unmarshal([]byte(encoded), &cursor); err != nil {
		return errors.New("invalid maintenance cursor")
	}
	if cursor == nil {
		cursor = make(map[string]json.RawMessage)
	}
	for key, value := range map[string]int64{"capacity_observed_ms": observedMS, "capacity_free_bytes": freeBytes, "capacity_pending_bulk_bytes": pendingBulkBytes} {
		cursor[key], _ = json.Marshal(value)
	}
	updated, err := json.Marshal(cursor)
	if err != nil || len(updated) > 65536 {
		return errors.New("capacity maintenance cursor exceeds bound")
	}
	_, err = tx.ExecContext(ctx, `UPDATE maintenance SET evaluator_cursor_json=? WHERE deployment_id=?`, string(updated), deploymentID)
	return err
}

func readCapacityCursor(encoded string) (observedMS, freeBytes, pendingBulkBytes int64, err error) {
	var cursor map[string]json.RawMessage
	if json.Unmarshal([]byte(encoded), &cursor) != nil {
		return 0, 0, 0, ErrCapacityMeasurementUnavailable
	}
	for key, destination := range map[string]*int64{"capacity_observed_ms": &observedMS, "capacity_free_bytes": &freeBytes, "capacity_pending_bulk_bytes": &pendingBulkBytes} {
		raw, ok := cursor[key]
		if !ok || json.Unmarshal(raw, destination) != nil || *destination < 0 {
			return 0, 0, 0, ErrCapacityMeasurementUnavailable
		}
	}
	return observedMS, freeBytes, pendingBulkBytes, nil
}

func (s *Store) capacityAdmissionTx(ctx context.Context, tx *sql.Tx, deploymentID string, nowMS, requestedBytes int64) error {
	if requestedBytes < 0 {
		return ErrBulkIngestPaused
	}
	var state, cursorJSON string
	if err := tx.QueryRowContext(ctx, `SELECT storage_state,evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&state, &cursorJSON); err != nil {
		return ErrCapacityMeasurementUnavailable
	}
	observedMS, freeBytes, pending, err := readCapacityCursor(cursorJSON)
	if err != nil || observedMS > nowMS+5000 || nowMS-observedMS > CapacityMeasurementMaxAge.Milliseconds() || pending > math.MaxInt64-requestedBytes {
		return ErrCapacityMeasurementUnavailable
	}
	pendingRecovery, err := readPendingRecoveryCapacity(cursorJSON)
	if err != nil {
		return ErrCapacityMeasurementUnavailable
	}
	if state == StorageBulkIngestPaused || state == StorageReadOnlyENOSPC {
		return ErrBulkIngestPaused
	}
	for _, class := range []string{"live_total", "bulk_database"} {
		var limit, current, reserved int64
		if err := tx.QueryRowContext(ctx, `SELECT byte_limit,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class=?`, deploymentID, class).Scan(&limit, &current, &reserved); err != nil {
			return ErrCapacityMeasurementUnavailable
		}
		classPending := pending
		if class == "live_total" {
			if classPending > math.MaxInt64-pendingRecovery {
				return ErrCapacityMeasurementUnavailable
			}
			classPending += pendingRecovery
		}
		if requestedBytes > limit || current > math.MaxInt64-reserved || current+reserved > math.MaxInt64-classPending || current+reserved+classPending > limit-requestedBytes {
			return ErrBulkIngestPaused
		}
	}
	return writeCapacityCursor(ctx, tx, deploymentID, observedMS, freeBytes, pending+requestedBytes)
}

func batchCapacityBytes(payloadBytes, frameCount int) (int64, error) {
	if payloadBytes < 0 || frameCount < 0 || int64(frameCount) > (math.MaxInt64-int64(payloadBytes))/capacityFrameSafetyBytes {
		return 0, ErrBulkIngestPaused
	}
	return int64(payloadBytes) + int64(frameCount)*capacityFrameSafetyBytes, nil
}

func readCapacityState(ctx context.Context, tx *sql.Tx, deploymentID string, freeBytes int64, enospc bool) (CapacityState, error) {
	rows, err := tx.QueryContext(ctx, `SELECT class,byte_limit,warning_ratio,stop_ratio,pause_ratio,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? ORDER BY class`, deploymentID)
	if err != nil {
		return CapacityState{}, err
	}
	defer rows.Close()
	state := CapacityState{State: StorageNormal, FreeBytes: freeBytes, LiveLimitBytes: LiveDataLimitBytes, Reasons: make([]string, 0), BulkIngestAllowed: true, OptionalJobsAllowed: true, ControlWritesAllowed: true}
	controlExhausted := false
	count := 0
	for rows.Next() {
		var class string
		var limit, current, reserved int64
		var warning, stop, pause float64
		if err := rows.Scan(&class, &limit, &warning, &stop, &pause, &current, &reserved); err != nil {
			return CapacityState{}, err
		}
		count++
		if class == "live_total" {
			state.LiveLimitBytes, state.LivePhysicalBytes, state.LiveReservedBytes = limit, current, reserved
		}
		used := current + reserved
		if class == "control_ledger" && used >= limit {
			controlExhausted = true
		}
		// The emergency file is outside the live cap and is intentionally
		// preallocated. Its reservation is not pressure-triggering usage.
		if class == "emergency_outside_live" {
			continue
		}
		ratio := float64(used) / float64(limit)
		switch {
		case ratio >= pause:
			state.raise(StorageBulkIngestPaused, "quota:"+class+":pause")
		case ratio >= stop:
			state.raise(StorageOptionalJobsStopped, "quota:"+class+":stop")
		case ratio >= warning:
			state.raise(StorageWarning, "quota:"+class+":warning")
		}
	}
	if err := rows.Err(); err != nil {
		return CapacityState{}, err
	}
	if count != len(quotaClasses) {
		return CapacityState{}, errors.New("capacity quota contract is incomplete")
	}
	switch {
	case enospc:
		state.raise(StorageReadOnlyENOSPC, "write:enospc")
	case freeBytes < capacityPauseFreeBytes:
		state.raise(StorageBulkIngestPaused, "free_space:pause")
	case freeBytes < capacityStopFreeBytes:
		state.raise(StorageOptionalJobsStopped, "free_space:stop")
	case freeBytes < capacityWarningFreeBytes:
		state.raise(StorageWarning, "free_space:warning")
	}
	state.BulkIngestAllowed = state.State != StorageBulkIngestPaused && state.State != StorageReadOnlyENOSPC
	state.OptionalJobsAllowed = state.State == StorageNormal || state.State == StorageWarning
	state.ControlWritesAllowed = state.State != StorageReadOnlyENOSPC && !controlExhausted
	sort.Strings(state.Reasons)
	return state, nil
}

func (state *CapacityState) raise(next, reason string) {
	if capacitySeverity(next) > capacitySeverity(state.State) {
		state.State = next
	}
	state.Reasons = append(state.Reasons, reason)
}

func capacitySeverity(value string) int {
	switch value {
	case StorageWarning:
		return 1
	case StorageOptionalJobsStopped:
		return 2
	case StorageBulkIngestPaused:
		return 3
	case StorageReadOnlyENOSPC:
		return 4
	default:
		return 0
	}
}

// CheckCapacityAdmission applies the last persisted state and a class-local
// physical limit. It is advisory until called inside the owning write path;
// it never reserves bytes or promises admission across a later transaction.
func (s *Store) CheckCapacityAdmission(ctx context.Context, deploymentID, class string, requestedBytes int64) (CapacityAdmission, error) {
	if deploymentID == "" || !quotaClasses[class] || requestedBytes < 0 {
		return CapacityAdmission{}, errors.New("invalid capacity admission request")
	}
	var state string
	var limit, current, reserved int64
	err := s.db.QueryRowContext(ctx, `SELECT m.storage_state,q.byte_limit,q.current_physical_bytes,q.reserved_physical_bytes FROM maintenance m JOIN quota_classes q ON q.deployment_id=m.deployment_id WHERE m.deployment_id=? AND q.class=?`, deploymentID, class).Scan(&state, &limit, &current, &reserved)
	if err != nil {
		return CapacityAdmission{}, err
	}
	available := limit - current - reserved
	if available < 0 {
		available = 0
	}
	result := CapacityAdmission{Allowed: requestedBytes <= available, State: state, AvailableBytes: available, SafeCode: "capacity_available"}
	if state == StorageReadOnlyENOSPC {
		result.Allowed, result.SafeCode = false, "storage_read_only_enospc"
	} else if class == "control_ledger" || class == "incident_ledger" || class == "metadata" {
		if !result.Allowed {
			result.SafeCode = "protected_capacity_exhausted"
		}
	} else if state == StorageBulkIngestPaused && bulkCapacityClasses[class] {
		result.Allowed, result.SafeCode = false, "bulk_ingest_paused"
	} else if capacitySeverity(state) >= capacitySeverity(StorageOptionalJobsStopped) && optionalCapacityClasses[class] {
		result.Allowed, result.SafeCode = false, "optional_jobs_stopped"
	} else if !result.Allowed {
		result.SafeCode = "class_capacity_exhausted"
	}
	return result, nil
}

// ReadCapacityState returns the last persisted physical observation. Missing
// or stale measurement is exposed as bulk_ingest_paused, matching the write
// fence, while preserving a stronger persisted ENOSPC state.
func (s *Store) ReadCapacityState(ctx context.Context, deploymentID string, nowMS int64) (CapacityState, error) {
	if deploymentID == "" || nowMS < 0 {
		return CapacityState{}, errors.New("invalid capacity state request")
	}
	var persisted, cursorJSON string
	if err := s.db.QueryRowContext(ctx, `SELECT storage_state,evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, deploymentID).Scan(&persisted, &cursorJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CapacityState{State: StorageBulkIngestPaused, LiveLimitBytes: LiveDataLimitBytes, Reasons: []string{"measurement:unavailable"}}, nil
		}
		return CapacityState{}, err
	}
	var limit, current, reserved int64
	if err := s.db.QueryRowContext(ctx, `SELECT byte_limit,current_physical_bytes,reserved_physical_bytes FROM quota_classes WHERE deployment_id=? AND class='live_total'`, deploymentID).Scan(&limit, &current, &reserved); err != nil {
		return CapacityState{}, err
	}
	state := CapacityState{State: persisted, LiveLimitBytes: limit, LivePhysicalBytes: current, LiveReservedBytes: reserved, Reasons: make([]string, 0), BulkIngestAllowed: persisted != StorageBulkIngestPaused && persisted != StorageReadOnlyENOSPC, OptionalJobsAllowed: persisted == StorageNormal || persisted == StorageWarning, ControlWritesAllowed: persisted != StorageReadOnlyENOSPC}
	observedMS, freeBytes, _, err := readCapacityCursor(cursorJSON)
	if err != nil || observedMS > nowMS+5000 || nowMS-observedMS > CapacityMeasurementMaxAge.Milliseconds() {
		if state.State != StorageReadOnlyENOSPC {
			state.State = StorageBulkIngestPaused
		}
		state.BulkIngestAllowed = false
		state.OptionalJobsAllowed = false
		state.Reasons = append(state.Reasons, "measurement:unavailable_or_stale")
		return state, nil
	}
	state.MeasurementMS = &observedMS
	state.MeasurementFresh = true
	state.FreeBytes = freeBytes
	return state, nil
}

func (s *Store) CoverageGapCount(ctx context.Context, deploymentID string) (int, error) {
	if deploymentID == "" {
		return 0, errors.New("invalid coverage gap request")
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM coverage_gaps WHERE deployment_id=?`, deploymentID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// ForecastBackupSpace reports the conservative simultaneous footprint. It
// assumes no compression: live L + two verified backups 2L + rotation staging
// L + one pre-activation upgrade snapshot L + the fixed 4GiB allowance.
func ForecastBackupSpace(measuredLiveBytes int64) (BackupSpaceForecast, error) {
	if measuredLiveBytes <= 0 || measuredLiveBytes > LiveDataLimitBytes || measuredLiveBytes > (math.MaxInt64-MaintenanceFixedAllowanceBytes)/5 {
		return BackupSpaceForecast{}, errors.New("invalid measured live bytes")
	}
	return BackupSpaceForecast{
		MeasuredLiveBytes:            measuredLiveBytes,
		TwoVerifiedBackupsBytes:      2 * measuredLiveBytes,
		RotationStagingBytes:         measuredLiveBytes,
		UpgradeSnapshotBytes:         measuredLiveBytes,
		FixedReserveAndPackageBytes:  MaintenanceFixedAllowanceBytes,
		PeakInstallationBytes:        5*measuredLiveBytes + MaintenanceFixedAllowanceBytes,
		MaximumFleetRecommendedBytes: MaximumFleetRecommendedBytes,
	}, nil
}

// PhysicalDatabaseAllocation measures allocated filesystem blocks for the
// SQLite main, WAL and SHM files. It is a component of live_total, not a full
// live-data measurement because external blobs/staging are measured by their
// owning subsystems.
func (s *Store) PhysicalDatabaseAllocation(ctx context.Context) (PhysicalDatabaseUsage, error) {
	return physicalDatabaseAllocation(ctx, s.db)
}

func physicalDatabaseAllocation(ctx context.Context, query capacityQuerier) (PhysicalDatabaseUsage, error) {
	path, err := sqlitePath(ctx, query)
	if err != nil {
		return PhysicalDatabaseUsage{}, err
	}
	mainBytes, err := allocatedFileBytes(path)
	if err != nil {
		return PhysicalDatabaseUsage{}, err
	}
	walBytes, err := allocatedOptionalFileBytes(path + "-wal")
	if err != nil {
		return PhysicalDatabaseUsage{}, err
	}
	shmBytes, err := allocatedOptionalFileBytes(path + "-shm")
	if err != nil {
		return PhysicalDatabaseUsage{}, err
	}
	return PhysicalDatabaseUsage{MainBytes: mainBytes, WALBytes: walBytes, SHMBytes: shmBytes, TotalBytes: mainBytes + walBytes + shmBytes}, nil
}

// MeasureAndRecordCapacity measures exact total allocated SQLite blocks and
// bounded aggregate dbstat pages, adds explicitly supplied external artifacts,
// and records all live quota classes in one observation. Per-class SQLite
// values are proportional page attribution, not an independently measured
// physical claim; exact live_total plus persisted reservations remains the
// admission bound. dbstat aggregate mode returns one row per b-tree rather
// than walking an unbounded page stream. Disposable-volume qualification of
// the class attribution remains a release gate.
func (s *Store) MeasureAndRecordCapacity(ctx context.Context, deploymentID string, observedMS int64, external ExternalCapacityUsage) (CapacityState, error) {
	if deploymentID == "" || observedMS < 0 || !validExternalCapacity(external) {
		return CapacityState{}, errors.New("invalid capacity measurement request")
	}
	release, err := s.acquireWrite(ctx)
	if err != nil {
		return CapacityState{}, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CapacityState{}, err
	}
	defer tx.Rollback()

	// Keep the SQLite snapshot and the pending-reservation reset in the same
	// transaction. With the store's single SQLite connection, no later ingest
	// can be admitted between these operations and have its reservation erased.
	physical, err := physicalDatabaseAllocation(ctx, tx)
	if err != nil {
		return CapacityState{}, err
	}
	logical, requestLogical, err := sqliteClassPages(ctx, tx)
	if err != nil {
		return CapacityState{}, err
	}
	var logicalTotal int64
	for _, bytes := range logical {
		if bytes > math.MaxInt64-logicalTotal {
			return CapacityState{}, errors.New("sqlite class allocation overflow")
		}
		logicalTotal += bytes
	}
	if logicalTotal <= 0 {
		return CapacityState{}, errors.New("sqlite class allocation unavailable")
	}
	allocated := make(map[string]int64, len(logical)+3)
	var assigned int64
	for class, bytes := range logical {
		value := scaledAllocation(bytes, logicalTotal, physical.MainBytes)
		allocated[class] = value
		assigned += value
	}
	if assigned < physical.MainBytes {
		allocated["live_headroom"] += physical.MainBytes - assigned
	}
	allocated["transient"] += physical.WALBytes + physical.SHMBytes
	allocated["request_samples"] = scaledAllocation(requestLogical, logicalTotal, physical.MainBytes)

	for class, bytes := range map[string]int64{
		"detailed_snapshots": external.DetailedSnapshotsBytes,
		"incident_ledger":    external.IncidentLedgerBytes,
		"metadata":           external.MetadataBytes,
		"saved_comparisons":  external.SavedComparisonsBytes,
		"completed_exports":  external.CompletedExportsBytes,
		"transient":          external.TransientBytes,
	} {
		if allocated[class] > math.MaxInt64-bytes {
			return CapacityState{}, errors.New("external capacity allocation overflow")
		}
		allocated[class] += bytes
	}
	allocated["attachment_staging"] = external.AttachmentStagingBytes
	externalTotal := external.DetailedSnapshotsBytes + external.IncidentLedgerBytes + external.MetadataBytes + external.SavedComparisonsBytes + external.CompletedExportsBytes + external.TransientBytes
	if physical.TotalBytes > math.MaxInt64-externalTotal {
		return CapacityState{}, errors.New("live capacity allocation overflow")
	}
	allocated["live_total"] = physical.TotalBytes + externalTotal

	databasePath, err := sqlitePath(ctx, tx)
	if err != nil {
		return CapacityState{}, err
	}
	freeBytes, err := filesystemFreeBytes(databasePath)
	if err != nil {
		return CapacityState{}, err
	}
	usage := make([]QuotaUsage, 0, len(quotaClasses)-1)
	for class := range quotaClasses {
		if class == "emergency_outside_live" {
			continue
		}
		usage = append(usage, QuotaUsage{Class: class, PhysicalBytes: allocated[class]})
	}
	sort.Slice(usage, func(i, j int) bool { return usage[i].Class < usage[j].Class })
	if s.capacityMeasurementCaptured != nil {
		s.capacityMeasurementCaptured()
	}
	observation := CapacityObservation{Usage: usage, FreeBytes: freeBytes, ObservedMS: observedMS}
	if err := validateCapacityObservation(deploymentID, observation); err != nil {
		return CapacityState{}, err
	}
	state, err := recordCapacityObservationTx(ctx, tx, deploymentID, observation, true)
	if err != nil {
		return CapacityState{}, err
	}
	// The new physical snapshot now includes completed/revoked recovery rows.
	// Only this exact dbstat/filesystem measurement may clear their conservative
	// post-release safety charge.
	if err := writePendingRecoveryCapacity(ctx, tx, deploymentID, 0); err != nil {
		return CapacityState{}, err
	}
	// The same exact dbstat/filesystem snapshot also contains every alert row
	// committed before this transaction. Clear only the conservative alert
	// deltas; ordinary externally supplied observations retain them.
	if err := clearPendingAlertCapacityTx(ctx, tx, deploymentID); err != nil {
		return CapacityState{}, err
	}
	// Manual incident reservations use the same measured-delta discipline as
	// alert envelopes. They remain charged to live_total until this exact
	// SQLite/filesystem snapshot observes the committed rows.
	if err := writePendingManualIncidentCapacity(ctx, tx, deploymentID, 0); err != nil {
		return CapacityState{}, err
	}
	if err := tx.Commit(); err != nil {
		return CapacityState{}, err
	}
	return state, nil
}

type capacityQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func sqlitePath(ctx context.Context, query capacityQuerier) (string, error) {
	var sequence int
	var schemaName, path string
	if err := query.QueryRowContext(ctx, `PRAGMA database_list`).Scan(&sequence, &schemaName, &path); err != nil {
		return "", err
	}
	if schemaName != "main" || path == "" {
		return "", errors.New("sqlite main database path unavailable")
	}
	return path, nil
}

func sqliteClassPages(ctx context.Context, query capacityQuerier) (map[string]int64, int64, error) {
	rows, err := query.QueryContext(ctx, `SELECT d.name,d.pgsize,COALESCE(m.tbl_name,d.name) FROM dbstat AS d LEFT JOIN sqlite_schema AS m ON m.name=d.name WHERE d.aggregate=TRUE ORDER BY d.name`)
	if err != nil {
		return nil, 0, fmt.Errorf("measure sqlite b-trees: %w", err)
	}
	defer rows.Close()
	result := map[string]int64{"bulk_database": 0, "detailed_snapshots": 0, "incident_ledger": 0, "control_ledger": 0, "metadata": 0}
	var requestBytes int64
	for rows.Next() {
		var name, table string
		var bytes int64
		if err := rows.Scan(&name, &bytes, &table); err != nil {
			return nil, 0, err
		}
		if bytes < 0 {
			return nil, 0, errors.New("negative sqlite b-tree allocation")
		}
		class := sqliteTableCapacityClass(table)
		if result[class] > math.MaxInt64-bytes {
			return nil, 0, errors.New("sqlite b-tree allocation overflow")
		}
		result[class] += bytes
		if table == "request_runs" || table == "request_samples" {
			requestBytes += bytes
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return result, requestBytes, nil
}

func sqliteTableCapacityClass(table string) string {
	switch table {
	case "source_frames", "counter_epochs", "rollup_minutes", "rollup_hours", "request_runs", "request_samples", "process_observations", "model_load_observations":
		return "bulk_database"
	case "snapshots":
		return "detailed_snapshots"
	case "incidents", "incident_capsules", "alert_instances", "alert_transitions":
		return "incident_ledger"
	case "comparisons":
		return "saved_comparisons"
	case "source_status", "coverage_gaps", "retention_loss_ledger":
		return "control_ledger"
	default:
		return "metadata"
	}
}

func scaledAllocation(value, total, allocated int64) int64 {
	if value <= 0 || total <= 0 || allocated <= 0 {
		return 0
	}
	numerator := new(big.Int).Mul(big.NewInt(value), big.NewInt(allocated))
	numerator.Quo(numerator, big.NewInt(total))
	return numerator.Int64()
}

func validExternalCapacity(value ExternalCapacityUsage) bool {
	values := []int64{value.DetailedSnapshotsBytes, value.IncidentLedgerBytes, value.MetadataBytes, value.SavedComparisonsBytes, value.CompletedExportsBytes, value.TransientBytes, value.AttachmentStagingBytes}
	var total int64
	for _, bytes := range values[:6] {
		if bytes < 0 || bytes > math.MaxInt64-total {
			return false
		}
		total += bytes
	}
	return value.AttachmentStagingBytes >= 0 && value.AttachmentStagingBytes <= value.TransientBytes && total <= LiveDataLimitBytes
}
