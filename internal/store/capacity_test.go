package store

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
)

func TestCapacityStatePreservesControlLaneWhenBulkPauses(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "monitor.db"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	state, _, err := store.EnsureDeployment(context.Background(), "capacity")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	observed, err := store.RecordCapacityObservation(context.Background(), state.DeploymentID, CapacityObservation{
		ObservedMS: now,
		FreeBytes:  8 << 30,
		Usage: []QuotaUsage{
			{Class: "live_total", PhysicalBytes: 15 << 30},
			{Class: "bulk_database", PhysicalBytes: 12 << 30},
			{Class: "control_ledger", PhysicalBytes: 1 << 20},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observed.State != StorageBulkIngestPaused || observed.BulkIngestAllowed || observed.OptionalJobsAllowed || !observed.ControlWritesAllowed {
		t.Fatalf("capacity state = %#v", observed)
	}
	bulk, err := store.CheckCapacityAdmission(context.Background(), state.DeploymentID, "bulk_database", 1)
	if err != nil || bulk.Allowed || bulk.SafeCode != "bulk_ingest_paused" {
		t.Fatalf("bulk admission = %#v, %v", bulk, err)
	}
	control, err := store.CheckCapacityAdmission(context.Background(), state.DeploymentID, "control_ledger", 1)
	if err != nil || !control.Allowed || control.SafeCode != "capacity_available" {
		t.Fatalf("control admission = %#v, %v", control, err)
	}

	observed, err = store.RecordCapacityObservation(context.Background(), state.DeploymentID, CapacityObservation{
		ObservedMS: now + 1,
		FreeBytes:  8 << 30,
		Usage:      []QuotaUsage{{Class: "control_ledger", PhysicalBytes: 32 << 20}},
	})
	if err != nil || observed.ControlWritesAllowed {
		t.Fatalf("exhausted control ledger = %#v, %v", observed, err)
	}
	control, err = store.CheckCapacityAdmission(context.Background(), state.DeploymentID, "control_ledger", 1)
	if err != nil || control.Allowed || control.SafeCode != "protected_capacity_exhausted" {
		t.Fatalf("exhausted control admission = %#v, %v", control, err)
	}
}

func TestCapacityFreeSpaceAndENOSPCStateAreExplicit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "monitor.db"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	state, _, err := store.EnsureDeployment(context.Background(), "capacity")
	if err != nil {
		t.Fatal(err)
	}
	base := CapacityObservation{ObservedMS: time.Now().UnixMilli(), FreeBytes: capacityWarningFreeBytes - 1, Usage: []QuotaUsage{{Class: "live_total", PhysicalBytes: 1 << 30}}}
	warning, err := store.RecordCapacityObservation(context.Background(), state.DeploymentID, base)
	if err != nil || warning.State != StorageWarning {
		t.Fatalf("free-space warning = %#v, %v", warning, err)
	}
	base.ObservedMS++
	base.FreeBytes = capacityPauseFreeBytes - 1
	paused, err := store.RecordCapacityObservation(context.Background(), state.DeploymentID, base)
	if err != nil || paused.State != StorageBulkIngestPaused || paused.BulkIngestAllowed {
		t.Fatalf("free-space pause = %#v, %v", paused, err)
	}
	base.ObservedMS++
	base.FreeBytes = 8 << 30
	base.ENOSPC = true
	readonly, err := store.RecordCapacityObservation(context.Background(), state.DeploymentID, base)
	if err != nil || readonly.State != StorageReadOnlyENOSPC || readonly.ControlWritesAllowed {
		t.Fatalf("ENOSPC state = %#v, %v", readonly, err)
	}
}

func TestBackupForecastAndPhysicalDatabaseAllocation(t *testing.T) {
	maximum, err := ForecastBackupSpace(LiveDataLimitBytes)
	if err != nil {
		t.Fatal(err)
	}
	if maximum.PeakInstallationBytes != 84<<30 || maximum.TwoVerifiedBackupsBytes != 32<<30 || maximum.MaximumFleetRecommendedBytes != 96<<30 {
		t.Fatalf("maximum forecast = %#v", maximum)
	}
	trial, err := ForecastBackupSpace(2 << 30)
	if err != nil || trial.PeakInstallationBytes != 14<<30 {
		t.Fatalf("trial forecast = %#v, %v", trial, err)
	}
	if _, err := ForecastBackupSpace(0); err == nil {
		t.Fatal("zero live measurement accepted")
	}

	store, err := Open(filepath.Join(t.TempDir(), "monitor.db"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	usage, err := store.PhysicalDatabaseAllocation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if usage.MainBytes <= 0 || usage.TotalBytes != usage.MainBytes+usage.WALBytes+usage.SHMBytes {
		t.Fatalf("physical database usage = %#v", usage)
	}
}

func TestMeasureCapacityAccountsSQLiteClassesAndResetsBulkSafetyAllowance(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	batch := testBatch(setup)
	if _, err := setup.store.IngestCollectorBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	var cursorJSON string
	if err := setup.store.db.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, setup.state.DeploymentID).Scan(&cursorJSON); err != nil {
		t.Fatal(err)
	}
	_, _, pending, err := readCapacityCursor(cursorJSON)
	if err != nil || pending <= int64(len(batch.Frames[0].Gauges)) {
		t.Fatalf("pending bulk safety allowance = %d, %v", pending, err)
	}
	state, err := setup.store.MeasureAndRecordCapacity(ctx, setup.state.DeploymentID, setup.store.clock.Now().UnixMilli(), ExternalCapacityUsage{})
	if err != nil {
		t.Fatal(err)
	}
	if state.LivePhysicalBytes <= 0 || state.LiveLimitBytes != LiveDataLimitBytes {
		t.Fatalf("measured state = %#v", state)
	}
	if err := setup.store.db.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, setup.state.DeploymentID).Scan(&cursorJSON); err != nil {
		t.Fatal(err)
	}
	_, _, pending, err = readCapacityCursor(cursorJSON)
	if err != nil || pending != 0 {
		t.Fatalf("measurement did not clear bulk allowance = %d, %v", pending, err)
	}
	var classified int64
	if err := setup.store.db.QueryRowContext(ctx, `SELECT sum(current_physical_bytes) FROM quota_classes WHERE deployment_id=? AND class IN ('bulk_database','detailed_snapshots','incident_ledger','control_ledger','metadata','saved_comparisons','completed_exports','transient','live_headroom')`, setup.state.DeploymentID).Scan(&classified); err != nil || classified != state.LivePhysicalBytes {
		t.Fatalf("classified physical allocation = %d live=%d err=%v", classified, state.LivePhysicalBytes, err)
	}
}

func TestCapacityMeasurementCannotEraseConcurrentIngestReservation(t *testing.T) {
	setup := newIngestSetup(t)
	ctx := context.Background()
	captured := make(chan struct{})
	continueMeasurement := make(chan struct{})
	setup.store.capacityMeasurementCaptured = func() {
		close(captured)
		<-continueMeasurement
	}
	t.Cleanup(func() { setup.store.capacityMeasurementCaptured = nil })

	measurement := make(chan error, 1)
	go func() {
		_, err := setup.store.MeasureAndRecordCapacity(ctx, setup.state.DeploymentID, setup.store.clock.Now().UnixMilli(), ExternalCapacityUsage{})
		measurement <- err
	}()
	select {
	case <-captured:
	case <-time.After(time.Second):
		t.Fatal("capacity measurement did not reach captured snapshot")
	}

	baseWaits := setup.store.db.Stats().WaitCount
	ingest := make(chan error, 1)
	go func() {
		_, err := setup.store.IngestCollectorBatch(ctx, testBatch(setup))
		ingest <- err
	}()
	deadline := time.Now().Add(time.Second)
	for setup.store.db.Stats().WaitCount == baseWaits && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if setup.store.db.Stats().WaitCount == baseWaits {
		close(continueMeasurement)
		t.Fatal("ingest did not wait behind capacity measurement transaction")
	}
	select {
	case err := <-ingest:
		close(continueMeasurement)
		t.Fatalf("ingest escaped measurement transaction: %v", err)
	default:
	}

	close(continueMeasurement)
	if err := <-measurement; err != nil {
		t.Fatal(err)
	}
	if err := <-ingest; err != nil {
		t.Fatal(err)
	}
	var cursorJSON string
	if err := setup.store.db.QueryRowContext(ctx, `SELECT evaluator_cursor_json FROM maintenance WHERE deployment_id=?`, setup.state.DeploymentID).Scan(&cursorJSON); err != nil {
		t.Fatal(err)
	}
	_, _, pending, err := readCapacityCursor(cursorJSON)
	if err != nil || pending < capacityFrameSafetyBytes {
		t.Fatalf("concurrent ingest reservation was lost: pending=%d err=%v", pending, err)
	}
}
