//go:build sqlite_dbstat

package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestCalibrateIncidentLedgerWorstCaseOpenCapsulesDBStat is an opt-in,
// bounded calibration witness. It records the actual SQLite b-tree and file
// allocation for the normative maximum 1000 protected open capsules using the
// storage schema's maximum capsule and scope sizes and the API's maximum title
// size. The output is evidence for a later reservation value; the test does
// not install or guess that value.
func TestCalibrateIncidentLedgerWorstCaseOpenCapsulesDBStat(t *testing.T) {
	if os.Getenv("RMT_RUN_INCIDENT_CALIBRATION") != "1" {
		t.Skip("set RMT_RUN_INCIDENT_CALIBRATION=1 for the bounded 1000-capsule dbstat witness")
	}
	st, clock, admin := newEnrollmentStore(t)
	ctx := context.Background()
	if _, err := st.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	baselineClasses, baselineFile := incidentCalibrationAllocation(t, ctx, st)

	title := strings.Repeat("𐍈", 160)
	scopePrefix := `{"kind":"host","id":"43000000-0000-4000-8000-000000000001","padding":"`
	scopeSuffix := `"}`
	scope := scopePrefix + strings.Repeat("s", 65536-len(scopePrefix)-len(scopeSuffix)) + scopeSuffix
	payload := []byte(`"` + strings.Repeat("p", int(incidentCapsulePayloadLimitBytes)-2) + `"`)
	if len(title) != 640 || len(scope) != 65536 || len(payload) != int(incidentCapsulePayloadLimitBytes) {
		t.Fatalf("fixture sizes title=%d scope=%d payload=%d", len(title), len(scope), len(payload))
	}

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	incidentStatement, err := tx.PrepareContext(ctx, `INSERT INTO incidents(id,deployment_id,target_scope_json,title,origin,start_ms,end_ms,workflow_state,version,created_ms,updated_ms) VALUES(?,?,?,?, 'manual',?,?, 'open',1,?,?)`)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	capsuleStatement, err := tx.PrepareContext(ctx, `INSERT INTO incident_capsules(deployment_id,incident_id,schema_revision,card_revision,payload,payload_sha256,physical_reservation_bytes,evidence_state) VALUES(?,?, 'incident-capsule-1','ec01-ec07-mac-1',?,?,?,'partial')`)
	if err != nil {
		incidentStatement.Close()
		tx.Rollback()
		t.Fatal(err)
	}
	now := clock.Now().UnixMilli()
	for index := 1; index <= int(incidentOpenLimit); index++ {
		incidentID := fmt.Sprintf("44000000-0000-4000-8000-%012d", index)
		if _, err := incidentStatement.ExecContext(ctx, incidentID, admin.DeploymentID, scope, title, now+int64(index), now+int64(index)+300000, now, now); err != nil {
			capsuleStatement.Close()
			incidentStatement.Close()
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := capsuleStatement.ExecContext(ctx, admin.DeploymentID, incidentID, payload, strings.Repeat("f", 64), incidentCapsulePayloadReservationBytes); err != nil {
			capsuleStatement.Close()
			incidentStatement.Close()
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := capsuleStatement.Close(); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := incidentStatement.Close(); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	classes, file := incidentCalibrationAllocation(t, ctx, st)
	incidentDelta := classes - baselineClasses
	fileDelta := file - baselineFile
	directBytes := incidentOpenLimit * (incidentCapsulePayloadLimitBytes + int64(len(scope)) + int64(len(title)))
	if incidentDelta <= directBytes || fileDelta < incidentDelta {
		t.Fatalf("calibration allocation incident_delta=%d file_delta=%d direct_fields=%d", incidentDelta, fileDelta, directBytes)
	}
	var sqliteVersion, sqliteSourceID string
	var pageSize int64
	if err := st.db.QueryRowContext(ctx, `SELECT sqlite_version(),sqlite_source_id()`).Scan(&sqliteVersion, &sqliteSourceID); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	perCapsuleCeiling := (incidentDelta + incidentOpenLimit - 1) / incidentOpenLimit
	pageRoundedReservation := ((perCapsuleCeiling + pageSize - 1) / pageSize) * pageSize
	if pageRoundedReservation != incidentManualCapsuleAdmissionReservationBytes {
		t.Fatalf("manual admission reservation=%d measured page-rounded=%d", incidentManualCapsuleAdmissionReservationBytes, pageRoundedReservation)
	}
	t.Logf("INCIDENT_DBSTAT_CALIBRATION sqlite_version=%s sqlite_source_id=%q page_size=%d open_capsules=%d payload_bytes=%d scope_bytes=%d title_bytes=%d incident_btree_delta=%d allocated_file_delta=%d measured_per_capsule_ceiling=%d", sqliteVersion, sqliteSourceID, pageSize, incidentOpenLimit, incidentCapsulePayloadLimitBytes, len(scope), len(title), incidentDelta, fileDelta, perCapsuleCeiling)
}

func incidentCalibrationAllocation(t *testing.T, ctx context.Context, st *Store) (int64, int64) {
	t.Helper()
	tx, err := st.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	classes, _, err := sqliteClassPages(ctx, tx)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	physical, err := st.PhysicalDatabaseAllocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return classes["incident_ledger"], physical.TotalBytes
}
