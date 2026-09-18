package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"rmt.local/monitor/internal/alerts"
	"rmt.local/monitor/internal/domain"
)

func TestRuleCreateReadExactRetryAndVersionedEdit(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	hostID := insertAlertTestHost(t, st, admin)
	definition := fixedRuleDefinition(alerts.RuleHeavyCPU, hostID, json.RawMessage(`0.9`), 60_000, 60_000)
	key := "00000000-0000-4000-8000-000000000701"
	hash := strings.Repeat("a", 64)
	created, err := st.CreateRule(context.Background(), admin, key, hash, definition)
	if err != nil || created.Revision != 1 || created.Definition.ExpectedRevision == nil || *created.Definition.ExpectedRevision != 1 {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	retry, err := st.CreateRule(context.Background(), admin, key, hash, definition)
	if err != nil || retry.ID != created.ID {
		t.Fatalf("retry=%#v err=%v", retry, err)
	}
	if _, err := st.CreateRule(context.Background(), admin, key, strings.Repeat("b", 64), definition); !errors.Is(err, ErrRuleConflict) {
		t.Fatalf("changed retry err=%v", err)
	}
	read, err := st.ReadRule(context.Background(), admin, created.ID)
	if err != nil || read.ID != created.ID || read.Definition.ScopeID != hostID {
		t.Fatalf("read=%#v err=%v", read, err)
	}
	listed, err := st.ListRules(context.Background(), admin)
	if err != nil || len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("list=%#v err=%v", listed, err)
	}

	instanceID, _ := domain.NewUUID()
	now := clock.Now().UnixMilli()
	if _, err := st.db.Exec(`INSERT INTO alert_instances(id,deployment_id,rule_id,rule_version,scope_fingerprint,active_generation,state,data_state,dwell_ms,last_eval_ms,opened_ms,transition_seq) VALUES(?,?,?,?,?,1,'FIRING','valid',0,?,?,1)`, instanceID, admin.DeploymentID, created.ID, 1, strings.Repeat("c", 64), now, now); err != nil {
		t.Fatal(err)
	}
	expected := int64(1)
	definition.ExpectedRevision = &expected
	definition.Enabled = false
	updated, err := st.UpdateRule(context.Background(), admin, created.ID, "00000000-0000-4000-8000-000000000702", strings.Repeat("d", 64), definition)
	if err != nil || updated.Revision != 2 || updated.Definition.Enabled || updated.Definition.ExpectedRevision == nil || *updated.Definition.ExpectedRevision != 2 {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
	var state string
	var transitions int
	if err := st.db.QueryRow(`SELECT state FROM alert_instances WHERE id=?`, instanceID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT count(*) FROM alert_transitions WHERE instance_id=? AND new_state='superseded'`, instanceID).Scan(&transitions); err != nil {
		t.Fatal(err)
	}
	if state != "superseded" || transitions != 1 {
		t.Fatalf("state=%s transitions=%d", state, transitions)
	}
	if _, err := st.UpdateRule(context.Background(), admin, created.ID, "00000000-0000-4000-8000-000000000703", strings.Repeat("e", 64), definition); !errors.Is(err, ErrRuleRevision) {
		t.Fatalf("stale revision err=%v", err)
	}
}

func TestRuleDefinitionsAreClosedToShippedMacSemantics(t *testing.T) {
	st, _, admin := newEnrollmentStore(t)
	hostID := insertAlertTestHost(t, st, admin)
	cases := []struct {
		name       string
		definition RuleDefinition
	}{
		{"changed CPU threshold", fixedRuleDefinition(alerts.RuleHeavyCPU, hostID, json.RawMessage(`0.8`), 60_000, 60_000)},
		{"changed pressure dwell", fixedRuleDefinition(alerts.RuleMemoryPressure, hostID, json.RawMessage(`"warning"`), 1, 60_000)},
		{"wrong scope kind", fixedRuleDefinition(alerts.RuleDiskMonitorHealth, hostID, json.RawMessage(`15000`), 30_000, 30_000)},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := "00000000-0000-4000-8000-00000000071" + string(rune('0'+index))
			if _, err := st.CreateRule(context.Background(), admin, key, strings.Repeat(string(rune('f'-index)), 64), tc.definition); !errors.Is(err, ErrRuleInvalid) && !errors.Is(err, ErrOwnershipMismatch) {
				t.Fatalf("definition accepted: %v", err)
			}
		})
	}
}

func fixedRuleDefinition(ruleType alerts.RuleType, scopeID string, threshold json.RawMessage, dwell, recovery int64) RuleDefinition {
	return RuleDefinition{EvaluatorType: ruleType, ScopeID: scopeID, Enabled: true, Threshold: threshold, DwellMS: dwell, RecoveryMS: recovery}
}

func insertAlertTestHost(t *testing.T, st *Store, admin SessionRecord) string {
	t.Helper()
	hostID, _ := domain.NewUUID()
	installationID, _ := domain.NewUUID()
	now := st.clock.Now().UnixMilli()
	if _, err := st.db.Exec(`INSERT INTO hosts(id,deployment_id,display_name,installation_uuid,current_session_generation,capabilities_json,created_ms,updated_ms) VALUES(?,?,?, ?,0,'{}',?,?)`, hostID, admin.DeploymentID, "Alert Host", installationID, now, now); err != nil {
		t.Fatal(err)
	}
	return hostID
}
