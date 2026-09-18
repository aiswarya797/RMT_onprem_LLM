package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

const (
	maxInvestigationConfigs = 16
	maxInvestigationEvents  = 32
)

type InvestigationFacts struct {
	HostID           string
	TargetID         *string
	Configs          []InvestigationConfig
	ConfigsTruncated bool
	Events           []InvestigationEvent
	EventsTruncated  bool
}

type InvestigationConfig struct {
	ID                  string
	ConfigHash          string
	ObservedMS          int64
	PrecedingObservedMS *int64
	FieldsJSON          json.RawMessage
	ProvenanceJSON      json.RawMessage
}

type InvestigationEvent struct {
	ID                    string
	Code                  string
	Severity              string
	OccurredStartMS       int64
	OccurredEndMS         int64
	DetectedMS            int64
	Source                string
	AllowlistedFieldsJSON json.RawMessage
	ProvenanceJSON        json.RawMessage
}

// ReadInvestigationFacts returns bounded metadata that is not represented by
// metric series. Identity resolution is independent of the selected time
// window, so a known retained scope with no samples in that window remains a
// valid investigation with explicit gaps.
func (s *Store) ReadInvestigationFacts(ctx context.Context, deploymentID, scopeKind, scopeID string, startMS, endMS int64) (InvestigationFacts, error) {
	if !validUUIDText(deploymentID) || startMS < 0 || endMS <= startMS || (scopeKind == "process" && !sha256HexPattern.MatchString(scopeID)) || (scopeKind != "process" && !validUUIDText(scopeID)) {
		return InvestigationFacts{}, ErrIncidentInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return InvestigationFacts{}, err
	}
	defer tx.Rollback()
	facts, err := resolveInvestigationScope(ctx, tx, deploymentID, scopeKind, scopeID)
	if err != nil {
		return InvestigationFacts{}, err
	}
	if facts.TargetID != nil {
		// Include the last captured state before the comparison range so a
		// change detected inside W can retain both exact config identities.
		rows, err := tx.QueryContext(ctx, `SELECT id,config_hash,observed_ms,preceding_observed_ms,fields_json,provenance_json FROM config_snapshots WHERE deployment_id=? AND host_id=? AND target_id=? AND observed_ms<? ORDER BY observed_ms DESC,id DESC LIMIT ?`, deploymentID, facts.HostID, *facts.TargetID, endMS, maxInvestigationConfigs+1)
		if err != nil {
			return InvestigationFacts{}, err
		}
		for rows.Next() {
			var item InvestigationConfig
			var preceding sql.NullInt64
			var fields, provenance string
			if err := rows.Scan(&item.ID, &item.ConfigHash, &item.ObservedMS, &preceding, &fields, &provenance); err != nil {
				rows.Close()
				return InvestigationFacts{}, err
			}
			item.PrecedingObservedMS = nullableInt64Pointer(preceding)
			item.FieldsJSON, item.ProvenanceJSON = json.RawMessage(fields), json.RawMessage(provenance)
			facts.Configs = append(facts.Configs, item)
		}
		if err := rows.Close(); err != nil {
			return InvestigationFacts{}, err
		}
		if len(facts.Configs) > maxInvestigationConfigs {
			facts.Configs, facts.ConfigsTruncated = facts.Configs[:maxInvestigationConfigs], true
		}
		for left, right := 0, len(facts.Configs)-1; left < right; left, right = left+1, right-1 {
			facts.Configs[left], facts.Configs[right] = facts.Configs[right], facts.Configs[left]
		}
	}
	eventQuery := `SELECT id,code,severity,occurred_start_ms,occurred_end_ms,detected_ms,source,allowlisted_fields_json,provenance_json FROM events WHERE deployment_id=? AND host_id=? AND occurred_start_ms<? AND occurred_end_ms>=?`
	arguments := []any{deploymentID, facts.HostID, endMS, startMS}
	if facts.TargetID != nil {
		eventQuery += ` AND (target_id=? OR target_id IS NULL)`
		arguments = append(arguments, *facts.TargetID)
	}
	eventQuery += ` ORDER BY occurred_start_ms,id LIMIT ?`
	arguments = append(arguments, maxInvestigationEvents+1)
	rows, err := tx.QueryContext(ctx, eventQuery, arguments...)
	if err != nil {
		return InvestigationFacts{}, err
	}
	for rows.Next() {
		var item InvestigationEvent
		var fields, provenance string
		if err := rows.Scan(&item.ID, &item.Code, &item.Severity, &item.OccurredStartMS, &item.OccurredEndMS, &item.DetectedMS, &item.Source, &fields, &provenance); err != nil {
			rows.Close()
			return InvestigationFacts{}, err
		}
		item.AllowlistedFieldsJSON, item.ProvenanceJSON = json.RawMessage(fields), json.RawMessage(provenance)
		facts.Events = append(facts.Events, item)
	}
	if err := rows.Close(); err != nil {
		return InvestigationFacts{}, err
	}
	if len(facts.Events) > maxInvestigationEvents {
		facts.Events, facts.EventsTruncated = facts.Events[:maxInvestigationEvents], true
	}
	if err := tx.Commit(); err != nil {
		return InvestigationFacts{}, err
	}
	return facts, nil
}

func resolveInvestigationScope(ctx context.Context, tx *sql.Tx, deploymentID, kind, id string) (InvestigationFacts, error) {
	var facts InvestigationFacts
	var target sql.NullString
	var err error
	switch kind {
	case "host":
		err = tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE deployment_id=? AND id=?`, deploymentID, id).Scan(&facts.HostID)
	case "runtime":
		err = tx.QueryRowContext(ctx, `SELECT host_id,id FROM targets WHERE deployment_id=? AND id=?`, deploymentID, id).Scan(&facts.HostID, &target)
	case "model":
		err = tx.QueryRowContext(ctx, `SELECT host_id,target_id FROM model_revisions WHERE deployment_id=? AND id=?`, deploymentID, id).Scan(&facts.HostID, &target)
	case "process":
		err = tx.QueryRowContext(ctx, `SELECT host_id,target_id FROM process_observations WHERE deployment_id=? AND process_key_sha256=? ORDER BY observed_ms DESC,source_id LIMIT 1`, deploymentID, id).Scan(&facts.HostID, &target)
	default:
		return InvestigationFacts{}, ErrIncidentInvalid
	}
	if errors.Is(err, sql.ErrNoRows) {
		return InvestigationFacts{}, ErrIncidentNotFound
	}
	if err != nil {
		return InvestigationFacts{}, err
	}
	if target.Valid {
		facts.TargetID = nullableStringPointer(target)
	}
	facts.Configs, facts.Events = []InvestigationConfig{}, []InvestigationEvent{}
	return facts, nil
}
