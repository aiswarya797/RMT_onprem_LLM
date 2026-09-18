package investigation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"rmt.local/monitor/internal/domain"
)

const (
	CapsuleSchemaRevision = "incident-capsule-1"
	CatalogueRevision     = "ec01-ec07-mac-1"
	CardRevision          = "ec01-ec07-mac-1"
	MaxCapsuleBytes       = 64 << 10
)

var ErrCapsuleTooLarge = errors.New("incident capsule exceeds 64 KiB")

type Scope struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type Window struct {
	StartMS int64 `json:"start_ms"`
	EndMS   int64 `json:"end_ms"`
}

type Gap struct {
	StartMS int64                `json:"start_ms"`
	EndMS   int64                `json:"end_ms"`
	Reason  domain.MissingReason `json:"reason"`
}

type CardInput struct {
	Name          string                `json:"name"`
	Value         any                   `json:"value"`
	Unit          string                `json:"unit"`
	ObservedMS    *int64                `json:"observed_ms"`
	Quality       domain.Quality        `json:"quality"`
	MissingReason *domain.MissingReason `json:"missing_reason"`
	Provenance    domain.Provenance     `json:"provenance"`
}

type SourceLink struct {
	ScopeID string `json:"scope_id"`
	Metric  string `json:"metric"`
	StartMS int64  `json:"start_ms"`
	EndMS   int64  `json:"end_ms"`
}

type EvidenceCard struct {
	CardID              string       `json:"card_id"`
	Priority            int          `json:"priority"`
	CopyTemplateID      string       `json:"copy_template_id"`
	Scope               Scope        `json:"scope"`
	Title               string       `json:"title"`
	Summary             string       `json:"summary"`
	Eligibility         string       `json:"eligibility"`
	ReasonCodes         []string     `json:"reason_codes"`
	RequestedWindow     Window       `json:"requested_window"`
	EffectiveWindow     *Window      `json:"effective_window"`
	CoverageRatio       *float64     `json:"coverage_ratio"`
	SourceIDs           []string     `json:"source_ids"`
	DefinitionRevisions []string     `json:"definition_revisions"`
	ConfigIDs           []string     `json:"config_ids"`
	Inputs              []CardInput  `json:"inputs"`
	Gaps                []Gap        `json:"gaps"`
	ReferencedEventIDs  []string     `json:"referenced_event_ids"`
	SourceLinks         []SourceLink `json:"source_links"`
	NextCheckCode       string       `json:"next_check_code"`
	NextCheckLabel      string       `json:"next_check_label"`
}

type Capsule struct {
	SchemaRevision     string         `json:"schema_revision"`
	CatalogueRevision  string         `json:"catalogue_revision"`
	GeneratedMS        int64          `json:"generated_ms"`
	Scope              Scope          `json:"scope"`
	FocusWindow        Window         `json:"focus_window"`
	BaselineWindow     Window         `json:"baseline_window"`
	EvidenceState      string         `json:"evidence_state"`
	Cards              []EvidenceCard `json:"cards"`
	CollapsedCardCount int            `json:"collapsed_card_count"`
}

func (capsule Capsule) Marshal() ([]byte, string, error) {
	payload, err := json.Marshal(capsule)
	if err != nil {
		return nil, "", err
	}
	if len(payload) > MaxCapsuleBytes {
		return nil, "", ErrCapsuleTooLarge
	}
	digest := sha256.Sum256(payload)
	return payload, hex.EncodeToString(digest[:]), nil
}
