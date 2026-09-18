package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"rmt.local/monitor/internal/domain"
)

const (
	MaxRecoveryManifestBytes int64 = 64 << 10
	MaxRecoverySegmentFrames       = 4
	MaxRecoverySegmentBytes  int64 = 1 << 20
	// A replay request carries complete reviewed segments. Four canonical
	// frames are the largest request whose decoded frame bodies remain within
	// the 1 MiB collector processing budget (4 * MaxFrameBytes). The separate
	// MaxBatchBytes decoder limit bounds JSON expansion on the wire.
	MaxRecoveryReplayFrames            = 4
	MaxRecoveryReceiptStateBytes int64 = 16 << 20
)

// DecodeStrictRecoveryReceiptJSON applies the same duplicate, depth, UTF-8,
// closed-field and single-value checks as collector wire decoding, with the
// separate finite local receipt-ledger ceiling. It does not enlarge a network
// request limit.
func DecodeStrictRecoveryReceiptJSON(reader io.Reader, target any) error {
	_, err := decodeStrictJSONWithCeiling(reader, MaxRecoveryReceiptStateBytes, MaxRecoveryReceiptStateBytes, target)
	return err
}

type RecoverySegment struct {
	SourceID      string `json:"source_id"`
	FromSequence  int64  `json:"from_sequence"`
	ToSequence    int64  `json:"to_sequence"`
	FirstMS       int64  `json:"first_ms"`
	LastMS        int64  `json:"last_ms"`
	FrameCount    int    `json:"frame_count"`
	Bytes         int64  `json:"bytes"`
	SegmentSHA256 string `json:"segment_sha256"`
}

// RecoveryDescriptor is the complete content identity covered by a reviewed
// segment hash. Each compact JSON descriptor is length-prefixed, preventing
// ambiguity when a segment contains several frames.
type RecoveryDescriptor struct {
	SourceID      string `json:"source_id"`
	Sequence      int64  `json:"sequence"`
	ObservedMS    int64  `json:"observed_ms"`
	PayloadSHA256 string `json:"payload_sha256"`
}

func WriteRecoveryDescriptor(writer io.Writer, value RecoveryDescriptor) error {
	if !validUUID(value.SourceID) || value.Sequence < 0 || value.Sequence > MaxUint53 || value.ObservedMS < 0 || value.ObservedMS > MaxUint53 || !sha256Pattern.MatchString(value.PayloadSHA256) {
		return errors.New("invalid recovery segment descriptor")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if _, err := writer.Write(length[:]); err != nil {
		return err
	}
	_, err = writer.Write(encoded)
	return err
}

type RecoveryLoss struct {
	StartMS   int64  `json:"start_ms"`
	EndMS     int64  `json:"end_ms"`
	LostCount int64  `json:"lost_count"`
	Reason    string `json:"reason"`
}

type RecoveryDefinitions struct {
	HistoricalOnly bool              `json:"historical_only"`
	Sources        []InventorySource `json:"sources"`
	Targets        []InventoryTarget `json:"targets"`
	Models         []InventoryModel  `json:"models"`
}

type ApprovedRecoverySegment struct {
	SourceID      string `json:"source_id"`
	FromSequence  int64  `json:"from_sequence"`
	ToSequence    int64  `json:"to_sequence"`
	SegmentSHA256 string `json:"segment_sha256"`
}

type RecoveryManifest struct {
	SchemaVersion              string              `json:"schema_version"`
	DeploymentID               string              `json:"deployment_id"`
	HostID                     string              `json:"host_id"`
	OriginalSecurityGeneration string              `json:"original_security_generation"`
	OriginalCollectorBootID    string              `json:"original_collector_boot_id"`
	CreatedMS                  int64               `json:"created_ms"`
	TotalBytes                 int64               `json:"total_bytes"`
	TotalFrames                int                 `json:"total_frames"`
	Sources                    []string            `json:"sources"`
	HistoricalDefinitions      RecoveryDefinitions `json:"historical_definitions"`
	Segments                   []RecoverySegment   `json:"segments"`
	LossIntervals              []RecoveryLoss      `json:"loss_intervals"`
	ManifestSHA256             string              `json:"manifest_sha256"`
}

type RecoveryGrant struct {
	SchemaVersion              string                    `json:"schema_version"`
	GrantID                    string                    `json:"grant_id"`
	DeploymentID               string                    `json:"deployment_id"`
	HostID                     string                    `json:"host_id"`
	CurrentSecurityGeneration  string                    `json:"current_security_generation"`
	OriginalSecurityGeneration string                    `json:"original_security_generation"`
	OriginalCollectorBootID    string                    `json:"original_collector_boot_id"`
	ManifestSHA256             string                    `json:"manifest_sha256"`
	ApprovedSegments           []ApprovedRecoverySegment `json:"approved_segments"`
	MaxBytes                   int64                     `json:"max_bytes"`
	MaxFrames                  int                       `json:"max_frames"`
	IssuedMS                   int64                     `json:"issued_ms"`
	ExpiresMS                  int64                     `json:"expires_ms"`
	GrantSHA256                string                    `json:"grant_sha256"`
}

type RecoveryFrame struct {
	OriginalSourceID      string         `json:"original_source_id"`
	OriginalSequence      int64          `json:"original_sequence"`
	OriginalObservedMS    int64          `json:"original_observed_ms"`
	OriginalPayloadSHA256 string         `json:"original_payload_sha256"`
	Frame                 CollectorFrame `json:"frame"`
}

type RecoveryReplay struct {
	Protocol                    string          `json:"protocol"`
	GrantID                     string          `json:"grant_id"`
	GrantSHA256                 string          `json:"grant_sha256"`
	ReplayRequestID             string          `json:"replay_request_id"`
	ScopeSHA256                 string          `json:"scope_sha256"`
	AdmittingSecurityGeneration string          `json:"admitting_security_generation"`
	AdmittingSessionGeneration  int64           `json:"admitting_session_generation"`
	AdmittingCollectorBootID    string          `json:"admitting_collector_boot_id"`
	DeploymentID                string          `json:"deployment_id"`
	HostID                      string          `json:"host_id"`
	OriginalSecurityGeneration  string          `json:"original_security_generation"`
	OriginalCollectorBootID     string          `json:"original_collector_boot_id"`
	Frames                      []RecoveryFrame `json:"frames"`
}

type RecoveryReceipt struct {
	OriginalCollectorBootID string `json:"original_collector_boot_id"`
	OriginalSourceID        string `json:"original_source_id"`
	OriginalSequence        int64  `json:"original_sequence"`
	OriginalPayloadSHA256   string `json:"original_payload_sha256"`
	Disposition             string `json:"disposition"`
}

type RecoveryACK struct {
	GrantID         string            `json:"grant_id"`
	GrantSHA256     string            `json:"grant_sha256"`
	ReplayRequestID string            `json:"replay_request_id"`
	ScopeSHA256     string            `json:"scope_sha256"`
	Durable         bool              `json:"durable"`
	Accepted        int               `json:"accepted"`
	Duplicate       int               `json:"duplicate"`
	Rejected        int               `json:"rejected"`
	Receipts        []RecoveryReceipt `json:"receipts"`
	Complete        bool              `json:"complete"`
	HubTimeMS       int64             `json:"hub_time_ms"`
}

func CanonicalRecoveryManifestHash(value RecoveryManifest) (string, error) {
	body := struct {
		SchemaVersion              string              `json:"schema_version"`
		DeploymentID               string              `json:"deployment_id"`
		HostID                     string              `json:"host_id"`
		OriginalSecurityGeneration string              `json:"original_security_generation"`
		OriginalCollectorBootID    string              `json:"original_collector_boot_id"`
		CreatedMS                  int64               `json:"created_ms"`
		TotalBytes                 int64               `json:"total_bytes"`
		TotalFrames                int                 `json:"total_frames"`
		Sources                    []string            `json:"sources"`
		HistoricalDefinitions      RecoveryDefinitions `json:"historical_definitions"`
		Segments                   []RecoverySegment   `json:"segments"`
		LossIntervals              []RecoveryLoss      `json:"loss_intervals"`
	}{value.SchemaVersion, value.DeploymentID, value.HostID, value.OriginalSecurityGeneration, value.OriginalCollectorBootID, value.CreatedMS, value.TotalBytes, value.TotalFrames, value.Sources, value.HistoricalDefinitions, value.Segments, value.LossIntervals}
	return canonicalRecoveryHash(body)
}

func CanonicalRecoveryGrantHash(value RecoveryGrant) (string, error) {
	body := struct {
		SchemaVersion              string                    `json:"schema_version"`
		GrantID                    string                    `json:"grant_id"`
		DeploymentID               string                    `json:"deployment_id"`
		HostID                     string                    `json:"host_id"`
		CurrentSecurityGeneration  string                    `json:"current_security_generation"`
		OriginalSecurityGeneration string                    `json:"original_security_generation"`
		OriginalCollectorBootID    string                    `json:"original_collector_boot_id"`
		ManifestSHA256             string                    `json:"manifest_sha256"`
		ApprovedSegments           []ApprovedRecoverySegment `json:"approved_segments"`
		MaxBytes                   int64                     `json:"max_bytes"`
		MaxFrames                  int                       `json:"max_frames"`
		IssuedMS                   int64                     `json:"issued_ms"`
		ExpiresMS                  int64                     `json:"expires_ms"`
	}{value.SchemaVersion, value.GrantID, value.DeploymentID, value.HostID, value.CurrentSecurityGeneration, value.OriginalSecurityGeneration, value.OriginalCollectorBootID, value.ManifestSHA256, value.ApprovedSegments, value.MaxBytes, value.MaxFrames, value.IssuedMS, value.ExpiresMS}
	return canonicalRecoveryHash(body)
}

func CanonicalRecoveryScopeHash(value RecoveryReplay) (string, error) {
	body := struct {
		GrantSHA256                 string          `json:"grant_sha256"`
		ReplayRequestID             string          `json:"replay_request_id"`
		AdmittingSecurityGeneration string          `json:"admitting_security_generation"`
		AdmittingSessionGeneration  int64           `json:"admitting_session_generation"`
		AdmittingCollectorBootID    string          `json:"admitting_collector_boot_id"`
		DeploymentID                string          `json:"deployment_id"`
		HostID                      string          `json:"host_id"`
		OriginalSecurityGeneration  string          `json:"original_security_generation"`
		OriginalCollectorBootID     string          `json:"original_collector_boot_id"`
		Frames                      []RecoveryFrame `json:"frames"`
	}{value.GrantSHA256, value.ReplayRequestID, value.AdmittingSecurityGeneration, value.AdmittingSessionGeneration, value.AdmittingCollectorBootID, value.DeploymentID, value.HostID, value.OriginalSecurityGeneration, value.OriginalCollectorBootID, value.Frames}
	return canonicalRecoveryHash(body)
}

func canonicalRecoveryHash(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func DecodeRecoveryManifest(reader io.Reader) (RecoveryManifest, error) {
	var value RecoveryManifest
	data, err := decodeStrictJSON(reader, MaxRecoveryManifestBytes, &value)
	if err != nil {
		return value, err
	}
	if err := validateRecoveryManifestShape(data); err != nil {
		return value, err
	}
	return value, value.Validate()
}

func DecodeRecoveryReplay(reader io.Reader) (RecoveryReplay, error) {
	var value RecoveryReplay
	data, err := decodeStrictJSON(reader, MaxBatchBytes, &value)
	if err != nil {
		return value, err
	}
	top, err := requireObject(data, []string{"protocol", "grant_id", "grant_sha256", "replay_request_id", "scope_sha256", "admitting_security_generation", "admitting_session_generation", "admitting_collector_boot_id", "deployment_id", "host_id", "original_security_generation", "original_collector_boot_id", "frames"})
	if err != nil {
		return value, err
	}
	frames, err := requireArray(top["frames"], "frames")
	if err != nil {
		return value, err
	}
	frameValues := make([]json.RawMessage, 0, len(frames))
	for index, raw := range frames {
		item, err := requireNestedObject(raw, fmt.Sprintf("frames[%d]", index), []string{"original_source_id", "original_sequence", "original_observed_ms", "original_payload_sha256", "frame"})
		if err != nil {
			return value, err
		}
		frameValues = append(frameValues, item["frame"])
	}
	shape, _ := json.Marshal(map[string]any{
		"protocol": "1.0", "delivery_mode": "replay", "security_generation": "00000000-0000-4000-8000-000000000001",
		"session_generation": 1, "deployment_id": "00000000-0000-4000-8000-000000000002", "host_id": "00000000-0000-4000-8000-000000000003",
		"collector_boot_id": "00000000-0000-4000-8000-000000000004", "batch_id": "00000000-0000-4000-8000-000000000005", "frames": frameValues,
	})
	if err := validateBatchShape(shape); err != nil {
		return value, err
	}
	return value, value.Validate()
}

func DecodeRecoveryGrant(reader io.Reader) (RecoveryGrant, error) {
	var value RecoveryGrant
	data, err := decodeStrictJSON(reader, MaxRecoveryManifestBytes, &value)
	if err != nil {
		return value, err
	}
	top, err := requireObject(data, []string{"schema_version", "grant_id", "deployment_id", "host_id", "current_security_generation", "original_security_generation", "original_collector_boot_id", "manifest_sha256", "approved_segments", "max_bytes", "max_frames", "issued_ms", "expires_ms", "grant_sha256"})
	if err != nil {
		return value, err
	}
	segments, err := requireArray(top["approved_segments"], "approved_segments")
	if err != nil {
		return value, err
	}
	for index, raw := range segments {
		if _, err := requireNestedObject(raw, fmt.Sprintf("approved_segments[%d]", index), []string{"source_id", "from_sequence", "to_sequence", "segment_sha256"}); err != nil {
			return value, err
		}
	}
	return value, value.Validate()
}

func validateRecoveryManifestShape(data []byte) error {
	top, err := requireObject(data, []string{"schema_version", "deployment_id", "host_id", "original_security_generation", "original_collector_boot_id", "created_ms", "total_bytes", "total_frames", "sources", "historical_definitions", "segments", "loss_intervals", "manifest_sha256"})
	if err != nil {
		return err
	}
	if _, err := requireArray(top["sources"], "sources"); err != nil {
		return err
	}
	definitions, err := requireNestedObject(top["historical_definitions"], "historical_definitions", []string{"historical_only", "sources", "targets", "models"})
	if err != nil {
		return err
	}
	for name, required := range map[string][]string{
		"sources": {"source_id", "kind", "target_id", "capability_revision", "active"},
		"targets": {"target_id", "adapter_id", "local_selector_sha256", "association_state"},
		"models":  {"model_id", "target_id", "alias", "digest", "reported_loaded"},
	} {
		values, err := requireArray(definitions[name], "historical_definitions."+name)
		if err != nil {
			return err
		}
		for index, raw := range values {
			if _, err := requireNestedObject(raw, fmt.Sprintf("historical_definitions.%s[%d]", name, index), required); err != nil {
				return err
			}
		}
	}
	for name, required := range map[string][]string{
		"segments":       {"source_id", "from_sequence", "to_sequence", "first_ms", "last_ms", "frame_count", "bytes", "segment_sha256"},
		"loss_intervals": {"start_ms", "end_ms", "lost_count", "reason"},
	} {
		values, err := requireArray(top[name], name)
		if err != nil {
			return err
		}
		for index, raw := range values {
			if _, err := requireNestedObject(raw, fmt.Sprintf("%s[%d]", name, index), required); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m RecoveryManifest) Validate() error {
	if m.SchemaVersion != domain.SchemaVersion || !validUUIDs(m.DeploymentID, m.HostID, m.OriginalSecurityGeneration, m.OriginalCollectorBootID) || m.CreatedMS < 0 || m.CreatedMS > MaxUint53 || m.TotalBytes < 1 || m.TotalBytes > 256<<20 || m.TotalFrames < 1 || m.TotalFrames > 1_000_000 || len(m.Sources) < 1 || len(m.Sources) > 8 || len(m.Segments) < 1 || len(m.Segments) > 4096 || len(m.LossIntervals) > 1024 || !sha256Pattern.MatchString(m.ManifestSHA256) {
		return errors.New("invalid recovery manifest envelope")
	}
	if err := m.HistoricalDefinitions.validate(m.Sources); err != nil {
		return err
	}
	seen := map[string]bool{}
	var totalBytes int64
	totalFrames := 0
	lastTo := map[string]int64{}
	ordered := append([]RecoverySegment(nil), m.Segments...)
	SortRecoverySegments(ordered)
	for _, source := range m.Sources {
		if !validUUID(source) || seen[source] {
			return errors.New("invalid recovery source set")
		}
		seen[source] = true
	}
	for _, s := range ordered {
		expectedFrames := s.ToSequence - s.FromSequence + 1
		if !seen[s.SourceID] || s.FromSequence < 0 || s.ToSequence < s.FromSequence || s.ToSequence > MaxUint53 || s.FirstMS < 0 || s.LastMS < s.FirstMS || s.LastMS > MaxUint53 || s.FrameCount < 1 || s.FrameCount > MaxRecoverySegmentFrames || expectedFrames != int64(s.FrameCount) || s.Bytes < 1 || s.Bytes > MaxRecoverySegmentBytes || !sha256Pattern.MatchString(s.SegmentSHA256) {
			return errors.New("invalid recovery segment")
		}
		if previous, ok := lastTo[s.SourceID]; ok && s.FromSequence <= previous {
			return errors.New("overlapping recovery segments")
		}
		lastTo[s.SourceID] = s.ToSequence
		totalBytes += s.Bytes
		totalFrames += s.FrameCount
	}
	if totalBytes != m.TotalBytes || totalFrames != m.TotalFrames {
		return errors.New("recovery manifest totals mismatch")
	}
	for _, loss := range m.LossIntervals {
		if loss.StartMS < 0 || loss.EndMS < loss.StartMS || loss.EndMS > MaxUint53 || loss.LostCount < 1 || loss.LostCount > MaxUint53 || !validSafeCode(loss.Reason) {
			return errors.New("invalid recovery loss interval")
		}
	}
	hash, err := CanonicalRecoveryManifestHash(m)
	if err != nil || hash != m.ManifestSHA256 {
		return errors.New("recovery manifest hash mismatch")
	}
	return nil
}

func (g RecoveryGrant) Validate() error {
	if g.SchemaVersion != domain.SchemaVersion || !validUUIDs(g.GrantID, g.DeploymentID, g.HostID, g.CurrentSecurityGeneration, g.OriginalSecurityGeneration, g.OriginalCollectorBootID) || !sha256Pattern.MatchString(g.ManifestSHA256) || !sha256Pattern.MatchString(g.GrantSHA256) || len(g.ApprovedSegments) < 1 || len(g.ApprovedSegments) > 4096 || g.MaxBytes < 1 || g.MaxBytes > 256<<20 || g.MaxFrames < 1 || g.MaxFrames > 1_000_000 || g.IssuedMS < 0 || g.ExpiresMS <= g.IssuedMS || g.ExpiresMS > g.IssuedMS+3_600_000 || g.ExpiresMS > MaxUint53 {
		return errors.New("invalid recovery grant")
	}
	seen := map[string]bool{}
	for _, segment := range g.ApprovedSegments {
		key := fmt.Sprintf("%s/%d/%d", segment.SourceID, segment.FromSequence, segment.ToSequence)
		if !validUUID(segment.SourceID) || segment.FromSequence < 0 || segment.ToSequence < segment.FromSequence || segment.ToSequence > MaxUint53 || segment.ToSequence-segment.FromSequence+1 > MaxRecoverySegmentFrames || !sha256Pattern.MatchString(segment.SegmentSHA256) || seen[key] {
			return errors.New("invalid approved recovery segment")
		}
		seen[key] = true
	}
	hash, err := CanonicalRecoveryGrantHash(g)
	if err != nil || hash != g.GrantSHA256 {
		return errors.New("recovery grant hash mismatch")
	}
	return nil
}

func (d RecoveryDefinitions) validate(sourceIDs []string) error {
	if !d.HistoricalOnly || len(d.Sources) < 1 || len(d.Sources) > 8 || len(d.Targets) > 1 || len(d.Models) > 64 {
		return errors.New("invalid historical definitions")
	}
	want := map[string]bool{}
	for _, id := range sourceIDs {
		want[id] = true
	}
	targets := map[string]bool{}
	for _, t := range d.Targets {
		if !validUUID(t.TargetID) || t.AdapterID != "ollama" || !sha256Pattern.MatchString(t.LocalSelectorSHA256) || (t.AssociationState != "verified" && t.AssociationState != "declared_unverified" && t.AssociationState != "ambiguous") || targets[t.TargetID] {
			return errors.New("invalid historical target definition")
		}
		targets[t.TargetID] = true
	}
	seen := map[string]bool{}
	for _, s := range d.Sources {
		if !want[s.SourceID] || seen[s.SourceID] || s.Active || s.CapabilityRevision != domain.RegistryRevision || (s.Kind != "host" && s.Kind != "runtime") {
			return errors.New("invalid historical source definition")
		}
		if (s.Kind == "host") != (s.TargetID == nil) {
			return errors.New("historical source target mismatch")
		}
		if s.TargetID != nil && !targets[*s.TargetID] {
			return errors.New("historical source target absent")
		}
		seen[s.SourceID] = true
	}
	if len(seen) != len(want) {
		return errors.New("historical source definitions incomplete")
	}
	models := map[string]bool{}
	for _, m := range d.Models {
		if !validUUIDs(m.ModelID, m.TargetID) || !targets[m.TargetID] || models[m.ModelID] || !safeString(m.Alias) || m.ReportedLoaded || (m.Digest != nil && !sha256Pattern.MatchString(*m.Digest)) {
			return errors.New("invalid historical model definition")
		}
		models[m.ModelID] = true
	}
	return nil
}

func (r RecoveryReplay) Validate() error {
	if r.Protocol != domain.ProtocolVersion || !validUUIDs(r.GrantID, r.ReplayRequestID, r.AdmittingSecurityGeneration, r.AdmittingCollectorBootID, r.DeploymentID, r.HostID, r.OriginalSecurityGeneration, r.OriginalCollectorBootID) || !sha256Pattern.MatchString(r.GrantSHA256) || !sha256Pattern.MatchString(r.ScopeSHA256) || r.AdmittingSessionGeneration < 1 || r.AdmittingSessionGeneration > MaxUint53 || len(r.Frames) < 1 || len(r.Frames) > MaxRecoveryReplayFrames {
		return errors.New("invalid recovery replay envelope")
	}
	seen := map[string]bool{}
	for i := range r.Frames {
		f := r.Frames[i]
		if !validUUID(f.OriginalSourceID) || f.OriginalSequence < 0 || f.OriginalSequence > MaxUint53 || f.OriginalObservedMS < 0 || f.OriginalObservedMS > MaxUint53 || !sha256Pattern.MatchString(f.OriginalPayloadSHA256) || f.Frame.SourceID != f.OriginalSourceID || f.Frame.Sequence != f.OriginalSequence || f.Frame.ObservedWallMS != f.OriginalObservedMS {
			return fmt.Errorf("invalid recovery frame %d", i)
		}
		if err := f.Frame.Validate(); err != nil {
			return err
		}
		key := f.OriginalSourceID + fmt.Sprint("/", f.OriginalSequence)
		if seen[key] {
			return errors.New("duplicate recovery frame")
		}
		seen[key] = true
	}
	hash, err := CanonicalRecoveryScopeHash(r)
	if err != nil || hash != r.ScopeSHA256 {
		return errors.New("recovery replay scope hash mismatch")
	}
	return nil
}

func (a RecoveryACK) Validate(replay RecoveryReplay) error {
	if a.GrantID != replay.GrantID || a.GrantSHA256 != replay.GrantSHA256 || a.ReplayRequestID != replay.ReplayRequestID || a.ScopeSHA256 != replay.ScopeSHA256 || !a.Durable || a.HubTimeMS < 0 || a.HubTimeMS > MaxUint53 || len(a.Receipts) != len(replay.Frames) || a.Accepted+a.Duplicate+a.Rejected != len(a.Receipts) {
		return errors.New("recovery acknowledgement conflicts with request")
	}
	want := map[string]string{}
	for _, f := range replay.Frames {
		want[fmt.Sprintf("%s/%s/%d", replay.OriginalCollectorBootID, f.OriginalSourceID, f.OriginalSequence)] = f.OriginalPayloadSHA256
	}
	counts := map[string]int{}
	for _, receipt := range a.Receipts {
		key := fmt.Sprintf("%s/%s/%d", receipt.OriginalCollectorBootID, receipt.OriginalSourceID, receipt.OriginalSequence)
		if want[key] != receipt.OriginalPayloadSHA256 {
			return errors.New("recovery receipt identity mismatch")
		}
		delete(want, key)
		counts[receipt.Disposition]++
	}
	rejected := len(a.Receipts) - counts["recovered"] - counts["duplicate"]
	if len(want) != 0 || counts["recovered"] != a.Accepted || counts["duplicate"] != a.Duplicate || rejected != a.Rejected {
		return errors.New("recovery receipt counts mismatch")
	}
	return nil
}

func SortRecoverySegments(segments []RecoverySegment) {
	sort.Slice(segments, func(i, j int) bool {
		if segments[i].SourceID != segments[j].SourceID {
			return segments[i].SourceID < segments[j].SourceID
		}
		return segments[i].FromSequence < segments[j].FromSequence
	})
}
