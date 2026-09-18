package query

import (
	"context"

	"rmt.local/monitor/internal/domain"
)

const maxHistoryScopes = 256

var historyMetrics = map[string][]string{
	"host": {
		"host.cpu.busy_ratio", "host.memory.pressure_level", "host.memory.compressed_bytes",
		"host.memory.swap_used_bytes", "host.disk.free_bytes",
	},
	"runtime": {"runtime.reachable"},
	"model": {
		"runtime.model.loaded", "runtime.model.reported_size_bytes", "runtime.model.reported_size_vram_bytes",
	},
	"process": {"process.cpu.busy_ratio", "process.physical_footprint_bytes"},
}

type HistoryScope struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	DisplayName string   `json:"display_name"`
	Retired     bool     `json:"retired"`
	HostID      string   `json:"host_id"`
	TargetID    *string  `json:"target_id"`
	EarliestMS  int64    `json:"earliest_retained_ms"`
	LatestMS    int64    `json:"latest_retained_ms"`
	Metrics     []string `json:"metrics"`
}

type HistoryCatalog struct {
	SchemaVersion      string         `json:"schema_version"`
	GeneratedMS        int64          `json:"generated_ms"`
	EarliestRetainedMS *int64         `json:"earliest_retained_ms"`
	LatestRetainedMS   *int64         `json:"latest_retained_ms"`
	Scopes             []HistoryScope `json:"scopes"`
	Truncated          bool           `json:"truncated"`
}

func (s *Service) HistoryCatalog(ctx context.Context) (HistoryCatalog, error) {
	nowMS := s.clock.Now().UnixMilli()
	inventory, err := s.store.ReadQueryInventory(ctx)
	if err != nil {
		return HistoryCatalog{}, err
	}
	retained, err := s.store.ReadHistoryCatalogData(ctx, inventory.Deployment.DeploymentID, nowMS)
	if err != nil {
		return HistoryCatalog{}, err
	}
	result := HistoryCatalog{
		SchemaVersion: domain.SchemaVersion, GeneratedMS: nowMS,
		EarliestRetainedMS: retained.EarliestMS, LatestRetainedMS: retained.LatestMS,
		Scopes: []HistoryScope{}, Truncated: retained.Truncated,
	}
	seen := make(map[string]bool)
	for _, source := range retained.Sources {
		id := source.HostID
		if source.Kind == "runtime" && source.TargetID != nil {
			id = *source.TargetID
		}
		if seen[source.Kind+":"+id] {
			continue
		}
		seen[source.Kind+":"+id] = true
		appendHistoryScope(&result, HistoryScope{ID: id, Kind: source.Kind, DisplayName: source.DisplayName, Retired: source.Retired, HostID: source.HostID, TargetID: source.TargetID, EarliestMS: source.EarliestMS, LatestMS: source.LatestMS, Metrics: cloneStrings(historyMetrics[source.Kind])})
	}
	for _, retainedModel := range retained.Models {
		targetID := retainedModel.TargetID
		appendHistoryScope(&result, HistoryScope{ID: retainedModel.ModelID, Kind: "model", DisplayName: retainedModel.DisplayName, Retired: retainedModel.Retired, HostID: retainedModel.HostID, TargetID: &targetID, EarliestMS: retainedModel.EarliestMS, LatestMS: retainedModel.LatestMS + 1, Metrics: cloneStrings(historyMetrics["model"])})
	}
	for _, process := range retained.Processes {
		appendHistoryScope(&result, HistoryScope{ID: process.ProcessKey, Kind: "process", DisplayName: "Observed process " + process.ProcessKey[:12], Retired: process.Retired, HostID: process.HostID, TargetID: process.TargetID, EarliestMS: process.EarliestMS, LatestMS: process.LatestMS + 1, Metrics: cloneStrings(historyMetrics["process"])})
	}
	return result, nil
}

func appendHistoryScope(catalog *HistoryCatalog, scope HistoryScope) {
	if len(catalog.Scopes) == maxHistoryScopes {
		catalog.Truncated = true
		return
	}
	catalog.Scopes = append(catalog.Scopes, scope)
}

func cloneStrings(values []string) []string { return append([]string(nil), values...) }
