package scheduler

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

// Alignment is an observation, never a request to adjust the operating clock.
// An absent or uncertain exchange keeps original timing but omits alignment.
type Alignment struct {
	OffsetMS      int64
	UncertaintyMS int64
	MeasuredAt    time.Time
	Valid         bool
}

func TimeExchange(sent, received time.Time, hubMS int64) Alignment {
	elapsed := received.Sub(sent)
	if elapsed < 0 || elapsed > 2*time.Second {
		return Alignment{}
	}
	offset := hubMS - sent.Add(elapsed/2).UnixMilli()
	if offset < -86400000 || offset > 86400000 {
		return Alignment{}
	}
	return Alignment{OffsetMS: offset, UncertaintyMS: (elapsed.Milliseconds() + 1) / 2, MeasuredAt: received, Valid: true}
}

func baseFrame(source string, timing domain.ComponentTiming, provenance domain.Provenance, alignment Alignment, now time.Time) protocol.CollectorFrame {
	frame := protocol.CollectorFrame{
		SourceID: source, ObservedWallMS: timing.ObservedWallMS,
		MonotonicStartNS: timing.MonotonicStartNS, MonotonicEndNS: timing.MonotonicEndNS, DurationMS: timing.DurationMS,
		DefinitionRevision: domain.RegistryRevision, Quality: domain.QualityMeasured, Provenance: provenance,
		Gauges: map[string]protocol.MetricValue{}, NetworkObservations: []domain.NetworkObservation{},
		ModelObservations: []domain.ModelObservation{}, ProcessObservations: []domain.ProcessObservation{}, CapabilitiesMissing: []domain.MissingCapability{},
	}
	if alignment.Valid && alignment.UncertaintyMS <= 1000 && now.Sub(alignment.MeasuredAt) >= 0 && now.Sub(alignment.MeasuredAt) <= 120*time.Second {
		aligned := frame.ObservedWallMS + alignment.OffsetMS
		if aligned >= 0 {
			offset, uncertainty := alignment.OffsetMS, alignment.UncertaintyMS
			frame.EstimatedUTCMS = &aligned
			frame.OffsetMS = &offset
			frame.UncertaintyMS = &uncertainty
		}
	}
	if frame.EstimatedUTCMS == nil {
		frame.CapabilitiesMissing = append(frame.CapabilitiesMissing, domain.MissingCapability{ID: "clock.alignment", Reason: domain.MissingAlignmentUnavailable})
	}
	return frame
}

func gaugeFrame[T any](source, id string, value domain.MetricObservation[T], timing domain.ComponentTiming, alignment Alignment, now time.Time) protocol.CollectorFrame {
	frame := baseFrame(source, timing, value.Provenance, alignment, now)
	encoded, _ := json.Marshal(value.Value)
	frame.Gauges[id] = protocol.MetricValue{Value: encoded, Quality: value.Quality, MissingReason: value.MissingReason, Provenance: value.Provenance}
	frame.Quality = value.Quality
	return frame
}

// HostFrames preserves each component's midpoint/duration. A single broad
// frame would misrepresent short independent reads when another read times out.
func HostFrames(source string, host domain.HostObservation, processes *domain.ProcessCollection, alignment Alignment, now time.Time) []protocol.CollectorFrame {
	timing := host.ComponentTimings
	frames := []protocol.CollectorFrame{
		gaugeFrame(source, "host.cpu.busy_ratio", host.Gauges.CPUBusyRatio, timing.CPU, alignment, now),
		gaugeFrame(source, "host.memory.pressure_level", host.Gauges.PressureLevel, timing.Pressure, alignment, now),
		gaugeFrame(source, "host.memory.compressed_bytes", host.Gauges.CompressedBytes, timing.Compressed, alignment, now),
		gaugeFrame(source, "host.memory.swap_used_bytes", host.Gauges.SwapUsedBytes, timing.Swap, alignment, now),
		gaugeFrame(source, "host.disk.free_bytes", host.Gauges.DiskFreeBytes, timing.Disk, alignment, now),
	}
	provenance := domain.Provenance{Source: domain.ProvenanceDarwinAPI, MethodRevision: "darwin-net-rt-iflist2-ifdata64-candidate-1", Verification: domain.VerificationDirectCapture}
	frame := baseFrame(source, timing.Network, provenance, alignment, now)
	frame.NetworkObservations = append(frame.NetworkObservations, host.NetworkObservations...)
	frame.CapabilitiesMissing = append(frame.CapabilitiesMissing, host.CapabilitiesMissing...)
	frames = append(frames, frame)
	if processes != nil {
		provenance.MethodRevision = processes.Summary.MethodRevision
		frame := baseFrame(source, processes.Timing, provenance, alignment, now)
		frame.ProcessObservations = append(frame.ProcessObservations, processes.Processes...)
		frame.ProcessSummary = &processes.Summary
		if processes.Association.TargetID != "" {
			association := processes.Association
			frame.EndpointAssociation = &association
		}
		if processes.Summary.Coverage != "complete" {
			frame.CapabilitiesMissing = append(frame.CapabilitiesMissing, domain.MissingCapability{ID: "host.process.coverage", Reason: domain.MissingPopulationPartial})
		}
		frames = append(frames, frame)
	}
	// Independent component intervals may overlap. Sequence order follows the
	// monotonic start; intervals must never be rewritten to look sequential.
	sort.SliceStable(frames, func(i, j int) bool {
		a, _ := strconv.ParseUint(string(frames[i].MonotonicStartNS), 10, 64)
		b, _ := strconv.ParseUint(string(frames[j].MonotonicStartNS), 10, 64)
		return a < b
	})
	return frames
}

func RuntimeFrames(source string, runtime domain.RuntimeObservation, reachability, inventory bool, alignment Alignment, now time.Time) []protocol.CollectorFrame {
	frames := []protocol.CollectorFrame{}
	if reachability {
		frame := gaugeFrame(source, "runtime.reachable", runtime.Reachable, runtime.ComponentTimings.Reachability, alignment, now)
		frame.CapabilitiesMissing = append(frame.CapabilitiesMissing, runtime.CapabilitiesMissing...)
		frames = append(frames, frame)
	}
	if inventory && runtime.ComponentTimings.LoadedModels != nil {
		provenance := domain.Provenance{Source: domain.ProvenanceRuntimeAPI, MethodRevision: "ollama-0.34.0-bounded-read-v1", Verification: domain.VerificationDirectCapture}
		loadedValid := true
		for _, missing := range runtime.CapabilitiesMissing {
			if missing.ID == "runtime.model.loaded" || missing.ID == "runtime.model.digest" || missing.ID == "runtime.model.identity" {
				loadedValid = false
			}
		}
		if loadedValid {
			provenance.MethodRevision = "ollama-0.34.0-bounded-ps-v1"
		}
		frame := baseFrame(source, *runtime.ComponentTimings.LoadedModels, provenance, alignment, now)
		frame.Quality = domain.QualityRuntimeReported
		frame.ModelObservations = append(frame.ModelObservations, runtime.Models...)
		frame.CapabilitiesMissing = append(frame.CapabilitiesMissing, runtime.CapabilitiesMissing...)
		frames = append(frames, frame)
	}
	if inventory && runtime.Config != nil && runtime.ComponentTimings.Config != nil {
		provenance := runtime.Config.FieldProvenance.ServerVersion
		frame := baseFrame(source, *runtime.ComponentTimings.Config, provenance, alignment, now)
		frame.Quality = domain.QualityRuntimeReported
		frame.ConfigObservation = runtime.Config
		frames = append(frames, frame)
	}
	return frames
}
