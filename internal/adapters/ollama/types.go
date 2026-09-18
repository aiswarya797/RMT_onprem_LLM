package ollama

import "time"

const (
	AdapterRevision  = "ollama-readonly-v1"
	RegistryRevision = "mac-ollama-1"

	RootBodyLimit      int64 = 64 << 10
	VersionBodyLimit   int64 = 64 << 10
	InventoryBodyLimit int64 = 1 << 20
	StreamBodyLimit    int64 = 4 << 20

	RequestTimeout  = 2 * time.Second
	GenerateTimeout = 60 * time.Second
	MaxArrayItems   = 64
	MaxObjectKeys   = 64
	MaxLoadedModels = 2
	MaxStringBytes  = 256
	MaxJSONDepth    = 16
)

type CompatibilityState string

const (
	CompatibilityUnverified CompatibilityState = "unverified"
)

type RuntimeVersion struct {
	Version            string
	SourcePinID        string
	CompatibilityState CompatibilityState
}

type RootObservation struct {
	Reachable bool
}

type ModelDetails struct {
	Format            *string
	Family            *string
	ParameterSize     *string
	QuantizationLevel *string
	ContextLength     *uint64
}

// Model is bounded, content-free Ollama inventory metadata. Alias and digest
// stay separate: callers must never use Alias as immutable model identity.
type Model struct {
	Alias             string
	Digest            *string
	Loaded            bool
	Local             bool
	ReportedSizeBytes *uint64
	SizeVRAMBytes     *uint64
	ContextLength     *uint64
	Details           ModelDetails
}

type ModelInventory struct {
	Models        []Model
	UnknownFields uint64
}

type ModelInfo struct {
	Alias         string
	Digest        *string
	Details       ModelDetails
	Capabilities  []string
	ModifiedAt    *time.Time
	UnknownFields uint64
}

type TerminalStatus string

const (
	TerminalCompleted  TerminalStatus = "completed"
	TerminalCancelled  TerminalStatus = "cancelled"
	TerminalFailed     TerminalStatus = "failed"
	TerminalIncomplete TerminalStatus = "incomplete"
)

type RuntimeMetrics struct {
	TotalDurationMS      *float64
	LoadDurationMS       *float64
	PromptEvalDurationMS *float64
	EvalDurationMS       *float64
	PromptTokens         *uint64
	OutputTokens         *uint64
}

type StreamResult struct {
	HTTPStatus             *int
	TerminalStatus         TerminalStatus
	TerminalRecordObserved bool
	DoneReason             *string
	SafeErrorCategory      *string
	Metrics                RuntimeMetrics
	UnknownFields          uint64
}

type StreamOptions struct {
	HTTPStatus      *int
	ClientCancelled bool
}

// GenerateRequest is the deliberately narrow, explicit request surface. It
// is not used by the collector, which remains read-only. Callers must apply
// their own admission policy before invoking Generate.
type GenerateRequest struct {
	Model       string
	Prompt      string
	NumCtx      int
	NumPredict  int
	Temperature float64
	Seed        int64
	Think       bool
	Stream      bool
}

// RequestTimings are monotonic client observations. The body is parsed only
// long enough to identify the first non-empty thinking/content boundary; no
// text is returned or retained.
type RequestTimings struct {
	HeadersNS       uint64
	FirstByteNS     *uint64
	FirstThinkingNS *uint64
	FirstContentNS  *uint64
	EndNS           uint64
}
