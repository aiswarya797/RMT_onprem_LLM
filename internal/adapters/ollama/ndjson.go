package ollama

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
)

const (
	maxRuntimeDurationNS = uint64(120_000_000_000)
	maxRuntimeTokenCount = uint64(1_000_000)
)

type rawStreamObject struct {
	Done               *bool         `json:"done"`
	DoneReason         string        `json:"done_reason"`
	Error              *string       `json:"error"`
	TotalDuration      *strictNumber `json:"total_duration"`
	LoadDuration       *strictNumber `json:"load_duration"`
	PromptEvalDuration *strictNumber `json:"prompt_eval_duration"`
	EvalDuration       *strictNumber `json:"eval_duration"`
	PromptEvalCount    *strictNumber `json:"prompt_eval_count"`
	EvalCount          *strictNumber `json:"eval_count"`
}

// encoding/json accepts a quoted string into json.Number. Ollama's metric
// fields are JSON numbers, so retain the token distinction before conversion.
type strictNumber json.Number

func (n *strictNumber) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] == '"' || bytes.Equal(data, []byte("null")) {
		return &json.UnmarshalTypeError{Value: "non-number", Type: reflect.TypeOf(strictNumber(""))}
	}
	var value json.Number
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*n = strictNumber(value)
	return nil
}

// DecodeObservedResponse normalizes an already-observed Ollama response
// stream. It never sends a request. Response, thinking, context, prompt and
// arbitrary content fields are validated within the parse budget and then
// discarded without appearing in StreamResult.
func DecodeObservedResponse(reader io.Reader, options StreamOptions) (StreamResult, error) {
	result := StreamResult{HTTPStatus: options.HTTPStatus}
	if options.HTTPStatus != nil && (*options.HTTPStatus < 200 || *options.HTTPStatus > 299) {
		return failedStream(result, "http_error"), nil
	}
	body, err := readBounded(reader, StreamBodyLimit)
	if err != nil {
		if errorKind(err) == ErrorLimitExceeded {
			return failedStream(result, "limit_exceeded"), nil
		}
		return incompleteStream(result, options.ClientCancelled), nil
	}

	lines := bytes.Split(body, []byte{'\n'})
	terminalIndex := -1
	var terminal rawStreamObject
	objectCount := 0
	for _, line := range lines {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		objectCount++
		if objectCount > MaxArrayItems {
			return failedStream(result, "limit_exceeded"), nil
		}
		var object rawStreamObject
		if err := strictDecode(line, &object); err != nil {
			return failedStream(result, "malformed_stream"), nil
		}
		var keys map[string]json.RawMessage
		_ = json.Unmarshal(line, &keys)
		result.UnknownFields += unknownKeys(keys,
			"model", "remote_model", "remote_host", "created_at", "response", "thinking", "done", "done_reason", "context",
			"total_duration", "load_duration", "prompt_eval_count", "prompt_eval_cached_count", "prompt_eval_duration", "eval_count", "eval_duration",
			"error", "tool_calls", "_debug_info", "logprobs")

		isTerminal := object.Error != nil || (object.Done != nil && *object.Done)
		if terminalIndex >= 0 {
			return failedStream(result, "malformed_stream"), nil
		}
		if isTerminal {
			terminalIndex = objectCount - 1
			terminal = object
		}
	}

	if terminalIndex < 0 {
		return incompleteStream(result, options.ClientCancelled), nil
	}
	result.TerminalRecordObserved = true
	if terminal.Error != nil {
		reason := "error"
		result.DoneReason = &reason
		return failedStream(result, "runtime_error"), nil
	}

	metrics, err := decodeRuntimeMetrics(terminal)
	if err != nil {
		result.TerminalRecordObserved = true
		return failedStream(result, "malformed_stream"), nil
	}
	result.Metrics = metrics
	switch terminal.DoneReason {
	case "stop", "length":
		result.TerminalStatus = TerminalCompleted
		reason := terminal.DoneReason
		result.DoneReason = &reason
		return result, nil
	case "load", "unload":
		result.TerminalStatus = TerminalIncomplete
		reason := terminal.DoneReason
		result.DoneReason = &reason
		return result, nil
	case "error":
		reason := terminal.DoneReason
		result.DoneReason = &reason
		return failedStream(result, "runtime_error"), nil
	default:
		return failedStream(result, "malformed_stream"), nil
	}
}

func decodeRuntimeMetrics(raw rawStreamObject) (RuntimeMetrics, error) {
	total, err := exactStreamUint(raw.TotalDuration, "total_duration", maxRuntimeDurationNS)
	if err != nil {
		return RuntimeMetrics{}, err
	}
	load, err := exactStreamUint(raw.LoadDuration, "load_duration", maxRuntimeDurationNS)
	if err != nil {
		return RuntimeMetrics{}, err
	}
	promptDuration, err := exactStreamUint(raw.PromptEvalDuration, "prompt_eval_duration", maxRuntimeDurationNS)
	if err != nil {
		return RuntimeMetrics{}, err
	}
	evalDuration, err := exactStreamUint(raw.EvalDuration, "eval_duration", maxRuntimeDurationNS)
	if err != nil {
		return RuntimeMetrics{}, err
	}
	promptCount, err := exactStreamUint(raw.PromptEvalCount, "prompt_eval_count", maxRuntimeTokenCount)
	if err != nil {
		return RuntimeMetrics{}, err
	}
	evalCount, err := exactStreamUint(raw.EvalCount, "eval_count", maxRuntimeTokenCount)
	if err != nil {
		return RuntimeMetrics{}, err
	}
	return RuntimeMetrics{
		TotalDurationMS: nanosecondsToMilliseconds(total), LoadDurationMS: nanosecondsToMilliseconds(load),
		PromptEvalDurationMS: nanosecondsToMilliseconds(promptDuration), EvalDurationMS: nanosecondsToMilliseconds(evalDuration),
		PromptTokens: promptCount, OutputTokens: evalCount,
	}, nil
}

func exactStreamUint(value *strictNumber, field string, maximum uint64) (*uint64, error) {
	if value == nil {
		return nil, nil
	}
	number := json.Number(*value)
	return exactUint(&number, field, maximum)
}

func nanosecondsToMilliseconds(value *uint64) *float64 {
	if value == nil {
		return nil
	}
	converted := float64(*value) / 1_000_000
	return &converted
}

func failedStream(result StreamResult, category string) StreamResult {
	result.TerminalStatus = TerminalFailed
	result.SafeErrorCategory = &category
	result.Metrics = RuntimeMetrics{}
	return result
}

func incompleteStream(result StreamResult, cancelled bool) StreamResult {
	if cancelled {
		result.TerminalStatus = TerminalCancelled
		category := "cancelled"
		result.SafeErrorCategory = &category
	} else {
		result.TerminalStatus = TerminalIncomplete
		category := "incomplete_stream"
		result.SafeErrorCategory = &category
	}
	return result
}
