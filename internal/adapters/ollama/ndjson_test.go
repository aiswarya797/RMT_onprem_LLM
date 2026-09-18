package ollama

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestObservedStreamGoldenFiles(t *testing.T) {
	status := 200
	cases := []struct {
		file       string
		wantStatus TerminalStatus
		wantError  string
	}{
		{"stream-stop.ndjson", TerminalCompleted, ""},
		{"stream-missing-terminal.ndjson", TerminalIncomplete, "incomplete_stream"},
		{"stream-http200-error.ndjson", TerminalFailed, "runtime_error"},
		{"stream-duplicate-key.ndjson", TerminalFailed, "malformed_stream"},
		{"stream-post-terminal.ndjson", TerminalFailed, "malformed_stream"},
	}
	for _, test := range cases {
		t.Run(test.file, func(t *testing.T) {
			data, err := os.ReadFile(fixturePath(test.file))
			if err != nil {
				t.Fatal(err)
			}
			result, err := DecodeObservedResponse(bytes.NewReader(data), StreamOptions{HTTPStatus: &status})
			if err != nil || result.TerminalStatus != test.wantStatus || pointerValue(result.SafeErrorCategory) != test.wantError {
				t.Fatalf("result = %#v, err = %v", result, err)
			}
			if strings.Contains(fmt.Sprintf("%#v", result), "SYNTHETIC_SECRET_CANARY") {
				t.Fatalf("content escaped normalization: %#v", result)
			}
		})
	}
}

func TestObservedStopPreservesPresentZeroAndOmittedValues(t *testing.T) {
	status := 200
	data, _ := os.ReadFile(fixturePath("stream-stop.ndjson"))
	result, err := DecodeObservedResponse(bytes.NewReader(data), StreamOptions{HTTPStatus: &status})
	if err != nil || result.Metrics.LoadDurationMS == nil || *result.Metrics.LoadDurationMS != 0 {
		t.Fatalf("present zero lost: %#v, %v", result, err)
	}
	if result.Metrics.TotalDurationMS == nil || *result.Metrics.TotalDurationMS != 9 || result.Metrics.PromptTokens == nil || *result.Metrics.PromptTokens != 8 {
		t.Fatalf("metrics = %#v", result.Metrics)
	}
}

func TestObservedResponseAcceptedContractCases(t *testing.T) {
	type expected struct {
		TerminalStatus    string `json:"terminal_status"`
		DoneReason        string `json:"done_reason"`
		SafeErrorCategory string `json:"safe_error_category"`
		AllNull           bool   `json:"runtime_metrics_all_null"`
	}
	type fixtureCase struct {
		ID              string            `json:"id"`
		HTTPStatus      *int              `json:"http_status"`
		Objects         []json.RawMessage `json:"objects"`
		ClientCancelled bool              `json:"client_cancelled"`
		Expected        expected          `json:"expected"`
	}
	var fixture struct {
		Cases []fixtureCase `json:"cases"`
	}
	data, err := os.ReadFile("../../../fixtures/contracts/probe/ollama-ndjson-cases.json")
	if err != nil || json.Unmarshal(data, &fixture) != nil {
		t.Fatal("read accepted NDJSON contract fixture")
	}
	for _, test := range fixture.Cases {
		t.Run(test.ID, func(t *testing.T) {
			var stream bytes.Buffer
			for _, object := range test.Objects {
				var compact bytes.Buffer
				if err := json.Compact(&compact, object); err != nil {
					t.Fatal(err)
				}
				stream.Write(compact.Bytes())
				stream.WriteByte('\n')
			}
			result, err := DecodeObservedResponse(&stream, StreamOptions{HTTPStatus: test.HTTPStatus, ClientCancelled: test.ClientCancelled})
			if err != nil || string(result.TerminalStatus) != test.Expected.TerminalStatus {
				t.Fatalf("result = %#v, err = %v", result, err)
			}
			if test.Expected.DoneReason != "" && pointerValue(result.DoneReason) != test.Expected.DoneReason {
				t.Fatalf("done reason = %v", result.DoneReason)
			}
			if test.Expected.SafeErrorCategory != "" && pointerValue(result.SafeErrorCategory) != test.Expected.SafeErrorCategory {
				t.Fatalf("safe error = %v", result.SafeErrorCategory)
			}
			if test.Expected.AllNull && result.Metrics != (RuntimeMetrics{}) {
				t.Fatalf("omitted metrics became values: %#v", result.Metrics)
			}
		})
	}
}

func TestObservedResponseAllowsLongDiscardedContentAndContext(t *testing.T) {
	status := 200
	contextValues := make([]string, 200)
	for index := range contextValues {
		contextValues[index] = fmt.Sprint(index)
	}
	stream := `{"response":"` + strings.Repeat("private", 1000) + `","thinking":"` + strings.Repeat("secret", 1000) + `","context":[` + strings.Join(contextValues, ",") + `],"done":true,"done_reason":"stop"}`
	result, err := DecodeObservedResponse(strings.NewReader(stream), StreamOptions{HTTPStatus: &status})
	if err != nil || result.TerminalStatus != TerminalCompleted {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", result), "private") || strings.Contains(fmt.Sprintf("%#v", result), "secret") {
		t.Fatal("discarded stream content was retained")
	}
}

func TestObservedResponseRejectsNumericAndStreamLimits(t *testing.T) {
	status := 200
	for name, stream := range map[string]string{
		"negative duration":  `{"done":true,"done_reason":"stop","total_duration":-1}`,
		"fractional count":   `{"done":true,"done_reason":"stop","eval_count":1.5}`,
		"overflow count":     `{"done":true,"done_reason":"stop","eval_count":1000001}`,
		"nonfinite exponent": `{"done":true,"done_reason":"stop","total_duration":1e999}`,
		"unknown reason":     `{"done":true,"done_reason":"other"}`,
	} {
		result, err := DecodeObservedResponse(strings.NewReader(stream), StreamOptions{HTTPStatus: &status})
		if err != nil || result.TerminalStatus != TerminalFailed || pointerValue(result.SafeErrorCategory) != "malformed_stream" {
			t.Errorf("%s result = %#v, err = %v", name, result, err)
		}
	}
	oversized := strings.Repeat(" ", int(StreamBodyLimit)+1)
	result, err := DecodeObservedResponse(strings.NewReader(oversized), StreamOptions{HTTPStatus: &status})
	if err != nil || pointerValue(result.SafeErrorCategory) != "limit_exceeded" {
		t.Fatalf("oversized result = %#v, err = %v", result, err)
	}
}

func TestObservedResponseCancellationAndHTTPFailureStaySeparate(t *testing.T) {
	result, _ := DecodeObservedResponse(strings.NewReader(""), StreamOptions{ClientCancelled: true})
	if result.TerminalStatus != TerminalCancelled || result.TerminalRecordObserved || pointerValue(result.SafeErrorCategory) != "cancelled" {
		t.Fatalf("cancelled = %#v", result)
	}
	status := 503
	result, _ = DecodeObservedResponse(strings.NewReader(`{"done":true,"done_reason":"stop"}`), StreamOptions{HTTPStatus: &status})
	if result.TerminalStatus != TerminalFailed || result.TerminalRecordObserved || pointerValue(result.SafeErrorCategory) != "http_error" {
		t.Fatalf("http failure = %#v", result)
	}
}

func pointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
