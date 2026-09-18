package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

var errStreamBodyLimit = errors.New("generate response exceeds the bounded stream limit")

// Generate sends one explicitly admitted request to the already validated
// loopback Ollama endpoint. There is no retry, redirect or generic path, and
// the per-client mutex keeps the target at concurrency one.
func (c *Client) Generate(ctx context.Context, input GenerateRequest) (StreamResult, RequestTimings, error) {
	if err := validateGenerateRequest(input); err != nil {
		return StreamResult{}, RequestTimings{}, err
	}
	if !c.requestMu.TryLock() {
		return StreamResult{}, RequestTimings{}, &AdapterError{Kind: ErrorBusy, Op: "generate", Err: errors.New("another request for this target is still active")}
	}
	defer c.requestMu.Unlock()

	started := time.Now()
	requestContext, cancel := context.WithTimeout(ctx, GenerateTimeout)
	defer cancel()
	body, err := json.Marshal(struct {
		Model   string `json:"model"`
		Prompt  string `json:"prompt"`
		Stream  bool   `json:"stream"`
		Think   bool   `json:"think"`
		Options struct {
			NumCtx      int     `json:"num_ctx"`
			NumPredict  int     `json:"num_predict"`
			Temperature float64 `json:"temperature"`
			Seed        int64   `json:"seed"`
		} `json:"options"`
	}{Model: input.Model, Prompt: input.Prompt, Stream: input.Stream, Think: input.Think, Options: struct {
		NumCtx      int     `json:"num_ctx"`
		NumPredict  int     `json:"num_predict"`
		Temperature float64 `json:"temperature"`
		Seed        int64   `json:"seed"`
	}{NumCtx: input.NumCtx, NumPredict: input.NumPredict, Temperature: input.Temperature, Seed: input.Seed}})
	if err != nil {
		return StreamResult{}, RequestTimings{}, &AdapterError{Kind: ErrorMalformed, Op: "generate", Err: err}
	}
	requestURL := *c.baseURL
	requestURL.Path = "/api/generate"
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return StreamResult{}, RequestTimings{}, &AdapterError{Kind: ErrorInvalidTarget, Op: "generate", Err: err}
	}
	request.Header.Set("Accept", "application/x-ndjson")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "llm-monitor/ollama-direct-probe-v1")
	response, err := c.httpClient.Do(request)
	if err != nil {
		timings := RequestTimings{EndNS: elapsedNS(started)}
		if errors.Is(err, context.Canceled) {
			return failedGenerateResult("cancelled", nil), timings, &AdapterError{Kind: ErrorCancelled, Op: "generate", Err: err}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return failedGenerateResult("deadline", nil), timings, &AdapterError{Kind: ErrorTimeout, Op: "generate", Err: err}
		}
		return failedGenerateResult("connection", nil), timings, &AdapterError{Kind: ErrorUnreachable, Op: "generate", Err: err}
	}
	defer response.Body.Close()
	status := response.StatusCode
	timings := RequestTimings{HeadersNS: elapsedNS(started)}
	if status < 200 || status > 299 {
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, RootBodyLimit))
		timings.EndNS = elapsedNS(started)
		if readErr != nil && errors.Is(readErr, context.DeadlineExceeded) {
			return failedGenerateResult("deadline", &status), timings, &AdapterError{Kind: ErrorTimeout, Op: "generate", Err: readErr}
		}
		return failedGenerateResult("http_error", &status), timings, nil
	}

	streamBody, markers, readErr := readObservedStream(response.Body, started)
	timings.FirstByteNS = markers.firstByte
	timings.FirstThinkingNS = markers.firstThinking
	timings.FirstContentNS = markers.firstContent
	timings.EndNS = elapsedNS(started)
	if readErr != nil {
		category := "incomplete_stream"
		kind := ErrorProtocol
		if errors.Is(readErr, errStreamBodyLimit) {
			category, kind = "limit_exceeded", ErrorLimitExceeded
		} else if errors.Is(readErr, context.Canceled) {
			category, kind = "cancelled", ErrorCancelled
		} else if errors.Is(readErr, context.DeadlineExceeded) {
			category, kind = "deadline", ErrorTimeout
		}
		result := failedGenerateResult(category, &status)
		if category == "cancelled" {
			result.TerminalStatus = TerminalCancelled
		}
		return result, timings, &AdapterError{Kind: kind, Op: "generate", Err: readErr}
	}
	result, decodeErr := DecodeObservedResponse(bytes.NewReader(streamBody), StreamOptions{HTTPStatus: &status})
	if decodeErr != nil {
		return failedGenerateResult("malformed_stream", &status), timings, &AdapterError{Kind: ErrorProtocol, Op: "generate", Err: decodeErr}
	}
	return result, timings, nil
}

func validateGenerateRequest(input GenerateRequest) error {
	if input.Model == "" || len(input.Model) > MaxStringBytes || !utf8.ValidString(input.Model) {
		return &AdapterError{Kind: ErrorInvalidTarget, Op: "generate", Err: errors.New("model alias is invalid")}
	}
	if input.Prompt == "" || len(input.Prompt) > 4096 || !utf8.ValidString(input.Prompt) || strings.IndexFunc(input.Prompt, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return &AdapterError{Kind: ErrorMalformed, Op: "generate", Err: errors.New("prompt is invalid")}
	}
	if input.NumCtx < 1 || input.NumCtx > 1024 || input.NumPredict < 1 || input.NumPredict > 64 || input.Temperature < 0 || input.Temperature > 2 || input.Seed < 0 || input.Seed > 2147483647 || !input.Stream {
		return &AdapterError{Kind: ErrorLimitExceeded, Op: "generate", Err: errors.New("request exceeds the bounded inference profile")}
	}
	return nil
}

type streamMarkers struct {
	firstByte, firstThinking, firstContent *uint64
	objectCount                            int
}

func readObservedStream(reader io.Reader, started time.Time) ([]byte, streamMarkers, error) {
	var body bytes.Buffer
	markers := streamMarkers{}
	chunk := make([]byte, 32*1024)
	pending := make([]byte, 0, 32*1024)
	for {
		n, err := reader.Read(chunk)
		if n > 0 {
			if markers.firstByte == nil {
				value := elapsedNS(started)
				markers.firstByte = &value
			}
			if int64(body.Len()+n) > StreamBodyLimit {
				return nil, markers, errStreamBodyLimit
			}
			_, _ = body.Write(chunk[:n])
			pending = append(pending, chunk[:n]...)
			for {
				index := bytes.IndexByte(pending, '\n')
				if index < 0 {
					break
				}
				if err := observeStreamObject(pending[:index], &markers, elapsedNS(started)); err != nil {
					return nil, markers, err
				}
				pending = pending[index+1:]
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, markers, err
		}
	}
	if err := observeStreamObject(pending, &markers, elapsedNS(started)); err != nil {
		return nil, markers, err
	}
	return body.Bytes(), markers, nil
}

func observeStreamObject(line []byte, markers *streamMarkers, now uint64) error {
	if len(bytes.TrimSpace(line)) == 0 {
		return nil
	}
	markers.objectCount++
	if markers.objectCount > MaxArrayItems {
		return errStreamBodyLimit
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(line, &object) != nil {
		return nil
	}
	for field, destination := range map[string]**uint64{"thinking": &markers.firstThinking, "response": &markers.firstContent} {
		value, ok := object[field]
		if !ok {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) == nil && text != "" && *destination == nil {
			captured := now
			*destination = &captured
		}
	}
	return nil
}

func elapsedNS(started time.Time) uint64 {
	return uint64(time.Since(started).Nanoseconds())
}

func failedGenerateResult(category string, status *int) StreamResult {
	result := StreamResult{HTTPStatus: status, TerminalStatus: TerminalFailed}
	result.SafeErrorCategory = &category
	return result
}
