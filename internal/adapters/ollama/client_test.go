package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientUsesOnlyBoundedReadOnlyRoutes(t *testing.T) {
	fixture := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(fixturePath(name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var mu sync.Mutex
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		calls = append(calls, request.Method+" "+request.URL.Path)
		mu.Unlock()
		switch request.Method + " " + request.URL.Path {
		case "GET /":
			_, _ = response.Write([]byte("Ollama is running"))
		case "GET /api/version":
			_, _ = response.Write(fixture("version-0.34.0.json"))
		case "GET /api/ps":
			_, _ = response.Write(fixture("ps-loaded.json"))
		case "GET /api/tags":
			_, _ = response.Write(fixture("tags.json"))
		case "POST /api/show":
			body, err := readBounded(request.Body, 1024)
			if err != nil || string(body) != `{"model":"qwen3:0.6b"}` {
				http.Error(response, "unexpected show body", http.StatusBadRequest)
				return
			}
			_, _ = response.Write(fixture("show.json"))
		default:
			http.Error(response, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if root, err := client.Root(context.Background()); err != nil || !root.Reachable {
		t.Fatalf("root = %#v, %v", root, err)
	}
	version, err := client.Version(context.Background())
	if err != nil || version.Version != "0.34.0" || version.SourcePinID != "ollama-0.34.0-source" || version.CompatibilityState != CompatibilityUnverified {
		t.Fatalf("version = %#v, %v", version, err)
	}
	loaded, err := client.LoadedModels(context.Background())
	if err != nil || len(loaded.Models) != 1 || !loaded.Models[0].Loaded || loaded.Models[0].SizeVRAMBytes == nil {
		t.Fatalf("loaded = %#v, %v", loaded, err)
	}
	tags, err := client.Tags(context.Background())
	if err != nil || len(tags.Models) != 1 || tags.Models[0].Loaded {
		t.Fatalf("tags = %#v, %v", tags, err)
	}
	show, err := client.Show(context.Background(), "qwen3:0.6b", tags.Models[0].Digest)
	if err != nil || show.Details.Family == nil || *show.Details.Family != "qwen3" || len(show.Capabilities) != 2 {
		t.Fatalf("show = %#v, %v", show, err)
	}
	if rendered := fmt.Sprintf("%#v", show); strings.Contains(rendered, "SYNTHETIC_SECRET_CANARY") {
		t.Fatalf("discarded show content escaped normalization: %s", rendered)
	}
	want := []string{"GET /", "GET /api/version", "GET /api/ps", "GET /api/tags", "POST /api/show"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %v", calls)
	}
}

func TestClientRejectsUnsafeTargets(t *testing.T) {
	for _, endpoint := range []string{
		"http://localhost:11434", "http://127.0.0.2:11434", "http://192.0.2.1:11434",
		"https://127.0.0.1:11434", "http://user:pass@127.0.0.1:11434", "http://127.0.0.1",
		"http://127.0.0.1:11434/api", "http://127.0.0.1:11434?model=x",
	} {
		if _, err := NewClient(endpoint); ErrorKindOf(err) != ErrorInvalidTarget {
			t.Errorf("NewClient(%q) error = %v", endpoint, err)
		}
	}
	if _, err := NewClient("http://[::1]:11434"); err != nil {
		t.Fatalf("IPv6 loopback rejected: %v", err)
	}
	client, err := NewClient("http://127.0.0.1:11434")
	if err != nil {
		t.Fatal(err)
	}
	if transport := client.httpClient.Transport.(*http.Transport); transport.Proxy != nil {
		t.Fatal("environment proxy remained enabled")
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	destinationCalled := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalled = true }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	client, err := NewClient(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Root(context.Background())
	if ErrorKindOf(err) != ErrorProtocol || destinationCalled {
		t.Fatalf("redirect error = %v, destination called = %v", err, destinationCalled)
	}
}

func TestClientRejectsWrongRootProtocolAndOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/" {
			_, _ = response.Write([]byte("another service"))
			return
		}
		_, _ = response.Write([]byte(`{"version":"` + strings.Repeat("x", int(VersionBodyLimit)) + `"}`))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL)
	if _, err := client.Root(context.Background()); ErrorKindOf(err) != ErrorProtocol {
		t.Fatalf("root error = %v", err)
	}
	if _, err := client.Version(context.Background()); ErrorKindOf(err) != ErrorLimitExceeded {
		t.Fatalf("version error = %v", err)
	}
}

func TestClientSkipsConcurrentTargetCall(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = response.Write([]byte("Ollama is running"))
	}))
	defer server.Close()
	client, _ := NewClient(server.URL)
	done := make(chan error, 1)
	go func() { _, err := client.Root(context.Background()); done <- err }()
	<-entered
	started := time.Now()
	_, err := client.Root(context.Background())
	if ErrorKindOf(err) != ErrorBusy || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("concurrent call error = %v, elapsed = %v", err, time.Since(started))
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDecodeInventoryRejectsMalformedAndCardinalityViolations(t *testing.T) {
	model := `{"model":"m","size":1,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	three := `{"models":[` + strings.Join([]string{model, model, model}, ",") + `]}`
	for name, data := range map[string][]byte{
		"duplicate key": []byte(`{"models":[],"models":[]}`),
		"invalid utf8":  {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"trailing":      []byte(`{"models":[]} {}`),
		"negative":      []byte(`{"models":[{"model":"m","size":-1}]}`),
		"fraction":      []byte(`{"models":[{"model":"m","size":1.5}]}`),
		"overflow":      []byte(`{"models":[{"model":"m","size":9223372036854775808}]}`),
	} {
		if _, err := decodeModels(data, true, MaxLoadedModels); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := decodeModels([]byte(three), true, MaxLoadedModels); ErrorKindOf(err) != ErrorLimitExceeded {
		t.Fatalf("loaded cardinality error = %v", err)
	}
	large, err := decodeModels([]byte(`{"models":[{"model":"m","size":9007199254740993,"size_vram":0,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`), true, MaxLoadedModels)
	if err != nil || large.Models[0].ReportedSizeBytes == nil || *large.Models[0].ReportedSizeBytes != 9007199254740993 || large.Models[0].SizeVRAMBytes == nil || *large.Models[0].SizeVRAMBytes != 0 {
		t.Fatalf("exact large/zero counters = %#v, %v", large, err)
	}
}

func TestUnknownVersionNeverInheritsSourceCertification(t *testing.T) {
	if got := sourcePinForVersion("0.34.1"); got != "runtime-version-unverified" {
		t.Fatalf("source pin = %q", got)
	}
}

func TestShowDiscardsLongUnadmittedText(t *testing.T) {
	data := []byte(`{"template":"` + strings.Repeat("private", 1000) + `","system":"` + strings.Repeat("secret", 1000) + `","details":{"family":"qwen3"},"capabilities":["completion"]}`)
	show, err := decodeShow(data, "selected", nil)
	if err != nil || show.Details.Family == nil || *show.Details.Family != "qwen3" {
		t.Fatalf("show = %#v, %v", show, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", show), "private") || strings.Contains(fmt.Sprintf("%#v", show), "secret") {
		t.Fatal("discarded text was retained")
	}
}

func TestContextDeadlineCanBeShorterThanAdapterDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	client, _ := NewClient(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := client.Root(ctx)
	if err == nil || ErrorKindOf(err) != ErrorTimeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v", err)
	}
}

func TestGenerateCapturesBoundedTimingsAndRuntimeMetricsWithoutContent(t *testing.T) {
	var seenBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/generate" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&seenBody); err != nil {
			t.Fatalf("request body: %v", err)
		}
		response.Header().Set("Content-Type", "application/x-ndjson")
		flusher, ok := response.(http.Flusher)
		if !ok {
			t.Fatal("test server does not support flushing")
		}
		_, _ = response.Write([]byte(`{"model":"qwen3:0.6b","thinking":"","response":"hello" ,"done":false}` + "\n"))
		flusher.Flush()
		time.Sleep(2 * time.Millisecond)
		_, _ = response.Write([]byte(`{"model":"qwen3:0.6b","response":"","done":true,"done_reason":"stop","total_duration":9000000,"load_duration":1000000,"prompt_eval_duration":2000000,"eval_duration":6000000,"prompt_eval_count":8,"eval_count":4}` + "\n"))
		flusher.Flush()
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, timings, err := client.Generate(context.Background(), GenerateRequest{Model: "qwen3:0.6b", Prompt: "Say hello.", NumCtx: 1024, NumPredict: 64, Temperature: 0, Seed: 7, Stream: true})
	if err != nil {
		t.Fatalf("generate error = %v", err)
	}
	if result.TerminalStatus != TerminalCompleted || result.DoneReason == nil || *result.DoneReason != "stop" || result.Metrics.OutputTokens == nil || *result.Metrics.OutputTokens != 4 {
		t.Fatalf("result = %#v", result)
	}
	if timings.HeadersNS == 0 || timings.FirstByteNS == nil || timings.FirstContentNS == nil || timings.EndNS < *timings.FirstContentNS {
		t.Fatalf("timings = %#v", timings)
	}
	if seenBody["model"] != "qwen3:0.6b" || seenBody["stream"] != true || seenBody["think"] != false {
		t.Fatalf("request body = %#v", seenBody)
	}
	options, ok := seenBody["options"].(map[string]any)
	if !ok || options["num_ctx"] != float64(1024) || options["num_predict"] != float64(64) || options["seed"] != float64(7) {
		t.Fatalf("request options = %#v", seenBody["options"])
	}
	if strings.Contains(fmt.Sprintf("%#v", result), "hello") {
		t.Fatalf("response content escaped normalization: %#v", result)
	}
}

func TestGenerateRejectsOutOfProfileRequestBeforeHTTP(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	client, _ := NewClient(server.URL)
	_, _, err := client.Generate(context.Background(), GenerateRequest{Model: "model", Prompt: "prompt", NumCtx: 2048, NumPredict: 64, Stream: true})
	if ErrorKindOf(err) != ErrorLimitExceeded || called {
		t.Fatalf("error = %v, server called = %t", err, called)
	}
}

func fixturePath(name string) string { return "../../../fixtures/ollama/" + name }
