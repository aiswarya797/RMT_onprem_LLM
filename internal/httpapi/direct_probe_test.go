package httpapi

import (
	"testing"

	"rmt.local/monitor/internal/adapters/ollama"
)

func TestConfigureLocalProbeEndpointAcceptsOnlyLiteralLoopback(t *testing.T) {
	server := &Server{}
	if err := server.ConfigureLocalProbeEndpoint("http://127.0.0.1:11436"); err != nil {
		t.Fatalf("loopback endpoint rejected: %v", err)
	}
	if server.localProbeEndpoint != "http://127.0.0.1:11436" {
		t.Fatalf("endpoint not retained: %q", server.localProbeEndpoint)
	}
	if err := server.ConfigureLocalProbeEndpoint("http://example.invalid:11436"); err == nil {
		t.Fatal("non-loopback endpoint accepted")
	}
}

func TestSmallQuantizedModelAcceptsMegaparameterSize(t *testing.T) {
	parameterSize := "751.63M"
	quantization := "Q4_0"
	model := ollama.Model{Local: true, Details: ollama.ModelDetails{ParameterSize: &parameterSize, QuantizationLevel: &quantization}}
	if !smallQuantizedModel(model) {
		t.Fatal("751.63M quantized model was rejected")
	}
	parameterSize = "1.1B"
	if smallQuantizedModel(model) {
		t.Fatal("1.1B model was admitted")
	}
}
