package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"rmt.local/monitor/internal/domain"
)

func TestDecodeAcceptedCollectorBatchFixture(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/contracts/valid/collector-batch.json")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := DecodeCollectorBatch(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Frames) != 3 || batch.Frames[0].SourceID == batch.Frames[1].SourceID || batch.Frames[2].ConfigObservation == nil {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestCollectorDecoderRejectsUnknownDuplicateTrailingAndOversized(t *testing.T) {
	valid := `{"protocol":"1.0","deployment_id":"00000000-0000-4000-8000-000000000001","host_id":"00000000-0000-4000-8000-000000000002","security_generation":"77777777-7777-4777-8777-777777777777","activation_request_id":"22222222-2222-4222-8222-222222222222","collector_boot_id":"11111111-1111-4111-8111-111111111111","expected_previous_generation":0}`
	for name, data := range map[string]string{
		"unknown":   strings.TrimSuffix(valid, "}") + `,"extra":true}`,
		"duplicate": strings.Replace(valid, `"protocol":"1.0"`, `"protocol":"1.0","protocol":"1.0"`, 1),
		"trailing":  valid + ` {}`,
	} {
		if _, err := DecodeSessionActivation(strings.NewReader(data)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := DecodeSourceStatus(strings.NewReader(strings.Repeat(" ", int(MaxStatusBytes)+1))); err == nil {
		t.Fatal("oversized status accepted")
	}
}

func TestBatchRejectsDuplicateFrameKey(t *testing.T) {
	data, _ := os.ReadFile("../../fixtures/contracts/valid/collector-batch.json")
	batch, err := DecodeCollectorBatch(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	batch.Frames = append(batch.Frames, batch.Frames[0])
	if err := batch.Validate(); err == nil {
		t.Fatal("duplicate frame key accepted")
	}
}

func TestInventoryAllowsOnlyInactiveHistoricalSourceWithoutCurrentTarget(t *testing.T) {
	inventory := CollectorInventory{
		Protocol:           "1.0",
		DeploymentID:       "00000000-0000-4000-8000-000000000001",
		HostID:             "00000000-0000-4000-8000-000000000002",
		SecurityGeneration: "77777777-7777-4777-8777-777777777777",
		SessionGeneration:  1,
		CollectorBootID:    "11111111-1111-4111-8111-111111111111",
		InventoryRevision:  strings.Repeat("a", 64),
		Sources: []InventorySource{{
			SourceID:           "22222222-2222-4222-8222-222222222222",
			Kind:               "runtime",
			TargetID:           stringPointer("33333333-3333-4333-8333-333333333333"),
			CapabilityRevision: "mac-ollama-1",
			Active:             false,
		}},
	}
	if err := inventory.Validate(); err != nil {
		t.Fatalf("inactive historical source = %v", err)
	}
	inventory.Sources[0].Active = true
	if err := inventory.Validate(); err == nil {
		t.Fatal("active source without current target accepted")
	}
}

func TestDecodeStrictJSONIsReusableForClosedLocalManifests(t *testing.T) {
	type manifest struct {
		Name string `json:"name"`
	}
	var value manifest
	if err := DecodeStrictJSON(strings.NewReader(`{"name":"local"}`), 64, &value); err != nil || value.Name != "local" {
		t.Fatalf("valid local manifest = %#v, %v", value, err)
	}
	if err := DecodeStrictJSON(strings.NewReader(`{"name":"a","name":"b"}`), 64, &value); err == nil {
		t.Fatal("duplicate local manifest key accepted")
	}
	if err := DecodeStrictJSON(strings.NewReader(`{"name":"local","unknown":true}`), 64, &value); err == nil {
		t.Fatal("unknown local manifest field accepted")
	}
}

func TestCollectorRoutesRejectOmittedAndNullRequiredProperties(t *testing.T) {
	batchData, err := os.ReadFile("../../fixtures/contracts/valid/collector-batch.json")
	if err != nil {
		t.Fatal(err)
	}
	var batch map[string]any
	if err := json.Unmarshal(batchData, &batch); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"omitted nullable offset": func(frame map[string]any) { delete(frame, "offset_ms") },
		"omitted process summary": func(frame map[string]any) { delete(frame, "process_summary") },
		"null required array":     func(frame map[string]any) { frame["network_observations"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			copyBatch := cloneMap(t, batch)
			frame := copyBatch["frames"].([]any)[0].(map[string]any)
			mutate(frame)
			encoded, _ := json.Marshal(copyBatch)
			if _, err := DecodeCollectorBatch(bytes.NewReader(encoded)); err == nil {
				t.Fatal("malformed required shape accepted")
			}
		})
	}

	activation := map[string]any{
		"protocol": "1.0", "deployment_id": "00000000-0000-4000-8000-000000000001", "host_id": "00000000-0000-4000-8000-000000000002",
		"security_generation": "77777777-7777-4777-8777-777777777777", "activation_request_id": "22222222-2222-4222-8222-222222222222", "collector_boot_id": "11111111-1111-4111-8111-111111111111",
	}
	encoded, _ := json.Marshal(activation)
	if _, err := DecodeSessionActivation(bytes.NewReader(encoded)); err == nil {
		t.Fatal("omitted zero-valued expected_previous_generation accepted")
	}

	inventory := CollectorInventory{
		Protocol: "1.0", DeploymentID: testContractUUID(1), HostID: testContractUUID(2), SecurityGeneration: testContractUUID(3), SessionGeneration: 1,
		CollectorBootID: testContractUUID(4), InventoryRevision: strings.Repeat("a", 64),
		Sources: []InventorySource{{SourceID: testContractUUID(5), Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true}},
		Targets: []InventoryTarget{}, Models: []InventoryModel{},
	}
	inventoryData, _ := json.Marshal(inventory)
	var inventoryMap map[string]any
	_ = json.Unmarshal(inventoryData, &inventoryMap)
	inventoryMap["models"] = nil
	inventoryData, _ = json.Marshal(inventoryMap)
	if _, err := DecodeCollectorInventory(bytes.NewReader(inventoryData)); err == nil {
		t.Fatal("null required inventory models accepted")
	}

	status := SourceStatus{
		Protocol: "1.0", DeploymentID: testContractUUID(1), HostID: testContractUUID(2), SecurityGeneration: testContractUUID(3), SessionGeneration: 1,
		CollectorBootID: testContractUUID(4), ObservedWallMS: 1, Heartbeat: "fresh", Sources: []SourceState{}, LossIntervals: []LossInterval{},
	}
	statusData, _ := json.Marshal(status)
	var statusMap map[string]any
	_ = json.Unmarshal(statusData, &statusMap)
	statusMap["sources"] = nil
	statusData, _ = json.Marshal(statusMap)
	if _, err := DecodeSourceStatus(bytes.NewReader(statusData)); err == nil {
		t.Fatal("null required source-status array accepted")
	}
}

func TestCollectorFrameRejectsDurationContradiction(t *testing.T) {
	data, _ := os.ReadFile("../../fixtures/contracts/valid/collector-batch.json")
	batch, err := DecodeCollectorBatch(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	batch.Frames[0].DurationMS = 5000
	if err := batch.Frames[0].Validate(); err == nil {
		t.Fatal("duration contradicting monotonic endpoints accepted")
	}
}

func TestCollectorConfigObservationRejectsHashAndRequiredShapeChanges(t *testing.T) {
	data, _ := os.ReadFile("../../fixtures/contracts/valid/collector-batch.json")
	batch, err := DecodeCollectorBatch(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	configFrame := batch.Frames[2]
	configFrame.ConfigObservation.ConfigHash = strings.Repeat("f", 64)
	if err := configFrame.Validate(); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("config hash error=%v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	frame := document["frames"].([]any)[2].(map[string]any)
	fields := frame["config_observation"].(map[string]any)["fields"].(map[string]any)
	delete(fields, "server_build")
	malformed, _ := json.Marshal(document)
	if _, err := DecodeCollectorBatch(bytes.NewReader(malformed)); err == nil || !strings.Contains(err.Error(), "server_build") {
		t.Fatalf("missing config field error=%v", err)
	}
}

func TestCollectorEndpointAssociationIsClosedVerifiedAndBackwardOptional(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/contracts/valid/collector-batch.json")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := DecodeCollectorBatch(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if batch.Frames[0].EndpointAssociation != nil {
		t.Fatal("legacy fixture unexpectedly requires endpoint association")
	}
	if _, err := DecodeCollectorBatch(bytes.NewReader(data)); err != nil {
		t.Fatalf("older retained frame without optional association=%v", err)
	}
	frame := batch.Frames[0]
	frame.Gauges = map[string]MetricValue{}
	frame.NetworkObservations = []domain.NetworkObservation{}
	version, sourcePin := "0.12.10", "ollama-0.12.10-source"
	pid, start, key := frame.ProcessObservations[0].PID, frame.ProcessObservations[0].ProcessStartIdentity, frame.ProcessObservations[0].ProcessKey
	frame.EndpointAssociation = &domain.EndpointAssociation{TargetID: *frame.ProcessObservations[0].TargetID, EndpointHash: strings.Repeat("e", 64), TargetRevision: 3, ManifestRevision: 2, ManifestSHA256: strings.Repeat("f", 64), SelectorSHA256: strings.Repeat("e", 64), IdentityRevision: strings.Repeat("a", 64), RuntimeVersion: &version, RuntimeSourcePinID: &sourcePin, PID: &pid, ProcessStartIdentity: &start, ProcessKey: &key, Quality: domain.AssociationVerified, Provenance: frame.ProcessObservations[0].Provenance}
	if err := frame.Validate(); err != nil {
		t.Fatalf("verified association frame=%v", err)
	}
	batch.Frames[0] = frame
	associationJSON, _ := json.Marshal(batch)

	unknown := cloneMap(t, mustJSONMap(t, associationJSON))
	unknown["frames"].([]any)[0].(map[string]any)["endpoint_association"].(map[string]any)["unexpected"] = true
	encoded, _ := json.Marshal(unknown)
	if _, err := DecodeCollectorBatch(bytes.NewReader(encoded)); err == nil {
		t.Fatal("unknown association field accepted")
	}

	invalid := frame
	associationCopy := *frame.EndpointAssociation
	wrongPID := pid + 1
	associationCopy.PID = &wrongPID
	invalid.EndpointAssociation = &associationCopy
	if err := invalid.Validate(); err == nil {
		t.Fatal("verified association with mismatched PID accepted")
	}
	invalid = frame
	associationCopy = *frame.EndpointAssociation
	invalid.EndpointAssociation = &associationCopy
	invalid.EndpointAssociation.ProcessKey = nil
	if err := invalid.Validate(); err == nil {
		t.Fatal("verified association without exact process identity accepted")
	}
}

func mustJSONMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func cloneMap(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	return output
}

func testContractUUID(suffix byte) string {
	return "00000000-0000-4000-8000-00000000000" + string('0'+suffix)
}

func stringPointer(value string) *string { return &value }
