package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func recoveryFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../fixtures/contracts/valid/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRecoveryFixturesBindCanonicalHashesAndExactReceipts(t *testing.T) {
	manifest, err := DecodeRecoveryManifest(bytes.NewReader(recoveryFixture(t, "recovery-manifest.json")))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := DecodeRecoveryGrant(bytes.NewReader(recoveryFixture(t, "recovery-grant.json")))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := DecodeRecoveryReplay(bytes.NewReader(recoveryFixture(t, "recovery-replay.json")))
	if err != nil {
		t.Fatal(err)
	}
	var ack RecoveryACK
	if err := json.Unmarshal(recoveryFixture(t, "recovery-ack.json"), &ack); err != nil {
		t.Fatal(err)
	}
	if manifest.ManifestSHA256 != grant.ManifestSHA256 || grant.GrantSHA256 != replay.GrantSHA256 {
		t.Fatal("recovery chain hashes are not bound")
	}
	if err := ack.Validate(replay); err != nil {
		t.Fatal(err)
	}
	ack.Accepted, ack.Rejected = 0, 1
	if err := ack.Validate(replay); err == nil {
		t.Fatal("swapped terminal counts were accepted")
	}
}

func TestRecoveryDecodersRejectMissingNullAndSelfHashMutation(t *testing.T) {
	var manifest map[string]any
	if err := json.Unmarshal(recoveryFixture(t, "recovery-manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"null loss array": func(value map[string]any) { value["loss_intervals"] = nil },
		"missing historical models": func(value map[string]any) {
			delete(value["historical_definitions"].(map[string]any), "models")
		},
		"mutated self hash input": func(value map[string]any) { value["total_bytes"] = value["total_bytes"].(float64) + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			copyValue := make(map[string]any)
			encoded, _ := json.Marshal(manifest)
			_ = json.Unmarshal(encoded, &copyValue)
			mutate(copyValue)
			encoded, _ = json.Marshal(copyValue)
			if _, err := DecodeRecoveryManifest(bytes.NewReader(encoded)); err == nil {
				t.Fatal("invalid recovery manifest accepted")
			}
		})
	}

	var replay map[string]any
	if err := json.Unmarshal(recoveryFixture(t, "recovery-replay.json"), &replay); err != nil {
		t.Fatal(err)
	}
	delete(replay["frames"].([]any)[0].(map[string]any)["frame"].(map[string]any), "process_summary")
	encoded, _ := json.Marshal(replay)
	if _, err := DecodeRecoveryReplay(bytes.NewReader(encoded)); err == nil {
		t.Fatal("recovery replay with an incomplete nested frame was accepted")
	}
}

func TestRecoveryReceiptDecoderHasSeparateLocalBound(t *testing.T) {
	type receiptFile struct {
		Version int `json:"version"`
	}
	data := []byte(`{"version":1}`)
	var value receiptFile
	if err := DecodeStrictJSON(bytes.NewReader(data), MaxBatchBytes+1, &value); err == nil {
		t.Fatal("collector network decoder accepted a limit above its wire cap")
	}
	if err := DecodeStrictRecoveryReceiptJSON(bytes.NewReader(data), &value); err != nil || value.Version != 1 {
		t.Fatalf("bounded local receipt decode failed: value=%#v err=%v", value, err)
	}
	if err := DecodeStrictRecoveryReceiptJSON(bytes.NewBufferString(`{"version":1,"version":1}`), &value); err == nil {
		t.Fatal("local recovery receipt decoder accepted a duplicate key")
	}
	if err := DecodeStrictRecoveryReceiptJSON(bytes.NewBufferString(`{"version":1,"unknown":true}`), &value); err == nil {
		t.Fatal("local recovery receipt decoder accepted an unknown field")
	}
}
