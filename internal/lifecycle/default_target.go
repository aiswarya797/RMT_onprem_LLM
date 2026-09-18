package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/domain"
)

// ensureDefaultOllamaTarget creates the safe, read-only local endpoint that a
// fresh collector can check without asking the operator to edit a manifest.
// The endpoint is deliberately loopback-only; a remote collector creates this
// target on the remote Mac, so target authority remains collector-side.
func ensureDefaultOllamaTarget(directory, generation string) (bool, error) {
	state, err := pairing.ReadTargets(directory, generation)
	if err != nil {
		return false, err
	}
	for _, target := range state.Targets {
		if !target.Retired {
			return false, nil
		}
	}

	manifestID, err := domain.NewUUID()
	if err != nil {
		return false, err
	}
	endpoint := pairing.Endpoint{Scheme: "http", Host: "127.0.0.1", Port: 11434}
	endpointJSON, err := json.Marshal(endpoint)
	if err != nil {
		return false, err
	}
	endpointDigest := sha256.Sum256(endpointJSON)
	manifest := pairing.TargetManifest{
		SchemaVersion:    domain.SchemaVersion,
		ManifestID:       manifestID,
		ManifestRevision: 1,
		AdapterID:        "ollama",
		Endpoint:         endpoint,
		IdentityRevision: hex.EncodeToString(endpointDigest[:]),
		DisplayName:      "Local Ollama",
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return false, err
	}
	manifestDigest := sha256.Sum256(manifestJSON)
	key, err := domain.NewUUID()
	if err != nil {
		return false, err
	}
	if _, err := pairing.ApplyTarget(directory, generation, key, "add", "", 0, &manifest, hex.EncodeToString(manifestDigest[:])); err != nil {
		return false, fmt.Errorf("create default local Ollama target: %w", err)
	}
	return true, nil
}

func hasActiveTarget(directory, generation string) (bool, error) {
	state, err := pairing.ReadTargets(directory, generation)
	if err != nil {
		return false, err
	}
	for _, target := range state.Targets {
		if !target.Retired {
			return true, nil
		}
	}
	return false, nil
}

func requireActiveTarget(directory, generation string) error {
	active, err := hasActiveTarget(directory, generation)
	if err != nil {
		return err
	}
	if !active {
		return errors.New("no local Ollama target is configured")
	}
	return nil
}
