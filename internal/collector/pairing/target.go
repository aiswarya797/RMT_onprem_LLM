package pairing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

type Endpoint struct {
	Scheme   string `json:"scheme"`
	Host     string `json:"loopback_host"`
	Port     int    `json:"port"`
	BasePath string `json:"base_path"`
}

func (e Endpoint) URL() string {
	return e.Scheme + "://" + net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

type TargetManifest struct {
	SchemaVersion    string   `json:"schema_version"`
	ManifestID       string   `json:"manifest_id"`
	ManifestRevision int      `json:"manifest_revision"`
	AdapterID        string   `json:"adapter_id"`
	Endpoint         Endpoint `json:"endpoint"`
	IdentityRevision string   `json:"identity_revision"`
	DisplayName      string   `json:"display_name"`
}

var targetUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
var targetHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (m TargetManifest) Validate() error {
	if m.SchemaVersion != "1.0" || !targetUUID.MatchString(m.ManifestID) || m.ManifestRevision < 1 || m.ManifestRevision > 1000000 || m.AdapterID != "ollama" || !targetHash.MatchString(m.IdentityRevision) {
		return errors.New("invalid manifest identity or revision")
	}
	if m.Endpoint.Scheme != "http" || (m.Endpoint.Host != "127.0.0.1" && m.Endpoint.Host != "::1") || m.Endpoint.Port < 1 || m.Endpoint.Port > 65535 || m.Endpoint.BasePath != "" {
		return errors.New("manifest endpoint must be literal loopback HTTP with an explicit port and no path")
	}
	if len(m.DisplayName) == 0 || len(m.DisplayName) > 256 || !utf8.ValidString(m.DisplayName) {
		return errors.New("invalid target display name")
	}
	for _, r := range m.DisplayName {
		if unicode.IsControl(r) {
			return errors.New("invalid target display name")
		}
	}
	return nil
}

type LocalTarget struct {
	TargetID       string         `json:"target_id"`
	SourceID       string         `json:"source_id"`
	Revision       int            `json:"revision"`
	Manifest       TargetManifest `json:"manifest"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	SelectorSHA256 string         `json:"selector_sha256"`
	Retired        bool           `json:"retired"`
}
type TargetResult struct {
	Status     string  `json:"status"`
	ResourceID *string `json:"resource_id"`
	SafeCode   string  `json:"safe_code"`
}
type targetReceipt struct {
	Key, Hash string
	AtMS      int64
	Result    TargetResult
}
type TargetState struct {
	Version    int             `json:"version"`
	Generation string          `json:"deployment_generation"`
	Targets    []LocalTarget   `json:"targets"`
	Receipts   []targetReceipt `json:"receipts"`
}

func ReadTargets(directory, generation string) (TargetState, error) {
	value := TargetState{Version: 1, Generation: generation, Targets: []LocalTarget{}, Receipts: []targetReceipt{}}
	path := filepath.Join(directory, "targets.json")
	if err := config.ValidatePrivateFile(path); errors.Is(err, os.ErrNotExist) {
		return value, nil
	} else if err != nil {
		return value, err
	}
	f, err := os.Open(path)
	if err != nil {
		return value, err
	}
	defer f.Close()
	if err := protocol.DecodeStrictJSON(f, maxStateBytes, &value); err != nil {
		return value, err
	}
	if err := validateTargetState(value, generation); err != nil {
		return value, err
	}
	return value, nil
}

func validateTargetState(value TargetState, generation string) error {
	if value.Version != 1 || value.Generation != generation || len(value.Targets) > 128 || len(value.Receipts) > 256 {
		return errors.New("target state requires recovery")
	}
	active := 0
	for _, target := range value.Targets {
		if err := target.Manifest.Validate(); err != nil {
			return err
		}
		if !targetUUID.MatchString(target.TargetID) || !targetUUID.MatchString(target.SourceID) || !targetHash.MatchString(target.SelectorSHA256) {
			return errors.New("invalid target state")
		}
		if !target.Retired {
			active++
		}
	}
	if active > 1 {
		return errors.New("more than one local target configured")
	}
	return nil
}

// reEnrollTargets advances only the generation-bound local action state. The
// target and source identities remain stable so retained observations keep
// their owner relationship after the reviewed host is reactivated.
func reEnrollTargets(directory, previousGeneration, nextGeneration string) error {
	path := filepath.Join(directory, "targets.json")
	if err := config.ValidatePrivateFile(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	var value TargetState
	decodeErr := protocol.DecodeStrictJSON(io.LimitReader(file, maxStateBytes+1), maxStateBytes, &value)
	closeErr := file.Close()
	if decodeErr != nil {
		return decodeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if value.Generation != previousGeneration && value.Generation != nextGeneration {
		return errors.New("target generation changed during re-enrollment")
	}
	if err := validateTargetState(value, value.Generation); err != nil {
		return err
	}
	if value.Generation == nextGeneration {
		return nil
	}
	value.Generation = nextGeneration
	value.Receipts = []targetReceipt{}
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxStateBytes {
		return errors.New("target state capacity exceeded during re-enrollment")
	}
	return config.WritePrivateFile(path, data)
}

// ApplyTarget is a local-owner operation. One atomic file contains both the
// configuration and its idempotency receipt, so retry cannot apply it twice.
func ApplyTarget(directory, generation, key, operation, targetID string, expectedRevision int, manifest *TargetManifest, manifestHash string) (TargetResult, error) {
	if !targetUUID.MatchString(key) {
		return TargetResult{}, errors.New("idempotency key must be a UUID")
	}
	lockPath := filepath.Join(directory, "targets.lock")
	if err := config.RejectSymlinkTree(lockPath); err != nil {
		return TargetResult{}, err
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return TargetResult{}, err
	}
	defer lock.Close()
	if err := config.ValidatePrivateFile(lockPath); err != nil {
		return TargetResult{}, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return TargetResult{}, errors.New("target configuration busy; retry")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	state, err := ReadTargets(directory, generation)
	if err != nil {
		return TargetResult{}, err
	}
	requestBytes, _ := json.Marshal(struct {
		Operation, TargetID, ManifestHash string
		Revision                          int
		Manifest                          *TargetManifest
	}{operation, targetID, manifestHash, expectedRevision, manifest})
	digest := sha256.Sum256(requestBytes)
	requestHash := hex.EncodeToString(digest[:])
	now := time.Now().UnixMilli()
	receipts := []targetReceipt{}
	for _, receipt := range state.Receipts {
		if now-receipt.AtMS > int64(24*time.Hour/time.Millisecond) {
			continue
		}
		if receipt.Key == key {
			if receipt.Hash != requestHash {
				return TargetResult{}, errors.New("idempotency key was used for different input")
			}
			return receipt.Result, nil
		}
		receipts = append(receipts, receipt)
	}
	if len(receipts) >= 256 {
		return TargetResult{}, errors.New("local action receipt capacity busy; retry after receipts expire")
	}
	active := -1
	for i, target := range state.Targets {
		if !target.Retired {
			active = i
		}
	}
	if operation != "remove" {
		if manifest == nil || !targetHash.MatchString(manifestHash) {
			return TargetResult{}, errors.New("reviewed manifest and hash required")
		}
		if err := manifest.Validate(); err != nil {
			return TargetResult{}, err
		}
	}
	switch operation {
	case "add":
		if active >= 0 {
			return TargetResult{}, errors.New("a local target already exists; use targets edit")
		}
		if len(state.Targets) >= 128 {
			return TargetResult{}, errors.New("retired target identity capacity reached; preserve history and review maintenance")
		}
		id, err := domain.NewUUID()
		if err != nil {
			return TargetResult{}, err
		}
		source, err := domain.NewUUID()
		if err != nil {
			return TargetResult{}, err
		}
		state.Targets = append(state.Targets, LocalTarget{TargetID: id, SourceID: source, Revision: 1})
		active = len(state.Targets) - 1
	case "edit":
		if active < 0 || state.Targets[active].TargetID != targetID || state.Targets[active].Revision != expectedRevision {
			return TargetResult{}, errors.New("target revision changed; reread current state")
		}
		if manifest.ManifestID != state.Targets[active].Manifest.ManifestID || manifest.ManifestRevision <= state.Targets[active].Manifest.ManifestRevision {
			return TargetResult{}, errors.New("edited manifest must advance the same manifest revision")
		}
		selector, _ := json.Marshal(manifest.Endpoint)
		hash := sha256.Sum256(selector)
		selectorHash := hex.EncodeToString(hash[:])
		if selectorHash != state.Targets[active].SelectorSHA256 {
			// Endpoint identity is immutable in the hub. Retire the old source
			// rather than relabeling its historical observations with a new URL.
			// If this exact reviewed endpoint is being restored, reuse its retired
			// identity so the immutable selector history remains unique.
			state.Targets[active].Retired = true
			reused := -1
			for i, candidate := range state.Targets {
				if i != active && candidate.Retired && candidate.SelectorSHA256 == selectorHash && candidate.Manifest.ManifestID == manifest.ManifestID && candidate.Manifest.AdapterID == manifest.AdapterID {
					reused = i
					break
				}
			}
			if reused >= 0 {
				state.Targets[reused].Manifest = *manifest
				state.Targets[reused].ManifestSHA256 = manifestHash
				state.Targets[reused].SelectorSHA256 = selectorHash
				state.Targets[reused].Revision++
				state.Targets[reused].Retired = false
				active = reused
			} else {
				if len(state.Targets) >= 128 {
					return TargetResult{}, errors.New("retired target identity capacity reached")
				}
				id, err := domain.NewUUID()
				if err != nil {
					return TargetResult{}, err
				}
				source, err := domain.NewUUID()
				if err != nil {
					return TargetResult{}, err
				}
				state.Targets = append(state.Targets, LocalTarget{TargetID: id, SourceID: source, Revision: 1})
				active = len(state.Targets) - 1
			}
		} else {
			state.Targets[active].Revision++
		}
	case "remove":
		if active < 0 || state.Targets[active].TargetID != targetID {
			return TargetResult{}, errors.New("target is not active")
		}
		state.Targets[active].Retired = true
		state.Targets[active].Revision++
	default:
		return TargetResult{}, errors.New("unknown target operation")
	}
	target := &state.Targets[active]
	if operation != "remove" {
		target.Manifest = *manifest
		target.ManifestSHA256 = manifestHash
		selector, _ := json.Marshal(manifest.Endpoint)
		hash := sha256.Sum256(selector)
		target.SelectorSHA256 = hex.EncodeToString(hash[:])
	}
	result := TargetResult{Status: "succeeded", ResourceID: &target.TargetID, SafeCode: "local_target_" + operation}
	state.Receipts = append(receipts, targetReceipt{Key: key, Hash: requestHash, AtMS: now, Result: result})
	data, err := json.Marshal(state)
	if err != nil {
		return TargetResult{}, err
	}
	if len(data) > maxStateBytes {
		return TargetResult{}, errors.New("target state capacity exceeded")
	}
	if err := config.WritePrivateFile(filepath.Join(directory, "targets.json"), data); err != nil {
		return TargetResult{}, err
	}
	return result, nil
}

func LoadManifest(path, expectedHash string) (TargetManifest, error) {
	var manifest TargetManifest
	if err := config.ValidatePrivateFile(path); err != nil {
		return manifest, err
	}
	f, err := os.Open(path)
	if err != nil {
		return manifest, err
	}
	defer f.Close()
	// Read the same bytes for hash and decode; never reopen a mutable path.
	var data bytes.Buffer
	if _, err := data.ReadFrom(io.LimitReader(f, (64<<10)+1)); err != nil {
		return manifest, err
	}
	if data.Len() > 64<<10 {
		return manifest, errors.New("manifest exceeds 64KiB")
	}
	hash := sha256.Sum256(data.Bytes())
	if hex.EncodeToString(hash[:]) != expectedHash {
		return manifest, fmt.Errorf("manifest SHA-256 changed; review the current file")
	}
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data.Bytes()), 64<<10, &manifest); err != nil {
		return manifest, err
	}
	return manifest, manifest.Validate()
}
