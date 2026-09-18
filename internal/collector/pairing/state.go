package pairing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

const maxStateBytes = 256 << 10

type ModelIdentity struct {
	ID       string `json:"id"`
	TargetID string `json:"target_id"`
	Alias    string `json:"alias"`
	Digest   string `json:"digest"`
}

type State struct {
	Version                  int                         `json:"version"`
	DeploymentID             string                      `json:"deployment_id"`
	Generation               string                      `json:"security_generation"`
	InstallationID           string                      `json:"installation_id"`
	HostID                   string                      `json:"host_id"`
	HostSourceID             string                      `json:"host_source_id"`
	Registered               bool                        `json:"registered"`
	PreviousSession          int64                       `json:"previous_session"`
	PendingActivation        *protocol.SessionActivation `json:"pending_activation"`
	Models                   []ModelIdentity             `json:"models"`
	InventorySources         []protocol.InventorySource  `json:"inventory_sources"`
	PendingInventoryRevision string                      `json:"pending_inventory_revision"`
}

type LocalState struct {
	mu    sync.Mutex
	path  string
	value State
}

// Create is only for initial local pairing. An existing installation missing
// this file must use explicit recovery; it must not guess its next generation.
func Create(directory, deploymentID, generation string) (*LocalState, error) {
	if err := config.EnsurePrivateDir(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "pairing.json")
	if _, err := os.Lstat(path); err == nil {
		return Open(directory, deploymentID, generation)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	value := State{Version: 1, DeploymentID: deploymentID, Generation: generation, Models: []ModelIdentity{}}
	for _, target := range []*string{&value.InstallationID, &value.HostID, &value.HostSourceID} {
		id, err := domain.NewUUID()
		if err != nil {
			return nil, err
		}
		*target = id
	}
	state := &LocalState{path: path, value: value}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return Open(directory, deploymentID, generation)
	}
	if err != nil {
		return nil, err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return nil, err
	}
	return state, nil
}

// CreateEnrolled installs the certificate-bound identity returned by a remote
// enrollment. The hub host row already exists, so local-pair registration is
// permanently skipped for this state.
func CreateEnrolled(directory, deploymentID, generation, installationID, hostID string) (*LocalState, error) {
	if deploymentID == "" || generation == "" || installationID == "" || hostID == "" {
		return nil, errors.New("remote enrollment identity is incomplete")
	}
	if err := config.EnsurePrivateDir(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "pairing.json")
	if _, err := os.Lstat(path); err == nil {
		return Open(directory, deploymentID, generation)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	hostSourceID, err := domain.NewUUID()
	if err != nil {
		return nil, err
	}
	value := State{Version: 1, DeploymentID: deploymentID, Generation: generation, InstallationID: installationID, HostID: hostID, HostSourceID: hostSourceID, Registered: true, Models: []ModelIdentity{}, InventorySources: []protocol.InventorySource{}}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return Open(directory, deploymentID, generation)
	}
	if err != nil {
		return nil, err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return nil, err
	}
	return &LocalState{path: path, value: value}, nil
}

func Open(directory, deploymentID, generation string) (*LocalState, error) {
	path := filepath.Join(directory, "pairing.json")
	if err := config.ValidatePrivateFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStateBytes {
		return nil, errors.New("pairing state exceeds limit")
	}
	var value State
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, errors.New("pairing state invalid; explicit recovery required")
	}
	if err := validateState(value); err != nil || value.DeploymentID != deploymentID || value.Generation != generation {
		return nil, errors.New("pairing identity changed; explicit recovery required")
	}
	return &LocalState{path: path, value: value}, nil
}

func validateState(value State) error {
	if value.Version != 1 || value.DeploymentID == "" || value.Generation == "" || value.HostID == "" || value.HostSourceID == "" || value.InstallationID == "" || value.PreviousSession < 0 || len(value.Models) > 256 || len(value.InventorySources) > 8 {
		return errors.New("pairing state is invalid")
	}
	return nil
}

// ReadRetained returns the stable collector identity without accepting a new
// trust generation. It exists only for an explicit restored-host
// re-enrollment flow; ordinary startup must continue to use Open.
func ReadRetained(directory, deploymentID, hostID string) (State, error) {
	path := filepath.Join(directory, "pairing.json")
	if err := config.ValidatePrivateFile(path); err != nil {
		return State{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer file.Close()
	var value State
	if err := protocol.DecodeStrictJSON(io.LimitReader(file, maxStateBytes+1), maxStateBytes, &value); err != nil || validateState(value) != nil {
		return State{}, errors.New("retained pairing state is invalid; explicit recovery required")
	}
	if value.DeploymentID != deploymentID || (hostID != "" && value.HostID != hostID) {
		return State{}, errors.New("retained pairing identity does not match reviewed host")
	}
	return value, nil
}

// ReEnroll advances a retained pairing to the reviewed restore generation.
// Stable host/source/model/target IDs are preserved. Session generations and
// in-flight acknowledgements are trust-generation scoped and are reset.
func ReEnroll(directory, deploymentID, previousGeneration, nextGeneration, installationID, hostID string) (*LocalState, error) {
	if deploymentID == "" || previousGeneration == "" || nextGeneration == "" || previousGeneration == nextGeneration || installationID == "" || hostID == "" {
		return nil, errors.New("re-enrollment identity is incomplete")
	}
	value, err := ReadRetained(directory, deploymentID, hostID)
	if err != nil {
		return nil, err
	}
	if value.InstallationID != installationID || (value.Generation != previousGeneration && value.Generation != nextGeneration) {
		return nil, errors.New("retained pairing identity changed during re-enrollment")
	}
	if value.Generation == nextGeneration {
		if value.PreviousSession != 0 || value.PendingActivation != nil || value.PendingInventoryRevision != "" || !value.Registered {
			return nil, errors.New("new-generation pairing is already active; refusing to reset it")
		}
		return &LocalState{path: filepath.Join(directory, "pairing.json"), value: value}, nil
	}
	if err := reEnrollTargets(directory, previousGeneration, nextGeneration); err != nil {
		return nil, err
	}
	value.Generation = nextGeneration
	value.Registered = true
	value.PreviousSession = 0
	value.PendingActivation = nil
	value.PendingInventoryRevision = ""
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxStateBytes {
		return nil, errors.New("re-enrolled pairing state exceeds limit")
	}
	path := filepath.Join(directory, "pairing.json")
	if err := config.WritePrivateFile(path, data); err != nil {
		return nil, err
	}
	return &LocalState{path: path, value: value}, nil
}

func (s *LocalState) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := s.value
	value.Models = append([]ModelIdentity(nil), value.Models...)
	value.InventorySources = append([]protocol.InventorySource(nil), value.InventorySources...)
	if value.PendingActivation != nil {
		copy := *value.PendingActivation
		value.PendingActivation = &copy
	}
	return value
}

// RememberInventory runs before transmission. Its source set includes both
// acknowledged and possibly acknowledged identities until retirement is ACKed.
func (s *LocalState) RememberInventory(inventory protocol.CollectorInventory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := inventory.Validate(); err != nil {
		return err
	}
	if inventory.DeploymentID != s.value.DeploymentID || inventory.HostID != s.value.HostID || inventory.SecurityGeneration != s.value.Generation || inventory.SessionGeneration != s.value.PreviousSession {
		return errors.New("inventory does not match local pairing")
	}
	for _, previous := range s.value.InventorySources {
		found := false
		for _, next := range inventory.Sources {
			if previous.SourceID == next.SourceID {
				found = true
				break
			}
		}
		if !found {
			return errors.New("inventory omitted possibly admitted source retirement")
		}
	}
	next := s.value
	next.InventorySources = append([]protocol.InventorySource(nil), inventory.Sources...)
	next.PendingInventoryRevision = inventory.InventoryRevision
	return s.save(next)
}

func (s *LocalState) AckInventory(result protocol.InventoryResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !result.Durable || !result.Current || result.InventoryRevision == "" || result.InventoryRevision != s.value.PendingInventoryRevision {
		return errors.New("inventory ACK does not match durable local request")
	}
	next := s.value
	next.InventorySources = []protocol.InventorySource{}
	next.PendingInventoryRevision = ""
	for _, source := range s.value.InventorySources {
		if source.Active {
			next.InventorySources = append(next.InventorySources, source)
		}
	}
	return s.save(next)
}

func (s *LocalState) Registered() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.value
	next.Registered = true
	return s.save(next)
}

func (s *LocalState) PrepareActivation(boot string) (protocol.SessionActivation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.value.PendingActivation != nil {
		return *s.value.PendingActivation, nil
	}
	id, err := domain.NewUUID()
	if err != nil {
		return protocol.SessionActivation{}, err
	}
	request := protocol.SessionActivation{Protocol: "1.0", DeploymentID: s.value.DeploymentID, HostID: s.value.HostID, SecurityGeneration: s.value.Generation, ActivationRequestID: id, CollectorBootID: boot, ExpectedPreviousGeneration: s.value.PreviousSession}
	if err := request.Validate(); err != nil {
		return request, err
	}
	next := s.value
	next.PendingActivation = &request
	if err := s.save(next); err != nil {
		return request, err
	}
	return request, nil
}

func (s *LocalState) CompleteActivation(result protocol.SessionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	request := s.value.PendingActivation
	if request == nil || result.ActivationRequestID != request.ActivationRequestID || result.SecurityGeneration != request.SecurityGeneration || result.CollectorBootID != request.CollectorBootID || !result.Current || result.SessionGeneration <= request.ExpectedPreviousGeneration || result.SessionGeneration > protocol.MaxUint53 || result.ActivatedMS < 0 {
		return errors.New("activation result conflicts with durable local request; recovery required")
	}
	next := s.value
	next.PendingActivation = nil
	next.PreviousSession = result.SessionGeneration
	return s.save(next)
}

func (s *LocalState) ResolveModelID(ctx context.Context, target, alias, digest string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, model := range s.value.Models {
		if model.TargetID == target && model.Alias == alias && model.Digest == digest {
			return model.ID, nil
		}
	}
	if len(s.value.Models) >= 256 || len(alias) > 256 || len(digest) > 256 || target == "" {
		return "", errors.New("local model identity capacity exceeded")
	}
	id, err := domain.NewUUID()
	if err != nil {
		return "", err
	}
	next := s.value
	next.Models = append(append([]ModelIdentity(nil), next.Models...), ModelIdentity{ID: id, TargetID: target, Alias: alias, Digest: digest})
	if err := s.save(next); err != nil {
		return "", err
	}
	return id, nil
}

func (s *LocalState) save(value State) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > maxStateBytes {
		return fmt.Errorf("pairing state exceeds %d bytes", maxStateBytes)
	}
	if err := config.WritePrivateFile(s.path, data); err != nil {
		return err
	}
	s.value = value
	return nil
}
