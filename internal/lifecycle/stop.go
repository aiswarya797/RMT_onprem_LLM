package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"rmt.local/monitor/internal/domain"
)

// Stop unloads only the two services owned by this installation. It is safe to
// repeat and deliberately has no code path that stops or edits Ollama.
func (m *Manager) Stop(ctx context.Context) (StopResult, error) {
	result := StopResult{SchemaVersion: domain.SchemaVersion, Status: "stopped", HubState: "already_stopped", CollectorState: "already_stopped", Failures: []string{}, OllamaUnchanged: true}
	for _, service := range []struct {
		label string
		state *string
	}{
		{label: CollectorLabel, state: &result.CollectorState},
		{label: HubLabel, state: &result.HubState},
	} {
		state, err := m.stopService(ctx, service.label)
		*service.state = state
		if err != nil {
			result.Failures = append(result.Failures, service.label+": "+err.Error())
		}
	}
	if len(result.Failures) != 0 {
		result.Status = "partial"
		return result, errors.New("one or more LLM Monitor services could not be stopped; retry after resolving the reported state")
	}
	return result, nil
}

func (m *Manager) stopService(ctx context.Context, label string) (string, error) {
	presence, err := m.serviceState(ctx, label)
	if err != nil || presence == ServicePresenceUnknown {
		if err == nil {
			err = errors.New("service state is unknown")
		}
		return "unknown", err
	}
	if presence == ServicePresenceAbsent {
		return "already_stopped", nil
	}
	target := "gui/" + strconv.Itoa(os.Getuid()) + "/" + label
	_, stopErr := m.Runner.Run(ctx, "launchctl", "bootout", target)
	after, afterErr := m.Runner.ServiceState(ctx, target)
	if afterErr != nil || after == ServicePresenceUnknown {
		if afterErr == nil {
			afterErr = errors.New("service state is unknown after stop")
		}
		return "unknown", afterErr
	}
	if after != ServicePresenceAbsent {
		return "running", fmt.Errorf("service remains loaded after stop (%v)", stopErr)
	}
	// A nonzero unload result followed by confirmed absence is safe: a second
	// lifecycle action may have completed the stop concurrently.
	return "stopped", nil
}
