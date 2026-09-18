package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

type ServicePresence int

const (
	ServicePresenceUnknown ServicePresence = iota
	ServicePresenceAbsent
	ServicePresenceLoaded
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	ServiceState(ctx context.Context, target string) (ServicePresence, error)
}

type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s failed: %w", name, err)
	}
	return output, nil
}

func (CommandRunner) ServiceState(ctx context.Context, target string) (ServicePresence, error) {
	command := exec.CommandContext(ctx, "launchctl", "print", target)
	output, err := command.CombinedOutput()
	if err == nil {
		return ServicePresenceLoaded, nil
	}
	if ctx.Err() != nil {
		return ServicePresenceUnknown, ctx.Err()
	}
	var exitErr *exec.ExitError
	// launchctl uses EX_NOTFOUND (113) when the service is absent. Other exits,
	// including permission and transport failures, are deliberately unknown.
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 113 {
		return ServicePresenceAbsent, nil
	}
	return ServicePresenceUnknown, fmt.Errorf("launchctl service state unavailable: %w (%s)", err, boundedOutput(output))
}

func boundedOutput(output []byte) string {
	if len(output) > 256 {
		output = output[:256]
	}
	return string(output)
}
