package config

import (
	"errors"
	"fmt"
	"path/filepath"
)

type RuntimeOptions struct {
	InstallationRoot    string
	RuntimeDir          string
	ListenAddress       string
	ListenAddressSet    bool
	LocalProbeAdmission string
}

func ExtractRuntimeOptions(args []string) ([]string, RuntimeOptions, error) {
	clean := make([]string, 0, len(args))
	var result RuntimeOptions
	for i := 0; i < len(args); i++ {
		if args[i] != "--installation-root" && args[i] != "--runtime-dir" && args[i] != "--listen" && args[i] != "--local-probe-admission" {
			clean = append(clean, args[i])
			continue
		}
		if i+1 >= len(args) || args[i+1] == "" {
			return nil, RuntimeOptions{}, fmt.Errorf("%s requires one value", args[i])
		}
		value := args[i+1]
		switch args[i] {
		case "--installation-root":
			if result.InstallationRoot != "" || !filepath.IsAbs(value) {
				return nil, RuntimeOptions{}, errors.New("--installation-root requires one absolute path")
			}
			result.InstallationRoot = filepath.Clean(value)
		case "--runtime-dir":
			if result.RuntimeDir != "" || !filepath.IsAbs(value) {
				return nil, RuntimeOptions{}, errors.New("--runtime-dir requires one absolute path")
			}
			result.RuntimeDir = filepath.Clean(value)
		case "--listen":
			if result.ListenAddressSet {
				return nil, RuntimeOptions{}, errors.New("--listen may be provided once")
			}
			result.ListenAddress = value
			result.ListenAddressSet = true
		case "--local-probe-admission":
			if result.LocalProbeAdmission != "" {
				return nil, RuntimeOptions{}, errors.New("--local-probe-admission may be provided once")
			}
			result.LocalProbeAdmission = value
		}
		i++
	}
	return clean, result, nil
}
