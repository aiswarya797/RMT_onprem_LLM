package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/store"
)

// SetupMaster installs only the dashboard/storage hub and its reviewed remote
// collector listener. It intentionally does not create a collector identity or
// touch the Ollama installation on this Mac.
func (m *Manager) SetupMaster(ctx context.Context, start bool) (SetupResult, error) {
	if _, err := m.readRemovalReceipt(); err == nil {
		return SetupResult{}, errors.New("setup is blocked while an authenticated removal retry is pending; retry uninstall first")
	} else if !errors.Is(err, os.ErrNotExist) {
		return SetupResult{}, fmt.Errorf("inspect pending removal retry: %w", err)
	}
	if err := m.resolveSetupListen(); err != nil {
		return SetupResult{}, err
	}
	if m.CollectorListenExplicit && m.CollectorListenAddress == "" {
		return SetupResult{}, errors.New("master setup requires a collector listener; omit --collector-listen for automatic selection")
	}
	if m.CollectorListenAddress == "" {
		address, err := discoverCollectorListenAddress()
		if err != nil {
			return SetupResult{}, err
		}
		m.CollectorListenAddress = address
	}
	if err := m.ValidateSettings(); err != nil {
		return SetupResult{}, err
	}
	if err := ValidateCollectorListenAddress(m.CollectorListenAddress); err != nil {
		return SetupResult{}, err
	}
	if m.ListenAddress == m.CollectorListenAddress {
		return SetupResult{}, errors.New("collector TLS and browser listeners require different ports")
	}
	if start {
		presence, err := m.serviceState(ctx, HubLabel)
		if err != nil {
			return SetupResult{}, fmt.Errorf("cannot determine existing hub service before setup: %w", err)
		}
		if presence == ServicePresenceAbsent {
			if err := preflightTCPAddress(m.ListenAddress); err != nil {
				return SetupResult{}, fmt.Errorf("hub listen address is occupied; no process was stopped: %w", err)
			}
			if err := preflightTCPAddress(m.CollectorListenAddress); err != nil {
				return SetupResult{}, fmt.Errorf("collector listener is occupied; no process was stopped: %w", err)
			}
		}
	}
	for _, dir := range []string{m.Paths.Support, m.Paths.Bin, m.Paths.Hub, m.Paths.Logs, m.Paths.Run} {
		if err := config.EnsurePrivateDir(dir); err != nil {
			return SetupResult{}, err
		}
	}
	st, err := store.Open(m.Paths.Database, m.Clock)
	if err != nil {
		return SetupResult{}, err
	}
	defer st.Close()
	state, created, err := st.EnsureDeployment(ctx, "LLM Monitor Master")
	if err != nil {
		return SetupResult{}, err
	}
	if err := m.validateCollectorListenChange(state, created); err != nil {
		return SetupResult{}, err
	}
	if _, err := ensureLocalCA(m.Paths, m.Clock.Now()); err != nil {
		return SetupResult{}, fmt.Errorf("configure local CA: %w", err)
	}
	if err := ensureRemoteHubCertificate(m.Paths, m.CollectorListenAddress, m.Clock.Now()); err != nil {
		return SetupResult{}, fmt.Errorf("configure collector TLS: %w", err)
	}
	hubConfig := map[string]any{
		"schema_version": domain.SchemaVersion, "deployment_id": state.DeploymentID,
		"listen": m.ListenAddress, "database": m.Paths.Database, "owner_socket": m.Paths.HubSocket,
		"collection_enabled": true, "inference_enabled": false, "collector_listen": m.CollectorListenAddress,
	}
	if err := writeJSONFile(m.Paths.HubConfig, hubConfig); err != nil {
		return SetupResult{}, err
	}
	authService, err := auth.NewService(st, m.Paths, m.Clock)
	if err != nil {
		return SetupResult{}, err
	}
	tokenPath, expires, _, bootstrapErr := authService.EnsureFirstBootstrap(ctx)
	if bootstrapErr != nil && !errors.Is(bootstrapErr, store.ErrAdminExists) {
		return SetupResult{}, bootstrapErr
	}
	hubArgs := m.HubProgramArguments()[1:]
	if err := config.WritePrivateFile(m.Paths.HubPlist, []byte(m.plist(HubLabel, m.HubBinary, hubArgs, "hub"))); err != nil {
		return SetupResult{}, err
	}
	hubState := "not_started"
	if start {
		hubState, err = m.ensureLoaded(ctx, HubLabel, m.Paths.HubPlist)
		if err != nil {
			return SetupResult{}, err
		}
	}
	result := SetupResult{SchemaVersion: domain.SchemaVersion, Status: "configured", DeploymentID: state.DeploymentID, DeploymentGeneration: state.DeploymentGeneration, BootstrapTokenPath: tokenPath, HubState: hubState, CollectorState: "not_configured", CollectorListen: m.CollectorListenAddress, Created: created}
	if !expires.IsZero() {
		result.BootstrapExpiresMS = expires.UnixMilli()
	}
	return result, nil
}

func discoverCollectorListenAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("could not inspect network interfaces: %w", err)
	}
	type candidate struct {
		address netip.Addr
		name    string
	}
	candidates := make([]candidate, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			address := prefix.Addr().Unmap()
			if address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() || !address.IsPrivate() {
				continue
			}
			candidates = append(candidates, candidate{address: address, name: iface.Name})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].address.BitLen() != candidates[j].address.BitLen() {
			return candidates[i].address.BitLen() < candidates[j].address.BitLen()
		}
		if candidates[i].name != candidates[j].name {
			return candidates[i].name < candidates[j].name
		}
		return candidates[i].address.String() < candidates[j].address.String()
	})
	for _, candidate := range candidates {
		for port := 9444; port <= 9454; port++ {
			address := net.JoinHostPort(candidate.address.String(), strconv.Itoa(port))
			if err := preflightTCPAddress(address); err == nil {
				return address, nil
			}
		}
	}
	if len(candidates) == 0 {
		return "", errors.New("no private network address is available; connect this Mac to a private network and retry master setup")
	}
	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.address.String())
	}
	return "", fmt.Errorf("all automatic collector listener ports are occupied on %s", strings.Join(names, ", "))
}

func preflightTCPAddress(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return listener.Close()
}
