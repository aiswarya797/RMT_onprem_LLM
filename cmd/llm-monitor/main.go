package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rmt.local/monitor/internal/alertruntime"
	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/collector/remote"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/httpapi"
	"rmt.local/monitor/internal/lifecycle"
	"rmt.local/monitor/internal/notify"
	"rmt.local/monitor/internal/query"
	"rmt.local/monitor/internal/store"
	"rmt.local/monitor/internal/uiassets"
)

const oneOffObservationAdmissionPolicy = "phase2-observation-v1"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	args, options, err := config.ExtractRuntimeOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var paths config.Paths
	if options.InstallationRoot != "" {
		paths = config.ForHome(options.InstallationRoot)
	} else {
		paths, err = config.DefaultPaths()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(8)
		}
	}
	if options.RuntimeDir != "" {
		paths = paths.WithRuntimeDir(options.RuntimeDir)
	}
	manager := lifecycle.NewManager(paths, nil, domain.RealClock{})
	if options.ListenAddress != "" {
		manager.ListenAddress = options.ListenAddress
	}
	manager.ListenAddressExplicit = options.ListenAddressSet
	if len(args) >= 2 && args[0] == "hub" && args[1] == "serve" {
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "hub serve does not accept positional arguments")
			os.Exit(2)
		}
		if options.LocalProbeAdmission != "" && options.LocalProbeAdmission != oneOffObservationAdmissionPolicy {
			fmt.Fprintln(os.Stderr, "unsupported local probe admission policy")
			os.Exit(2)
		}
		if err := runHub(ctx, paths, options.ListenAddress, options.LocalProbeAdmission); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(8)
		}
		return
	}
	os.Exit(lifecycle.RunCLI(ctx, args, os.Stdout, os.Stderr, manager))
}

func runHub(ctx context.Context, paths config.Paths, address, localProbeAdmission string) error {
	if address == "" {
		var hubConfig struct {
			Listen string `json:"listen"`
		}
		data, readErr := os.ReadFile(paths.HubConfig)
		if readErr != nil || json.Unmarshal(data, &hubConfig) != nil || hubConfig.Listen == "" {
			return errors.New("hub configuration is invalid; run setup local")
		}
		address = hubConfig.Listen
	}
	validator := lifecycle.NewManager(paths, nil, domain.RealClock{})
	validator.ListenAddress = address
	if err := validator.ValidateSettings(); err != nil {
		return err
	}
	lease, err := config.AcquireInstallationLease(paths, false)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err := lifecycle.RequireRecoveryReady(paths); err != nil {
		return err
	}
	st, err := store.OpenExisting(paths.Database, domain.RealClock{})
	if err != nil {
		return err
	}
	defer st.Close()
	state, err := st.DeploymentState(ctx)
	if err != nil {
		return errors.New("hub is not configured; run setup local or setup master")
	}
	if err := lifecycle.ValidateRecoveryDeployment(paths, state); err != nil {
		return err
	}
	measurementCtx, finishMeasurement := context.WithTimeout(ctx, 2*time.Second)
	_, measurementErr := st.MeasureAndRecordCapacity(measurementCtx, state.DeploymentID, time.Now().UnixMilli(), store.ExternalCapacityUsage{})
	finishMeasurement()
	if measurementErr != nil {
		fmt.Fprintln(os.Stderr, "storage measurement unavailable; bulk collection waits for a valid measurement")
	}
	authService, err := auth.NewService(st, paths, domain.RealClock{})
	if err != nil {
		return err
	}
	collectorServer, err := lifecycle.RemoteCollectorServer(paths, st, domain.RealClock{})
	if err != nil {
		return err
	}
	apiServer := httpapi.New(st, authService, domain.RealClock{}, address, uiassets.Handler())
	if err := configureLocalProbeTarget(apiServer, paths, state.DeploymentGeneration); err != nil {
		return err
	}
	if localProbeAdmission == oneOffObservationAdmissionPolicy {
		apiServer.ConfigureLocalProbeAdmission(func() (bool, string) { return true, "" })
	}
	apiServer.ConfigureNotifications(notify.Vault{Dir: paths.NotificationSecrets, KeyFile: paths.NotificationKey})
	if collectorServer != nil {
		if err := config.ValidatePrivateFile(paths.CACert); err != nil {
			return err
		}
		caPEM, err := os.ReadFile(paths.CACert)
		if err != nil {
			return err
		}
		if err := apiServer.ConfigureEnrollmentIssuance("https://"+collectorServer.Addr, caPEM); err != nil {
			return err
		}
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen %s without disturbing the current occupant: %w", address, err)
	}
	server := &http.Server{Handler: apiServer, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	servers := []*http.Server{server}
	var collectorListener net.Listener
	if collectorServer != nil {
		collectorListener, err = net.Listen("tcp", collectorServer.Addr)
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("collector listener unavailable; existing occupant was not changed: %w", err)
		}
		bounded, boundErr := remote.NewBoundedListener(collectorListener, remote.MaxTLSConnections)
		if boundErr != nil {
			_ = collectorListener.Close()
			_ = listener.Close()
			return boundErr
		}
		collectorListener = bounded
		servers = append(servers, collectorServer)
	}
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		runMaintenance(serveCtx, st)
	}()
	evaluator := alertruntime.New(query.New(st, domain.RealClock{}), func(error) {
		// Do not expose SQL, private paths or source payloads in service logs.
		fmt.Fprintln(os.Stderr, "bounded alert evaluation did not complete; retrying on next tick")
	})
	apiServer.ConfigureAlertEvaluator(evaluator.Status)
	evaluatorDone := make(chan struct{})
	go func() {
		defer close(evaluatorDone)
		evaluator.Run(serveCtx)
	}()
	dispatcher := notify.NewDispatcher(st, notify.Vault{Dir: paths.NotificationSecrets, KeyFile: paths.NotificationKey}, func(error) {
		// Keep receiver details, credentials and payloads out of the service log.
		fmt.Fprintln(os.Stderr, "bounded notification delivery did not complete; retrying on next tick")
	})
	dispatcherDone := make(chan struct{})
	go func() {
		defer close(dispatcherDone)
		if config.ExperimentalFeaturesEnabled() {
			dispatcher.Run(serveCtx)
		}
	}()
	// Cancel and join both bounded background loops before closing the database.
	defer func() {
		stopServing()
		<-maintenanceDone
		<-evaluatorDone
		<-dispatcherDone
	}()
	serverCount := len(servers) + 1 // HTTP/TLS servers and local owner socket.
	errCh := make(chan error, serverCount)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	go func() {
		errCh <- lifecycle.ServeOwnerSocketHandler(serveCtx, paths.HubSocket, lifecycle.LocalCollectorHandler(st, paths))
	}()
	if collectorServer != nil {
		go func() {
			err := collectorServer.ServeTLS(collectorListener, "", "")
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}()
	}
	select {
	case <-ctx.Done():
		stopServing()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, service := range servers {
			if err := service.Shutdown(shutdownCtx); err != nil {
				_ = service.Close()
			}
		}
		// Both servers must finish before main exits or closes SQLite. The owner
		// server removes its socket in a defer before publishing its result.
		for range serverCount {
			select {
			case <-errCh:
			case <-shutdownCtx.Done():
				return errors.New("hub shutdown did not finish before deadline")
			}
		}
		return nil
	case err := <-errCh:
		stopServing()
		for _, service := range servers {
			_ = service.Close()
		}
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for range serverCount - 1 {
			select {
			case <-errCh:
			case <-deadline.C:
				return errors.New("hub shutdown did not finish before deadline")
			}
		}
		return err
	}
}

func configureLocalProbeTarget(apiServer *httpapi.Server, paths config.Paths, generation string) error {
	targets, err := pairing.ReadTargets(paths.Collector, generation)
	if err != nil {
		return fmt.Errorf("read local target configuration for direct probe: %w", err)
	}
	for _, target := range targets.Targets {
		if target.Retired {
			continue
		}
		if err := apiServer.ConfigureLocalProbeEndpoint(target.Manifest.Endpoint.URL()); err != nil {
			return fmt.Errorf("configure direct probe endpoint: %w", err)
		}
		break
	}
	return nil
}

func runMaintenance(ctx context.Context, st *store.Store) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			passCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			state, err := st.DeploymentState(passCtx)
			if err == nil && state.MutationsAllowed {
				_, err = st.MeasureAndRecordCapacity(passCtx, state.DeploymentID, now.UnixMilli(), store.ExternalCapacityUsage{})
				if err == nil {
					_, err = st.RunMaintenance(passCtx, state.DeploymentID, now.UnixMilli(), store.DefaultMaintenanceLimits())
				}
			}
			cancel()
			if err != nil && ctx.Err() == nil {
				// Keep SQL details and private paths out of the service log. A failed
				// pass preserves its transaction boundaries and retries next tick.
				fmt.Fprintln(os.Stderr, "bounded storage maintenance did not complete; retrying on next tick")
			}
		}
	}
}
