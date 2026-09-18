package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"rmt.local/monitor/internal/collector/scheduler"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/lifecycle"
	"rmt.local/monitor/internal/protocol"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	args, options, err := config.ExtractRuntimeOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var paths config.Paths
	if options.ListenAddress != "" {
		fmt.Fprintln(os.Stderr, "--listen is valid only for llm-monitor")
		os.Exit(2)
	}
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
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version") {
		if !onlyJSONFlags(args[1:]) {
			fmt.Fprintln(os.Stderr, "version accepts only --json")
			os.Exit(2)
		}
		if contains(args, "--json") {
			_ = protocol.WriteJSON(os.Stdout, protocol.CurrentIdentity())
		} else {
			id := protocol.CurrentIdentity()
			fmt.Fprintf(os.Stdout, "llm-monitor-collector %s (%s) registry %s protocol %s\n", id.Version, id.Build, id.RegistryRevision, id.ProtocolVersion)
		}
		return
	}
	if len(args) != 1 || args[0] != "serve" {
		fmt.Fprintln(os.Stderr, "Use: llm-monitor-collector serve")
		os.Exit(2)
	}
	runner, err := scheduler.NewRunner(paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(8)
	}
	defer runner.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errors := make(chan error, 2)
	go func() { errors <- runner.Run(runCtx) }()
	go func() { errors <- lifecycle.ServeOwnerSocket(runCtx, paths.CollectorSocket, runner.Status) }()
	first := <-errors
	cancel()
	second := <-errors
	if first != nil {
		err = first
	} else {
		err = second
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(8)
	}
}

func contains(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func onlyJSONFlags(args []string) bool {
	for _, arg := range args {
		if arg != "--json" {
			return false
		}
	}
	return true
}
