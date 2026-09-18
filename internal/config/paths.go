package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type Paths struct {
	Home                  string
	Support               string
	Bin                   string
	Hub                   string
	Collector             string
	Docs                  string
	Share                 string
	Logs                  string
	Run                   string
	LaunchAgents          string
	HubPlist              string
	CollectorPlist        string
	HubSocket             string
	CollectorSocket       string
	Database              string
	HubConfig             string
	CollectorConfig       string
	BootstrapToken        string
	SessionSecret         string
	CAKey                 string
	CACert                string
	HubKey                string
	HubCert               string
	RemoteCollectorConfig string
	CollectorKey          string
	CollectorCert         string
	CollectorCA           string
	CollectorRenewal      string
	CollectorReEnrollment string
	CollectorNextKey      string
	RemovalReceipt        string
	NotificationSecrets   string
	NotificationKey       string
}

func ForHome(home string) Paths {
	support := filepath.Join(home, "Library", "Application Support", "LLM Monitor")
	run := filepath.Join(home, "Library", "Caches", "LLM Monitor", "run")
	launch := filepath.Join(home, "Library", "LaunchAgents")
	return Paths{
		Home: home, Support: support, Bin: filepath.Join(support, "bin"), Hub: filepath.Join(support, "hub"), Collector: filepath.Join(support, "collector"), Docs: filepath.Join(support, "docs"), Share: filepath.Join(support, "share"),
		Logs: filepath.Join(home, "Library", "Logs", "LLM Monitor"), Run: run, LaunchAgents: launch,
		HubPlist: filepath.Join(launch, "com.llm-monitor.hub.plist"), CollectorPlist: filepath.Join(launch, "com.llm-monitor.collector.plist"),
		HubSocket: filepath.Join(run, "hub.sock"), CollectorSocket: filepath.Join(run, "collector.sock"), Database: filepath.Join(support, "hub", "monitor.sqlite3"),
		HubConfig: filepath.Join(support, "hub.json"), CollectorConfig: filepath.Join(support, "collector.json"), BootstrapToken: filepath.Join(support, "bootstrap.token"),
		SessionSecret: filepath.Join(support, "session.key"), CAKey: filepath.Join(support, "ca.key"), CACert: filepath.Join(support, "ca.pem"),
		HubKey: filepath.Join(support, "hub.key"), HubCert: filepath.Join(support, "hub.pem"),
		RemoteCollectorConfig: filepath.Join(support, "collector", "remote.json"), CollectorKey: filepath.Join(support, "collector", "client.key"),
		CollectorCert: filepath.Join(support, "collector", "client.pem"), CollectorCA: filepath.Join(support, "collector", "hub-ca.pem"),
		CollectorRenewal:      filepath.Join(support, "collector", "renewal.json"),
		CollectorReEnrollment: filepath.Join(support, "collector", "reenrollment.json"),
		CollectorNextKey:      filepath.Join(support, "collector", "client.next.key"),
		RemovalReceipt:        filepath.Join(support, "removal-receipt.json"),
		NotificationSecrets:   filepath.Join(support, "hub", "notification-secrets"),
		NotificationKey:       filepath.Join(support, "hub", "notification-secrets", "key"),
	}
}

func (p Paths) WithRuntimeDir(run string) Paths {
	p.Run = run
	p.HubSocket = filepath.Join(run, "hub.sock")
	p.CollectorSocket = filepath.Join(run, "collector.sock")
	return p
}

func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve user home: %w", err)
	}
	return ForHome(home), nil
}

func (p Paths) DataPaths() []string {
	return []string{p.NotificationSecrets, p.Database, p.Database + "-wal", p.Database + "-shm", p.HubConfig, p.CollectorConfig, p.BootstrapToken, p.SessionSecret, p.CAKey, p.CACert, p.HubKey, p.HubCert, p.RemoteCollectorConfig, p.CollectorKey, p.CollectorCert, p.CollectorCA, p.CollectorRenewal, p.CollectorReEnrollment, p.CollectorNextKey, filepath.Join(p.Collector, "spool"), filepath.Join(p.Collector, "pairing.json"), filepath.Join(p.Collector, "targets.json"), filepath.Join(p.Collector, "targets.lock"), filepath.Join(p.Collector, "recovery-receipts.json")}
}

func (p Paths) ServicePaths() []string {
	return []string{
		p.HubPlist, p.CollectorPlist, p.HubSocket, p.CollectorSocket,
		filepath.Join(p.Bin, "llm-monitor"), filepath.Join(p.Bin, "llm-monitor-collector"),
		filepath.Join(p.Docs, "install.html"), filepath.Join(p.Docs, "operate.html"), filepath.Join(p.Docs, "recover.html"),
		filepath.Join(p.Share, "compatibility-unverified.json"), filepath.Join(p.Share, "sbom.spdx.json"), filepath.Join(p.Share, "build-provenance.json"), filepath.Join(p.Share, "THIRD-PARTY-NOTICES.txt"),
		filepath.Join(p.Logs, "hub.log"), filepath.Join(p.Logs, "hub.error.log"), filepath.Join(p.Logs, "collector.log"), filepath.Join(p.Logs, "collector.error.log"),
		p.RemovalReceipt,
	}
}

func (p Paths) PurgePaths() []string {
	return append(p.ServicePaths(), p.DataPaths()...)
}

func EnsurePrivateDir(path string) error {
	if err := rejectSymlinkPath(path); err != nil {
		return err
	}
	if err := requireOwner(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private directory %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("chmod private directory %s: %w", path, err)
	}
	return nil
}

func WritePrivateFile(path string, data []byte) error {
	if err := ensureParentDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refuse symlink file %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rmt-write-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install private file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open private file directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync private file directory: %w", err)
	}
	return nil
}

func rejectSymlinkPath(path string) error {
	clean := filepath.Clean(path)
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse symlink path component %s", current)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func RejectSymlinkTree(path string) error { return rejectSymlinkPath(path) }

func ValidatePrivateFile(path string) error {
	if err := rejectSymlinkPath(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private path is not a regular file: %s", path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("private file permissions must be 0600: %s", path)
	}
	return requireOwner(path)
}

func requireOwner(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("path is not owned by current user: %s", path)
	}
	return nil
}

func ensureParentDir(path string) error {
	if err := rejectSymlinkPath(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("parent is not a directory: %s", path)
		}
		return requireOwner(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(path, 0o700)
}
