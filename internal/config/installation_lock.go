package config

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// InstallationLease coordinates a running hub and local administration with
// offline replacement. The inode stays in place after release: removing a
// flock file would allow two different inodes to grant simultaneous leases.
type InstallationLease struct{ file *os.File }

// AcquireInstallationLease never waits. Hubs and ordinary administration take
// shared leases; offline restore takes an exclusive lease before reading or
// replacing any live state. The support directory must already exist.
func AcquireInstallationLease(paths Paths, exclusive bool) (*InstallationLease, error) {
	if err := rejectSymlinkPath(paths.Support); err != nil {
		return nil, err
	}
	if err := requireOwner(paths.Support); err != nil {
		return nil, err
	}
	path := filepath.Join(paths.Support, "installation.lock")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		file.Close()
		return nil, errors.New("installation lock must be a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		file.Close()
		return nil, errors.New("installation lock ownership is invalid")
	}
	operation := syscall.LOCK_SH
	if exclusive {
		operation = syscall.LOCK_EX
	}
	if err := syscall.Flock(fd, operation|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("installation is in use; stop the hub and finish local administration before recovery")
	}
	return &InstallationLease{file: file}, nil
}

func (lease *InstallationLease) Close() error {
	if lease == nil || lease.file == nil {
		return nil
	}
	err := lease.file.Close()
	lease.file = nil
	return err
}
