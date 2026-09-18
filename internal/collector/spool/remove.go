package spool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"rmt.local/monitor/internal/config"
)

// RemoveOwned is only for an explicit installing-user purge after service
// shutdown. Unknown neighbors remain in place and prevent a successful purge.
// The lock is retained until all recognized data files have been removed.
func RemoveOwned(ctx context.Context, dir string) error {
	if err := config.RejectSymlinkTree(dir); err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	lockPath := filepath.Join(dir, "collector.lock")
	if _, err := os.Lstat(lockPath); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("spool ownership lock missing; nonempty directory retained")
		}
		if err := os.Remove(dir); err != nil {
			return err
		}
		return syncDir(filepath.Dir(dir))
	}
	if err := config.ValidatePrivateFile(lockPath); err != nil {
		return err
	}
	lock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return ErrLocked
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > maxSegments+3 {
		return fmt.Errorf("unexpected spool directory contents")
	}
	for _, entry := range entries {
		name := entry.Name()
		known := name == "collector.lock" || name == "offsets.json" || name == "losses.json"
		if len(name) == 60 && strings.HasSuffix(name, ".seg") && name[19] == '-' && validID(name[20:56]) {
			known = true
			for _, character := range name[:19] {
				if character < '0' || character > '9' {
					known = false
				}
			}
		}
		if !known {
			return fmt.Errorf("unknown spool neighbor retained")
		}
		if err := config.ValidatePrivateFile(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Name() == "collector.lock" {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	if err := os.Remove(lockPath); err != nil {
		return err
	}
	if err := os.Remove(dir); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dir))
}
