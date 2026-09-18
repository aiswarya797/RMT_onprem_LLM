//go:build darwin

package store

import (
	"errors"
	"math"
	"os"
	"syscall"
)

func allocatedFileBytes(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Blocks < 0 || stat.Blocks > math.MaxInt64/512 {
		return 0, errors.New("allocated block count unavailable")
	}
	return stat.Blocks * 512, nil
}

func filesystemFreeBytes(path string) (int64, error) {
	if path == "" {
		return 0, errors.New("filesystem path unavailable")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 || stat.Bavail > uint64(math.MaxInt64)/uint64(stat.Bsize) {
		return 0, errors.New("filesystem free-space value unavailable")
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func allocatedOptionalFileBytes(path string) (int64, error) {
	bytes, err := allocatedFileBytes(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	return bytes, err
}
