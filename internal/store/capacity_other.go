//go:build !darwin

package store

import "errors"

func allocatedFileBytes(string) (int64, error) {
	return 0, errors.New("physical allocation measurement requires darwin")
}

func allocatedOptionalFileBytes(string) (int64, error) {
	return 0, errors.New("physical allocation measurement requires darwin")
}

func filesystemFreeBytes(string) (int64, error) {
	return 0, errors.New("physical allocation measurement requires darwin")
}
