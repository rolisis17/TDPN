package fsguard

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	// ErrNotRegularFile indicates the opened path is not a regular file.
	ErrNotRegularFile = errors.New("path must reference a regular file")
	// ErrSymlinkPath indicates the resolved path currently points to a symlink.
	ErrSymlinkPath = errors.New("path must not be a symlink")
	// ErrPathChanged indicates the on-disk path changed while being validated.
	ErrPathChanged = errors.New("path changed during read")
	// ErrFileTooLarge indicates file contents exceeded the configured read budget.
	ErrFileTooLarge = errors.New("file exceeds maximum allowed size")
)

// ReadRegularFileBounded reads a regular file with bounded memory usage and
// race-aware path validation.
func ReadRegularFileBounded(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("max bytes must be positive: %d", maxBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}
	if openedInfo.Size() > maxBytes {
		return nil, fmt.Errorf("%w: %s", ErrFileTooLarge, path)
	}

	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlinkPath, path)
	}

	resolvedInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(openedInfo, resolvedInfo) {
		return nil, fmt.Errorf("%w: %s", ErrPathChanged, path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: %s", ErrFileTooLarge, path)
	}

	return data, nil
}
