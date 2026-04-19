package fsguard

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadRegularFileBounded(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	filePath := filepath.Join(baseDir, "payload.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	payload, err := ReadRegularFileBounded(filePath, 16)
	if err != nil {
		t.Fatalf("ReadRegularFileBounded returned error: %v", err)
	}
	if got, want := string(payload), "hello"; got != want {
		t.Fatalf("payload=%q want=%q", got, want)
	}
}

func TestReadRegularFileBoundedRejectsOversize(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	filePath := filepath.Join(baseDir, "large.txt")
	if err := os.WriteFile(filePath, []byte("this file is too large"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := ReadRegularFileBounded(filePath, 8)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("error=%v, want ErrFileTooLarge", err)
	}
}

func TestReadRegularFileBoundedRejectsSymlink(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on some Windows setups")
	}

	baseDir := t.TempDir()
	targetPath := filepath.Join(baseDir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	linkPath := filepath.Join(baseDir, "link.txt")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := ReadRegularFileBounded(linkPath, 64)
	if !errors.Is(err, ErrSymlinkPath) {
		t.Fatalf("error=%v, want ErrSymlinkPath", err)
	}
}

func TestReadRegularFileBoundedNotExist(t *testing.T) {
	t.Parallel()

	_, err := ReadRegularFileBounded(filepath.Join(t.TempDir(), "missing.txt"), 64)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error=%v, want os.ErrNotExist", err)
	}
}
