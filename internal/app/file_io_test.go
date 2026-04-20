package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAppFileBoundedRejectsNonPositiveLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := readAppFileBounded(path, 0)
	if err == nil {
		t.Fatalf("expected non-positive max-bytes validation error")
	}
	if !strings.Contains(err.Error(), "max bytes must be positive") {
		t.Fatalf("expected max-bytes validation error, got %v", err)
	}
}

func TestReadAppFileBoundedReadsWithinLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	want := "FOO=bar\n"
	if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	got, err := readAppFileBounded(path, int64(len(want)))
	if err != nil {
		t.Fatalf("readAppFileBounded returned error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("readAppFileBounded=%q want %q", string(got), want)
	}
}

func TestReadAppFileBoundedRejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := readAppFileBounded(path, 2)
	if err == nil {
		t.Fatalf("expected oversize error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected exceeds error, got %v", err)
	}
}

func TestReadAppFileBoundedRejectsEmptyPath(t *testing.T) {
	_, err := readAppFileBounded(" \t\r\n ", 16)
	if err == nil {
		t.Fatalf("expected empty path validation error")
	}
	if !strings.Contains(err.Error(), "file path is required") {
		t.Fatalf("expected required path error, got %v", err)
	}
}

func TestReadAppFileBoundedRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := readAppFileBounded(dir, 16)
	if err == nil {
		t.Fatalf("expected non-regular file rejection")
	}
	if !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("expected regular file validation error, got %v", err)
	}
}

func TestReadAppFileBoundedRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.env")
	if err := os.WriteFile(target, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	link := filepath.Join(dir, "config.env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported in test environment: %v", err)
	}
	_, err := readAppFileBounded(link, 64)
	if err == nil {
		t.Fatalf("expected symlink rejection")
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("expected symlink validation error, got %v", err)
	}
}
