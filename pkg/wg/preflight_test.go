package wg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeFileInfo struct {
	dir  bool
	mode os.FileMode
}

func (f fakeFileInfo) Name() string { return "key" }
func (f fakeFileInfo) Size() int64  { return 32 }
func (f fakeFileInfo) Mode() os.FileMode {
	if f.mode == 0 {
		return 0o600
	}
	return f.mode
}
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.dir }
func (f fakeFileInfo) Sys() interface{}   { return nil }

func TestRunPreflightOK(t *testing.T) {
	calls := 0
	const ipPath = "/sbin/ip"
	expectedIPPath := expectedResolvedBinaryPathForTest(ipPath)
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			switch name {
			case "wg":
				return "/usr/bin/wg", nil
			case "ip":
				return ipPath, nil
			default:
				return "", errors.New("unexpected binary lookup")
			}
		},
		stat: func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil },
		open: os.Open,
		run: func(_ context.Context, name string, args ...string) error {
			calls++
			if name != expectedIPPath {
				t.Fatalf("expected ip command path %q, got %s", expectedIPPath, name)
			}
			if len(args) != 4 || args[0] != "link" || args[1] != "show" || args[2] != "dev" || args[3] != "wg0" {
				t.Fatalf("unexpected args: %v", args)
			}
			return nil
		},
	}
	keyPath := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := runPreflight(context.Background(), "wg0", keyPath, "client", deps); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one run call, got %d", calls)
	}
}

func TestRunPreflightMissingWG(t *testing.T) {
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			if name == "wg" {
				return "", errors.New("missing")
			}
			return "/bin/x", nil
		},
		stat: func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil },
		open: os.Open,
		run:  func(context.Context, string, ...string) error { return nil },
	}
	keyPath := filepath.Join(t.TempDir(), "exit.key")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	err := runPreflight(context.Background(), "wg0", keyPath, "exit", deps)
	if err == nil || !strings.Contains(err.Error(), "wg binary not found") {
		t.Fatalf("expected wg binary error, got %v", err)
	}
}

func TestRunPreflightBadKeyPath(t *testing.T) {
	deps := preflightDeps{
		lookPath: func(string) (string, error) { return "/bin/x", nil },
		stat:     func(string) (os.FileInfo, error) { return nil, errors.New("not found") },
		open:     func(string) (*os.File, error) { return nil, errors.New("not found") },
		run:      func(context.Context, string, ...string) error { return nil },
	}
	err := runPreflight(context.Background(), "wg0", "/missing/key", "client", deps)
	if err == nil || !strings.Contains(err.Error(), "private key path invalid") {
		t.Fatalf("expected private key error, got %v", err)
	}
}

func TestRunPreflightBadInterface(t *testing.T) {
	deps := preflightDeps{
		lookPath: func(string) (string, error) { return "/bin/x", nil },
		stat:     func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil },
		open:     os.Open,
		run:      func(context.Context, string, ...string) error { return errors.New("device not found") },
	}
	keyPath := filepath.Join(t.TempDir(), "exit.key")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	err := runPreflight(context.Background(), "wg-bad", keyPath, "exit", deps)
	if err == nil || !strings.Contains(err.Error(), "wg interface wg-bad unavailable") {
		t.Fatalf("expected interface error, got %v", err)
	}
}

func TestRunPreflightRejectsInsecureKeyPerms(t *testing.T) {
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			if name == "wg" {
				return "/usr/bin/wg", nil
			}
			return "/sbin/ip", nil
		},
		stat: func(string) (os.FileInfo, error) {
			return fakeFileInfo{mode: 0o644}, nil
		},
		open: os.Open,
		run:  func(context.Context, string, ...string) error { return nil },
	}
	keyPath := filepath.Join(t.TempDir(), "exit.key")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	err := runPreflight(context.Background(), "wg0", keyPath, "exit", deps)
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf("expected windows to skip unix permission checks, got %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "permissions are too broad") {
		t.Fatalf("expected insecure permission error, got %v", err)
	}
}

func TestRunPreflightRejectsSymlinkKeyPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics vary across Windows environments")
	}
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			switch name {
			case "wg":
				return "/usr/bin/wg", nil
			case "ip":
				return "/sbin/ip", nil
			default:
				return "", errors.New("unexpected binary lookup")
			}
		},
		stat:  os.Stat,
		lstat: os.Lstat,
		open:  os.Open,
		run:   func(context.Context, string, ...string) error { return nil },
	}
	tmp := t.TempDir()
	realKey := filepath.Join(tmp, "real.key")
	linkKey := filepath.Join(tmp, "link.key")
	if err := os.WriteFile(realKey, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Symlink(realKey, linkKey); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	err := runPreflight(context.Background(), "wg0", linkKey, "exit", deps)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("expected symlink rejection error, got %v", err)
	}
}
