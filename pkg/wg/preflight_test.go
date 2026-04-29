package wg

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testPreflightWGPath() string {
	if runtime.GOOS == "windows" {
		return testAbsPath("Program Files", "WireGuard", "wg.exe")
	}
	return testAbsPath("usr", "bin", "wg")
}

func testPreflightOKInterface(name string) (*net.Interface, error) {
	if name != "wg0" {
		return nil, errors.New("device not found")
	}
	return &net.Interface{Name: name}, nil
}

func testPreflightOwnerOnlyOK(string, os.FileInfo) error {
	return nil
}

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
	if runtime.GOOS == "windows" {
		t.Skip("command backend is fail-closed on Windows until a native adapter manager lands")
	}
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	calls := 0
	ipPath := testAbsPath("sbin", "ip")
	expectedIPPath := expectedResolvedBinaryPathForTest(ipPath)
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			switch name {
			case "wg":
				return testPreflightWGPath(), nil
			case "ip":
				if runtime.GOOS == "windows" {
					return "", errors.New("ip must not be required on Windows")
				}
				return ipPath, nil
			default:
				return "", errors.New("unexpected binary lookup")
			}
		},
		stat: func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil },
		open: os.Open,
		run: func(_ context.Context, name string, args ...string) error {
			if runtime.GOOS == "windows" {
				t.Fatalf("Windows preflight must not shell out to ip, got %s %v", name, args)
			}
			calls++
			if name != expectedIPPath {
				t.Fatalf("expected ip command path %q, got %s", expectedIPPath, name)
			}
			if len(args) != 4 || args[0] != "link" || args[1] != "show" || args[2] != "dev" || args[3] != "wg0" {
				t.Fatalf("unexpected args: %v", args)
			}
			return nil
		},
		interfaceByName:   testPreflightOKInterface,
		validateOwnerOnly: testPreflightOwnerOnlyOK,
	}
	keyPath := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := runPreflight(context.Background(), "wg0", keyPath, "client", deps); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	wantCalls := 1
	if runtime.GOOS == "windows" {
		wantCalls = 0
	}
	if calls != wantCalls {
		t.Fatalf("expected one run call, got %d", calls)
	}
}

func TestRunPreflightMissingWG(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("command backend is fail-closed on Windows before binary lookup")
	}
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			if name == "wg" {
				return "", errors.New("missing")
			}
			return testAbsPath("bin", "x"), nil
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
	if runtime.GOOS == "windows" {
		t.Skip("command backend is fail-closed on Windows before key-path probing")
	}
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	deps := preflightDeps{
		lookPath: func(string) (string, error) { return testAbsPath("bin", "x"), nil },
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
	if runtime.GOOS == "windows" {
		t.Skip("command backend is fail-closed on Windows before interface probing")
	}
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			if runtime.GOOS == "windows" && name == "ip" {
				return "", errors.New("ip must not be required on Windows")
			}
			return testAbsPath("bin", "x"), nil
		},
		stat: func(string) (os.FileInfo, error) { return fakeFileInfo{}, nil },
		open: os.Open,
		run: func(context.Context, string, ...string) error {
			return errors.New("device not found")
		},
		interfaceByName: func(string) (*net.Interface, error) {
			return nil, errors.New("device not found")
		},
		validateOwnerOnly: testPreflightOwnerOnlyOK,
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
	if runtime.GOOS == "windows" {
		t.Skip("command backend is fail-closed on Windows; ACL validation is covered in internal/fileperm")
	}
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			if name == "wg" {
				return testPreflightWGPath(), nil
			}
			if runtime.GOOS == "windows" {
				return "", errors.New("ip must not be required on Windows")
			}
			return testAbsPath("sbin", "ip"), nil
		},
		stat: func(string) (os.FileInfo, error) {
			return fakeFileInfo{mode: 0o644}, nil
		},
		open: os.Open,
		run:  func(context.Context, string, ...string) error { return nil },
		validateOwnerOnly: func(string, os.FileInfo) error {
			return errors.New("permissions are too broad")
		},
	}
	keyPath := filepath.Join(t.TempDir(), "exit.key")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	err := runPreflight(context.Background(), "wg0", keyPath, "exit", deps)
	if err == nil || !strings.Contains(err.Error(), "permissions are too broad") {
		t.Fatalf("expected insecure permission error, got %v", err)
	}
}

func TestRunPreflightWindowsFailsClosedUntilNativeAdapterLands(t *testing.T) {
	deps := preflightDeps{
		platform: "windows",
		lookPath: func(string) (string, error) {
			t.Fatal("preflight must fail before probing wg or ip on Windows")
			return "", nil
		},
		stat: func(string) (os.FileInfo, error) {
			t.Fatal("preflight must fail before key-path stat on Windows")
			return nil, nil
		},
		open: os.Open,
		run: func(context.Context, string, ...string) error {
			t.Fatal("preflight must fail before shelling out on Windows")
			return nil
		},
		interfaceByName: func(string) (*net.Interface, error) {
			t.Fatal("preflight must fail before interface probing on Windows")
			return nil, nil
		},
		validateOwnerOnly: testPreflightOwnerOnlyOK,
	}
	keyPath := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	err := runPreflight(context.Background(), "wg0", keyPath, "client", deps)
	if err == nil {
		t.Fatalf("expected Windows command backend unsupported error")
	}
	assertWindowsCommandBackendGuidance(t, err)
}

func TestRunPreflightRejectsSymlinkKeyPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics vary across Windows environments")
	}
	deps := preflightDeps{
		lookPath: func(name string) (string, error) {
			switch name {
			case "wg":
				return testAbsPath("usr", "bin", "wg"), nil
			case "ip":
				return testAbsPath("sbin", "ip"), nil
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
