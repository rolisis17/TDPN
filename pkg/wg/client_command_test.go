package wg

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func testWGPublicKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func newTestCommandClientManager(fr *fakeRunner) *CommandClientManager {
	return &CommandClientManager{
		runner:   fr,
		wgBinary: "/usr/bin/wg",
		ipBinary: "/usr/bin/ip",
	}
}

func TestCommandClientConfigureSession(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: "/tmp/client.key",
		ExitPublicKey:    testWGPublicKey(),
		ClientInnerIP:    "10.90.0.2/32",
		AllowedIPs:       "0.0.0.0/0",
		Endpoint:         "127.0.0.1:51820",
		KeepaliveSec:     25,
		MTU:              1280,
	}
	if err := m.ConfigureClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	if len(fr.calls) != 5 {
		t.Fatalf("expected 5 commands, got %d", len(fr.calls))
	}
	if fr.calls[0].name != "/usr/bin/wg" {
		t.Fatalf("expected first command /usr/bin/wg")
	}
	wantFirst := []string{"set", "wg-client0", "private-key", "/tmp/client.key"}
	if !reflect.DeepEqual(fr.calls[0].args, wantFirst) {
		t.Fatalf("first command mismatch got=%v want=%v", fr.calls[0].args, wantFirst)
	}
	if fr.calls[1].name != "/usr/bin/ip" || !reflect.DeepEqual(fr.calls[1].args, []string{"link", "set", "dev", "wg-client0", "up"}) {
		t.Fatalf("expected interface-up command, got name=%s args=%v", fr.calls[1].name, fr.calls[1].args)
	}
}

func TestCommandClientConfigureSessionInstallsRoutes(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: "/tmp/client.key",
		ExitPublicKey:    testWGPublicKey(),
		AllowedIPs:       "10.90.0.0/24, 10.91.0.0/24",
		InstallRoute:     true,
	}
	if err := m.ConfigureClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	if len(fr.calls) != 5 {
		t.Fatalf("expected 5 commands with two routes, got %d", len(fr.calls))
	}
	wantRouteA := runCall{name: "/usr/bin/ip", args: []string{"route", "replace", "10.90.0.0/24", "dev", "wg-client0"}}
	wantRouteB := runCall{name: "/usr/bin/ip", args: []string{"route", "replace", "10.91.0.0/24", "dev", "wg-client0"}}
	if !reflect.DeepEqual(fr.calls[3], wantRouteA) {
		t.Fatalf("first route command mismatch got=%+v want=%+v", fr.calls[3], wantRouteA)
	}
	if !reflect.DeepEqual(fr.calls[4], wantRouteB) {
		t.Fatalf("second route command mismatch got=%+v want=%+v", fr.calls[4], wantRouteB)
	}
}

func TestCommandClientRemoveSession(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	cfg := ClientSessionConfig{Interface: "wg-client0", ExitPublicKey: testWGPublicKey()}
	if err := m.RemoveClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected 1 command, got %d", len(fr.calls))
	}
}

func TestCommandClientConfigureSessionRejectsInvalidInputs(t *testing.T) {
	validCfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: "/tmp/client.key",
		ExitPublicKey:    testWGPublicKey(),
		ClientInnerIP:    "10.90.0.2/32",
		AllowedIPs:       "0.0.0.0/0",
		Endpoint:         "127.0.0.1:51820",
	}
	tests := []struct {
		name    string
		mutate  func(*ClientSessionConfig)
		wantErr string
	}{
		{
			name: "invalid interface",
			mutate: func(cfg *ClientSessionConfig) {
				cfg.Interface = "eth0"
			},
			wantErr: "invalid interface",
		},
		{
			name: "invalid private key path option-like",
			mutate: func(cfg *ClientSessionConfig) {
				cfg.ClientPrivateKey = "-/tmp/client.key"
			},
			wantErr: "invalid client private key path",
		},
		{
			name: "invalid exit pubkey",
			mutate: func(cfg *ClientSessionConfig) {
				cfg.ExitPublicKey = "not-a-pubkey"
			},
			wantErr: "invalid exit public key",
		},
		{
			name: "invalid client inner ip cidr",
			mutate: func(cfg *ClientSessionConfig) {
				cfg.ClientInnerIP = "10.90.0.2"
			},
			wantErr: "invalid client inner ip CIDR",
		},
		{
			name: "invalid allowed ips cidr",
			mutate: func(cfg *ClientSessionConfig) {
				cfg.AllowedIPs = "10.90.0.0/24, not-cidr"
			},
			wantErr: "invalid allowed ips CIDR",
		},
		{
			name: "invalid endpoint hostport",
			mutate: func(cfg *ClientSessionConfig) {
				cfg.Endpoint = "bad-endpoint"
			},
			wantErr: "invalid endpoint",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{}
			m := newTestCommandClientManager(fr)
			cfg := validCfg
			tc.mutate(&cfg)
			err := m.ConfigureClientSession(context.Background(), cfg)
			if err == nil {
				t.Fatalf("expected validation error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v want substring %q", err, tc.wantErr)
			}
			if len(fr.calls) != 0 {
				t.Fatalf("validation should fail before command execution, got calls=%d", len(fr.calls))
			}
		})
	}
}

func TestCommandClientRemoveSessionRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ClientSessionConfig
		wantErr string
	}{
		{
			name:    "invalid interface",
			cfg:     ClientSessionConfig{Interface: "eth0", ExitPublicKey: testWGPublicKey()},
			wantErr: "invalid interface",
		},
		{
			name:    "invalid exit public key",
			cfg:     ClientSessionConfig{Interface: "wg-client0", ExitPublicKey: "not-a-pubkey"},
			wantErr: "invalid exit public key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{}
			m := newTestCommandClientManager(fr)
			err := m.RemoveClientSession(context.Background(), tc.cfg)
			if err == nil {
				t.Fatalf("expected validation error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v want substring %q", err, tc.wantErr)
			}
			if len(fr.calls) != 0 {
				t.Fatalf("validation should fail before command execution, got calls=%d", len(fr.calls))
			}
		})
	}
}

func TestNewCommandClientManagerUsesResolvedBinaryPaths(t *testing.T) {
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	original := commandClientLookPath
	t.Cleanup(func() {
		commandClientLookPath = original
	})

	commandClientLookPath = func(name string) (string, error) {
		switch name {
		case "wg":
			return "/opt/wireguard/wg", nil
		case "ip":
			return "/usr/sbin/ip", nil
		default:
			return "", fmt.Errorf("unexpected binary %s", name)
		}
	}

	fr := &fakeRunner{}
	m := NewCommandClientManager()
	m.runner = fr
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: "/tmp/client.key",
		ExitPublicKey:    testWGPublicKey(),
		AllowedIPs:       "0.0.0.0/0",
	}
	if err := m.ConfigureClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	if len(fr.calls) < 2 {
		t.Fatalf("expected at least 2 commands, got %d", len(fr.calls))
	}
	wantWG, _ := filepath.Abs("/opt/wireguard/wg")
	wantIP, _ := filepath.Abs("/usr/sbin/ip")
	wantWG = expectedResolvedBinaryPathForTest(wantWG)
	wantIP = expectedResolvedBinaryPathForTest(wantIP)
	if fr.calls[0].name != wantWG {
		t.Fatalf("expected first command %q, got %q", wantWG, fr.calls[0].name)
	}
	if fr.calls[1].name != wantIP {
		t.Fatalf("expected second command %q, got %q", wantIP, fr.calls[1].name)
	}
}

func TestNewCommandClientManagerRejectsUntrustedBinaryPaths(t *testing.T) {
	original := commandClientLookPath
	t.Cleanup(func() {
		commandClientLookPath = original
	})
	commandClientLookPath = func(name string) (string, error) {
		switch name {
		case "wg":
			return "/opt/wireguard/wg", nil
		case "ip":
			return "/opt/wireguard/ip", nil
		default:
			return "", fmt.Errorf("unexpected binary %s", name)
		}
	}

	fr := &fakeRunner{}
	m := NewCommandClientManager()
	m.runner = fr
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: "/tmp/client.key",
		ExitPublicKey:    testWGPublicKey(),
		AllowedIPs:       "0.0.0.0/0",
	}
	err := m.ConfigureClientSession(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected untrusted path rejection")
	}
	if !strings.Contains(err.Error(), "untrusted path") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("expected no command execution on untrusted path, got %d calls", len(fr.calls))
	}
}

func TestNewCommandClientManagerLookupFailureFailsClosed(t *testing.T) {
	original := commandClientLookPath
	t.Cleanup(func() {
		commandClientLookPath = original
	})

	commandClientLookPath = func(name string) (string, error) {
		if name == "wg" {
			return "/usr/bin/wg", nil
		}
		return "", fmt.Errorf("%s not found", name)
	}

	fr := &fakeRunner{}
	m := NewCommandClientManager()
	m.runner = fr
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: "/tmp/client.key",
		ExitPublicKey:    testWGPublicKey(),
		AllowedIPs:       "0.0.0.0/0",
	}
	err := m.ConfigureClientSession(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected lookup failure")
	}
	if !strings.Contains(err.Error(), "resolve ip binary") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("expected no command execution on lookup failure, got %d calls", len(fr.calls))
	}

	err = m.RemoveClientSession(context.Background(), ClientSessionConfig{
		Interface:     "wg-client0",
		ExitPublicKey: testWGPublicKey(),
	})
	if err == nil {
		t.Fatalf("expected lookup failure in remove")
	}
	if len(fr.calls) != 0 {
		t.Fatalf("expected no command execution on lookup failure during remove, got %d calls", len(fr.calls))
	}
}

func TestIsTrustedBinaryPathForOSWindowsRoots(t *testing.T) {
	t.Setenv("SystemRoot", `C:\Windows`)
	t.Setenv("WINDIR", `C:\Windows`)
	t.Setenv("ProgramFiles", `C:\Program Files`)
	t.Setenv("ProgramFiles(x86)", `C:\Program Files (x86)`)

	tests := []struct {
		path string
		want bool
	}{
		{path: `C:\Windows\System32\wg.exe`, want: true},
		{path: `c:\windows\system32\WG.EXE`, want: true},
		{path: `C:\Program Files\WireGuard\wg.exe`, want: true},
		{path: `C:\Program Files (x86)\WireGuard\wg.exe`, want: true},
		{path: `C:\Users\alice\AppData\Local\Temp\wg.exe`, want: false},
		{path: `D:\Windows\System32\wg.exe`, want: false},
	}
	for _, tc := range tests {
		if got := isTrustedBinaryPathForOS("windows", tc.path); got != tc.want {
			t.Fatalf("isTrustedBinaryPathForOS(windows, %q)=%t want=%t", tc.path, got, tc.want)
		}
	}
}

func TestIsTrustedBinaryPathForOSUnixRoots(t *testing.T) {
	if !isTrustedBinaryPathForOS("linux", "/usr/bin/wg") {
		t.Fatalf("expected /usr/bin/wg to be trusted on unix policy")
	}
	if isTrustedBinaryPathForOS("linux", "/tmp/wg") {
		t.Fatalf("expected /tmp/wg to be untrusted on unix policy")
	}
}

func TestResolveClientBinaryPathUsesCanonicalResolvedPath(t *testing.T) {
	lookupPath, canonicalPath, _ := testClientBinaryPathsForOS()
	originalEval := commandClientEvalSymlinks
	t.Cleanup(func() {
		commandClientEvalSymlinks = originalEval
	})
	commandClientEvalSymlinks = func(path string) (string, error) {
		if path != lookupPath {
			t.Fatalf("unexpected lookup path %q", path)
		}
		return canonicalPath, nil
	}
	resolved, err := resolveClientBinaryPath("wg", func(name string) (string, error) {
		if name != "wg" {
			t.Fatalf("unexpected binary name %q", name)
		}
		return lookupPath, nil
	})
	if err != nil {
		t.Fatalf("resolveClientBinaryPath returned error: %v", err)
	}
	if resolved != filepath.Clean(canonicalPath) {
		t.Fatalf("expected canonical path %q, got %q", filepath.Clean(canonicalPath), resolved)
	}
}

func TestResolveClientBinaryPathRejectsUntrustedCanonicalPath(t *testing.T) {
	lookupPath, _, untrustedPath := testClientBinaryPathsForOS()
	originalEval := commandClientEvalSymlinks
	t.Cleanup(func() {
		commandClientEvalSymlinks = originalEval
	})
	commandClientEvalSymlinks = func(path string) (string, error) {
		if path != lookupPath {
			t.Fatalf("unexpected lookup path %q", path)
		}
		return untrustedPath, nil
	}
	_, err := resolveClientBinaryPath("wg", func(name string) (string, error) {
		if name != "wg" {
			t.Fatalf("unexpected binary name %q", name)
		}
		return lookupPath, nil
	})
	if err == nil {
		t.Fatalf("expected untrusted canonical path rejection")
	}
	if !strings.Contains(err.Error(), "untrusted path") {
		t.Fatalf("expected untrusted path error, got %v", err)
	}
}

func testClientBinaryPathsForOS() (lookupPath string, canonicalPath string, untrustedPath string) {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\wg.exe`, `C:\Windows\System32\drivers\wg.exe`, `C:\Users\Public\wg.exe`
	}
	return "/usr/bin/wg", "/usr/sbin/wg", "/tmp/wg"
}
