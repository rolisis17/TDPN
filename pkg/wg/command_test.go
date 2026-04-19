package wg

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func expectedResolvedBinaryPathForTest(path string) string {
	path = filepath.Clean(path)
	if evalPath := commandClientEvalSymlinks; evalPath != nil {
		if canonical, err := evalPath(path); err == nil && strings.TrimSpace(canonical) != "" {
			path = filepath.Clean(canonical)
		}
	}
	return path
}

type runCall struct {
	name string
	args []string
}

type fakeRunner struct {
	calls []runCall
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	cp := make([]string, len(args))
	copy(cp, args)
	f.calls = append(f.calls, runCall{name: name, args: cp})
	return nil
}

func newTestCommandManager(fr *fakeRunner) *CommandManager {
	return &CommandManager{
		runner:   fr,
		wgBinary: "/usr/bin/wg",
		ipBinary: "/usr/bin/ip",
	}
}

func testWGPublicKeyForCommand() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func TestCommandConfigureSession(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandManager(fr)
	cfg := SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: "/tmp/exit.key",
		ClientPubKey:   testWGPublicKeyForCommand(),
		ClientInnerIP:  "10.90.0.2/32",
		ExitInnerIP:    "10.90.0.1/32",
		ListenPort:     51820,
		KeepaliveSec:   25,
		MTU:            1280,
	}
	if err := m.ConfigureSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	if len(fr.calls) != 5 {
		t.Fatalf("expected 5 commands, got %d", len(fr.calls))
	}
	if fr.calls[0].name != "/usr/bin/wg" {
		t.Fatalf("expected first command /usr/bin/wg, got %s", fr.calls[0].name)
	}
	wantFirst := []string{"set", "wg0", "private-key", "/tmp/exit.key", "listen-port", "51820"}
	if !reflect.DeepEqual(fr.calls[0].args, wantFirst) {
		t.Fatalf("first command mismatch: got %v want %v", fr.calls[0].args, wantFirst)
	}
	if fr.calls[1].name != "/usr/bin/ip" || !reflect.DeepEqual(fr.calls[1].args, []string{"link", "set", "dev", "wg0", "up"}) {
		t.Fatalf("expected interface-up command, got name=%s args=%v", fr.calls[1].name, fr.calls[1].args)
	}
}

func TestCommandRemoveSession(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandManager(fr)
	cfg := SessionConfig{Interface: "wg0", ClientPubKey: testWGPublicKeyForCommand()}
	if err := m.RemoveSession(context.Background(), cfg); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected 1 command, got %d", len(fr.calls))
	}
}

func TestNewCommandManagerUsesResolvedBinaryPaths(t *testing.T) {
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	original := commandManagerLookPath
	t.Cleanup(func() { commandManagerLookPath = original })
	commandManagerLookPath = func(name string) (string, error) {
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
	m := NewCommandManager()
	m.runner = fr
	cfg := SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: "/tmp/exit.key",
		ClientPubKey:   testWGPublicKeyForCommand(),
		ClientInnerIP:  "10.90.0.2/32",
		ListenPort:     51820,
		KeepaliveSec:   25,
	}
	if err := m.ConfigureSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	if len(fr.calls) < 2 {
		t.Fatalf("expected at least 2 calls, got %d", len(fr.calls))
	}
	wantWG, _ := filepath.Abs("/opt/wireguard/wg")
	wantIP, _ := filepath.Abs("/usr/sbin/ip")
	wantWG = expectedResolvedBinaryPathForTest(wantWG)
	wantIP = expectedResolvedBinaryPathForTest(wantIP)
	if fr.calls[0].name != wantWG {
		t.Fatalf("expected wg command %q, got %q", wantWG, fr.calls[0].name)
	}
	if fr.calls[1].name != wantIP {
		t.Fatalf("expected ip command %q, got %q", wantIP, fr.calls[1].name)
	}
}

func TestNewCommandManagerRejectsUntrustedBinaryPaths(t *testing.T) {
	original := commandManagerLookPath
	t.Cleanup(func() { commandManagerLookPath = original })
	commandManagerLookPath = func(name string) (string, error) {
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
	m := NewCommandManager()
	m.runner = fr
	cfg := SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: "/tmp/exit.key",
		ClientPubKey:   testWGPublicKeyForCommand(),
		ClientInnerIP:  "10.90.0.2/32",
		ListenPort:     51820,
		KeepaliveSec:   25,
	}
	err := m.ConfigureSession(context.Background(), cfg)
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

func TestNewCommandManagerLookupFailureFailsClosed(t *testing.T) {
	original := commandManagerLookPath
	t.Cleanup(func() { commandManagerLookPath = original })
	commandManagerLookPath = func(name string) (string, error) {
		if name == "wg" {
			return "/usr/bin/wg", nil
		}
		return "", fmt.Errorf("%s not found", name)
	}

	fr := &fakeRunner{}
	m := NewCommandManager()
	m.runner = fr
	cfg := SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: "/tmp/exit.key",
		ClientPubKey:   testWGPublicKeyForCommand(),
		ClientInnerIP:  "10.90.0.2/32",
		ListenPort:     51820,
		KeepaliveSec:   25,
	}
	err := m.ConfigureSession(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected lookup failure")
	}
	if !strings.Contains(err.Error(), "resolve ip binary") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("expected no command execution on lookup failure, got %d calls", len(fr.calls))
	}
}
