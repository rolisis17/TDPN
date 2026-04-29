package wg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func testAbsPath(parts ...string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(append([]string{`C:\gpm-test`}, parts...)...)
	}
	return filepath.Join(append([]string{"/"}, parts...)...)
}

func expectedResolvedBinaryPathForTest(path string) string {
	path = filepath.Clean(path)
	if evalPath := commandClientEvalSymlinks; evalPath != nil {
		if canonical, err := evalPath(path); err == nil && strings.TrimSpace(canonical) != "" {
			path = filepath.Clean(canonical)
		}
	}
	return path
}

func withCommandBackendPlatform(t *testing.T, platform string) {
	t.Helper()
	original := commandBackendRuntimeGOOS
	t.Cleanup(func() { commandBackendRuntimeGOOS = original })
	commandBackendRuntimeGOOS = platform
}

func clearCommandProductionModeEnv(t *testing.T) {
	t.Helper()
	for _, key := range commandProductionModeEnvKeys {
		t.Setenv(key, "")
	}
}

type runCall struct {
	name string
	args []string
}

type fakeRunner struct {
	calls     []runCall
	failOn    func(name string, args []string) bool
	onRun     func(name string, args []string)
	outputFor func(name string, args []string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	cp := make([]string, len(args))
	copy(cp, args)
	f.calls = append(f.calls, runCall{name: name, args: cp})
	if f.onRun != nil {
		f.onRun(name, cp)
	}
	if f.failOn != nil && f.failOn(name, cp) {
		return errors.New("injected command failure")
	}
	return nil
}

func (f *fakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	cp := make([]string, len(args))
	copy(cp, args)
	if f.outputFor != nil {
		return f.outputFor(name, cp)
	}
	return nil, nil
}

func newTestCommandManager(fr *fakeRunner) *CommandManager {
	return &CommandManager{
		runner:   fr,
		wgBinary: testAbsPath("usr", "bin", "wg"),
		ipBinary: testAbsPath("usr", "bin", "ip"),
		platform: "linux",
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
		ExitPrivateKey: testAbsPath("tmp", "exit.key"),
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
	if fr.calls[0].name != m.wgBinary {
		t.Fatalf("expected first command %s, got %s", m.wgBinary, fr.calls[0].name)
	}
	wantFirst := []string{"set", "wg0", "private-key", cfg.ExitPrivateKey, "listen-port", "51820"}
	if !reflect.DeepEqual(fr.calls[0].args, wantFirst) {
		t.Fatalf("first command mismatch: got %v want %v", fr.calls[0].args, wantFirst)
	}
	if fr.calls[1].name != m.ipBinary || !reflect.DeepEqual(fr.calls[1].args, []string{"link", "set", "dev", "wg0", "up"}) {
		t.Fatalf("expected interface-up command, got name=%s args=%v", fr.calls[1].name, fr.calls[1].args)
	}
}

func TestCommandConfigureSessionRollsBackAddressOnAddressFailure(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandManager(fr)
	cfg := validCommandSessionConfig()
	fr.failOn = func(name string, args []string) bool {
		return name == m.ipBinary && reflect.DeepEqual(args, []string{"addr", "replace", cfg.ExitInnerIP, "dev", cfg.Interface})
	}

	err := m.ConfigureSession(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("expected injected address failure, got %v", err)
	}

	wantSuffix := []runCall{
		{name: m.ipBinary, args: []string{"addr", "replace", cfg.ExitInnerIP, "dev", cfg.Interface}},
		{name: m.ipBinary, args: []string{"addr", "del", cfg.ExitInnerIP, "dev", cfg.Interface}},
	}
	assertCallSuffix(t, fr.calls, wantSuffix)
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandConfigureSessionRollsBackPeerAndAddressOnPeerFailure(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandManager(fr)
	cfg := validCommandSessionConfig()
	peerArgs := []string{"set", cfg.Interface, "peer", cfg.ClientPubKey, "allowed-ips", cfg.ClientInnerIP, "persistent-keepalive", strconv.Itoa(cfg.KeepaliveSec)}
	fr.failOn = func(name string, args []string) bool {
		return name == m.wgBinary && reflect.DeepEqual(args, peerArgs)
	}

	err := m.ConfigureSession(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("expected injected peer failure, got %v", err)
	}

	wantSuffix := []runCall{
		{name: m.wgBinary, args: peerArgs},
		{name: m.wgBinary, args: []string{"set", cfg.Interface, "peer", cfg.ClientPubKey, "remove"}},
		{name: m.ipBinary, args: []string{"addr", "del", cfg.ExitInnerIP, "dev", cfg.Interface}},
	}
	assertCallSuffix(t, fr.calls, wantSuffix)
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandConfigureSessionRollsBackPeerAndAddressOnMTUFailure(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandManager(fr)
	cfg := validCommandSessionConfig()
	fr.failOn = func(name string, args []string) bool {
		return name == m.ipBinary && reflect.DeepEqual(args, []string{"link", "set", "dev", cfg.Interface, "mtu", strconv.Itoa(cfg.MTU)})
	}

	err := m.ConfigureSession(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("expected injected MTU failure, got %v", err)
	}

	wantSuffix := []runCall{
		{name: m.ipBinary, args: []string{"link", "set", "dev", cfg.Interface, "mtu", strconv.Itoa(cfg.MTU)}},
		{name: m.wgBinary, args: []string{"set", cfg.Interface, "peer", cfg.ClientPubKey, "remove"}},
		{name: m.ipBinary, args: []string{"addr", "del", cfg.ExitInnerIP, "dev", cfg.Interface}},
	}
	assertCallSuffix(t, fr.calls, wantSuffix)
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandConfigureSessionRollsBackEarlyInterfaceMutationsOnMTUFailure(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandManager(fr)
	cfg := validCommandSessionConfig()
	previousWGConfig := "[Interface]\nPrivateKey = previous-private-key\nListenPort = 51819\n"
	var restoredWGConfig string
	fr.outputFor = func(name string, args []string) ([]byte, error) {
		if name == m.wgBinary && reflect.DeepEqual(args, []string{"showconf", cfg.Interface}) {
			return []byte(previousWGConfig), nil
		}
		if name == m.ipBinary && reflect.DeepEqual(args, []string{"-o", "link", "show", "dev", cfg.Interface}) {
			return []byte("7: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000\n"), nil
		}
		return nil, nil
	}
	fr.onRun = func(name string, args []string) {
		if name == m.wgBinary && len(args) == 3 && args[0] == "setconf" && args[1] == cfg.Interface {
			content, err := os.ReadFile(args[2])
			if err != nil {
				t.Fatalf("read rollback config: %v", err)
			}
			restoredWGConfig = string(content)
		}
	}
	fr.failOn = func(name string, args []string) bool {
		return name == m.ipBinary && reflect.DeepEqual(args, []string{"link", "set", "dev", cfg.Interface, "mtu", strconv.Itoa(cfg.MTU)})
	}

	err := m.ConfigureSession(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("expected injected MTU failure, got %v", err)
	}
	if restoredWGConfig != previousWGConfig {
		t.Fatalf("restored WG config mismatch got=%q want=%q", restoredWGConfig, previousWGConfig)
	}

	wantSuffix := []runCall{
		{name: m.ipBinary, args: []string{"link", "set", "dev", cfg.Interface, "mtu", strconv.Itoa(cfg.MTU)}},
		{name: m.wgBinary, args: []string{"set", cfg.Interface, "peer", cfg.ClientPubKey, "remove"}},
		{name: m.ipBinary, args: []string{"addr", "del", cfg.ExitInnerIP, "dev", cfg.Interface}},
	}
	if len(fr.calls) < len(wantSuffix)+2 {
		t.Fatalf("calls=%d want MTU failure plus early rollback cleanup: %+v", len(fr.calls), fr.calls)
	}
	gotSuffixStart := fr.calls[len(fr.calls)-len(wantSuffix)-2 : len(fr.calls)-2]
	if !reflect.DeepEqual(gotSuffixStart, wantSuffix) {
		t.Fatalf("cleanup suffix mismatch got=%+v want=%+v all=%+v", gotSuffixStart, wantSuffix, fr.calls)
	}
	setconfCall := fr.calls[len(fr.calls)-2]
	if setconfCall.name != m.wgBinary || len(setconfCall.args) != 3 || setconfCall.args[0] != "setconf" || setconfCall.args[1] != cfg.Interface {
		t.Fatalf("expected WireGuard setconf rollback before link down, got=%+v all=%+v", setconfCall, fr.calls)
	}
	wantDown := runCall{name: m.ipBinary, args: []string{"link", "set", "dev", cfg.Interface, "down"}}
	if !reflect.DeepEqual(fr.calls[len(fr.calls)-1], wantDown) {
		t.Fatalf("expected link-down rollback got=%+v want=%+v all=%+v", fr.calls[len(fr.calls)-1], wantDown, fr.calls)
	}
}

func TestCommandConfigureSessionDoesNotRollbackPreexistingConfigOnPeerFailure(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandManager(fr)
	cfg := validCommandSessionConfig()
	peerArgs := []string{"set", cfg.Interface, "peer", cfg.ClientPubKey, "allowed-ips", cfg.ClientInnerIP, "persistent-keepalive", strconv.Itoa(cfg.KeepaliveSec)}
	fr.outputFor = preexistingCommandOutput(m, cfg)
	fr.failOn = func(name string, args []string) bool {
		return name == m.wgBinary && reflect.DeepEqual(args, peerArgs)
	}

	err := m.ConfigureSession(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("expected injected peer failure, got %v", err)
	}

	assertNoCall(t, fr.calls, m.wgBinary, []string{"set", cfg.Interface, "peer", cfg.ClientPubKey, "remove"})
	assertNoCall(t, fr.calls, m.ipBinary, []string{"addr", "del", cfg.ExitInnerIP, "dev", cfg.Interface})
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandConfigureSessionDoesNotRollbackPreexistingConfigOnMTUFailure(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandManager(fr)
	cfg := validCommandSessionConfig()
	fr.outputFor = preexistingCommandOutput(m, cfg)
	fr.failOn = func(name string, args []string) bool {
		return name == m.ipBinary && reflect.DeepEqual(args, []string{"link", "set", "dev", cfg.Interface, "mtu", strconv.Itoa(cfg.MTU)})
	}

	err := m.ConfigureSession(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("expected injected MTU failure, got %v", err)
	}

	assertNoCall(t, fr.calls, m.wgBinary, []string{"set", cfg.Interface, "peer", cfg.ClientPubKey, "remove"})
	assertNoCall(t, fr.calls, m.ipBinary, []string{"addr", "del", cfg.ExitInnerIP, "dev", cfg.Interface})
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
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

func validCommandSessionConfig() SessionConfig {
	return SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: testAbsPath("tmp", "exit.key"),
		ClientPubKey:   testWGPublicKeyForCommand(),
		ClientInnerIP:  "10.90.0.2/32",
		ExitInnerIP:    "10.90.0.1/32",
		ListenPort:     51820,
		KeepaliveSec:   25,
		MTU:            1280,
	}
}

func preexistingCommandOutput(m *CommandManager, cfg SessionConfig) func(name string, args []string) ([]byte, error) {
	return func(name string, args []string) ([]byte, error) {
		if name == m.ipBinary && reflect.DeepEqual(args, []string{"-o", "addr", "show", "dev", cfg.Interface, "to", cfg.ExitInnerIP}) {
			return []byte("7: " + cfg.Interface + " inet " + cfg.ExitInnerIP + " scope global " + cfg.Interface + "\n"), nil
		}
		if name == m.wgBinary && reflect.DeepEqual(args, []string{"show", cfg.Interface, "allowed-ips"}) {
			return []byte(cfg.ClientPubKey + "\t" + cfg.ClientInnerIP + "\n"), nil
		}
		return nil, nil
	}
}

func assertCallSuffix(t *testing.T, calls []runCall, wantSuffix []runCall) {
	t.Helper()
	if len(calls) < len(wantSuffix) {
		t.Fatalf("calls=%d want at least suffix %d: %+v", len(calls), len(wantSuffix), calls)
	}
	gotSuffix := calls[len(calls)-len(wantSuffix):]
	if !reflect.DeepEqual(gotSuffix, wantSuffix) {
		t.Fatalf("call suffix mismatch got=%+v want=%+v all=%+v", gotSuffix, wantSuffix, calls)
	}
}

func assertNoCall(t *testing.T, calls []runCall, name string, args []string) {
	t.Helper()
	for _, call := range calls {
		if call.name == name && reflect.DeepEqual(call.args, args) {
			t.Fatalf("unexpected call name=%s args=%v in %+v", name, args, calls)
		}
	}
}

func assertHasCall(t *testing.T, calls []runCall, name string, args []string) {
	t.Helper()
	for _, call := range calls {
		if call.name == name && reflect.DeepEqual(call.args, args) {
			return
		}
	}
	t.Fatalf("missing call name=%s args=%v in %+v", name, args, calls)
}

func assertNoSharedInterfaceRollback(t *testing.T, calls []runCall, ipBinary string, iface string) {
	t.Helper()
	for _, call := range calls {
		if call.name == ipBinary && reflect.DeepEqual(call.args, []string{"link", "set", "dev", iface, "down"}) {
			t.Fatalf("rollback must not bring down shared interface: %+v", calls)
		}
		if call.name == ipBinary && len(call.args) >= 2 && call.args[0] == "addr" && call.args[1] == "flush" {
			t.Fatalf("rollback must not flush shared interface addresses: %+v", calls)
		}
	}
}

func TestNewCommandManagerUsesResolvedBinaryPaths(t *testing.T) {
	withCommandBackendPlatform(t, "linux")
	clearCommandProductionModeEnv(t)
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	original := commandManagerLookPath
	t.Cleanup(func() { commandManagerLookPath = original })
	commandManagerLookPath = func(name string) (string, error) {
		switch name {
		case "wg":
			return testAbsPath("opt", "wireguard", "wg"), nil
		case "ip":
			return testAbsPath("usr", "sbin", "ip"), nil
		default:
			return "", fmt.Errorf("unexpected binary %s", name)
		}
	}

	fr := &fakeRunner{}
	m := NewCommandManager()
	m.runner = fr
	m.platform = "linux"
	cfg := SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: testAbsPath("tmp", "exit.key"),
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
	wantWG, _ := filepath.Abs(testAbsPath("opt", "wireguard", "wg"))
	wantIP, _ := filepath.Abs(testAbsPath("usr", "sbin", "ip"))
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
	withCommandBackendPlatform(t, "linux")
	original := commandManagerLookPath
	t.Cleanup(func() { commandManagerLookPath = original })
	commandManagerLookPath = func(name string) (string, error) {
		switch name {
		case "wg":
			return testAbsPath("opt", "wireguard", "wg"), nil
		case "ip":
			return testAbsPath("opt", "wireguard", "ip"), nil
		default:
			return "", fmt.Errorf("unexpected binary %s", name)
		}
	}

	fr := &fakeRunner{}
	m := NewCommandManager()
	m.runner = fr
	m.platform = "linux"
	cfg := SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: testAbsPath("tmp", "exit.key"),
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
	withCommandBackendPlatform(t, "linux")
	original := commandManagerLookPath
	t.Cleanup(func() { commandManagerLookPath = original })
	commandManagerLookPath = func(name string) (string, error) {
		if name == "wg" {
			return testAbsPath("usr", "bin", "wg"), nil
		}
		return "", fmt.Errorf("%s not found", name)
	}

	fr := &fakeRunner{}
	m := NewCommandManager()
	m.runner = fr
	m.platform = "linux"
	cfg := SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: testAbsPath("tmp", "exit.key"),
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

func TestNewCommandManagerWindowsFailsBeforeLinuxCommandLookup(t *testing.T) {
	withCommandBackendPlatform(t, "windows")
	original := commandManagerLookPath
	t.Cleanup(func() { commandManagerLookPath = original })
	commandManagerLookPath = func(name string) (string, error) {
		t.Fatalf("Windows command backend must not probe Linux command %q", name)
		return "", nil
	}

	fr := &fakeRunner{}
	m := NewCommandManager()
	m.runner = fr
	err := m.ConfigureSession(context.Background(), SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: testAbsPath("tmp", "exit.key"),
		ClientPubKey:   testWGPublicKeyForCommand(),
		ClientInnerIP:  "10.90.0.2/32",
		ListenPort:     51820,
		KeepaliveSec:   25,
	})
	if err == nil {
		t.Fatalf("expected Windows unsupported error")
	}
	assertWindowsCommandBackendGuidance(t, err)
	if len(fr.calls) != 0 {
		t.Fatalf("expected no command execution on Windows, got %d calls", len(fr.calls))
	}
}

func TestCommandBackendWindowsFailsClosedUntilNativeAdapterLands(t *testing.T) {
	err := commandBackendPlatformError("windows")
	if err == nil {
		t.Fatalf("expected Windows command backend to fail closed")
	}
	assertWindowsCommandBackendGuidance(t, err)
}

func assertWindowsCommandBackendGuidance(t *testing.T, err error) {
	t.Helper()
	msg := err.Error()
	for _, want := range []string{"WireGuardNT", "wireguard.exe", "WSL", "Git Bash"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("expected Windows backend guidance to mention %q, got %v", want, err)
		}
	}
}
