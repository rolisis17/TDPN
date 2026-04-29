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
		wgBinary: testAbsPath("usr", "bin", "wg"),
		ipBinary: testAbsPath("usr", "bin", "ip"),
		platform: "linux",
	}
}

func TestCommandClientConfigureSession(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
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
	if fr.calls[0].name != m.wgBinary {
		t.Fatalf("expected first command %s", m.wgBinary)
	}
	wantFirst := []string{"set", "wg-client0", "private-key", cfg.ClientPrivateKey}
	if !reflect.DeepEqual(fr.calls[0].args, wantFirst) {
		t.Fatalf("first command mismatch got=%v want=%v", fr.calls[0].args, wantFirst)
	}
	if fr.calls[1].name != m.ipBinary || !reflect.DeepEqual(fr.calls[1].args, []string{"link", "set", "dev", "wg-client0", "up"}) {
		t.Fatalf("expected interface-up command, got name=%s args=%v", fr.calls[1].name, fr.calls[1].args)
	}
}

func TestCommandClientConfigureSessionInstallsRoutes(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
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
	wantRouteA := runCall{name: m.ipBinary, args: []string{"route", "add", "10.90.0.0/24", "dev", "wg-client0"}}
	wantRouteB := runCall{name: m.ipBinary, args: []string{"route", "add", "10.91.0.0/24", "dev", "wg-client0"}}
	if !reflect.DeepEqual(fr.calls[3], wantRouteA) {
		t.Fatalf("first route command mismatch got=%+v want=%+v", fr.calls[3], wantRouteA)
	}
	if !reflect.DeepEqual(fr.calls[4], wantRouteB) {
		t.Fatalf("second route command mismatch got=%+v want=%+v", fr.calls[4], wantRouteB)
	}
}

func TestCommandClientConfigureSessionDefaultsFullTunnelToIPv4AndIPv6(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
		ExitPublicKey:    testWGPublicKey(),
		InstallRoute:     true,
	}
	if err := m.ConfigureClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	wantPeer := []string{"set", "wg-client0", "peer", cfg.ExitPublicKey, "allowed-ips", DefaultFullTunnelAllowedIPs}
	if !reflect.DeepEqual(fr.calls[2].args, wantPeer) {
		t.Fatalf("peer allowed-ips mismatch got=%v want=%v", fr.calls[2].args, wantPeer)
	}
	wantIPv4Route := runCall{name: m.ipBinary, args: []string{"route", "add", "0.0.0.0/0", "dev", "wg-client0"}}
	wantIPv6Route := runCall{name: m.ipBinary, args: []string{"-6", "route", "add", "::/0", "dev", "wg-client0"}}
	if !reflect.DeepEqual(fr.calls[3], wantIPv4Route) || !reflect.DeepEqual(fr.calls[4], wantIPv6Route) {
		t.Fatalf("default route commands mismatch got=%+v want=%+v,%+v", fr.calls[3:5], wantIPv4Route, wantIPv6Route)
	}
}

func TestCommandClientConfigureSessionInstallsFullTunnelEndpointRouteException(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	fr.outputFor = func(name string, args []string) ([]byte, error) {
		switch {
		case name == m.ipBinary && reflect.DeepEqual(args, []string{"route", "show", "203.0.113.10/32"}):
			return nil, nil
		case name == m.ipBinary && reflect.DeepEqual(args, []string{"route", "get", "203.0.113.10"}):
			return []byte("203.0.113.10 via 192.0.2.1 dev eth0 src 192.0.2.10 uid 1000\n"), nil
		default:
			return nil, nil
		}
	}
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
		ExitPublicKey:    testWGPublicKey(),
		Endpoint:         "203.0.113.10:51820",
		InstallRoute:     true,
	}
	if err := m.ConfigureClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	if len(fr.calls) != 6 {
		t.Fatalf("expected 6 commands with endpoint exception and default routes, got %d: %+v", len(fr.calls), fr.calls)
	}
	wantEndpointRoute := runCall{name: m.ipBinary, args: []string{"route", "add", "203.0.113.10/32", "via", "192.0.2.1", "dev", "eth0"}}
	if !reflect.DeepEqual(fr.calls[3], wantEndpointRoute) {
		t.Fatalf("endpoint route exception mismatch got=%+v want=%+v all=%+v", fr.calls[3], wantEndpointRoute, fr.calls)
	}
	wantIPv4Route := runCall{name: m.ipBinary, args: []string{"route", "add", "0.0.0.0/0", "dev", "wg-client0"}}
	wantIPv6Route := runCall{name: m.ipBinary, args: []string{"-6", "route", "add", "::/0", "dev", "wg-client0"}}
	if !reflect.DeepEqual(fr.calls[4], wantIPv4Route) || !reflect.DeepEqual(fr.calls[5], wantIPv6Route) {
		t.Fatalf("full-tunnel route commands mismatch got=%+v want=%+v,%+v", fr.calls[4:6], wantIPv4Route, wantIPv6Route)
	}
}

func TestCommandClientRemoveSessionCleansOwnedEndpointRouteException(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	fr.outputFor = func(name string, args []string) ([]byte, error) {
		switch {
		case name == m.ipBinary && reflect.DeepEqual(args, []string{"route", "show", "203.0.113.10/32"}):
			return nil, nil
		case name == m.ipBinary && reflect.DeepEqual(args, []string{"route", "get", "203.0.113.10"}):
			return []byte("203.0.113.10 via 192.0.2.1 dev eth0 src 192.0.2.10 uid 1000\n"), nil
		default:
			return nil, nil
		}
	}
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
		ExitPublicKey:    testWGPublicKey(),
		Endpoint:         "203.0.113.10:51820",
		InstallRoute:     true,
	}
	if err := m.ConfigureClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	fr.calls = nil

	if err := m.RemoveClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	wantCalls := []runCall{
		{name: m.wgBinary, args: []string{"set", "wg-client0", "peer", cfg.ExitPublicKey, "remove"}},
		{name: m.ipBinary, args: []string{"route", "del", "0.0.0.0/0", "dev", "wg-client0"}},
		{name: m.ipBinary, args: []string{"-6", "route", "del", "::/0", "dev", "wg-client0"}},
		{name: m.ipBinary, args: []string{"route", "del", "203.0.113.10/32"}},
	}
	if !reflect.DeepEqual(fr.calls, wantCalls) {
		t.Fatalf("remove calls mismatch got=%+v want=%+v", fr.calls, wantCalls)
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
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandClientConfigureSessionCleansUpAfterRouteFailure(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	failCIDR := "10.91.0.0/24"
	fr.failOn = func(name string, args []string) bool {
		return name == m.ipBinary &&
			reflect.DeepEqual(args, []string{"route", "add", failCIDR, "dev", "wg-client0"})
	}
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
		ExitPublicKey:    testWGPublicKey(),
		ClientInnerIP:    "10.90.0.2/32",
		AllowedIPs:       "10.90.0.0/24, " + failCIDR,
		InstallRoute:     true,
	}
	err := m.ConfigureClientSession(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("expected injected route failure, got %v", err)
	}

	wantSuffix := []runCall{
		{name: m.ipBinary, args: []string{"route", "add", failCIDR, "dev", "wg-client0"}},
		{name: m.ipBinary, args: []string{"route", "del", "10.90.0.0/24", "dev", "wg-client0"}},
		{name: m.wgBinary, args: []string{"set", "wg-client0", "peer", cfg.ExitPublicKey, "remove"}},
		{name: m.ipBinary, args: []string{"addr", "del", "10.90.0.2/32", "dev", "wg-client0"}},
	}
	if len(fr.calls) < len(wantSuffix) {
		t.Fatalf("calls=%d want at least cleanup suffix %d: %+v", len(fr.calls), len(wantSuffix), fr.calls)
	}
	gotSuffix := fr.calls[len(fr.calls)-len(wantSuffix):]
	if !reflect.DeepEqual(gotSuffix, wantSuffix) {
		t.Fatalf("cleanup suffix mismatch got=%+v want=%+v all=%+v", gotSuffix, wantSuffix, fr.calls)
	}
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandClientConfigureSessionPreservesPreexistingRouteAndInterfaceOnRollback(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	preexistingCIDR := "10.90.0.0/24"
	failCIDR := "10.91.0.0/24"
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
		ExitPublicKey:    testWGPublicKey(),
		ClientInnerIP:    "10.90.0.2/32",
		AllowedIPs:       preexistingCIDR + ", " + failCIDR,
		InstallRoute:     true,
	}
	fr.outputFor = func(name string, args []string) ([]byte, error) {
		if name == m.ipBinary && reflect.DeepEqual(args, []string{"route", "show", preexistingCIDR, "dev", cfg.Interface}) {
			return []byte(preexistingCIDR + " dev " + cfg.Interface + " scope link\n"), nil
		}
		return nil, nil
	}
	fr.failOn = func(name string, args []string) bool {
		return name == m.ipBinary && reflect.DeepEqual(args, []string{"route", "add", failCIDR, "dev", cfg.Interface})
	}

	err := m.ConfigureClientSession(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "injected command failure") {
		t.Fatalf("expected injected route failure, got %v", err)
	}

	assertNoCall(t, fr.calls, m.ipBinary, []string{"route", "del", preexistingCIDR, "dev", cfg.Interface})
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandClientRemoveSessionPreservesUnownedRouteAndSharedInterface(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	cfg := ClientSessionConfig{
		Interface:     "wg-client0",
		ExitPublicKey: testWGPublicKey(),
		AllowedIPs:    "10.90.0.0/24",
		InstallRoute:  true,
	}
	fr.outputFor = func(name string, args []string) ([]byte, error) {
		if name == m.ipBinary && reflect.DeepEqual(args, []string{"route", "show", "10.90.0.0/24", "dev", cfg.Interface}) {
			return []byte("10.90.0.0/24 dev " + cfg.Interface + " scope link\n"), nil
		}
		return nil, nil
	}

	if err := m.RemoveClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	assertNoCall(t, fr.calls, m.ipBinary, []string{"route", "del", "10.90.0.0/24", "dev", cfg.Interface})
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandClientRemoveSessionPreservesUnownedRoutesStillBoundToInterfaceAfterRestart(t *testing.T) {
	fr := &fakeRunner{}
	m := newTestCommandClientManager(fr)
	cfg := ClientSessionConfig{
		Interface:     "wg-client0",
		ExitPublicKey: testWGPublicKey(),
		AllowedIPs:    "10.90.0.0/24, ::/0",
		InstallRoute:  true,
	}
	fr.outputFor = func(name string, args []string) ([]byte, error) {
		switch {
		case name == m.ipBinary && reflect.DeepEqual(args, []string{"route", "show", "10.90.0.0/24", "dev", cfg.Interface}):
			return []byte("10.90.0.0/24 dev " + cfg.Interface + " scope link\n"), nil
		case name == m.ipBinary && reflect.DeepEqual(args, []string{"-6", "route", "show", "::/0", "dev", cfg.Interface}):
			return []byte("::/0 dev " + cfg.Interface + " metric 1024\n"), nil
		default:
			return nil, nil
		}
	}

	if err := m.RemoveClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	assertNoCall(t, fr.calls, m.ipBinary, []string{"route", "del", "10.90.0.0/24", "dev", cfg.Interface})
	assertNoCall(t, fr.calls, m.ipBinary, []string{"-6", "route", "del", "::/0", "dev", cfg.Interface})
	assertNoSharedInterfaceRollback(t, fr.calls, m.ipBinary, cfg.Interface)
}

func TestCommandClientConfigureSessionRejectsInvalidInputs(t *testing.T) {
	validCfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
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
	withCommandBackendPlatform(t, "linux")
	clearCommandProductionModeEnv(t)
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	original := commandClientLookPath
	t.Cleanup(func() {
		commandClientLookPath = original
	})

	commandClientLookPath = func(name string) (string, error) {
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
	m := NewCommandClientManager()
	m.runner = fr
	m.platform = "linux"
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
		ExitPublicKey:    testWGPublicKey(),
		AllowedIPs:       "0.0.0.0/0",
	}
	if err := m.ConfigureClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	if len(fr.calls) < 2 {
		t.Fatalf("expected at least 2 commands, got %d", len(fr.calls))
	}
	wantWG, _ := filepath.Abs(testAbsPath("opt", "wireguard", "wg"))
	wantIP, _ := filepath.Abs(testAbsPath("usr", "sbin", "ip"))
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
	withCommandBackendPlatform(t, "linux")
	original := commandClientLookPath
	t.Cleanup(func() {
		commandClientLookPath = original
	})
	commandClientLookPath = func(name string) (string, error) {
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
	m := NewCommandClientManager()
	m.runner = fr
	m.platform = "linux"
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
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

func TestResolveClientBinaryPathAllowsUntrustedPathOutsideProduction(t *testing.T) {
	clearCommandProductionModeEnv(t)
	t.Setenv(allowUntrustedBinaryPathEnv, "1")

	untrustedPath := testAbsPath("opt", "wireguard-dev", "wg")
	resolved, err := resolveClientBinaryPath("wg", func(name string) (string, error) {
		if name != "wg" {
			t.Fatalf("unexpected binary name %q", name)
		}
		return untrustedPath, nil
	})
	if err != nil {
		t.Fatalf("resolveClientBinaryPath returned error: %v", err)
	}
	if resolved != expectedResolvedBinaryPathForTest(untrustedPath) {
		t.Fatalf("resolved=%q want=%q", resolved, expectedResolvedBinaryPathForTest(untrustedPath))
	}
}

func TestResolveClientBinaryPathRejectsUntrustedPathWhenAnyProductionAliasEnables(t *testing.T) {
	clearCommandProductionModeEnv(t)
	t.Setenv(allowUntrustedBinaryPathEnv, "1")
	t.Setenv("GPM_PRODUCTION_MODE", "0")
	t.Setenv("TDPN_PRODUCTION_MODE", "1")

	untrustedPath := testAbsPath("opt", "wireguard-dev", "wg")
	if _, err := resolveClientBinaryPath("wg", func(name string) (string, error) {
		if name != "wg" {
			t.Fatalf("unexpected binary name %q", name)
		}
		return untrustedPath, nil
	}); err == nil {
		t.Fatal("expected production alias to reject untrusted path")
	} else if !strings.Contains(err.Error(), allowUntrustedBinaryPathEnv) || !strings.Contains(err.Error(), "ignored in production mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveClientBinaryPathIgnoresUntrustedOverrideInProduction(t *testing.T) {
	tests := []struct {
		name string
		env  string
		val  string
	}{
		{name: "gpm production", env: "GPM_PRODUCTION_MODE", val: "1"},
		{name: "legacy gpm production", env: "TDPN_PRODUCTION_MODE", val: "true"},
		{name: "invalid gpm production fails closed", env: "GPM_PRODUCTION_MODE", val: "definitely-not-bool"},
		{name: "global prod strict", env: "PROD_STRICT_MODE", val: "1"},
		{name: "client prod strict", env: "CLIENT_PROD_STRICT", val: "1"},
		{name: "exit prod strict", env: "EXIT_PROD_STRICT", val: "1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearCommandProductionModeEnv(t)
			t.Setenv(allowUntrustedBinaryPathEnv, "1")
			t.Setenv(tc.env, tc.val)

			_, err := resolveClientBinaryPath("wg", func(name string) (string, error) {
				if name != "wg" {
					t.Fatalf("unexpected binary name %q", name)
				}
				return testAbsPath("opt", "wireguard-dev", "wg"), nil
			})
			if err == nil {
				t.Fatalf("expected production mode to reject untrusted binary path")
			}
			if !strings.Contains(err.Error(), allowUntrustedBinaryPathEnv+" is ignored in production mode") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewCommandClientManagerLookupFailureFailsClosed(t *testing.T) {
	withCommandBackendPlatform(t, "linux")
	original := commandClientLookPath
	t.Cleanup(func() {
		commandClientLookPath = original
	})

	commandClientLookPath = func(name string) (string, error) {
		if name == "wg" {
			return testAbsPath("usr", "bin", "wg"), nil
		}
		return "", fmt.Errorf("%s not found", name)
	}

	fr := &fakeRunner{}
	m := NewCommandClientManager()
	m.runner = fr
	m.platform = "linux"
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
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

func TestNewCommandClientManagerWindowsFailsBeforeLinuxCommandLookup(t *testing.T) {
	withCommandBackendPlatform(t, "windows")
	original := commandClientLookPath
	t.Cleanup(func() {
		commandClientLookPath = original
	})
	commandClientLookPath = func(name string) (string, error) {
		t.Fatalf("Windows command client backend must not probe Linux command %q", name)
		return "", nil
	}

	fr := &fakeRunner{}
	m := NewCommandClientManager()
	m.runner = fr
	err := m.ConfigureClientSession(context.Background(), ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: testAbsPath("tmp", "client.key"),
		ExitPublicKey:    testWGPublicKey(),
		AllowedIPs:       "0.0.0.0/0",
	})
	if err == nil {
		t.Fatalf("expected Windows unsupported error")
	}
	assertWindowsCommandBackendGuidance(t, err)
	if len(fr.calls) != 0 {
		t.Fatalf("expected no command execution on Windows, got %d calls", len(fr.calls))
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
