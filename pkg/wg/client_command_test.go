package wg

import (
	"context"
	"reflect"
	"testing"
)

func TestCommandClientConfigureSession(t *testing.T) {
	fr := &fakeRunner{}
	m := &CommandClientManager{runner: fr}
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: "/tmp/client.key",
		ExitPublicKey:    "exitpub",
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
	if fr.calls[0].name != "wg" {
		t.Fatalf("expected first command wg")
	}
	wantFirst := []string{"set", "wg-client0", "private-key", "/tmp/client.key"}
	if !reflect.DeepEqual(fr.calls[0].args, wantFirst) {
		t.Fatalf("first command mismatch got=%v want=%v", fr.calls[0].args, wantFirst)
	}
	if fr.calls[1].name != "ip" || !reflect.DeepEqual(fr.calls[1].args, []string{"link", "set", "dev", "wg-client0", "up"}) {
		t.Fatalf("expected interface-up command, got name=%s args=%v", fr.calls[1].name, fr.calls[1].args)
	}
}

func TestCommandClientConfigureSessionInstallsRoutes(t *testing.T) {
	fr := &fakeRunner{}
	m := &CommandClientManager{runner: fr}
	cfg := ClientSessionConfig{
		Interface:        "wg-client0",
		ClientPrivateKey: "/tmp/client.key",
		ExitPublicKey:    "exitpub",
		AllowedIPs:       "10.90.0.0/24, 10.91.0.0/24",
		InstallRoute:     true,
	}
	if err := m.ConfigureClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}
	if len(fr.calls) != 5 {
		t.Fatalf("expected 5 commands with two routes, got %d", len(fr.calls))
	}
	wantRouteA := runCall{name: "ip", args: []string{"route", "replace", "10.90.0.0/24", "dev", "wg-client0"}}
	wantRouteB := runCall{name: "ip", args: []string{"route", "replace", "10.91.0.0/24", "dev", "wg-client0"}}
	if !reflect.DeepEqual(fr.calls[3], wantRouteA) {
		t.Fatalf("first route command mismatch got=%+v want=%+v", fr.calls[3], wantRouteA)
	}
	if !reflect.DeepEqual(fr.calls[4], wantRouteB) {
		t.Fatalf("second route command mismatch got=%+v want=%+v", fr.calls[4], wantRouteB)
	}
}

func TestCommandClientRemoveSession(t *testing.T) {
	fr := &fakeRunner{}
	m := &CommandClientManager{runner: fr}
	cfg := ClientSessionConfig{Interface: "wg-client0", ExitPublicKey: "exitpub"}
	if err := m.RemoveClientSession(context.Background(), cfg); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected 1 command, got %d", len(fr.calls))
	}
}
