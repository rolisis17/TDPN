package wg

import (
	"context"
	"reflect"
	"testing"
)

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

func TestCommandConfigureSession(t *testing.T) {
	fr := &fakeRunner{}
	m := &CommandManager{runner: fr}
	cfg := SessionConfig{
		Interface:      "wg0",
		ExitPrivateKey: "/tmp/exit.key",
		ClientPubKey:   "clientpub",
		ClientInnerIP:  "10.90.0.2/32",
		ExitInnerIP:    "10.90.0.1/32",
		ListenPort:     51820,
		KeepaliveSec:   25,
		MTU:            1280,
	}
	if err := m.ConfigureSession(context.Background(), cfg); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	if len(fr.calls) != 4 {
		t.Fatalf("expected 4 commands, got %d", len(fr.calls))
	}
	if fr.calls[0].name != "wg" {
		t.Fatalf("expected first command wg, got %s", fr.calls[0].name)
	}
	wantFirst := []string{"set", "wg0", "private-key", "/tmp/exit.key", "listen-port", "51820"}
	if !reflect.DeepEqual(fr.calls[0].args, wantFirst) {
		t.Fatalf("first command mismatch: got %v want %v", fr.calls[0].args, wantFirst)
	}
}

func TestCommandRemoveSession(t *testing.T) {
	fr := &fakeRunner{}
	m := &CommandManager{runner: fr}
	cfg := SessionConfig{Interface: "wg0", ClientPubKey: "clientpub"}
	if err := m.RemoveSession(context.Background(), cfg); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected 1 command, got %d", len(fr.calls))
	}
}
