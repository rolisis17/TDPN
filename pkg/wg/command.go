package wg

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type execRunner struct{}

func (r execRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w (%s)", name, args, err, string(out))
	}
	return nil
}

type CommandManager struct {
	runner Runner
}

func NewCommandManager() *CommandManager {
	return &CommandManager{runner: execRunner{}}
}

func (m *CommandManager) ConfigureSession(ctx context.Context, cfg SessionConfig) error {
	if cfg.Interface == "" {
		return fmt.Errorf("missing interface")
	}
	if cfg.ExitPrivateKey == "" {
		return fmt.Errorf("missing exit private key")
	}
	if cfg.ClientPubKey == "" {
		return fmt.Errorf("missing client pubkey")
	}

	if err := m.runner.Run(ctx, "wg", "set", cfg.Interface,
		"private-key", cfg.ExitPrivateKey,
		"listen-port", strconv.Itoa(cfg.ListenPort)); err != nil {
		return err
	}
	if cfg.ExitInnerIP != "" {
		if err := m.runner.Run(ctx, "ip", "addr", "replace", cfg.ExitInnerIP, "dev", cfg.Interface); err != nil {
			return err
		}
	}
	if err := m.runner.Run(ctx, "wg", "set", cfg.Interface,
		"peer", cfg.ClientPubKey,
		"allowed-ips", cfg.ClientInnerIP,
		"persistent-keepalive", strconv.Itoa(cfg.KeepaliveSec)); err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := m.runner.Run(ctx, "ip", "link", "set", "dev", cfg.Interface, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
			return err
		}
	}
	return nil
}

func (m *CommandManager) RemoveSession(ctx context.Context, cfg SessionConfig) error {
	if cfg.Interface == "" || cfg.ClientPubKey == "" {
		return nil
	}
	if err := m.runner.Run(ctx, "wg", "set", cfg.Interface, "peer", cfg.ClientPubKey, "remove"); err != nil {
		return err
	}
	return nil
}
