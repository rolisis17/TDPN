package wg

import (
	"context"
	"fmt"
	"strconv"
)

type CommandClientManager struct {
	runner Runner
}

func NewCommandClientManager() *CommandClientManager {
	return &CommandClientManager{runner: execRunner{}}
}

func (m *CommandClientManager) ConfigureClientSession(ctx context.Context, cfg ClientSessionConfig) error {
	if cfg.Interface == "" {
		return fmt.Errorf("missing interface")
	}
	if cfg.ClientPrivateKey == "" {
		return fmt.Errorf("missing client private key")
	}
	if cfg.ExitPublicKey == "" {
		return fmt.Errorf("missing exit public key")
	}

	if err := m.runner.Run(ctx, "wg", "set", cfg.Interface, "private-key", cfg.ClientPrivateKey); err != nil {
		return err
	}
	if cfg.ClientInnerIP != "" {
		if err := m.runner.Run(ctx, "ip", "addr", "replace", cfg.ClientInnerIP, "dev", cfg.Interface); err != nil {
			return err
		}
	}

	args := []string{"set", cfg.Interface, "peer", cfg.ExitPublicKey, "allowed-ips", cfg.AllowedIPs}
	if cfg.KeepaliveSec > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(cfg.KeepaliveSec))
	}
	if cfg.Endpoint != "" {
		args = append(args, "endpoint", cfg.Endpoint)
	}
	if err := m.runner.Run(ctx, "wg", args...); err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := m.runner.Run(ctx, "ip", "link", "set", "dev", cfg.Interface, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
			return err
		}
	}
	return nil
}

func (m *CommandClientManager) RemoveClientSession(ctx context.Context, cfg ClientSessionConfig) error {
	if cfg.Interface == "" || cfg.ExitPublicKey == "" {
		return nil
	}
	if err := m.runner.Run(ctx, "wg", "set", cfg.Interface, "peer", cfg.ExitPublicKey, "remove"); err != nil {
		return err
	}
	return nil
}
