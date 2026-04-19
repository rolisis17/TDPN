package wg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	runner     Runner
	wgBinary   string
	ipBinary   string
	resolveErr error
}

var commandManagerLookPath = exec.LookPath

func NewCommandManager() *CommandManager {
	wgBinary, ipBinary, err := resolveCommandBinaryPaths(commandManagerLookPath)
	return &CommandManager{
		runner:     execRunner{},
		wgBinary:   wgBinary,
		ipBinary:   ipBinary,
		resolveErr: err,
	}
}

func resolveCommandBinaryPaths(lookup func(string) (string, error)) (string, string, error) {
	wgBinary, wgErr := resolveClientBinaryPath("wg", lookup)
	ipBinary, ipErr := resolveClientBinaryPath("ip", lookup)
	return wgBinary, ipBinary, errors.Join(wgErr, ipErr)
}

func (m *CommandManager) validateCommandBinaries() error {
	if m.resolveErr != nil {
		return m.resolveErr
	}
	if !filepath.IsAbs(m.wgBinary) || !filepath.IsAbs(m.ipBinary) {
		return fmt.Errorf("wireguard command binaries must be absolute paths")
	}
	return nil
}

func (m *CommandManager) wgCommand() string {
	return m.wgBinary
}

func (m *CommandManager) ipCommand() string {
	return m.ipBinary
}

func (m *CommandManager) ConfigureSession(ctx context.Context, cfg SessionConfig) error {
	if err := m.validateCommandBinaries(); err != nil {
		return err
	}
	iface := strings.TrimSpace(cfg.Interface)
	if iface == "" {
		return fmt.Errorf("missing interface")
	}
	if len(iface) > 15 || !commandClientInterfacePattern.MatchString(iface) {
		return fmt.Errorf("invalid interface %q", cfg.Interface)
	}
	privateKeyPath := strings.TrimSpace(cfg.ExitPrivateKey)
	if privateKeyPath == "" {
		return fmt.Errorf("missing exit private key")
	}
	if strings.HasPrefix(privateKeyPath, "-") {
		return fmt.Errorf("invalid exit private key path")
	}
	clientPub := strings.TrimSpace(cfg.ClientPubKey)
	if clientPub == "" {
		return fmt.Errorf("missing client pubkey")
	}
	if !IsValidPublicKey(clientPub) {
		return fmt.Errorf("invalid client pubkey")
	}
	clientInnerIP := strings.TrimSpace(cfg.ClientInnerIP)
	if clientInnerIP == "" {
		return fmt.Errorf("missing client inner ip")
	}
	if _, _, err := net.ParseCIDR(clientInnerIP); err != nil {
		return fmt.Errorf("invalid client inner ip CIDR %q: %w", clientInnerIP, err)
	}
	exitInnerIP := strings.TrimSpace(cfg.ExitInnerIP)
	if exitInnerIP != "" {
		if _, _, err := net.ParseCIDR(exitInnerIP); err != nil {
			return fmt.Errorf("invalid exit inner ip CIDR %q: %w", exitInnerIP, err)
		}
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port %d", cfg.ListenPort)
	}
	if cfg.KeepaliveSec < 0 || cfg.KeepaliveSec > 65535 {
		return fmt.Errorf("invalid keepalive seconds %d", cfg.KeepaliveSec)
	}
	if cfg.MTU != 0 && (cfg.MTU < 576 || cfg.MTU > 9500) {
		return fmt.Errorf("invalid mtu %d", cfg.MTU)
	}

	if err := m.runner.Run(ctx, m.wgCommand(), "set", iface,
		"private-key", privateKeyPath,
		"listen-port", strconv.Itoa(cfg.ListenPort)); err != nil {
		return err
	}
	if err := m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "up"); err != nil {
		return err
	}
	if exitInnerIP != "" {
		if err := m.runner.Run(ctx, m.ipCommand(), "addr", "replace", exitInnerIP, "dev", iface); err != nil {
			return err
		}
	}
	if err := m.runner.Run(ctx, m.wgCommand(), "set", iface,
		"peer", clientPub,
		"allowed-ips", clientInnerIP,
		"persistent-keepalive", strconv.Itoa(cfg.KeepaliveSec)); err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
			return err
		}
	}
	return nil
}

func (m *CommandManager) RemoveSession(ctx context.Context, cfg SessionConfig) error {
	iface := strings.TrimSpace(cfg.Interface)
	clientPub := strings.TrimSpace(cfg.ClientPubKey)
	if iface == "" || clientPub == "" {
		return nil
	}
	if err := m.validateCommandBinaries(); err != nil {
		return err
	}
	if len(iface) > 15 || !commandClientInterfacePattern.MatchString(iface) {
		return fmt.Errorf("invalid interface %q", cfg.Interface)
	}
	if !IsValidPublicKey(clientPub) {
		return fmt.Errorf("invalid client pubkey")
	}
	if err := m.runner.Run(ctx, m.wgCommand(), "set", iface, "peer", clientPub, "remove"); err != nil {
		return err
	}
	return nil
}
