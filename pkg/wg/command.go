package wg

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type commandOutputRunner interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
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

func (r execRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %v failed: %w (%s)", name, args, err, string(out))
	}
	return out, nil
}

type CommandManager struct {
	runner     Runner
	wgBinary   string
	ipBinary   string
	resolveErr error
	platform   string
}

var commandManagerLookPath = exec.LookPath

func NewCommandManager() *CommandManager {
	platform := commandBackendPlatform()
	wgBinary, ipBinary, err := resolveCommandBinaryPathsForPlatform(platform, commandManagerLookPath)
	return &CommandManager{
		runner:     execRunner{},
		wgBinary:   wgBinary,
		ipBinary:   ipBinary,
		resolveErr: err,
		platform:   platform,
	}
}

func resolveCommandBinaryPaths(lookup func(string) (string, error)) (string, string, error) {
	return resolveCommandBinaryPathsForPlatform(commandBackendPlatform(), lookup)
}

func resolveCommandBinaryPathsForPlatform(goos string, lookup func(string) (string, error)) (string, string, error) {
	return resolveClientBinaryPathsForPlatform(goos, lookup)
}

func (m *CommandManager) validateCommandBinaries() error {
	if err := commandBackendPlatformError(m.platform); err != nil {
		return err
	}
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

	interfaceSnapshot := m.captureCommandInterfaceSnapshot(ctx, iface)
	wgInterfaceMutatedByCall := false
	linkUpAttemptedByCall := false
	addrConfiguredByCall := false
	peerConfiguredByCall := false
	addrPreexisting := false
	peerPreexisting := false
	if outputRunner, ok := m.runner.(commandOutputRunner); ok {
		if exitInnerIP != "" {
			if out, err := outputRunner.Output(ctx, m.ipCommand(), "-o", "addr", "show", "dev", iface, "to", exitInnerIP); err == nil && strings.TrimSpace(string(out)) != "" {
				addrPreexisting = true
			}
		}
		if out, err := outputRunner.Output(ctx, m.wgCommand(), "show", iface, "allowed-ips"); err == nil && commandOutputHasPeer(out, clientPub) {
			peerPreexisting = true
		}
	}
	cleanupAfterFailure := func(removePeer bool, removeAddr bool) {
		if removePeer {
			_ = m.runner.Run(ctx, m.wgCommand(), "set", iface, "peer", clientPub, "remove")
		}
		if removeAddr && exitInnerIP != "" {
			_ = m.runner.Run(ctx, m.ipCommand(), "addr", "del", exitInnerIP, "dev", iface)
		}
		m.restoreCommandInterfaceSnapshot(ctx, iface, interfaceSnapshot, wgInterfaceMutatedByCall, linkUpAttemptedByCall)
	}
	failAfterMutation := func(err error) error {
		cleanupAfterFailure(peerConfiguredByCall, addrConfiguredByCall)
		return err
	}

	if err := m.runner.Run(ctx, m.wgCommand(), "set", iface,
		"private-key", privateKeyPath,
		"listen-port", strconv.Itoa(cfg.ListenPort)); err != nil {
		m.restoreCommandInterfaceSnapshot(ctx, iface, interfaceSnapshot, true, false)
		return err
	}
	wgInterfaceMutatedByCall = true
	if err := m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "up"); err != nil {
		linkUpAttemptedByCall = true
		cleanupAfterFailure(false, false)
		return err
	}
	linkUpAttemptedByCall = true
	if exitInnerIP != "" {
		if err := m.runner.Run(ctx, m.ipCommand(), "addr", "replace", exitInnerIP, "dev", iface); err != nil {
			cleanupAfterFailure(false, !addrPreexisting)
			return err
		}
		addrConfiguredByCall = !addrPreexisting
	}
	if err := m.runner.Run(ctx, m.wgCommand(), "set", iface,
		"peer", clientPub,
		"allowed-ips", clientInnerIP,
		"persistent-keepalive", strconv.Itoa(cfg.KeepaliveSec)); err != nil {
		cleanupAfterFailure(!peerPreexisting, addrConfiguredByCall)
		return err
	}
	peerConfiguredByCall = !peerPreexisting
	if cfg.MTU > 0 {
		if err := m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
			return failAfterMutation(err)
		}
	}
	return nil
}

func commandOutputHasPeer(out []byte, peer string) bool {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == peer {
			return true
		}
	}
	return false
}

type commandInterfaceSnapshot struct {
	wgConfig     []byte
	hasWGConfig  bool
	linkWasUp    bool
	hasLinkState bool
}

func (m *CommandManager) captureCommandInterfaceSnapshot(ctx context.Context, iface string) commandInterfaceSnapshot {
	outputRunner, ok := m.runner.(commandOutputRunner)
	if !ok {
		return commandInterfaceSnapshot{}
	}
	var snapshot commandInterfaceSnapshot
	if out, err := outputRunner.Output(ctx, m.wgCommand(), "showconf", iface); err == nil && strings.TrimSpace(string(out)) != "" {
		snapshot.wgConfig = append([]byte(nil), out...)
		snapshot.hasWGConfig = true
	}
	if out, err := outputRunner.Output(ctx, m.ipCommand(), "-o", "link", "show", "dev", iface); err == nil {
		if up, ok := commandLinkOutputIsUp(out); ok {
			snapshot.linkWasUp = up
			snapshot.hasLinkState = true
		}
	}
	return snapshot
}

func (m *CommandManager) restoreCommandInterfaceSnapshot(ctx context.Context, iface string, snapshot commandInterfaceSnapshot, restoreWG bool, restoreLinkUp bool) {
	if restoreWG && snapshot.hasWGConfig {
		_ = m.restoreCommandWGConfig(ctx, iface, snapshot.wgConfig)
	}
	if restoreLinkUp && snapshot.hasLinkState && !snapshot.linkWasUp {
		_ = m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "down")
	}
}

func (m *CommandManager) restoreCommandWGConfig(ctx context.Context, iface string, config []byte) error {
	tmp, err := os.CreateTemp("", "tdpn-wg-rollback-*.conf")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(config); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return m.runner.Run(ctx, m.wgCommand(), "setconf", iface, tmpPath)
}

func commandLinkOutputIsUp(out []byte) (bool, bool) {
	line := strings.TrimSpace(string(out))
	if line == "" {
		return false, false
	}
	if start := strings.Index(line, "<"); start >= 0 {
		if end := strings.Index(line[start:], ">"); end > 0 {
			for _, flag := range strings.Split(line[start+1:start+end], ",") {
				if strings.TrimSpace(flag) == "UP" {
					return true, true
				}
			}
			return false, true
		}
	}
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "state" {
			return fields[i+1] == "UP", true
		}
	}
	return false, false
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
