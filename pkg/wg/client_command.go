package wg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var commandClientInterfacePattern = regexp.MustCompile(`^wg[a-zA-Z0-9_.-]{0,13}$`)
var commandClientLookPath = exec.LookPath
var commandClientEvalSymlinks = filepath.EvalSymlinks

const allowUntrustedBinaryPathEnv = "WG_ALLOW_UNTRUSTED_BINARY_PATH"

type CommandClientManager struct {
	runner     Runner
	wgBinary   string
	ipBinary   string
	resolveErr error
}

func NewCommandClientManager() *CommandClientManager {
	wgBinary, ipBinary, err := resolveClientBinaryPaths(commandClientLookPath)
	return &CommandClientManager{
		runner:     execRunner{},
		wgBinary:   wgBinary,
		ipBinary:   ipBinary,
		resolveErr: err,
	}
}

func (m *CommandClientManager) ConfigureClientSession(ctx context.Context, cfg ClientSessionConfig) error {
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
	privateKeyPath := strings.TrimSpace(cfg.ClientPrivateKey)
	if privateKeyPath == "" {
		return fmt.Errorf("missing client private key")
	}
	if strings.HasPrefix(privateKeyPath, "-") {
		return fmt.Errorf("invalid client private key path")
	}
	exitPublicKey := strings.TrimSpace(cfg.ExitPublicKey)
	if exitPublicKey == "" {
		return fmt.Errorf("missing exit public key")
	}
	if !IsValidPublicKey(exitPublicKey) {
		return fmt.Errorf("invalid exit public key")
	}
	allowedIPs := strings.TrimSpace(cfg.AllowedIPs)
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0"
	}
	allowedCIDRs := splitCommaSeparated(allowedIPs)
	if len(allowedCIDRs) == 0 {
		return fmt.Errorf("missing allowed ips")
	}
	for _, cidr := range allowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid allowed ips CIDR %q: %w", cidr, err)
		}
	}
	clientInnerIP := strings.TrimSpace(cfg.ClientInnerIP)
	if clientInnerIP != "" {
		if _, _, err := net.ParseCIDR(clientInnerIP); err != nil {
			return fmt.Errorf("invalid client inner ip CIDR %q: %w", clientInnerIP, err)
		}
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint != "" {
		if _, err := net.ResolveUDPAddr("udp", endpoint); err != nil {
			return fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
		}
	}
	if cfg.KeepaliveSec < 0 || cfg.KeepaliveSec > 65535 {
		return fmt.Errorf("invalid keepalive seconds %d", cfg.KeepaliveSec)
	}
	if cfg.MTU != 0 && (cfg.MTU < 576 || cfg.MTU > 9500) {
		return fmt.Errorf("invalid mtu %d", cfg.MTU)
	}

	if err := m.runner.Run(ctx, m.wgCommand(), "set", iface, "private-key", privateKeyPath); err != nil {
		return err
	}
	if err := m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "up"); err != nil {
		return err
	}
	if clientInnerIP != "" {
		if err := m.runner.Run(ctx, m.ipCommand(), "addr", "replace", clientInnerIP, "dev", iface); err != nil {
			return err
		}
	}

	args := []string{"set", iface, "peer", exitPublicKey, "allowed-ips", strings.Join(allowedCIDRs, ",")}
	if cfg.KeepaliveSec > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(cfg.KeepaliveSec))
	}
	if endpoint != "" {
		args = append(args, "endpoint", endpoint)
	}
	if err := m.runner.Run(ctx, m.wgCommand(), args...); err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
			return err
		}
	}
	if cfg.InstallRoute {
		for _, cidr := range allowedCIDRs {
			if err := m.runner.Run(ctx, m.ipCommand(), "route", "replace", cidr, "dev", iface); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *CommandClientManager) RemoveClientSession(ctx context.Context, cfg ClientSessionConfig) error {
	iface := strings.TrimSpace(cfg.Interface)
	exitPublicKey := strings.TrimSpace(cfg.ExitPublicKey)
	if iface == "" || exitPublicKey == "" {
		return nil
	}
	if err := m.validateCommandBinaries(); err != nil {
		return err
	}
	if len(iface) > 15 || !commandClientInterfacePattern.MatchString(iface) {
		return fmt.Errorf("invalid interface %q", cfg.Interface)
	}
	if !IsValidPublicKey(exitPublicKey) {
		return fmt.Errorf("invalid exit public key")
	}
	if err := m.runner.Run(ctx, m.wgCommand(), "set", iface, "peer", exitPublicKey, "remove"); err != nil {
		return err
	}
	return nil
}

func resolveClientBinaryPaths(lookup func(string) (string, error)) (string, string, error) {
	wgBinary, wgErr := resolveClientBinaryPath("wg", lookup)
	ipBinary, ipErr := resolveClientBinaryPath("ip", lookup)
	return wgBinary, ipBinary, errors.Join(wgErr, ipErr)
}

func resolveClientBinaryPath(name string, lookup func(string) (string, error)) (string, error) {
	resolved, err := lookup(name)
	if err != nil {
		return "", fmt.Errorf("resolve %s binary: %w", name, err)
	}
	resolved = strings.TrimSpace(resolved)
	if resolved == "" {
		return "", fmt.Errorf("resolve %s binary: empty path", name)
	}
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("resolve %s binary: non-absolute path %q", name, resolved)
	}
	resolved = filepath.Clean(resolved)
	trustPath := resolved
	if evalPath := commandClientEvalSymlinks; evalPath != nil {
		if canonical, evalErr := evalPath(resolved); evalErr == nil {
			canonical = strings.TrimSpace(canonical)
			if canonical != "" {
				if !filepath.IsAbs(canonical) {
					return "", fmt.Errorf("resolve %s binary: non-absolute canonical path %q", name, canonical)
				}
				trustPath = filepath.Clean(canonical)
			}
		}
	}
	if !allowUntrustedBinaryPath() && !isTrustedBinaryPath(trustPath) {
		return "", fmt.Errorf("resolve %s binary: untrusted path %q (set %s=1 to allow)", name, trustPath, allowUntrustedBinaryPathEnv)
	}
	return trustPath, nil
}

func allowUntrustedBinaryPath() bool {
	return strings.TrimSpace(os.Getenv(allowUntrustedBinaryPathEnv)) == "1"
}

func isTrustedBinaryPath(path string) bool {
	return isTrustedBinaryPathForOS(runtime.GOOS, path)
}

func isTrustedBinaryPathForOS(goos string, binaryPath string) bool {
	if strings.EqualFold(strings.TrimSpace(goos), "windows") {
		return isTrustedWindowsBinaryPath(binaryPath)
	}
	return isTrustedUnixBinaryPath(binaryPath)
}

func isTrustedUnixBinaryPath(binaryPath string) bool {
	trustedRoots := []string{
		"/usr/bin",
		"/usr/sbin",
		"/bin",
		"/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
	}
	binaryPath = filepath.Clean(binaryPath)
	for _, root := range trustedRoots {
		rel, err := filepath.Rel(root, binaryPath)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

func isTrustedWindowsBinaryPath(binaryPath string) bool {
	trustedRoots := trustedWindowsBinaryRoots()
	normalizedBinaryPath := normalizeWindowsPathForCompare(binaryPath)
	if normalizedBinaryPath == "" {
		return false
	}
	for _, root := range trustedRoots {
		normalizedRoot := normalizeWindowsPathForCompare(root)
		if normalizedRoot == "" {
			continue
		}
		if normalizedBinaryPath == normalizedRoot || strings.HasPrefix(normalizedBinaryPath, normalizedRoot+"/") {
			return true
		}
	}
	return false
}

func trustedWindowsBinaryRoots() []string {
	roots := []string{
		filepath.Join("C:\\Windows", "System32"),
		filepath.Join("C:\\Windows", "SysWOW64"),
		filepath.Join("C:\\Program Files", "WireGuard"),
		filepath.Join("C:\\Program Files (x86)", "WireGuard"),
	}
	if base := strings.TrimSpace(os.Getenv("SystemRoot")); base != "" {
		roots = append(roots, filepath.Join(base, "System32"), filepath.Join(base, "SysWOW64"))
	}
	if base := strings.TrimSpace(os.Getenv("WINDIR")); base != "" {
		roots = append(roots, filepath.Join(base, "System32"), filepath.Join(base, "SysWOW64"))
	}
	if base := strings.TrimSpace(os.Getenv("ProgramFiles")); base != "" {
		roots = append(roots, filepath.Join(base, "WireGuard"))
	}
	if base := strings.TrimSpace(os.Getenv("ProgramFiles(x86)")); base != "" {
		roots = append(roots, filepath.Join(base, "WireGuard"))
	}
	seen := make(map[string]struct{}, len(roots))
	deduped := make([]string, 0, len(roots))
	for _, root := range roots {
		key := normalizeWindowsPathForCompare(root)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, root)
	}
	return deduped
}

func normalizeWindowsPathForCompare(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, "\\", "/")
	normalized := pathpkg.Clean(raw)
	if normalized == "." {
		return ""
	}
	return strings.ToLower(normalized)
}

func (m *CommandClientManager) validateCommandBinaries() error {
	if m.resolveErr != nil {
		return m.resolveErr
	}
	if !filepath.IsAbs(m.wgBinary) || !filepath.IsAbs(m.ipBinary) {
		return fmt.Errorf("wireguard command binaries must be absolute paths")
	}
	return nil
}

func (m *CommandClientManager) wgCommand() string {
	return m.wgBinary
}

func (m *CommandClientManager) ipCommand() string {
	return m.ipBinary
}

func splitCommaSeparated(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
