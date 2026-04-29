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
	"sync"
)

var commandClientInterfacePattern = regexp.MustCompile(`^wg[a-zA-Z0-9_.-]{0,13}$`)
var commandClientLookPath = exec.LookPath
var commandClientEvalSymlinks = filepath.EvalSymlinks
var commandBackendRuntimeGOOS = runtime.GOOS

const allowUntrustedBinaryPathEnv = "WG_ALLOW_UNTRUSTED_BINARY_PATH"
const windowsCommandBackendUnsupported = "wireguard command backend is unsupported on Windows: GPM does not yet manage WireGuardNT tunnel services through Windows-native wireguard.exe; refusing to use Linux wg/ip commands, WSL, or Git Bash paths. Install WireGuard for Windows (WireGuardNT driver plus wireguard.exe) and use the local/userspace path until the native service backend lands"
const DefaultFullTunnelAllowedIPs = "0.0.0.0/0,::/0"

var commandProductionModeEnvKeys = []string{
	"GPM_PRODUCTION_MODE",
	"TDPN_PRODUCTION_MODE",
	"PROD_STRICT_MODE",
	"CLIENT_PROD_STRICT",
	"EXIT_PROD_STRICT",
}

var commandProdStrictEnvKeys = []string{
	"PROD_STRICT_MODE",
	"CLIENT_PROD_STRICT",
	"EXIT_PROD_STRICT",
}

type CommandClientManager struct {
	runner              Runner
	wgBinary            string
	ipBinary            string
	resolveErr          error
	platform            string
	ownedMu             sync.Mutex
	ownedAddrs          map[string]struct{}
	ownedRoutes         map[string]struct{}
	ownedEndpointRoutes map[string]struct{}
}

func NewCommandClientManager() *CommandClientManager {
	platform := commandBackendPlatform()
	wgBinary, ipBinary, err := resolveClientBinaryPathsForPlatform(platform, commandClientLookPath)
	return &CommandClientManager{
		runner:     execRunner{},
		wgBinary:   wgBinary,
		ipBinary:   ipBinary,
		resolveErr: err,
		platform:   platform,
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
		allowedIPs = DefaultFullTunnelAllowedIPs
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

	peerConfiguredByCall := false
	addrConfiguredByCall := false
	installedRoutes := make([]string, 0, len(allowedCIDRs))
	installedEndpointRoutes := make([]string, 0, 1)
	cleanupAfterFailure := func() {
		var cleanupErr error
		for i := len(installedRoutes) - 1; i >= 0; i-- {
			cleanupErr = errors.Join(cleanupErr, m.runner.Run(ctx, m.ipCommand(), "route", "del", installedRoutes[i], "dev", iface))
			m.forgetOwnedRoute(iface, installedRoutes[i])
		}
		for i := len(installedEndpointRoutes) - 1; i >= 0; i-- {
			cleanupErr = errors.Join(cleanupErr, m.runner.Run(ctx, m.ipCommand(), clientEndpointRouteDelArgs(installedEndpointRoutes[i])...))
			m.forgetOwnedEndpointRoute(installedEndpointRoutes[i])
		}
		if peerConfiguredByCall {
			cleanupErr = errors.Join(cleanupErr, m.runner.Run(ctx, m.wgCommand(), "set", iface, "peer", exitPublicKey, "remove"))
		}
		if addrConfiguredByCall {
			cleanupErr = errors.Join(cleanupErr, m.runner.Run(ctx, m.ipCommand(), "addr", "del", clientInnerIP, "dev", iface))
			m.forgetOwnedAddr(iface, clientInnerIP)
		}
		_ = cleanupErr
	}
	failAfterMutation := func(err error) error {
		cleanupAfterFailure()
		return err
	}

	if err := m.runner.Run(ctx, m.wgCommand(), "set", iface, "private-key", privateKeyPath); err != nil {
		return err
	}
	if err := m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "up"); err != nil {
		return failAfterMutation(err)
	}
	if clientInnerIP != "" {
		addrPreexisting := true
		if exists, known := m.clientAddressExists(ctx, iface, clientInnerIP); known {
			addrPreexisting = exists
		}
		if !addrPreexisting {
			if err := m.runner.Run(ctx, m.ipCommand(), "addr", "add", clientInnerIP, "dev", iface); err != nil {
				return failAfterMutation(err)
			}
			addrConfiguredByCall = true
			m.rememberOwnedAddr(iface, clientInnerIP)
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
		return failAfterMutation(err)
	}
	peerConfiguredByCall = true
	if cfg.MTU > 0 {
		if err := m.runner.Run(ctx, m.ipCommand(), "link", "set", "dev", iface, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
			return failAfterMutation(err)
		}
	}
	if cfg.InstallRoute {
		if endpoint != "" && commandAllowedCIDRsIncludeFullTunnel(allowedCIDRs) {
			endpointRoute, installed, err := m.ensureEndpointRouteException(ctx, endpoint)
			if err != nil {
				return failAfterMutation(err)
			}
			if installed {
				installedEndpointRoutes = append(installedEndpointRoutes, endpointRoute)
			}
		}
		for _, cidr := range allowedCIDRs {
			routePreexisting := false
			if exists, known := m.clientRouteExists(ctx, iface, cidr); known {
				routePreexisting = exists
			}
			if !routePreexisting {
				if err := m.runner.Run(ctx, m.ipCommand(), clientRouteArgs("add", cidr, iface)...); err != nil {
					return failAfterMutation(err)
				}
				installedRoutes = append(installedRoutes, cidr)
				m.rememberOwnedRoute(iface, cidr)
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
	var cleanupErr error
	cleanupErr = errors.Join(cleanupErr, m.runner.Run(ctx, m.wgCommand(), "set", iface, "peer", exitPublicKey, "remove"))
	if cfg.InstallRoute {
		allowedIPs := strings.TrimSpace(cfg.AllowedIPs)
		if allowedIPs == "" {
			allowedIPs = DefaultFullTunnelAllowedIPs
		}
		allowedCIDRs := splitCommaSeparated(allowedIPs)
		for _, cidr := range allowedCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("invalid allowed ips CIDR %q: %w", cidr, err))
				continue
			}
			if m.ownsRoute(iface, cidr) {
				cleanupErr = errors.Join(cleanupErr, m.runner.Run(ctx, m.ipCommand(), clientRouteArgs("del", cidr, iface)...))
				m.forgetOwnedRoute(iface, cidr)
			}
		}
		endpoint := strings.TrimSpace(cfg.Endpoint)
		if endpoint != "" && commandAllowedCIDRsIncludeFullTunnel(allowedCIDRs) {
			if endpointRoute, err := clientEndpointRouteCIDR(endpoint); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			} else if m.ownsEndpointRoute(endpointRoute) {
				cleanupErr = errors.Join(cleanupErr, m.runner.Run(ctx, m.ipCommand(), clientEndpointRouteDelArgs(endpointRoute)...))
				m.forgetOwnedEndpointRoute(endpointRoute)
			}
		}
	}
	clientInnerIP := strings.TrimSpace(cfg.ClientInnerIP)
	if clientInnerIP != "" {
		if _, _, err := net.ParseCIDR(clientInnerIP); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("invalid client inner ip CIDR %q: %w", clientInnerIP, err))
		} else if m.ownsAddr(iface, clientInnerIP) {
			cleanupErr = errors.Join(cleanupErr, m.runner.Run(ctx, m.ipCommand(), "addr", "del", clientInnerIP, "dev", iface))
			m.forgetOwnedAddr(iface, clientInnerIP)
		}
	}
	return cleanupErr
}

func (m *CommandClientManager) ensureEndpointRouteException(ctx context.Context, endpoint string) (string, bool, error) {
	endpointRoute, err := clientEndpointRouteCIDR(endpoint)
	if err != nil {
		return "", false, err
	}
	if exists, known := m.clientEndpointRouteExists(ctx, endpointRoute); known && exists {
		return endpointRoute, false, nil
	}
	outputRunner, ok := m.runner.(commandOutputRunner)
	if !ok {
		return "", false, fmt.Errorf("endpoint route exception requires route lookup support")
	}
	endpointIP, _, err := net.ParseCIDR(endpointRoute)
	if err != nil {
		return "", false, fmt.Errorf("parse endpoint route CIDR %q: %w", endpointRoute, err)
	}
	routeGetOutput, err := outputRunner.Output(ctx, m.ipCommand(), clientEndpointRouteGetArgs(endpointIP.String())...)
	if err != nil {
		return "", false, fmt.Errorf("lookup endpoint route for %s: %w", endpointIP.String(), err)
	}
	addArgs, err := clientEndpointRouteAddArgs(endpointRoute, routeGetOutput)
	if err != nil {
		return "", false, err
	}
	if err := m.runner.Run(ctx, m.ipCommand(), addArgs...); err != nil {
		return "", false, err
	}
	m.rememberOwnedEndpointRoute(endpointRoute)
	return endpointRoute, true, nil
}

func (m *CommandClientManager) clientAddressExists(ctx context.Context, iface string, cidr string) (bool, bool) {
	outputRunner, ok := m.runner.(commandOutputRunner)
	if !ok {
		return false, false
	}
	out, err := outputRunner.Output(ctx, m.ipCommand(), "-o", "addr", "show", "dev", iface, "to", cidr)
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(out)) != "", true
}

func (m *CommandClientManager) clientRouteExists(ctx context.Context, iface string, cidr string) (bool, bool) {
	outputRunner, ok := m.runner.(commandOutputRunner)
	if !ok {
		return false, false
	}
	out, err := outputRunner.Output(ctx, m.ipCommand(), clientRouteArgs("show", cidr, iface)...)
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(out)) != "", true
}

func (m *CommandClientManager) clientEndpointRouteExists(ctx context.Context, cidr string) (bool, bool) {
	outputRunner, ok := m.runner.(commandOutputRunner)
	if !ok {
		return false, false
	}
	out, err := outputRunner.Output(ctx, m.ipCommand(), clientEndpointRouteShowArgs(cidr)...)
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(out)) != "", true
}

func clientRouteArgs(action string, cidr string, iface string) []string {
	if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil && ipNet.IP.To4() == nil {
		return []string{"-6", "route", action, cidr, "dev", iface}
	}
	return []string{"route", action, cidr, "dev", iface}
}

func clientEndpointRouteCIDR(endpoint string) (string, error) {
	addr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(endpoint))
	if err != nil {
		return "", fmt.Errorf("resolve endpoint route exception target %q: %w", endpoint, err)
	}
	if addr.IP == nil {
		return "", fmt.Errorf("resolve endpoint route exception target %q: missing IP", endpoint)
	}
	if ip4 := addr.IP.To4(); ip4 != nil {
		return ip4.String() + "/32", nil
	}
	return addr.IP.String() + "/128", nil
}

func clientEndpointRouteGetArgs(ip string) []string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed != nil && parsed.To4() == nil {
		return []string{"-6", "route", "get", parsed.String()}
	}
	return []string{"route", "get", strings.TrimSpace(ip)}
}

func clientEndpointRouteShowArgs(cidr string) []string {
	if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil && ipNet.IP.To4() == nil {
		return []string{"-6", "route", "show", cidr}
	}
	return []string{"route", "show", cidr}
}

func clientEndpointRouteDelArgs(cidr string) []string {
	if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil && ipNet.IP.To4() == nil {
		return []string{"-6", "route", "del", cidr}
	}
	return []string{"route", "del", cidr}
}

func clientEndpointRouteAddArgs(cidr string, routeGetOutput []byte) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint route CIDR %q: %w", cidr, err)
	}
	fields := strings.Fields(string(routeGetOutput))
	if len(fields) == 0 {
		return nil, fmt.Errorf("endpoint route lookup for %s returned no route", cidr)
	}
	var via string
	var dev string
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			if net.ParseIP(fields[i+1]) == nil {
				return nil, fmt.Errorf("endpoint route lookup for %s returned invalid gateway %q", cidr, fields[i+1])
			}
			via = fields[i+1]
		case "dev":
			dev = fields[i+1]
		}
	}
	if strings.TrimSpace(dev) == "" {
		return nil, fmt.Errorf("endpoint route lookup for %s returned no device", cidr)
	}
	args := []string{"route", "add", cidr}
	if ipNet.IP.To4() == nil {
		args = []string{"-6", "route", "add", cidr}
	}
	if via != "" {
		args = append(args, "via", via)
	}
	args = append(args, "dev", dev)
	return args, nil
}

func (m *CommandClientManager) rememberOwnedAddr(iface string, cidr string) {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	if m.ownedAddrs == nil {
		m.ownedAddrs = make(map[string]struct{})
	}
	m.ownedAddrs[ownedClientResourceKey(iface, cidr)] = struct{}{}
}

func (m *CommandClientManager) forgetOwnedAddr(iface string, cidr string) {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	delete(m.ownedAddrs, ownedClientResourceKey(iface, cidr))
}

func (m *CommandClientManager) ownsAddr(iface string, cidr string) bool {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	_, ok := m.ownedAddrs[ownedClientResourceKey(iface, cidr)]
	return ok
}

func (m *CommandClientManager) rememberOwnedRoute(iface string, cidr string) {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	if m.ownedRoutes == nil {
		m.ownedRoutes = make(map[string]struct{})
	}
	m.ownedRoutes[ownedClientResourceKey(iface, cidr)] = struct{}{}
}

func (m *CommandClientManager) forgetOwnedRoute(iface string, cidr string) {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	delete(m.ownedRoutes, ownedClientResourceKey(iface, cidr))
}

func (m *CommandClientManager) ownsRoute(iface string, cidr string) bool {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	_, ok := m.ownedRoutes[ownedClientResourceKey(iface, cidr)]
	return ok
}

func (m *CommandClientManager) rememberOwnedEndpointRoute(cidr string) {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	if m.ownedEndpointRoutes == nil {
		m.ownedEndpointRoutes = make(map[string]struct{})
	}
	m.ownedEndpointRoutes[cidr] = struct{}{}
}

func (m *CommandClientManager) forgetOwnedEndpointRoute(cidr string) {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	delete(m.ownedEndpointRoutes, cidr)
}

func (m *CommandClientManager) ownsEndpointRoute(cidr string) bool {
	m.ownedMu.Lock()
	defer m.ownedMu.Unlock()
	_, ok := m.ownedEndpointRoutes[cidr]
	return ok
}

func ownedClientResourceKey(iface string, cidr string) string {
	return iface + "\x00" + cidr
}

func (m *CommandClientManager) validateCommandBinaries() error {
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

func (m *CommandClientManager) wgCommand() string {
	return m.wgBinary
}

func (m *CommandClientManager) ipCommand() string {
	return m.ipBinary
}

func commandBackendPlatformError(goos string) error {
	goos = normalizeCommandBackendPlatform(goos)
	if goos == "windows" {
		return errors.New(windowsCommandBackendUnsupported)
	}
	return nil
}

func commandBackendPlatform() string {
	return normalizeCommandBackendPlatform(commandBackendRuntimeGOOS)
}

func normalizeCommandBackendPlatform(goos string) string {
	goos = strings.ToLower(strings.TrimSpace(goos))
	if goos == "" {
		goos = runtime.GOOS
	}
	return goos
}

func resolveClientBinaryPaths(lookup func(string) (string, error)) (string, string, error) {
	return resolveClientBinaryPathsForPlatform(commandBackendPlatform(), lookup)
}

func resolveClientBinaryPathsForPlatform(goos string, lookup func(string) (string, error)) (string, string, error) {
	if err := commandBackendPlatformError(goos); err != nil {
		return "", "", err
	}
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
	if !isTrustedBinaryPath(trustPath) {
		if allowUntrustedBinaryPath() {
			return trustPath, nil
		}
		if commandProductionModeEnabled() && strings.TrimSpace(os.Getenv(allowUntrustedBinaryPathEnv)) == "1" {
			return "", fmt.Errorf("resolve %s binary: untrusted path %q (%s is ignored in production mode)", name, trustPath, allowUntrustedBinaryPathEnv)
		}
		return "", fmt.Errorf("resolve %s binary: untrusted path %q (set %s=1 to allow outside production mode)", name, trustPath, allowUntrustedBinaryPathEnv)
	}
	return trustPath, nil
}

func allowUntrustedBinaryPath() bool {
	return strings.TrimSpace(os.Getenv(allowUntrustedBinaryPathEnv)) == "1" && !commandProductionModeEnabled()
}

func commandProductionModeEnabled() bool {
	if commandGPMProductionModeEnabled() {
		return true
	}
	for _, key := range commandProdStrictEnvKeys {
		if commandBoolEnvEnabled(key, false) {
			return true
		}
	}
	return false
}

func commandGPMProductionModeEnabled() bool {
	for _, key := range []string{"GPM_PRODUCTION_MODE", "TDPN_PRODUCTION_MODE"} {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw != "" && commandBoolEnvValueEnabled(raw, true) {
			return true
		}
	}
	return false
}

func commandBoolEnvEnabled(key string, invalidIsEnabled bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return false
	}
	return commandBoolEnvValueEnabled(raw, invalidIsEnabled)
}

func commandBoolEnvValueEnabled(raw string, invalidIsEnabled bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return false
	case "0", "false", "no", "n", "off":
		return false
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return invalidIsEnabled
	}
}

func commandAllowedCIDRsIncludeFullTunnel(allowedCIDRs []string) bool {
	for _, cidr := range allowedCIDRs {
		switch strings.TrimSpace(cidr) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
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
