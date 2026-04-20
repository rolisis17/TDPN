package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	"github.com/tdpn/tdpn-chain/internal/fsguard"
	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const gracefulShutdownTimeout = 5 * time.Second
const loopbackHostnameLookupTimeout = 2 * time.Second
const maxRuntimeAuthTokenFileBytes int64 = 16 << 10

const grpcHealthCheckMethod = "/grpc.health.v1.Health/Check"
const grpcHealthWatchMethod = "/grpc.health.v1.Health/Watch"

const dangerousInsecureAuthBindEnvVar = "TDPN_ALLOW_DANGEROUS_INSECURE_AUTH_BIND"
const dangerousPublicListenEnvVar = "TDPN_ALLOW_DANGEROUS_PUBLIC_LISTEN"

type chainScaffold interface {
	ModuleNames() []string
	RegisterGRPCServices(grpc.ServiceRegistrar) error
}

type grpcRuntimeServer interface {
	grpc.ServiceRegistrar
	Serve(net.Listener) error
	GracefulStop()
	Stop()
}

type runtimeDeps struct {
	Listen          func(network, address string) (net.Listener, error)
	ListenHTTP      func(network, address string) (net.Listener, error)
	NewGRPCServer   func(opts ...grpc.ServerOption) grpcRuntimeServer
	NewCometRuntime func(ctx context.Context, cfg cometRuntimeConfig, scaffold chainScaffold) (cometRuntime, error)
}

type grpcRuntimeConfig struct {
	listenAddr  string
	tlsCertPath string
	tlsKeyPath  string
	authToken   string
}

type settlementHTTPConfig struct {
	listenAddr    string
	authToken     string
	authPrincipal string
}

type stateDirConfigurableScaffold interface {
	ConfigureStateDir(string) error
}

type hostLookupFunc func(context.Context, string) ([]net.IPAddr, error)

func newChainScaffold() chainScaffold {
	return app.NewChainScaffold()
}

func defaultRuntimeDeps() runtimeDeps {
	return runtimeDeps{
		Listen:          net.Listen,
		ListenHTTP:      net.Listen,
		NewCometRuntime: newDefaultCometRuntime,
		NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
			return grpc.NewServer(opts...)
		},
	}
}

func runTDPND(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	newScaffold func() chainScaffold,
	deps runtimeDeps,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if newScaffold == nil {
		return errors.New("scaffold factory is nil")
	}
	if deps.Listen == nil {
		deps.Listen = net.Listen
	}
	if deps.ListenHTTP == nil {
		deps.ListenHTTP = net.Listen
	}
	if deps.NewGRPCServer == nil {
		deps.NewGRPCServer = func(opts ...grpc.ServerOption) grpcRuntimeServer { return grpc.NewServer(opts...) }
	}

	allowDangerousInsecureAuthBind, insecureBindErr := dangerousInsecureAuthBindDefault()
	if insecureBindErr != nil {
		return insecureBindErr
	}
	allowDangerousPublicListen, publicListenErr := dangerousPublicListenDefault()
	if publicListenErr != nil {
		return publicListenErr
	}

	flags := flag.NewFlagSet("tdpnd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	grpcListen := flags.String("grpc-listen", "", "listen address for gRPC server")
	grpcTLSCert := flags.String("grpc-tls-cert", "", "path to TLS cert PEM for gRPC server")
	grpcTLSKey := flags.String("grpc-tls-key", "", "path to TLS key PEM for gRPC server")
	grpcAuthToken := flags.String("grpc-auth-token", "", "optional bearer token for module gRPC methods")
	grpcAuthTokenFile := flags.String("grpc-auth-token-file", "", "path to file containing gRPC bearer token")
	allowDangerousInsecureAuthBindFlag := flags.Bool("allow-dangerous-insecure-auth-bind", allowDangerousInsecureAuthBind, "allow non-loopback listeners when auth is enabled")
	allowDangerousPublicListenFlag := flags.Bool("allow-dangerous-public-listen", allowDangerousPublicListen, "allow unauthenticated non-loopback listeners")
	settlementHTTPListen := flags.String("settlement-http-listen", "", "listen address for settlement HTTP bridge")
	settlementHTTPAuthToken := flags.String("settlement-http-auth-token", "", "optional bearer token for settlement HTTP POST endpoints")
	settlementHTTPAuthTokenFile := flags.String("settlement-http-auth-token-file", "", "path to file containing settlement HTTP bearer token")
	settlementHTTPAuthPrincipal := flags.String("settlement-http-auth-principal", "", "optional caller principal bound to settlement identity fields in authenticated mode")
	cometHome := flags.String("comet-home", "", "home directory for CometBFT runtime")
	cometMoniker := flags.String("comet-moniker", "", "moniker for CometBFT runtime")
	cometP2PLAddr := flags.String("comet-p2p-laddr", "", "listen address for CometBFT p2p networking")
	cometRPCAddr := flags.String("comet-rpc-laddr", "", "listen address for CometBFT RPC server")
	cometProxyApp := flags.String("comet-proxy-app", "", "proxy app label for the in-process CometBFT ABCI app")
	stateDir := flags.String("state-dir", "", "optional state directory for file-backed module stores")
	if err := flags.Parse(args); err != nil {
		return err
	}

	scaffold := newScaffold()
	if configuredStateDir := strings.TrimSpace(*stateDir); configuredStateDir != "" {
		configurableScaffold, ok := scaffold.(stateDirConfigurableScaffold)
		if !ok {
			return errors.New("chain scaffold does not support --state-dir")
		}
		if err := configurableScaffold.ConfigureStateDir(configuredStateDir); err != nil {
			return fmt.Errorf("configure chain scaffold state dir: %w", err)
		}
	}

	modules := scaffold.ModuleNames()
	if len(modules) == 0 {
		return errors.New("tdpn-chain scaffold has no modules wired")
	}

	grpcListenAddr := strings.TrimSpace(*grpcListen)
	settlementListenAddr := strings.TrimSpace(*settlementHTTPListen)
	cometCfg, cometEnabled, cometErr := parseCometRuntimeConfig(
		*cometHome,
		*cometMoniker,
		*cometP2PLAddr,
		*cometRPCAddr,
		*cometProxyApp,
	)
	if cometErr != nil {
		return cometErr
	}

	if grpcListenAddr == "" && settlementListenAddr == "" && !cometEnabled {
		fmt.Fprintf(stdout, "tdpn-chain scaffold ready: %s\n", strings.Join(modules, ", "))
		return nil
	}

	grpcAuthTokenValue := strings.TrimSpace(*grpcAuthToken)
	grpcAuthTokenFileValue := strings.TrimSpace(*grpcAuthTokenFile)
	if grpcAuthTokenValue != "" && grpcAuthTokenFileValue != "" {
		return errors.New("only one of --grpc-auth-token and --grpc-auth-token-file may be set")
	}
	if grpcAuthTokenValue == "" && grpcAuthTokenFileValue != "" {
		rawToken, err := fsguard.ReadRegularFileBounded(grpcAuthTokenFileValue, maxRuntimeAuthTokenFileBytes)
		if err != nil {
			return fmt.Errorf("read --grpc-auth-token-file: %w", err)
		}
		grpcAuthTokenValue = strings.TrimSpace(string(rawToken))
		if grpcAuthTokenValue == "" {
			return errors.New("--grpc-auth-token-file is empty")
		}
	}
	if grpcAuthTokenValue == "" {
		grpcAuthTokenValue = strings.TrimSpace(os.Getenv("GRPC_AUTH_TOKEN"))
	}

	grpcCfg := grpcRuntimeConfig{
		listenAddr:  grpcListenAddr,
		tlsCertPath: strings.TrimSpace(*grpcTLSCert),
		tlsKeyPath:  strings.TrimSpace(*grpcTLSKey),
		authToken:   grpcAuthTokenValue,
	}
	settlementAuthToken := strings.TrimSpace(*settlementHTTPAuthToken)
	settlementAuthTokenFile := strings.TrimSpace(*settlementHTTPAuthTokenFile)
	if settlementAuthToken != "" && settlementAuthTokenFile != "" {
		return errors.New("only one of --settlement-http-auth-token and --settlement-http-auth-token-file may be set")
	}
	if settlementAuthToken == "" && settlementAuthTokenFile != "" {
		rawToken, err := fsguard.ReadRegularFileBounded(settlementAuthTokenFile, maxRuntimeAuthTokenFileBytes)
		if err != nil {
			return fmt.Errorf("read --settlement-http-auth-token-file: %w", err)
		}
		settlementAuthToken = strings.TrimSpace(string(rawToken))
		if settlementAuthToken == "" {
			return errors.New("--settlement-http-auth-token-file is empty")
		}
	}
	if settlementAuthToken == "" {
		settlementAuthToken = strings.TrimSpace(os.Getenv("SETTLEMENT_HTTP_AUTH_TOKEN"))
	}
	settlementAuthPrincipal := strings.TrimSpace(*settlementHTTPAuthPrincipal)
	if settlementAuthPrincipal == "" {
		settlementAuthPrincipal = strings.TrimSpace(os.Getenv("SETTLEMENT_HTTP_AUTH_PRINCIPAL"))
	}
	if settlementAuthPrincipal != "" && settlementAuthToken == "" {
		return errors.New("--settlement-http-auth-principal requires --settlement-http-auth-token, --settlement-http-auth-token-file, or SETTLEMENT_HTTP_AUTH_TOKEN")
	}
	settlementCfg := settlementHTTPConfig{
		listenAddr:    settlementListenAddr,
		authToken:     settlementAuthToken,
		authPrincipal: settlementAuthPrincipal,
	}

	var (
		grpcEnabled       = grpcCfg.listenAddr != ""
		settlementEnabled = settlementCfg.listenAddr != ""
		grpcOptions       []grpc.ServerOption
		err               error
	)

	if err := validateAuthBindPolicy(
		grpcCfg,
		settlementCfg,
		cometCfg,
		grpcEnabled,
		settlementEnabled,
		cometEnabled,
		*allowDangerousInsecureAuthBindFlag,
		*allowDangerousPublicListenFlag,
	); err != nil {
		return err
	}

	if grpcEnabled {
		if err = validateGRPCRuntimeConfig(grpcCfg); err != nil {
			return err
		}
		grpcOptions, err = buildGRPCServerOptions(grpcCfg)
		if err != nil {
			return err
		}
	}

	var settlementScaffold settlementBridgeScaffold
	if settlementEnabled {
		var ok bool
		settlementScaffold, ok = scaffold.(settlementBridgeScaffold)
		if !ok {
			return errors.New("chain scaffold does not support settlement HTTP bridge")
		}
	}

	if cometEnabled && grpcListenAddr == "" && settlementListenAddr == "" {
		if deps.NewCometRuntime == nil {
			deps.NewCometRuntime = newDefaultCometRuntime
		}
		return runCometMode(ctx, scaffold, cometCfg, deps.NewCometRuntime)
	}

	if cometEnabled {
		if deps.NewCometRuntime == nil {
			deps.NewCometRuntime = newDefaultCometRuntime
		}
		runners := make([]func(context.Context) error, 0, 3)
		runners = append(runners, func(runCtx context.Context) error {
			return runCometMode(runCtx, scaffold, cometCfg, deps.NewCometRuntime)
		})
		if grpcEnabled {
			runners = append(runners, func(runCtx context.Context) error {
				return runGRPCMode(runCtx, scaffold, grpcCfg, grpcOptions, deps)
			})
		}
		if settlementEnabled {
			runners = append(runners, func(runCtx context.Context) error {
				return runSettlementHTTPMode(runCtx, settlementScaffold, settlementCfg, deps)
			})
		}
		return runRuntimeServers(ctx, runners...)
	}

	if grpcEnabled && !settlementEnabled {
		return runGRPCMode(ctx, scaffold, grpcCfg, grpcOptions, deps)
	}
	if settlementEnabled && !grpcEnabled {
		return runSettlementHTTPMode(ctx, settlementScaffold, settlementCfg, deps)
	}

	return runRuntimeServers(
		ctx,
		func(runCtx context.Context) error {
			return runGRPCMode(runCtx, scaffold, grpcCfg, grpcOptions, deps)
		},
		func(runCtx context.Context) error {
			return runSettlementHTTPMode(runCtx, settlementScaffold, settlementCfg, deps)
		},
	)
}

func validateGRPCRuntimeConfig(cfg grpcRuntimeConfig) error {
	hasCert := cfg.tlsCertPath != ""
	hasKey := cfg.tlsKeyPath != ""
	if hasCert != hasKey {
		return errors.New("both --grpc-tls-cert and --grpc-tls-key must be provided together")
	}
	return nil
}

func dangerousInsecureAuthBindDefault() (bool, error) {
	raw, ok := os.LookupEnv(dangerousInsecureAuthBindEnvVar)
	if !ok {
		return false, nil
	}

	value := strings.TrimSpace(raw)
	if value == "" {
		return false, nil
	}

	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", dangerousInsecureAuthBindEnvVar, err)
	}
	return enabled, nil
}

func dangerousPublicListenDefault() (bool, error) {
	raw, ok := os.LookupEnv(dangerousPublicListenEnvVar)
	if !ok {
		return false, nil
	}

	value := strings.TrimSpace(raw)
	if value == "" {
		return false, nil
	}

	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", dangerousPublicListenEnvVar, err)
	}
	return enabled, nil
}

func validateAuthBindPolicy(
	grpcCfg grpcRuntimeConfig,
	settlementCfg settlementHTTPConfig,
	cometCfg cometRuntimeConfig,
	grpcEnabled bool,
	settlementEnabled bool,
	cometEnabled bool,
	allowDangerousInsecureAuthBind bool,
	allowDangerousPublicListen bool,
) error {
	if !allowDangerousPublicListen {
		if grpcEnabled && grpcCfg.authToken == "" && !isLoopbackListenAddr(grpcCfg.listenAddr) {
			return errors.New("--grpc-listen without --grpc-auth-token must be loopback unless --allow-dangerous-public-listen is set")
		}
		if settlementEnabled && settlementCfg.authToken == "" && !isLoopbackListenAddr(settlementCfg.listenAddr) {
			return errors.New("--settlement-http-listen without --settlement-http-auth-token must be loopback unless --allow-dangerous-public-listen is set")
		}
		if cometEnabled && !isLoopbackListenAddr(cometCfg.rpcListen) {
			return errors.New("--comet-rpc-laddr must be loopback unless --allow-dangerous-public-listen is set")
		}
	}

	if !allowDangerousInsecureAuthBind && grpcEnabled && grpcCfg.authToken != "" && grpcCfg.tlsCertPath == "" && grpcCfg.tlsKeyPath == "" && !isLoopbackListenAddr(grpcCfg.listenAddr) {
		return errors.New("--grpc-auth-token requires TLS or a loopback listener unless --allow-dangerous-insecure-auth-bind is set")
	}
	if !allowDangerousInsecureAuthBind && settlementEnabled && settlementCfg.authToken != "" && !isLoopbackListenAddr(settlementCfg.listenAddr) {
		return errors.New("--settlement-http-auth-token requires a loopback listener unless --allow-dangerous-insecure-auth-bind is set")
	}
	return nil
}

func isLoopbackListenAddr(listenAddr string) bool {
	return isLoopbackListenAddrWithLookup(listenAddr, lookupHostIPAddrs)
}

func isLoopbackListenAddrWithLookup(listenAddr string, lookup hostLookupFunc) bool {
	addr := strings.TrimSpace(listenAddr)
	if addr == "" {
		return false
	}
	if strings.HasPrefix(addr, "unix:") {
		return true
	}
	// Test harnesses and in-memory transports (for example "bufnet") are local.
	// Numeric port-only addresses (for example "8080") bind wildcard interfaces and are not loopback-safe.
	if !strings.Contains(addr, ":") {
		if _, err := strconv.Atoi(addr); err == nil {
			return false
		}
		if ip := net.ParseIP(addr); ip != nil {
			return ip.IsLoopback()
		}
		return true
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	host = strings.TrimSpace(host)
	if host == "" || strings.EqualFold(host, "*") {
		return false
	}
	return isLoopbackHostWithLookup(host, lookup)
}

func buildGRPCServerOptions(cfg grpcRuntimeConfig) ([]grpc.ServerOption, error) {
	options := make([]grpc.ServerOption, 0, 3)

	if cfg.tlsCertPath != "" && cfg.tlsKeyPath != "" {
		tlsCreds, err := credentials.NewServerTLSFromFile(cfg.tlsCertPath, cfg.tlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load grpc TLS credentials: %w", err)
		}
		options = append(options, grpc.Creds(tlsCreds))
	}

	options = append(options,
		grpc.UnaryInterceptor(authUnaryInterceptor(cfg.authToken)),
		grpc.StreamInterceptor(authStreamInterceptor(cfg.authToken)),
	)

	return options, nil
}

func runGRPCMode(
	ctx context.Context,
	scaffold chainScaffold,
	cfg grpcRuntimeConfig,
	serverOptions []grpc.ServerOption,
	deps runtimeDeps,
) error {
	listener, err := deps.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", cfg.listenAddr, err)
	}
	defer listener.Close()

	grpcServer := deps.NewGRPCServer(serverOptions...)

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	if cfg.authToken == "" {
		// Reflection is exposed only when auth is disabled to avoid unauthenticated service introspection.
		if reflectionServer, ok := any(grpcServer).(reflection.GRPCServer); ok {
			reflection.Register(reflectionServer)
		}
	}

	if err := scaffold.RegisterGRPCServices(grpcServer); err != nil {
		return fmt.Errorf("register grpc services: %w", err)
	}

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- grpcServer.Serve(listener)
	}()

	select {
	case err := <-serveErrCh:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve grpc: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownDone := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(shutdownDone)
		}()

		select {
		case <-shutdownDone:
		case <-time.After(gracefulShutdownTimeout):
			grpcServer.Stop()
		}

		err := <-serveErrCh
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve grpc: %w", err)
		}
		return nil
	}
}

func authUnaryInterceptor(expectedToken string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !methodRequiresAuth(info.FullMethod) {
			if expectedToken != "" && isHealthMethod(info.FullMethod) && !isLoopbackPeer(ctx) && !hasValidBearerToken(ctx, expectedToken) {
				return nil, status.Error(codes.Unauthenticated, "missing or invalid bearer token")
			}
			return handler(withRuntimeRequestContext(ctx), req)
		}
		if !hasValidBearerToken(ctx, expectedToken) {
			return nil, status.Error(codes.Unauthenticated, "missing or invalid bearer token")
		}
		return handler(withRuntimeRequestContext(ctx), req)
	}
}

func authStreamInterceptor(expectedToken string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		stream := runtimeContextServerStream{
			ServerStream: ss,
			ctx:          withRuntimeRequestContext(ss.Context()),
		}
		if !methodRequiresAuth(info.FullMethod) {
			if expectedToken != "" && isHealthMethod(info.FullMethod) && !isLoopbackPeer(ss.Context()) && !hasValidBearerToken(ss.Context(), expectedToken) {
				return status.Error(codes.Unauthenticated, "missing or invalid bearer token")
			}
			return handler(srv, stream)
		}
		if !hasValidBearerToken(ss.Context(), expectedToken) {
			return status.Error(codes.Unauthenticated, "missing or invalid bearer token")
		}
		return handler(srv, stream)
	}
}

func methodRequiresAuth(fullMethod string) bool {
	switch strings.TrimSpace(fullMethod) {
	case grpcHealthCheckMethod:
		return false
	default:
		return true
	}
}

func isHealthMethod(fullMethod string) bool {
	switch strings.TrimSpace(fullMethod) {
	case grpcHealthCheckMethod, grpcHealthWatchMethod:
		return true
	default:
		return false
	}
}

func isLoopbackPeer(ctx context.Context) bool {
	return isLoopbackPeerWithLookup(ctx, lookupHostIPAddrs)
}

func isLoopbackPeerWithLookup(ctx context.Context, lookup hostLookupFunc) bool {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo == nil || peerInfo.Addr == nil {
		return false
	}
	host := strings.TrimSpace(peerInfo.Addr.String())
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	return isLoopbackHostWithLookup(host, lookup)
}

func lookupHostIPAddrs(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func isLoopbackHost(host string) bool {
	return isLoopbackHostWithLookup(host, lookupHostIPAddrs)
}

func isLoopbackHostWithLookup(host string, lookup hostLookupFunc) bool {
	normalizedHost := normalizeHostForLookup(host)
	if normalizedHost == "" {
		return false
	}
	if ip := net.ParseIP(normalizedHost); ip != nil {
		return ip.IsLoopback()
	}
	if lookup == nil {
		return false
	}

	lookupCtx, cancel := context.WithTimeout(context.Background(), loopbackHostnameLookupTimeout)
	defer cancel()

	addrs, err := lookup(lookupCtx, normalizedHost)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		if addr.IP == nil || !addr.IP.IsLoopback() {
			return false
		}
	}
	return true
}

func normalizeHostForLookup(host string) string {
	normalizedHost := strings.Trim(strings.TrimSpace(host), "[]")
	if zoneIndex := strings.Index(normalizedHost, "%"); zoneIndex >= 0 {
		normalizedHost = normalizedHost[:zoneIndex]
	}
	return normalizedHost
}

func hasValidBearerToken(ctx context.Context, expectedToken string) bool {
	if expectedToken == "" {
		return true
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	values := md.Get("authorization")
	for _, value := range values {
		parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
		if len(parts) != 2 {
			continue
		}
		if !strings.EqualFold(parts[0], "bearer") {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedToken)) == 1 {
			return true
		}
	}
	return false
}

type runtimeContextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s runtimeContextServerStream) Context() context.Context {
	return s.ctx
}

func withRuntimeRequestContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if sponsormodule.CurrentTimeUnixFromContext(ctx) > 0 {
		return ctx
	}
	return sponsormodule.WithCurrentTimeUnix(ctx, time.Now().Unix())
}

func runRuntimeServers(ctx context.Context, runners ...func(context.Context) error) error {
	if len(runners) == 0 {
		return nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(runners))
	var wg sync.WaitGroup

	for _, runner := range runners {
		runner := runner
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- runner(runCtx)
		}()
	}

	var firstErr error
	for i := 0; i < len(runners); i++ {
		err := <-errCh
		if err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	wg.Wait()
	return firstErr
}
