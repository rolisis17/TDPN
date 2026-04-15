package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const gracefulShutdownTimeout = 5 * time.Second

const tdpnMethodPrefix = "/tdpn."

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
	Listen        func(network, address string) (net.Listener, error)
	ListenHTTP    func(network, address string) (net.Listener, error)
	NewGRPCServer func(opts ...grpc.ServerOption) grpcRuntimeServer
}

type grpcRuntimeConfig struct {
	listenAddr  string
	tlsCertPath string
	tlsKeyPath  string
	authToken   string
}

type settlementHTTPConfig struct {
	listenAddr string
	authToken  string
}

type stateDirConfigurableScaffold interface {
	ConfigureStateDir(string) error
}

func newChainScaffold() chainScaffold {
	return app.NewChainScaffold()
}

func defaultRuntimeDeps() runtimeDeps {
	return runtimeDeps{
		Listen:     net.Listen,
		ListenHTTP: net.Listen,
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

	flags := flag.NewFlagSet("tdpnd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	grpcListen := flags.String("grpc-listen", "", "listen address for gRPC server")
	grpcTLSCert := flags.String("grpc-tls-cert", "", "path to TLS cert PEM for gRPC server")
	grpcTLSKey := flags.String("grpc-tls-key", "", "path to TLS key PEM for gRPC server")
	grpcAuthToken := flags.String("grpc-auth-token", "", "optional bearer token for module gRPC methods")
	settlementHTTPListen := flags.String("settlement-http-listen", "", "listen address for settlement HTTP bridge")
	settlementHTTPAuthToken := flags.String("settlement-http-auth-token", "", "optional bearer token for settlement HTTP POST endpoints")
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
	if grpcListenAddr == "" && settlementListenAddr == "" {
		fmt.Fprintf(stdout, "tdpn-chain scaffold ready: %s\n", strings.Join(modules, ", "))
		return nil
	}

	grpcCfg := grpcRuntimeConfig{
		listenAddr:  grpcListenAddr,
		tlsCertPath: strings.TrimSpace(*grpcTLSCert),
		tlsKeyPath:  strings.TrimSpace(*grpcTLSKey),
		authToken:   strings.TrimSpace(*grpcAuthToken),
	}
	settlementCfg := settlementHTTPConfig{
		listenAddr: settlementListenAddr,
		authToken:  strings.TrimSpace(*settlementHTTPAuthToken),
	}

	var (
		grpcEnabled       = grpcCfg.listenAddr != ""
		settlementEnabled = settlementCfg.listenAddr != ""
		grpcOptions       []grpc.ServerOption
		err               error
	)

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

func buildGRPCServerOptions(cfg grpcRuntimeConfig) ([]grpc.ServerOption, error) {
	options := make([]grpc.ServerOption, 0, 3)

	if cfg.tlsCertPath != "" && cfg.tlsKeyPath != "" {
		tlsCreds, err := credentials.NewServerTLSFromFile(cfg.tlsCertPath, cfg.tlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load grpc TLS credentials: %w", err)
		}
		options = append(options, grpc.Creds(tlsCreds))
	}

	if cfg.authToken != "" {
		options = append(options,
			grpc.UnaryInterceptor(authUnaryInterceptor(cfg.authToken)),
			grpc.StreamInterceptor(authStreamInterceptor(cfg.authToken)),
		)
	}

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
			return handler(ctx, req)
		}
		if !hasValidBearerToken(ctx, expectedToken) {
			return nil, status.Error(codes.Unauthenticated, "missing or invalid bearer token")
		}
		return handler(ctx, req)
	}
}

func authStreamInterceptor(expectedToken string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !methodRequiresAuth(info.FullMethod) {
			return handler(srv, ss)
		}
		if !hasValidBearerToken(ss.Context(), expectedToken) {
			return status.Error(codes.Unauthenticated, "missing or invalid bearer token")
		}
		return handler(srv, ss)
	}
}

func methodRequiresAuth(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, tdpnMethodPrefix)
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
