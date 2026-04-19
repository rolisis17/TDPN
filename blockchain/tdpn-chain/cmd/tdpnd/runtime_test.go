package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	vpnbillingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	vpngovernancepb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpngovernance/v1"
	vpnrewardspb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1"
	vpnslashingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1"
	vpnsponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
	vpnvalidatorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnvalidator/v1"
	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	reflectionv1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type fakeScaffold struct {
	modules       []string
	registerErr   error
	registerCalls int
}

func (f *fakeScaffold) ModuleNames() []string {
	return append([]string(nil), f.modules...)
}

func (f *fakeScaffold) RegisterGRPCServices(registrar grpc.ServiceRegistrar) error {
	f.registerCalls++
	if f.registerErr != nil {
		return f.registerErr
	}
	_ = registrar
	return nil
}

type fakeStateDirScaffold struct {
	fakeScaffold
	configureCalls int
	configureDir   string
	configureErr   error
}

func (f *fakeStateDirScaffold) ConfigureStateDir(stateDir string) error {
	f.configureCalls++
	f.configureDir = stateDir
	return f.configureErr
}

type fakeGRPCServer struct {
	serveStarted   chan struct{}
	stopSignal     chan struct{}
	closeStopOnce  sync.Once
	serveErr       error
	gracefulCalls  int
	stopCalls      int
	registerCalls  int
	registeredName []string
}

func newFakeGRPCServer() *fakeGRPCServer {
	return &fakeGRPCServer{
		serveStarted: make(chan struct{}),
		stopSignal:   make(chan struct{}),
	}
}

func (f *fakeGRPCServer) RegisterService(desc *grpc.ServiceDesc, _ any) {
	f.registerCalls++
	f.registeredName = append(f.registeredName, desc.ServiceName)
}

func (f *fakeGRPCServer) Serve(_ net.Listener) error {
	close(f.serveStarted)
	<-f.stopSignal
	if f.serveErr != nil {
		return f.serveErr
	}
	return grpc.ErrServerStopped
}

func (f *fakeGRPCServer) GracefulStop() {
	f.gracefulCalls++
	f.closeStopOnce.Do(func() { close(f.stopSignal) })
}

func (f *fakeGRPCServer) Stop() {
	f.stopCalls++
	f.closeStopOnce.Do(func() { close(f.stopSignal) })
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "fake:0" }

type namedAddr string

func (a namedAddr) Network() string { return "tcp" }
func (a namedAddr) String() string  { return string(a) }

type fakeListener struct {
	mu         sync.Mutex
	closeCalls int
}

func (l *fakeListener) Accept() (net.Conn, error) {
	return nil, errors.New("accept not implemented")
}

func (l *fakeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeCalls++
	return nil
}

func (l *fakeListener) Addr() net.Addr {
	return fakeAddr{}
}

func (l *fakeListener) Closed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closeCalls > 0
}

func TestRunTDPNDDefaultModePrintsModulesAndExits(t *testing.T) {
	t.Parallel()

	scaffold := &fakeScaffold{
		modules: []string{"vpnbilling", "vpnrewards", "vpnslashing", "vpnsponsor", "vpnvalidator", "vpngovernance"},
	}
	var out bytes.Buffer

	err := runTDPND(
		context.Background(),
		nil,
		&out,
		func() chainScaffold { return scaffold },
		runtimeDeps{},
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := "tdpn-chain scaffold ready: vpnbilling, vpnrewards, vpnslashing, vpnsponsor, vpnvalidator, vpngovernance\n"
	if out.String() != expected {
		t.Fatalf("unexpected output %q", out.String())
	}
	if scaffold.registerCalls != 0 {
		t.Fatalf("expected no grpc registration in default mode, got %d", scaffold.registerCalls)
	}
}

func TestRunTDPNDConfiguresStateDirWhenSupported(t *testing.T) {
	t.Parallel()

	scaffold := &fakeStateDirScaffold{
		fakeScaffold: fakeScaffold{
			modules: []string{"vpnbilling"},
		},
	}
	var out bytes.Buffer

	err := runTDPND(
		context.Background(),
		[]string{"--state-dir", "runtime-state-dir"},
		&out,
		func() chainScaffold { return scaffold },
		runtimeDeps{},
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if scaffold.configureCalls != 1 {
		t.Fatalf("expected ConfigureStateDir to be called once, got %d", scaffold.configureCalls)
	}
	if scaffold.configureDir != "runtime-state-dir" {
		t.Fatalf("expected ConfigureStateDir arg runtime-state-dir, got %q", scaffold.configureDir)
	}
	if !strings.Contains(out.String(), "tdpn-chain scaffold ready:") {
		t.Fatalf("expected scaffold ready output, got %q", out.String())
	}
}

func TestRunTDPNDStateDirRequiresConfigurableScaffold(t *testing.T) {
	t.Parallel()

	scaffold := &fakeScaffold{
		modules: []string{"vpnbilling"},
	}

	err := runTDPND(
		context.Background(),
		[]string{"--state-dir", "runtime-state-dir"},
		nil,
		func() chainScaffold { return scaffold },
		runtimeDeps{},
	)
	if err == nil || !strings.Contains(err.Error(), "does not support --state-dir") {
		t.Fatalf("expected --state-dir unsupported error, got %v", err)
	}
}

func TestRunTDPNDStateDirConfigErrorPropagates(t *testing.T) {
	t.Parallel()

	scaffold := &fakeStateDirScaffold{
		fakeScaffold: fakeScaffold{
			modules: []string{"vpnbilling"},
		},
		configureErr: errors.New("bad state dir"),
	}

	err := runTDPND(
		context.Background(),
		[]string{"--state-dir", "runtime-state-dir"},
		nil,
		func() chainScaffold { return scaffold },
		runtimeDeps{},
	)
	if err == nil || !strings.Contains(err.Error(), "configure chain scaffold state dir") {
		t.Fatalf("expected wrapped configure error, got %v", err)
	}
}

func TestRunTDPNDGRPCModeInvalidTLSFlagCombinations(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		args []string
	}{
		{
			name: "cert-without-key",
			args: []string{"--grpc-listen", "127.0.0.1:7009", "--grpc-tls-cert", "/tmp/server.crt"},
		},
		{
			name: "key-without-cert",
			args: []string{"--grpc-listen", "127.0.0.1:7009", "--grpc-tls-key", "/tmp/server.key"},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scaffold := &fakeScaffold{modules: []string{"vpnbilling"}}
			err := runTDPND(
				context.Background(),
				tc.args,
				nil,
				func() chainScaffold { return scaffold },
				runtimeDeps{},
			)
			if err == nil {
				t.Fatal("expected TLS flag validation error")
			}
			if !strings.Contains(err.Error(), "both --grpc-tls-cert and --grpc-tls-key must be provided together") {
				t.Fatalf("unexpected TLS validation error: %v", err)
			}
			if scaffold.registerCalls != 0 {
				t.Fatalf("expected no grpc registration on TLS validation error, got %d", scaffold.registerCalls)
			}
		})
	}
}

func TestRunTDPNDGRPCModeListenError(t *testing.T) {
	t.Parallel()

	listenErr := errors.New("listen failed")
	scaffold := &fakeScaffold{modules: []string{"vpnbilling"}}

	err := runTDPND(
		context.Background(),
		[]string{"--grpc-listen", "127.0.0.1:7000"},
		nil,
		func() chainScaffold { return scaffold },
		runtimeDeps{
			Listen: func(_, _ string) (net.Listener, error) {
				return nil, listenErr
			},
			NewGRPCServer: func(_ ...grpc.ServerOption) grpcRuntimeServer {
				return newFakeGRPCServer()
			},
		},
	)
	if !errors.Is(err, listenErr) {
		t.Fatalf("expected wrapped listen error, got %v", err)
	}
	if scaffold.registerCalls != 0 {
		t.Fatalf("expected no register calls when listen fails, got %d", scaffold.registerCalls)
	}
}

func TestRunRuntimeServersCancelsPeerRunnerOnFirstError(t *testing.T) {
	t.Parallel()

	peerObservedCancel := make(chan struct{})
	leaderStarted := make(chan struct{})
	wantErr := errors.New("runner failed")

	err := runRuntimeServers(
		context.Background(),
		func(context.Context) error {
			close(leaderStarted)
			return wantErr
		},
		func(ctx context.Context) error {
			<-leaderStarted
			select {
			case <-ctx.Done():
				close(peerObservedCancel)
				return nil
			case <-time.After(2 * time.Second):
				return errors.New("peer runner did not observe cancellation")
			}
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected first error %v, got %v", wantErr, err)
	}

	select {
	case <-peerObservedCancel:
	case <-time.After(2 * time.Second):
		t.Fatal("expected peer runner to observe cancellation after first error")
	}
}

func TestRunTDPNDGRPCModeRegisterErrorClosesListener(t *testing.T) {
	t.Parallel()

	registerErr := errors.New("register failed")
	scaffold := &fakeScaffold{
		modules:     []string{"vpnbilling"},
		registerErr: registerErr,
	}
	listener := &fakeListener{}
	server := newFakeGRPCServer()

	err := runTDPND(
		context.Background(),
		[]string{"--grpc-listen", "127.0.0.1:7001"},
		nil,
		func() chainScaffold { return scaffold },
		runtimeDeps{
			Listen: func(_, _ string) (net.Listener, error) {
				return listener, nil
			},
			NewGRPCServer: func(_ ...grpc.ServerOption) grpcRuntimeServer {
				return server
			},
		},
	)
	if !errors.Is(err, registerErr) {
		t.Fatalf("expected wrapped register error, got %v", err)
	}
	if !listener.Closed() {
		t.Fatal("expected listener to be closed on register error")
	}
	select {
	case <-server.serveStarted:
		t.Fatal("serve should not start when registration fails")
	default:
	}
}

func TestRunTDPNDGRPCModeGracefulShutdownOnContextCancel(t *testing.T) {
	scaffold := &fakeScaffold{modules: []string{"vpnbilling"}}
	listener := &fakeListener{}
	server := newFakeGRPCServer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "127.0.0.1:7002"},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return listener, nil
				},
				NewGRPCServer: func(_ ...grpc.ServerOption) grpcRuntimeServer {
					return server
				},
			},
		)
	}()

	select {
	case <-server.serveStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for grpc serve to start")
	}

	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown")
	}

	if server.gracefulCalls == 0 {
		t.Fatal("expected GracefulStop to be called")
	}
	if !listener.Closed() {
		t.Fatal("expected listener to be closed on shutdown")
	}
	if scaffold.registerCalls != 1 {
		t.Fatalf("expected one registration call, got %d", scaffold.registerCalls)
	}
}

func TestRunTDPNDGRPCModeRegistersHealthAndReflection(t *testing.T) {
	scaffold := &fakeScaffold{modules: []string{"vpnbilling"}}
	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet"},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	healthClient := healthpb.NewHealthClient(conn)
	healthResp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if healthResp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("expected health status SERVING, got %v", healthResp.GetStatus())
	}

	reflectionClient := reflectionv1alpha.NewServerReflectionClient(conn)
	stream, err := reflectionClient.ServerReflectionInfo(context.Background())
	if err != nil {
		t.Fatalf("open reflection stream: %v", err)
	}
	if err := stream.Send(&reflectionv1alpha.ServerReflectionRequest{
		MessageRequest: &reflectionv1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		t.Fatalf("send reflection list request: %v", err)
	}

	reflectionResp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv reflection list response: %v", err)
	}

	serviceNames := make([]string, 0)
	for _, svc := range reflectionResp.GetListServicesResponse().GetService() {
		serviceNames = append(serviceNames, svc.GetName())
	}

	hasHealth := false
	hasReflection := false
	for _, name := range serviceNames {
		if name == "grpc.health.v1.Health" {
			hasHealth = true
		}
		if strings.HasPrefix(name, "grpc.reflection.") {
			hasReflection = true
		}
	}
	if !hasHealth {
		t.Fatalf("expected grpc.health.v1.Health in reflection service list, got %v", serviceNames)
	}
	if !hasReflection {
		t.Fatalf("expected reflection service in reflection list, got %v", serviceNames)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close reflection stream: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for grpc runtime shutdown")
	}
}

func TestRunTDPNDGRPCModeReflectionIncludesCoreModuleQueries(t *testing.T) {
	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	reflectionClient := reflectionv1alpha.NewServerReflectionClient(conn)
	stream, err := reflectionClient.ServerReflectionInfo(context.Background())
	if err != nil {
		t.Fatalf("open reflection stream: %v", err)
	}
	if err := stream.Send(&reflectionv1alpha.ServerReflectionRequest{
		MessageRequest: &reflectionv1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		t.Fatalf("send reflection list request: %v", err)
	}

	reflectionResp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv reflection list response: %v", err)
	}

	serviceNames := make([]string, 0)
	for _, svc := range reflectionResp.GetListServicesResponse().GetService() {
		serviceNames = append(serviceNames, svc.GetName())
	}

	for _, expectedQueryService := range []string{
		"tdpn.vpnbilling.v1.Query",
		"tdpn.vpnrewards.v1.Query",
		"tdpn.vpnslashing.v1.Query",
		"tdpn.vpnsponsor.v1.Query",
		"tdpn.vpnvalidator.v1.Query",
		"tdpn.vpngovernance.v1.Query",
	} {
		if !containsReflectionService(serviceNames, expectedQueryService) {
			t.Fatalf("expected reflected service %q, got %v", expectedQueryService, serviceNames)
		}
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close reflection stream: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for grpc runtime shutdown")
	}
}

func TestRunTDPNDGRPCModeAuthEnforcementAndHealth(t *testing.T) {
	const authToken = "tdpn-test-token"

	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet", "--grpc-auth-token", authToken},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	healthClient := healthpb.NewHealthClient(conn)
	_, err = healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated health check without token in auth mode, got %v", err)
	}

	healthCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+authToken)
	healthResp, err := healthClient.Check(healthCtx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if healthResp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("expected health status SERVING, got %v", healthResp.GetStatus())
	}

	// Reflection is disabled under auth mode by design.
	reflectionClient := reflectionv1alpha.NewServerReflectionClient(conn)
	reflectionStream, err := reflectionClient.ServerReflectionInfo(context.Background())
	if err == nil {
		sendErr := reflectionStream.Send(&reflectionv1alpha.ServerReflectionRequest{
			MessageRequest: &reflectionv1alpha.ServerReflectionRequest_ListServices{
				ListServices: "*",
			},
		})
		if sendErr != nil && !isReflectionDisabledErr(sendErr) {
			t.Fatalf("expected reflection send disabled in auth mode, got %v", sendErr)
		}
		if sendErr == nil {
			_, recvErr := reflectionStream.Recv()
			if !isReflectionDisabledErr(recvErr) {
				t.Fatalf("expected reflection recv disabled in auth mode, got %v", recvErr)
			}
		}
	} else if !isReflectionDisabledErr(err) {
		t.Fatalf("expected reflection disabled in auth mode, got %v", err)
	}

	billingMsg := vpnbillingpb.NewMsgClient(conn)
	billingQuery := vpnbillingpb.NewQueryClient(conn)
	rewardsQuery := vpnrewardspb.NewQueryClient(conn)
	slashingQuery := vpnslashingpb.NewQueryClient(conn)
	sponsorQuery := vpnsponsorpb.NewQueryClient(conn)
	validatorQuery := vpnvalidatorpb.NewQueryClient(conn)
	governanceQuery := vpngovernancepb.NewQueryClient(conn)

	_, err = billingMsg.ReserveCredits(context.Background(), &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: "res-auth-1",
			SessionId:     "sess-auth-1",
			Amount:        10,
		},
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated without token, got %v", err)
	}

	wrongTokenCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer wrong-token")
	_, err = billingMsg.ReserveCredits(wrongTokenCtx, &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: "res-auth-2",
			SessionId:     "sess-auth-2",
			Amount:        10,
		},
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated with wrong token, got %v", err)
	}

	okTokenCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+authToken)
	okResp, err := billingMsg.ReserveCredits(okTokenCtx, &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: "res-auth-3",
			SessionId:     "sess-auth-3",
			Amount:        10,
		},
	})
	if err != nil {
		t.Fatalf("expected authorized reserve success, got %v", err)
	}
	if okResp.GetReservation().GetReservationId() != "res-auth-3" {
		t.Fatalf("unexpected authorized reservation id %q", okResp.GetReservation().GetReservationId())
	}

	assertQueryAuthParity := func(name string, invoke func(context.Context) error) {
		if callErr := invoke(context.Background()); status.Code(callErr) != codes.Unauthenticated {
			t.Fatalf("expected unauthenticated %s without token, got %v", name, callErr)
		}
		if callErr := invoke(wrongTokenCtx); status.Code(callErr) != codes.Unauthenticated {
			t.Fatalf("expected unauthenticated %s with wrong token, got %v", name, callErr)
		}
		if callErr := invoke(okTokenCtx); callErr != nil {
			t.Fatalf("expected authorized %s success, got %v", name, callErr)
		}
	}

	assertQueryAuthParity("vpnbilling/ListCreditReservations", func(callCtx context.Context) error {
		_, callErr := billingQuery.ListCreditReservations(callCtx, &vpnbillingpb.QueryListCreditReservationsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnbilling/ListSettlementRecords", func(callCtx context.Context) error {
		_, callErr := billingQuery.ListSettlementRecords(callCtx, &vpnbillingpb.QueryListSettlementRecordsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnrewards/ListRewardAccruals", func(callCtx context.Context) error {
		_, callErr := rewardsQuery.ListRewardAccruals(callCtx, &vpnrewardspb.QueryListRewardAccrualsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnrewards/ListDistributionRecords", func(callCtx context.Context) error {
		_, callErr := rewardsQuery.ListDistributionRecords(callCtx, &vpnrewardspb.QueryListDistributionRecordsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnslashing/ListSlashEvidence", func(callCtx context.Context) error {
		_, callErr := slashingQuery.ListSlashEvidence(callCtx, &vpnslashingpb.QueryListSlashEvidenceRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnslashing/ListPenalties", func(callCtx context.Context) error {
		_, callErr := slashingQuery.ListPenaltyDecisions(callCtx, &vpnslashingpb.QueryListPenaltyDecisionsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnsponsor/ListSponsorAuthorizations", func(callCtx context.Context) error {
		_, callErr := sponsorQuery.ListSponsorAuthorizations(callCtx, &vpnsponsorpb.QueryListSponsorAuthorizationsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnsponsor/ListDelegatedSessionCredits", func(callCtx context.Context) error {
		_, callErr := sponsorQuery.ListDelegatedSessionCredits(callCtx, &vpnsponsorpb.QueryListDelegatedSessionCreditsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnvalidator/ListValidatorEligibilities", func(callCtx context.Context) error {
		_, callErr := validatorQuery.ListValidatorEligibilities(callCtx, &vpnvalidatorpb.QueryListValidatorEligibilitiesRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnvalidator/ListValidatorStatusRecords", func(callCtx context.Context) error {
		_, callErr := validatorQuery.ListValidatorStatusRecords(callCtx, &vpnvalidatorpb.QueryListValidatorStatusRecordsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpnvalidator/PreviewEpochSelection", func(callCtx context.Context) error {
		_, callErr := validatorQuery.PreviewEpochSelection(callCtx, &vpnvalidatorpb.QueryPreviewEpochSelectionRequest{
			Policy: &vpnvalidatorpb.EpochSelectionPolicy{
				Epoch:               99,
				StableSeatCount:     1,
				RotatingSeatCount:   0,
				MinStake:            1,
				MinStakeAgeEpochs:   1,
				MinHealthScore:      1,
				MinResourceHeadroom: 1,
			},
			Candidates: []*vpnvalidatorpb.EpochValidatorCandidate{
				{
					ValidatorId:         "validator-auth-preview-1",
					OperatorId:          "operator-auth-preview-1",
					Asn:                 "64512",
					Region:              "au-west",
					Stake:               100,
					StakeAgeEpochs:      10,
					HealthScore:         100,
					ResourceHeadroom:    100,
					Score:               100,
					StableSeatPreferred: true,
				},
			},
		})
		return callErr
	})
	assertQueryAuthParity("vpngovernance/ListGovernancePolicies", func(callCtx context.Context) error {
		_, callErr := governanceQuery.ListGovernancePolicies(callCtx, &vpngovernancepb.QueryListGovernancePoliciesRequest{})
		return callErr
	})
	assertQueryAuthParity("vpngovernance/ListGovernanceDecisions", func(callCtx context.Context) error {
		_, callErr := governanceQuery.ListGovernanceDecisions(callCtx, &vpngovernancepb.QueryListGovernanceDecisionsRequest{})
		return callErr
	})
	assertQueryAuthParity("vpngovernance/ListGovernanceAuditActions", func(callCtx context.Context) error {
		_, callErr := governanceQuery.ListGovernanceAuditActions(callCtx, &vpngovernancepb.QueryListGovernanceAuditActionsRequest{})
		return callErr
	})

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for grpc runtime shutdown")
	}
}

func TestRunTDPNDRejectsGRPCAuthTokenAndTokenFileTogether(t *testing.T) {
	dir := t.TempDir()
	tokenFile := dir + "/grpc-token.txt"
	if err := os.WriteFile(tokenFile, []byte("file-token"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	err := runTDPND(
		context.Background(),
		[]string{
			"--grpc-listen", "127.0.0.1:0",
			"--grpc-auth-token", "cli-token",
			"--grpc-auth-token-file", tokenFile,
		},
		nil,
		func() chainScaffold { return app.NewChainScaffold() },
		runtimeDeps{},
	)
	if err == nil || !strings.Contains(err.Error(), "only one of --grpc-auth-token and --grpc-auth-token-file may be set") {
		t.Fatalf("expected grpc auth token/file exclusivity error, got %v", err)
	}
}

func TestRunTDPNDGRPCModeAuthEnforcementWithTokenFile(t *testing.T) {
	const authToken = "tdpn-file-auth-token"

	dir := t.TempDir()
	tokenFile := dir + "/grpc-token.txt"
	if err := os.WriteFile(tokenFile, []byte(authToken+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet", "--grpc-auth-token-file", tokenFile},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	billingMsg := vpnbillingpb.NewMsgClient(conn)

	_, err = billingMsg.ReserveCredits(context.Background(), &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: "res-file-auth-1",
			SessionId:     "sess-file-auth-1",
			Amount:        10,
		},
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated without token, got %v", err)
	}

	okTokenCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+authToken)
	okResp, err := billingMsg.ReserveCredits(okTokenCtx, &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: "res-file-auth-2",
			SessionId:     "sess-file-auth-2",
			Amount:        10,
		},
	})
	if err != nil {
		t.Fatalf("expected authorized reserve success, got %v", err)
	}
	if okResp.GetReservation().GetReservationId() != "res-file-auth-2" {
		t.Fatalf("unexpected authorized reservation id %q", okResp.GetReservation().GetReservationId())
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for grpc runtime shutdown")
	}
}

func TestRunTDPNDGRPCModeAuthValidatorAndGovernanceCanonicalizationRoundTrip(t *testing.T) {
	const authToken = "tdpn-canonical-auth-token"

	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet", "--grpc-auth-token", authToken},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	authCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+authToken)

	validatorMsg := vpnvalidatorpb.NewMsgClient(conn)
	validatorQuery := vpnvalidatorpb.NewQueryClient(conn)
	governanceMsg := vpngovernancepb.NewMsgClient(conn)
	governanceQuery := vpngovernancepb.NewQueryClient(conn)

	eligibilityResp, err := validatorMsg.SetValidatorEligibility(authCtx, &vpnvalidatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &vpnvalidatorpb.ValidatorEligibility{
			ValidatorId:     "  VAL-AUTH-CANON-1  ",
			OperatorAddress: "  TDPNVALOPER1AUTHCANON  ",
			Eligible:        true,
			PolicyReason:    " auth canonicalization ",
			UpdatedAtUnix:   1713003001,
		},
	})
	if err != nil {
		t.Fatalf("set validator eligibility failed: %v", err)
	}
	if eligibilityResp.GetEligibility().GetValidatorId() != "val-auth-canon-1" {
		t.Fatalf("expected canonical validator id val-auth-canon-1, got %q", eligibilityResp.GetEligibility().GetValidatorId())
	}
	if eligibilityResp.GetEligibility().GetOperatorAddress() != "tdpnvaloper1authcanon" {
		t.Fatalf("expected canonical operator address tdpnvaloper1authcanon, got %q", eligibilityResp.GetEligibility().GetOperatorAddress())
	}

	eligibilityByID, err := validatorQuery.ValidatorEligibility(authCtx, &vpnvalidatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: "  VAL-AUTH-CANON-1  ",
	})
	if err != nil {
		t.Fatalf("query validator eligibility failed: %v", err)
	}
	if !eligibilityByID.GetFound() {
		t.Fatal("expected validator eligibility found=true")
	}
	if eligibilityByID.GetEligibility().GetValidatorId() != "val-auth-canon-1" {
		t.Fatalf("expected canonical queried validator id val-auth-canon-1, got %q", eligibilityByID.GetEligibility().GetValidatorId())
	}

	statusResp, err := validatorMsg.RecordValidatorStatus(authCtx, &vpnvalidatorpb.MsgRecordValidatorStatusRequest{
		Record: &vpnvalidatorpb.ValidatorStatusRecord{
			StatusId:         "  STATUS-AUTH-CANON-1  ",
			ValidatorId:      "  VAL-AUTH-CANON-1  ",
			ConsensusAddress: "  TDPNVALCONS1AUTHCANON  ",
			LifecycleStatus:  "  ACTIVE  ",
			EvidenceHeight:   88,
			EvidenceRef:      "  SHA256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789  ",
			RecordedAtUnix:   1713003002,
		},
	})
	if err != nil {
		t.Fatalf("record validator status failed: %v", err)
	}
	if statusResp.GetRecord().GetStatusId() != "status-auth-canon-1" {
		t.Fatalf("expected canonical status id status-auth-canon-1, got %q", statusResp.GetRecord().GetStatusId())
	}
	if statusResp.GetRecord().GetValidatorId() != "val-auth-canon-1" {
		t.Fatalf("expected canonical validator id val-auth-canon-1, got %q", statusResp.GetRecord().GetValidatorId())
	}

	statusByID, err := validatorQuery.ValidatorStatusRecord(authCtx, &vpnvalidatorpb.QueryValidatorStatusRecordRequest{
		StatusId: "  STATUS-AUTH-CANON-1  ",
	})
	if err != nil {
		t.Fatalf("query validator status failed: %v", err)
	}
	if !statusByID.GetFound() {
		t.Fatal("expected validator status found=true")
	}
	if statusByID.GetRecord().GetStatusId() != "status-auth-canon-1" {
		t.Fatalf("expected canonical queried status id status-auth-canon-1, got %q", statusByID.GetRecord().GetStatusId())
	}

	policyResp, err := governanceMsg.CreatePolicy(authCtx, &vpngovernancepb.MsgCreatePolicyRequest{
		Policy: &vpngovernancepb.GovernancePolicy{
			PolicyId:        "  GOV-AUTH-POLICY-CANON-1  ",
			Title:           "Auth canonical policy",
			Description:     "auth mode canonicalization roundtrip",
			Version:         1,
			ActivatedAtUnix: 1713003003,
		},
	})
	if err != nil {
		t.Fatalf("create governance policy failed: %v", err)
	}
	if policyResp.GetPolicy().GetPolicyId() != "gov-auth-policy-canon-1" {
		t.Fatalf("expected canonical policy id gov-auth-policy-canon-1, got %q", policyResp.GetPolicy().GetPolicyId())
	}

	policyByID, err := governanceQuery.GovernancePolicy(authCtx, &vpngovernancepb.QueryGovernancePolicyRequest{
		PolicyId: "  GOV-AUTH-POLICY-CANON-1  ",
	})
	if err != nil {
		t.Fatalf("query governance policy failed: %v", err)
	}
	if !policyByID.GetFound() {
		t.Fatal("expected governance policy found=true")
	}
	if policyByID.GetPolicy().GetPolicyId() != "gov-auth-policy-canon-1" {
		t.Fatalf("expected canonical queried policy id gov-auth-policy-canon-1, got %q", policyByID.GetPolicy().GetPolicyId())
	}

	decisionResp, err := governanceMsg.RecordDecision(authCtx, &vpngovernancepb.MsgRecordDecisionRequest{
		Decision: &vpngovernancepb.GovernanceDecision{
			DecisionId:    "  GOV-AUTH-DECISION-CANON-1  ",
			PolicyId:      "  GOV-AUTH-POLICY-CANON-1  ",
			ProposalId:    "  GOV-AUTH-PROPOSAL-CANON-1  ",
			Outcome:       "  APPROVE  ",
			Decider:       "  GOV-DECIDER-AUTH-1  ",
			Reason:        " auth mode decision canonicalization ",
			DecidedAtUnix: 1713003004,
		},
	})
	if err != nil {
		t.Fatalf("record governance decision failed: %v", err)
	}
	if decisionResp.GetDecision().GetDecisionId() != "gov-auth-decision-canon-1" {
		t.Fatalf("expected canonical decision id gov-auth-decision-canon-1, got %q", decisionResp.GetDecision().GetDecisionId())
	}
	if decisionResp.GetDecision().GetPolicyId() != "gov-auth-policy-canon-1" {
		t.Fatalf("expected canonical decision policy id gov-auth-policy-canon-1, got %q", decisionResp.GetDecision().GetPolicyId())
	}

	decisionByID, err := governanceQuery.GovernanceDecision(authCtx, &vpngovernancepb.QueryGovernanceDecisionRequest{
		DecisionId: "  GOV-AUTH-DECISION-CANON-1  ",
	})
	if err != nil {
		t.Fatalf("query governance decision failed: %v", err)
	}
	if !decisionByID.GetFound() {
		t.Fatal("expected governance decision found=true")
	}
	if decisionByID.GetDecision().GetDecisionId() != "gov-auth-decision-canon-1" {
		t.Fatalf("expected canonical queried decision id gov-auth-decision-canon-1, got %q", decisionByID.GetDecision().GetDecisionId())
	}

	actionResp, err := governanceMsg.RecordAuditAction(authCtx, &vpngovernancepb.MsgRecordAuditActionRequest{
		Action: &vpngovernancepb.GovernanceAuditAction{
			ActionId:        "  GOV-AUTH-ACTION-CANON-1  ",
			Action:          "  MANUAL_OVERRIDE  ",
			Actor:           "  GOV-ACTOR-AUTH-1  ",
			Reason:          " auth mode audit canonicalization ",
			EvidencePointer: "  obj://Governance/Auth/Canonical-1  ",
			TimestampUnix:   1713003005,
		},
	})
	if err != nil {
		t.Fatalf("record governance audit action failed: %v", err)
	}
	if actionResp.GetAction().GetActionId() != "gov-auth-action-canon-1" {
		t.Fatalf("expected canonical action id gov-auth-action-canon-1, got %q", actionResp.GetAction().GetActionId())
	}
	if actionResp.GetAction().GetActor() != "gov-actor-auth-1" {
		t.Fatalf("expected canonical actor gov-actor-auth-1, got %q", actionResp.GetAction().GetActor())
	}

	actionByID, err := governanceQuery.GovernanceAuditAction(authCtx, &vpngovernancepb.QueryGovernanceAuditActionRequest{
		ActionId: "  GOV-AUTH-ACTION-CANON-1  ",
	})
	if err != nil {
		t.Fatalf("query governance audit action failed: %v", err)
	}
	if !actionByID.GetFound() {
		t.Fatal("expected governance audit action found=true")
	}
	if actionByID.GetAction().GetActionId() != "gov-auth-action-canon-1" {
		t.Fatalf("expected canonical queried action id gov-auth-action-canon-1, got %q", actionByID.GetAction().GetActionId())
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for grpc runtime shutdown")
	}
}

func isReflectionDisabledErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	switch status.Code(err) {
	case codes.Unimplemented, codes.Unavailable, codes.Unknown:
		return true
	default:
		return false
	}
}

func TestRunTDPNDGRPCModeTLSServeHealthCheck(t *testing.T) {
	certPath, keyPath := writeSelfSignedTLSCertAndKey(t)

	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scaffold := &fakeScaffold{modules: []string{"vpnbilling"}}
	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--grpc-listen", "bufnet",
				"--grpc-tls-cert", certPath,
				"--grpc-tls-key", keyPath,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	tlsCreds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true, // test-only self-signed certificate
	})
	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc TLS bufconn: %v", err)
	}
	defer conn.Close()

	healthClient := healthpb.NewHealthClient(conn)
	healthResp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("tls health check failed: %v", err)
	}
	if healthResp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("expected health status SERVING over TLS, got %v", healthResp.GetStatus())
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TLS runtime shutdown")
	}
}

func TestRunTDPNDGRPCModeRealScaffoldBillingAndSponsorRoundTrip(t *testing.T) {
	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	billingMsg := vpnbillingpb.NewMsgClient(conn)
	billingQuery := vpnbillingpb.NewQueryClient(conn)
	rewardsMsg := vpnrewardspb.NewMsgClient(conn)
	rewardsQuery := vpnrewardspb.NewQueryClient(conn)
	sponsorMsg := vpnsponsorpb.NewMsgClient(conn)
	sponsorQuery := vpnsponsorpb.NewQueryClient(conn)

	delegateCtx := sponsormodule.WithCurrentTimeUnix(context.Background(), 4102444700)
	assertBillingRewardsSponsorCanonicalizationRoundTrip(
		t,
		"runtime",
		context.Background(),
		delegateCtx,
		billingMsg,
		billingQuery,
		rewardsMsg,
		rewardsQuery,
		sponsorMsg,
		sponsorQuery,
	)

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for runtime shutdown")
	}
}

func TestRunTDPNDGRPCModeAuthBillingRewardsSponsorCanonicalizationRoundTrip(t *testing.T) {
	const authToken = "tdpn-auth-billing-sponsor-canon-token"

	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet", "--grpc-auth-token", authToken},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	authCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+authToken)
	delegateCtx := sponsormodule.WithCurrentTimeUnix(authCtx, 4102444700)

	billingMsg := vpnbillingpb.NewMsgClient(conn)
	billingQuery := vpnbillingpb.NewQueryClient(conn)
	rewardsMsg := vpnrewardspb.NewMsgClient(conn)
	rewardsQuery := vpnrewardspb.NewQueryClient(conn)
	sponsorMsg := vpnsponsorpb.NewMsgClient(conn)
	sponsorQuery := vpnsponsorpb.NewQueryClient(conn)

	assertBillingRewardsSponsorCanonicalizationRoundTrip(
		t,
		"auth",
		authCtx,
		delegateCtx,
		billingMsg,
		billingQuery,
		rewardsMsg,
		rewardsQuery,
		sponsorMsg,
		sponsorQuery,
	)

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for grpc runtime shutdown")
	}
}

func TestRunTDPNDGRPCModeRealScaffoldValidatorAndGovernanceRoundTrip(t *testing.T) {
	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return bufListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	validatorMsg := vpnvalidatorpb.NewMsgClient(conn)
	validatorQuery := vpnvalidatorpb.NewQueryClient(conn)
	governanceMsg := vpngovernancepb.NewMsgClient(conn)
	governanceQuery := vpngovernancepb.NewQueryClient(conn)

	rawEligibilityID := "  VALIDATOR-RUNTIME-RT-1  "
	canonicalEligibilityID := "validator-runtime-rt-1"
	eligibilityResp, err := validatorMsg.SetValidatorEligibility(context.Background(), &vpnvalidatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &vpnvalidatorpb.ValidatorEligibility{
			ValidatorId:     rawEligibilityID,
			OperatorAddress: "tdpnvaloper1runtime1",
			Eligible:        true,
			PolicyReason:    "bootstrap allowlist",
			UpdatedAtUnix:   1713002001,
			Status:          vpnvalidatorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("set validator eligibility failed: %v", err)
	}
	if eligibilityResp.GetEligibility().GetValidatorId() != canonicalEligibilityID {
		t.Fatalf("unexpected validator eligibility id %q", eligibilityResp.GetEligibility().GetValidatorId())
	}

	eligibilityByID, err := validatorQuery.ValidatorEligibility(context.Background(), &vpnvalidatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: "VaLiDaToR-RuNtImE-Rt-1",
	})
	if err != nil {
		t.Fatalf("query validator eligibility failed: %v", err)
	}
	if !eligibilityByID.GetFound() {
		t.Fatal("expected validator eligibility found=true")
	}
	if eligibilityByID.GetEligibility().GetValidatorId() != canonicalEligibilityID {
		t.Fatalf("expected canonical queried validator id %q, got %q", canonicalEligibilityID, eligibilityByID.GetEligibility().GetValidatorId())
	}
	if eligibilityByID.GetEligibility().GetOperatorAddress() != "tdpnvaloper1runtime1" {
		t.Fatalf("unexpected validator operator address %q", eligibilityByID.GetEligibility().GetOperatorAddress())
	}

	eligibilityList, err := validatorQuery.ListValidatorEligibilities(context.Background(), &vpnvalidatorpb.QueryListValidatorEligibilitiesRequest{})
	if err != nil {
		t.Fatalf("list validator eligibilities failed: %v", err)
	}
	if !containsValidatorEligibilityID(eligibilityList.GetEligibilities(), canonicalEligibilityID) {
		t.Fatalf("expected validator eligibility %q in list, got %v", canonicalEligibilityID, eligibilityList.GetEligibilities())
	}

	previewResp, err := validatorQuery.PreviewEpochSelection(context.Background(), &vpnvalidatorpb.QueryPreviewEpochSelectionRequest{
		Policy: &vpnvalidatorpb.EpochSelectionPolicy{
			Epoch:               99,
			StableSeatCount:     1,
			RotatingSeatCount:   0,
			MinStake:            1,
			MinStakeAgeEpochs:   1,
			MinHealthScore:      1,
			MinResourceHeadroom: 1,
		},
		Candidates: []*vpnvalidatorpb.EpochValidatorCandidate{
			{
				ValidatorId:         canonicalEligibilityID,
				OperatorId:          "operator-runtime-1",
				Asn:                 "64512",
				Region:              "au-west",
				Stake:               100,
				StakeAgeEpochs:      10,
				HealthScore:         100,
				ResourceHeadroom:    100,
				Score:               100,
				StableSeatPreferred: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("preview epoch selection failed: %v", err)
	}
	if previewResp.GetResult() == nil {
		t.Fatal("expected non-nil preview epoch result")
	}
	if len(previewResp.GetResult().GetStableSeats())+len(previewResp.GetResult().GetRotatingSeats()) == 0 {
		t.Fatalf("expected preview epoch selection to choose candidate, got %+v", previewResp.GetResult())
	}

	rawStatusID := "  VALIDATOR-STATUS-RUNTIME-RT-1  "
	canonicalStatusID := "validator-status-runtime-rt-1"
	statusResp, err := validatorMsg.RecordValidatorStatus(context.Background(), &vpnvalidatorpb.MsgRecordValidatorStatusRequest{
		Record: &vpnvalidatorpb.ValidatorStatusRecord{
			StatusId:         rawStatusID,
			ValidatorId:      "  VALIDATOR-RUNTIME-RT-1  ",
			ConsensusAddress: "tdpnvalcons1runtime1",
			LifecycleStatus:  "active",
			EvidenceHeight:   77,
			EvidenceRef:      "obj://validator/runtime/77",
			RecordedAtUnix:   1713002002,
			Status:           vpnvalidatorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
		},
	})
	if err != nil {
		t.Fatalf("record validator status failed: %v", err)
	}
	if statusResp.GetRecord().GetStatusId() != canonicalStatusID {
		t.Fatalf("unexpected validator status id %q", statusResp.GetRecord().GetStatusId())
	}
	if statusResp.GetRecord().GetValidatorId() != canonicalEligibilityID {
		t.Fatalf("expected canonical status validator id %q, got %q", canonicalEligibilityID, statusResp.GetRecord().GetValidatorId())
	}

	statusByID, err := validatorQuery.ValidatorStatusRecord(context.Background(), &vpnvalidatorpb.QueryValidatorStatusRecordRequest{
		StatusId: "VaLiDaToR-StAtUs-RuNtImE-Rt-1",
	})
	if err != nil {
		t.Fatalf("query validator status failed: %v", err)
	}
	if !statusByID.GetFound() {
		t.Fatal("expected validator status found=true")
	}
	if statusByID.GetRecord().GetStatusId() != canonicalStatusID {
		t.Fatalf("expected canonical queried status id %q, got %q", canonicalStatusID, statusByID.GetRecord().GetStatusId())
	}
	if statusByID.GetRecord().GetLifecycleStatus() != "active" {
		t.Fatalf("unexpected validator lifecycle status %q", statusByID.GetRecord().GetLifecycleStatus())
	}

	statusList, err := validatorQuery.ListValidatorStatusRecords(context.Background(), &vpnvalidatorpb.QueryListValidatorStatusRecordsRequest{})
	if err != nil {
		t.Fatalf("list validator statuses failed: %v", err)
	}
	if !containsValidatorStatusID(statusList.GetRecords(), canonicalStatusID) {
		t.Fatalf("expected validator status %q in list, got %v", canonicalStatusID, statusList.GetRecords())
	}

	rawPolicyID := "  GOVERNANCE-POLICY-RUNTIME-RT-1  "
	canonicalPolicyID := "governance-policy-runtime-rt-1"
	policyResp, err := governanceMsg.CreatePolicy(context.Background(), &vpngovernancepb.MsgCreatePolicyRequest{
		Policy: &vpngovernancepb.GovernancePolicy{
			PolicyId:        rawPolicyID,
			Title:           "Runtime validator policy",
			Description:     "runtime roundtrip governance policy",
			Version:         1,
			ActivatedAtUnix: 1713002003,
			Status:          vpngovernancepb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
		},
	})
	if err != nil {
		t.Fatalf("create governance policy failed: %v", err)
	}
	if policyResp.GetPolicy().GetPolicyId() != canonicalPolicyID {
		t.Fatalf("unexpected governance policy id %q", policyResp.GetPolicy().GetPolicyId())
	}
	if policyResp.GetIdempotentReplay() || policyResp.GetConflict() {
		t.Fatalf("unexpected governance policy replay/conflict flags: replay=%v conflict=%v", policyResp.GetIdempotentReplay(), policyResp.GetConflict())
	}

	policyByID, err := governanceQuery.GovernancePolicy(context.Background(), &vpngovernancepb.QueryGovernancePolicyRequest{
		PolicyId: "GoVeRnAnCe-PoLiCy-RuNtImE-Rt-1",
	})
	if err != nil {
		t.Fatalf("query governance policy failed: %v", err)
	}
	if !policyByID.GetFound() {
		t.Fatal("expected governance policy found=true")
	}
	if policyByID.GetPolicy().GetPolicyId() != canonicalPolicyID {
		t.Fatalf("expected canonical queried policy id %q, got %q", canonicalPolicyID, policyByID.GetPolicy().GetPolicyId())
	}
	if policyByID.GetPolicy().GetTitle() != "Runtime validator policy" {
		t.Fatalf("unexpected governance policy title %q", policyByID.GetPolicy().GetTitle())
	}

	policyList, err := governanceQuery.ListGovernancePolicies(context.Background(), &vpngovernancepb.QueryListGovernancePoliciesRequest{})
	if err != nil {
		t.Fatalf("list governance policies failed: %v", err)
	}
	if !containsGovernancePolicyID(policyList.GetPolicies(), canonicalPolicyID) {
		t.Fatalf("expected governance policy %q in list, got %v", canonicalPolicyID, policyList.GetPolicies())
	}

	rawDecisionID := "  GOVERNANCE-DECISION-RUNTIME-RT-1  "
	canonicalDecisionID := "governance-decision-runtime-rt-1"
	decisionResp, err := governanceMsg.RecordDecision(context.Background(), &vpngovernancepb.MsgRecordDecisionRequest{
		Decision: &vpngovernancepb.GovernanceDecision{
			DecisionId:    rawDecisionID,
			PolicyId:      "  GOVERNANCE-POLICY-RUNTIME-RT-1  ",
			ProposalId:    "proposal-runtime-rt-1",
			Outcome:       "approve",
			Decider:       "bootstrap-multisig",
			Reason:        "objective eligibility criteria met",
			DecidedAtUnix: 1713002004,
			Status:        vpngovernancepb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("record governance decision failed: %v", err)
	}
	if decisionResp.GetDecision().GetDecisionId() != canonicalDecisionID {
		t.Fatalf("unexpected governance decision id %q", decisionResp.GetDecision().GetDecisionId())
	}
	if decisionResp.GetDecision().GetPolicyId() != canonicalPolicyID {
		t.Fatalf("expected canonical decision policy id %q, got %q", canonicalPolicyID, decisionResp.GetDecision().GetPolicyId())
	}
	if decisionResp.GetIdempotentReplay() || decisionResp.GetConflict() {
		t.Fatalf("unexpected governance decision replay/conflict flags: replay=%v conflict=%v", decisionResp.GetIdempotentReplay(), decisionResp.GetConflict())
	}

	decisionByID, err := governanceQuery.GovernanceDecision(context.Background(), &vpngovernancepb.QueryGovernanceDecisionRequest{
		DecisionId: "GoVeRnAnCe-DeCiSiOn-RuNtImE-Rt-1",
	})
	if err != nil {
		t.Fatalf("query governance decision failed: %v", err)
	}
	if !decisionByID.GetFound() {
		t.Fatal("expected governance decision found=true")
	}
	if decisionByID.GetDecision().GetDecisionId() != canonicalDecisionID {
		t.Fatalf("expected canonical queried decision id %q, got %q", canonicalDecisionID, decisionByID.GetDecision().GetDecisionId())
	}
	if decisionByID.GetDecision().GetPolicyId() != canonicalPolicyID {
		t.Fatalf("unexpected governance decision policy id %q", decisionByID.GetDecision().GetPolicyId())
	}

	decisionList, err := governanceQuery.ListGovernanceDecisions(context.Background(), &vpngovernancepb.QueryListGovernanceDecisionsRequest{})
	if err != nil {
		t.Fatalf("list governance decisions failed: %v", err)
	}
	if !containsGovernanceDecisionID(decisionList.GetDecisions(), canonicalDecisionID) {
		t.Fatalf("expected governance decision %q in list, got %v", canonicalDecisionID, decisionList.GetDecisions())
	}

	rawActionID := "  GOVERNANCE-AUDIT-RUNTIME-RT-1  "
	canonicalActionID := "governance-audit-runtime-rt-1"
	actionResp, err := governanceMsg.RecordAuditAction(context.Background(), &vpngovernancepb.MsgRecordAuditActionRequest{
		Action: &vpngovernancepb.GovernanceAuditAction{
			ActionId:        rawActionID,
			Action:          "manual_override",
			Actor:           "bootstrap-admin",
			Reason:          "runtime roundtrip audit trace",
			EvidencePointer: "ipfs://governance/runtime/audit-rt-1",
			TimestampUnix:   1713002005,
		},
	})
	if err != nil {
		t.Fatalf("record governance audit action failed: %v", err)
	}
	if actionResp.GetAction().GetActionId() != canonicalActionID {
		t.Fatalf("unexpected governance audit action id %q", actionResp.GetAction().GetActionId())
	}
	if actionResp.GetIdempotentReplay() || actionResp.GetConflict() {
		t.Fatalf("unexpected governance audit replay/conflict flags: replay=%v conflict=%v", actionResp.GetIdempotentReplay(), actionResp.GetConflict())
	}

	actionByID, err := governanceQuery.GovernanceAuditAction(context.Background(), &vpngovernancepb.QueryGovernanceAuditActionRequest{
		ActionId: "GoVeRnAnCe-AuDiT-RuNtImE-Rt-1",
	})
	if err != nil {
		t.Fatalf("query governance audit action failed: %v", err)
	}
	if !actionByID.GetFound() {
		t.Fatal("expected governance audit action found=true")
	}
	if actionByID.GetAction().GetActionId() != canonicalActionID {
		t.Fatalf("expected canonical queried action id %q, got %q", canonicalActionID, actionByID.GetAction().GetActionId())
	}
	if actionByID.GetAction().GetActor() != "bootstrap-admin" {
		t.Fatalf("unexpected governance audit actor %q", actionByID.GetAction().GetActor())
	}

	actionList, err := governanceQuery.ListGovernanceAuditActions(context.Background(), &vpngovernancepb.QueryListGovernanceAuditActionsRequest{})
	if err != nil {
		t.Fatalf("list governance audit actions failed: %v", err)
	}
	if !containsGovernanceActionID(actionList.GetActions(), canonicalActionID) {
		t.Fatalf("expected governance audit action %q in list, got %v", canonicalActionID, actionList.GetActions())
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected graceful shutdown success, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for runtime shutdown")
	}
}

func TestRunTDPNDSettlementHTTPEpochSelectionPreviewAuthAndMethodBehavior(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const authToken = "preview-bridge-secret"

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-preview-test",
				"--settlement-http-auth-token", authToken,
			},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-preview-test" {
						return nil, errors.New("unexpected settlement listen address")
					}
					return httpListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
			},
		)
	}()

	baseURL := "http://" + httpListener.Addr().String()
	waitForHTTPReady(t, baseURL+"/health")

	previewPath := baseURL + "/x/vpnvalidator/epoch-selection-preview"
	requestBody := `{"Policy":{"Epoch":99,"StableSeatCount":1,"RotatingSeatCount":0,"MinStake":1,"MinStakeAgeEpochs":1,"MinHealthScore":1,"MinResourceHeadroom":1,"WarmupEpochs":0,"CooldownEpochs":0,"MaxSeatsPerOperator":0,"MaxSeatsPerASN":0,"MaxSeatsPerRegion":0},"Candidates":[{"ValidatorID":"validator-preview-1","OperatorID":"operator-preview-1","ASN":"64512","Region":"au-west","Stake":100,"StakeAgeEpochs":10,"HealthScore":100,"ResourceHeadroom":100,"HasActiveSanction":false,"HasUnresolvedCriticalIssues":false,"ConsecutiveEligibleEpochs":10,"LastRemovedEpoch":-1,"Score":100,"StableSeatPreferred":true}]}`

	getStatus, getPayload := doJSONRequest(t, http.MethodGet, previewPath, "", nil)
	if getStatus != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated GET preview endpoint to return 401, got %d payload=%v", getStatus, getPayload)
	}

	postStatus, postPayload := doJSONRequest(t, http.MethodPost, previewPath, requestBody, nil)
	if postStatus != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated preview POST to return 401, got %d payload=%v", postStatus, postPayload)
	}

	validHeaders := map[string]string{"Authorization": "Bearer " + authToken}
	postStatus, postPayload = doJSONRequest(t, http.MethodPost, previewPath, requestBody, validHeaders)
	if postStatus != http.StatusOK {
		t.Fatalf("expected authenticated preview POST to return 200, got %d payload=%v", postStatus, postPayload)
	}

	if ok, _ := postPayload["ok"].(bool); !ok {
		t.Fatalf("expected ok=true preview payload, got %v", postPayload)
	}
	preview, ok := postPayload["preview"].(map[string]any)
	if !ok {
		t.Fatalf("expected preview object, got %#v", postPayload["preview"])
	}
	stableSeats, ok := preview["StableSeats"].([]any)
	if !ok {
		t.Fatalf("expected preview.StableSeats array, got %#v", preview["StableSeats"])
	}
	if len(stableSeats) != 1 {
		t.Fatalf("expected one stable seat in preview, got %d payload=%v", len(stableSeats), postPayload)
	}
	rotatingSeats, ok := preview["RotatingSeats"].([]any)
	if !ok {
		t.Fatalf("expected preview.RotatingSeats array, got %#v", preview["RotatingSeats"])
	}
	if len(rotatingSeats) != 0 {
		t.Fatalf("expected zero rotating seats in preview, got %d payload=%v", len(rotatingSeats), postPayload)
	}
	firstSeat, ok := stableSeats[0].(map[string]any)
	if !ok {
		t.Fatalf("expected preview stable seat object, got %#v", stableSeats[0])
	}
	if got := firstSeat["ValidatorID"]; got != "validator-preview-1" {
		t.Fatalf("expected stable preview validator validator-preview-1, got %v", got)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected clean shutdown, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for runtime shutdown")
	}
}

func writeSelfSignedTLSCertAndKey(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create self-signed certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	tempDir := t.TempDir()
	certPath := tempDir + "/server.crt"
	keyPath := tempDir + "/server.key"

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	return certPath, keyPath
}

func assertBillingRewardsSponsorCanonicalizationRoundTrip(
	t *testing.T,
	idPrefix string,
	rpcCtx context.Context,
	delegateCtx context.Context,
	billingMsg vpnbillingpb.MsgClient,
	billingQuery vpnbillingpb.QueryClient,
	rewardsMsg vpnrewardspb.MsgClient,
	rewardsQuery vpnrewardspb.QueryClient,
	sponsorMsg vpnsponsorpb.MsgClient,
	sponsorQuery vpnsponsorpb.QueryClient,
) {
	t.Helper()

	upperPrefix := strings.ToUpper(idPrefix)

	reservationInputID := "  RES-" + upperPrefix + "-CANON-1  "
	reservationCanonicalID := "res-" + idPrefix + "-canon-1"
	reservationMixedQueryID := "  ReS-" + upperPrefix + "-CaNoN-1  "
	reservationSponsorInputID := "  SPONSOR-" + upperPrefix + "-CANON-1  "
	reservationSponsorCanonicalID := "sponsor-" + idPrefix + "-canon-1"
	reservationSessionInputID := "  SESS-" + upperPrefix + "-CANON-1  "
	reservationSessionCanonicalID := "sess-" + idPrefix + "-canon-1"

	billingReserveResp, err := billingMsg.ReserveCredits(rpcCtx, &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: reservationInputID,
			SponsorId:     reservationSponsorInputID,
			SessionId:     reservationSessionInputID,
			AssetDenom:    "  UUSDC  ",
			Amount:        125,
		},
	})
	if err != nil {
		t.Fatalf("billing reserve credits failed: %v", err)
	}
	if billingReserveResp.GetReservation().GetReservationId() != reservationCanonicalID {
		t.Fatalf("expected canonical billing reservation id %q, got %q", reservationCanonicalID, billingReserveResp.GetReservation().GetReservationId())
	}
	if billingReserveResp.GetReservation().GetSponsorId() != reservationSponsorCanonicalID {
		t.Fatalf("expected canonical billing sponsor id %q, got %q", reservationSponsorCanonicalID, billingReserveResp.GetReservation().GetSponsorId())
	}
	if billingReserveResp.GetReservation().GetSessionId() != reservationSessionCanonicalID {
		t.Fatalf("expected canonical billing session id %q, got %q", reservationSessionCanonicalID, billingReserveResp.GetReservation().GetSessionId())
	}
	if billingReserveResp.GetReservation().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical billing denom uusdc, got %q", billingReserveResp.GetReservation().GetAssetDenom())
	}

	billingGetByCanonicalResp, err := billingQuery.CreditReservation(rpcCtx, &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: reservationCanonicalID,
	})
	if err != nil {
		t.Fatalf("billing get reservation by canonical id failed: %v", err)
	}
	if !billingGetByCanonicalResp.GetFound() {
		t.Fatal("expected billing reservation found=true for canonical id")
	}
	if billingGetByCanonicalResp.GetReservation().GetReservationId() != reservationCanonicalID {
		t.Fatalf("expected canonical queried billing reservation id %q, got %q", reservationCanonicalID, billingGetByCanonicalResp.GetReservation().GetReservationId())
	}

	billingGetByMixedResp, err := billingQuery.CreditReservation(rpcCtx, &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: reservationMixedQueryID,
	})
	if err != nil {
		t.Fatalf("billing get reservation by mixed-case id failed: %v", err)
	}
	if !billingGetByMixedResp.GetFound() {
		t.Fatal("expected billing reservation found=true for mixed-case id")
	}
	if billingGetByMixedResp.GetReservation().GetReservationId() != reservationCanonicalID {
		t.Fatalf("expected mixed-case billing query to resolve canonical reservation id %q, got %q", reservationCanonicalID, billingGetByMixedResp.GetReservation().GetReservationId())
	}

	billingListResp, err := billingQuery.ListCreditReservations(rpcCtx, &vpnbillingpb.QueryListCreditReservationsRequest{})
	if err != nil {
		t.Fatalf("billing list reservations failed: %v", err)
	}
	if !containsBillingReservationID(billingListResp.GetReservations(), reservationCanonicalID) {
		t.Fatalf("expected canonical reservation %q in billing list, got %v", reservationCanonicalID, billingListResp.GetReservations())
	}

	settlementInputID := "  SET-" + upperPrefix + "-CANON-1  "
	settlementCanonicalID := "set-" + idPrefix + "-canon-1"
	settlementMixedQueryID := "  SeT-" + upperPrefix + "-CaNoN-1  "
	billingFinalizeResp, err := billingMsg.FinalizeUsage(rpcCtx, &vpnbillingpb.MsgFinalizeUsageRequest{
		Settlement: &vpnbillingpb.SettlementRecord{
			SettlementId:  settlementInputID,
			ReservationId: reservationMixedQueryID,
			SessionId:     reservationSessionInputID,
			BilledAmount:  120,
			UsageBytes:    2048,
			AssetDenom:    "  UUSDC  ",
		},
	})
	if err != nil {
		t.Fatalf("billing finalize usage failed: %v", err)
	}
	if billingFinalizeResp.GetSettlement().GetSettlementId() != settlementCanonicalID {
		t.Fatalf("expected canonical billing settlement id %q, got %q", settlementCanonicalID, billingFinalizeResp.GetSettlement().GetSettlementId())
	}
	if billingFinalizeResp.GetSettlement().GetReservationId() != reservationCanonicalID {
		t.Fatalf("expected canonical billing settlement reservation id %q, got %q", reservationCanonicalID, billingFinalizeResp.GetSettlement().GetReservationId())
	}
	if billingFinalizeResp.GetSettlement().GetSessionId() != reservationSessionCanonicalID {
		t.Fatalf("expected canonical billing settlement session id %q, got %q", reservationSessionCanonicalID, billingFinalizeResp.GetSettlement().GetSessionId())
	}
	if billingFinalizeResp.GetSettlement().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical billing settlement denom uusdc, got %q", billingFinalizeResp.GetSettlement().GetAssetDenom())
	}

	billingSettlementByCanonicalResp, err := billingQuery.SettlementRecord(rpcCtx, &vpnbillingpb.QuerySettlementRecordRequest{
		SettlementId: settlementCanonicalID,
	})
	if err != nil {
		t.Fatalf("billing get settlement by canonical id failed: %v", err)
	}
	if !billingSettlementByCanonicalResp.GetFound() {
		t.Fatal("expected billing settlement found=true for canonical id")
	}
	if billingSettlementByCanonicalResp.GetSettlement().GetSettlementId() != settlementCanonicalID {
		t.Fatalf("expected canonical queried billing settlement id %q, got %q", settlementCanonicalID, billingSettlementByCanonicalResp.GetSettlement().GetSettlementId())
	}

	billingSettlementByMixedResp, err := billingQuery.SettlementRecord(rpcCtx, &vpnbillingpb.QuerySettlementRecordRequest{
		SettlementId: settlementMixedQueryID,
	})
	if err != nil {
		t.Fatalf("billing get settlement by mixed-case id failed: %v", err)
	}
	if !billingSettlementByMixedResp.GetFound() {
		t.Fatal("expected billing settlement found=true for mixed-case id")
	}
	if billingSettlementByMixedResp.GetSettlement().GetSettlementId() != settlementCanonicalID {
		t.Fatalf("expected mixed-case billing settlement query to resolve canonical id %q, got %q", settlementCanonicalID, billingSettlementByMixedResp.GetSettlement().GetSettlementId())
	}

	billingSettlementListResp, err := billingQuery.ListSettlementRecords(rpcCtx, &vpnbillingpb.QueryListSettlementRecordsRequest{})
	if err != nil {
		t.Fatalf("billing list settlements failed: %v", err)
	}
	if !containsBillingSettlementID(billingSettlementListResp.GetSettlements(), settlementCanonicalID) {
		t.Fatalf("expected canonical settlement %q in billing list, got %v", settlementCanonicalID, billingSettlementListResp.GetSettlements())
	}

	accrualInputID := "  ACCRUAL-" + upperPrefix + "-CANON-1  "
	accrualCanonicalID := "accrual-" + idPrefix + "-canon-1"
	accrualMixedQueryID := "  AcCrUaL-" + upperPrefix + "-CaNoN-1  "
	accrualSessionInputID := "  SESSION-REWARD-" + upperPrefix + "-CANON-1  "
	accrualSessionCanonicalID := "session-reward-" + idPrefix + "-canon-1"
	accrualProviderInputID := "  PROVIDER-REWARD-" + upperPrefix + "-CANON-1  "
	accrualProviderCanonicalID := "provider-reward-" + idPrefix + "-canon-1"
	rewardAccrualResp, err := rewardsMsg.RecordAccrual(rpcCtx, &vpnrewardspb.MsgRecordAccrualRequest{
		Accrual: &vpnrewardspb.RewardAccrual{
			AccrualId:      accrualInputID,
			SessionId:      accrualSessionInputID,
			ProviderId:     accrualProviderInputID,
			AssetDenom:     "  UUSDC  ",
			Amount:         70,
			OperationState: vpnrewardspb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("record reward accrual failed: %v", err)
	}
	if rewardAccrualResp.GetAccrual().GetAccrualId() != accrualCanonicalID {
		t.Fatalf("expected canonical reward accrual id %q, got %q", accrualCanonicalID, rewardAccrualResp.GetAccrual().GetAccrualId())
	}
	if rewardAccrualResp.GetAccrual().GetSessionId() != accrualSessionCanonicalID {
		t.Fatalf("expected canonical reward accrual session id %q, got %q", accrualSessionCanonicalID, rewardAccrualResp.GetAccrual().GetSessionId())
	}
	if rewardAccrualResp.GetAccrual().GetProviderId() != accrualProviderCanonicalID {
		t.Fatalf("expected canonical reward accrual provider id %q, got %q", accrualProviderCanonicalID, rewardAccrualResp.GetAccrual().GetProviderId())
	}
	if rewardAccrualResp.GetAccrual().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical reward accrual denom uusdc, got %q", rewardAccrualResp.GetAccrual().GetAssetDenom())
	}

	rewardAccrualByCanonicalResp, err := rewardsQuery.RewardAccrual(rpcCtx, &vpnrewardspb.QueryRewardAccrualRequest{
		AccrualId: accrualCanonicalID,
	})
	if err != nil {
		t.Fatalf("query reward accrual by canonical id failed: %v", err)
	}
	if !rewardAccrualByCanonicalResp.GetFound() {
		t.Fatal("expected reward accrual found=true for canonical id")
	}
	if rewardAccrualByCanonicalResp.GetAccrual().GetAccrualId() != accrualCanonicalID {
		t.Fatalf("expected canonical queried reward accrual id %q, got %q", accrualCanonicalID, rewardAccrualByCanonicalResp.GetAccrual().GetAccrualId())
	}

	rewardAccrualByMixedResp, err := rewardsQuery.RewardAccrual(rpcCtx, &vpnrewardspb.QueryRewardAccrualRequest{
		AccrualId: accrualMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query reward accrual by mixed-case id failed: %v", err)
	}
	if !rewardAccrualByMixedResp.GetFound() {
		t.Fatal("expected reward accrual found=true for mixed-case id")
	}
	if rewardAccrualByMixedResp.GetAccrual().GetAccrualId() != accrualCanonicalID {
		t.Fatalf("expected mixed-case reward accrual query to resolve canonical id %q, got %q", accrualCanonicalID, rewardAccrualByMixedResp.GetAccrual().GetAccrualId())
	}

	rewardAccrualListResp, err := rewardsQuery.ListRewardAccruals(rpcCtx, &vpnrewardspb.QueryListRewardAccrualsRequest{})
	if err != nil {
		t.Fatalf("list reward accruals failed: %v", err)
	}
	if !containsRewardAccrualID(rewardAccrualListResp.GetAccruals(), accrualCanonicalID) {
		t.Fatalf("expected canonical reward accrual %q in list, got %v", accrualCanonicalID, rewardAccrualListResp.GetAccruals())
	}

	distributionInputID := "  DIST-" + upperPrefix + "-CANON-1  "
	distributionCanonicalID := "dist-" + idPrefix + "-canon-1"
	distributionMixedQueryID := "  DiSt-" + upperPrefix + "-CaNoN-1  "
	rewardDistributionResp, err := rewardsMsg.RecordDistribution(rpcCtx, &vpnrewardspb.MsgRecordDistributionRequest{
		Distribution: &vpnrewardspb.DistributionRecord{
			DistributionId: distributionInputID,
			AccrualId:      accrualMixedQueryID,
			PayoutRef:      "payout-" + idPrefix + "-canon-1",
		},
	})
	if err != nil {
		t.Fatalf("record reward distribution failed: %v", err)
	}
	if rewardDistributionResp.GetDistribution().GetDistributionId() != distributionCanonicalID {
		t.Fatalf("expected canonical reward distribution id %q, got %q", distributionCanonicalID, rewardDistributionResp.GetDistribution().GetDistributionId())
	}
	if rewardDistributionResp.GetDistribution().GetAccrualId() != accrualCanonicalID {
		t.Fatalf("expected canonical reward distribution accrual id %q, got %q", accrualCanonicalID, rewardDistributionResp.GetDistribution().GetAccrualId())
	}

	rewardDistributionByCanonicalResp, err := rewardsQuery.DistributionRecord(rpcCtx, &vpnrewardspb.QueryDistributionRecordRequest{
		DistributionId: distributionCanonicalID,
	})
	if err != nil {
		t.Fatalf("query reward distribution by canonical id failed: %v", err)
	}
	if !rewardDistributionByCanonicalResp.GetFound() {
		t.Fatal("expected reward distribution found=true for canonical id")
	}
	if rewardDistributionByCanonicalResp.GetDistribution().GetDistributionId() != distributionCanonicalID {
		t.Fatalf("expected canonical queried reward distribution id %q, got %q", distributionCanonicalID, rewardDistributionByCanonicalResp.GetDistribution().GetDistributionId())
	}
	if rewardDistributionByCanonicalResp.GetDistribution().GetAccrualId() != accrualCanonicalID {
		t.Fatalf("expected canonical queried reward distribution accrual id %q, got %q", accrualCanonicalID, rewardDistributionByCanonicalResp.GetDistribution().GetAccrualId())
	}

	rewardDistributionByMixedResp, err := rewardsQuery.DistributionRecord(rpcCtx, &vpnrewardspb.QueryDistributionRecordRequest{
		DistributionId: distributionMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query reward distribution by mixed-case id failed: %v", err)
	}
	if !rewardDistributionByMixedResp.GetFound() {
		t.Fatal("expected reward distribution found=true for mixed-case id")
	}
	if rewardDistributionByMixedResp.GetDistribution().GetDistributionId() != distributionCanonicalID {
		t.Fatalf("expected mixed-case reward distribution query to resolve canonical id %q, got %q", distributionCanonicalID, rewardDistributionByMixedResp.GetDistribution().GetDistributionId())
	}

	rewardDistributionListResp, err := rewardsQuery.ListDistributionRecords(rpcCtx, &vpnrewardspb.QueryListDistributionRecordsRequest{})
	if err != nil {
		t.Fatalf("list reward distributions failed: %v", err)
	}
	if !containsRewardDistributionID(rewardDistributionListResp.GetDistributions(), distributionCanonicalID) {
		t.Fatalf("expected canonical reward distribution %q in list, got %v", distributionCanonicalID, rewardDistributionListResp.GetDistributions())
	}

	authorizationInputID := "  AUTH-" + upperPrefix + "-CANON-1  "
	authorizationCanonicalID := "auth-" + idPrefix + "-canon-1"
	authorizationMixedQueryID := "  AuTh-" + upperPrefix + "-CaNoN-1  "
	appInputID := "  APP-" + upperPrefix + "-CANON-1  "
	appCanonicalID := "app-" + idPrefix + "-canon-1"
	sponsorCreateResp, err := sponsorMsg.CreateAuthorization(rpcCtx, &vpnsponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &vpnsponsorpb.SponsorAuthorization{
			AuthorizationId: authorizationInputID,
			SponsorId:       reservationSponsorInputID,
			AppId:           appInputID,
			MaxCredits:      1000,
			ExpiresAtUnix:   4102444800,
		},
	})
	if err != nil {
		t.Fatalf("sponsor create authorization failed: %v", err)
	}
	if sponsorCreateResp.GetAuthorization().GetAuthorizationId() != authorizationCanonicalID {
		t.Fatalf("expected canonical sponsor authorization id %q, got %q", authorizationCanonicalID, sponsorCreateResp.GetAuthorization().GetAuthorizationId())
	}
	if sponsorCreateResp.GetAuthorization().GetSponsorId() != reservationSponsorCanonicalID {
		t.Fatalf("expected canonical sponsor authorization sponsor id %q, got %q", reservationSponsorCanonicalID, sponsorCreateResp.GetAuthorization().GetSponsorId())
	}
	if sponsorCreateResp.GetAuthorization().GetAppId() != appCanonicalID {
		t.Fatalf("expected canonical sponsor authorization app id %q, got %q", appCanonicalID, sponsorCreateResp.GetAuthorization().GetAppId())
	}

	sponsorGetAuthByCanonicalResp, err := sponsorQuery.SponsorAuthorization(rpcCtx, &vpnsponsorpb.QuerySponsorAuthorizationRequest{
		AuthorizationId: authorizationCanonicalID,
	})
	if err != nil {
		t.Fatalf("sponsor get authorization by canonical id failed: %v", err)
	}
	if !sponsorGetAuthByCanonicalResp.GetFound() {
		t.Fatal("expected sponsor authorization found=true for canonical id")
	}
	if sponsorGetAuthByCanonicalResp.GetAuthorization().GetAuthorizationId() != authorizationCanonicalID {
		t.Fatalf("expected canonical queried sponsor authorization id %q, got %q", authorizationCanonicalID, sponsorGetAuthByCanonicalResp.GetAuthorization().GetAuthorizationId())
	}

	sponsorGetAuthByMixedResp, err := sponsorQuery.SponsorAuthorization(rpcCtx, &vpnsponsorpb.QuerySponsorAuthorizationRequest{
		AuthorizationId: authorizationMixedQueryID,
	})
	if err != nil {
		t.Fatalf("sponsor get authorization by mixed-case id failed: %v", err)
	}
	if !sponsorGetAuthByMixedResp.GetFound() {
		t.Fatal("expected sponsor authorization found=true for mixed-case id")
	}
	if sponsorGetAuthByMixedResp.GetAuthorization().GetAuthorizationId() != authorizationCanonicalID {
		t.Fatalf("expected mixed-case sponsor authorization query to resolve canonical id %q, got %q", authorizationCanonicalID, sponsorGetAuthByMixedResp.GetAuthorization().GetAuthorizationId())
	}

	sponsorListAuthResp, err := sponsorQuery.ListSponsorAuthorizations(rpcCtx, &vpnsponsorpb.QueryListSponsorAuthorizationsRequest{})
	if err != nil {
		t.Fatalf("sponsor list authorizations failed: %v", err)
	}
	if !containsSponsorAuthorizationID(sponsorListAuthResp.GetAuthorizations(), authorizationCanonicalID) {
		t.Fatalf("expected canonical sponsor authorization %q in list, got %v", authorizationCanonicalID, sponsorListAuthResp.GetAuthorizations())
	}

	delegationReservationInputID := "  RES-DELEGATE-" + upperPrefix + "-CANON-1  "
	delegationReservationCanonicalID := "res-delegate-" + idPrefix + "-canon-1"
	delegationReservationMixedQueryID := "  ReS-DeLeGaTe-" + upperPrefix + "-CaNoN-1  "
	endUserTrimmed := "End-User-" + upperPrefix + "-Canon-1"
	sessionTrimmed := "Sess-Delegate-" + upperPrefix + "-Canon-1"
	sponsorDelegateResp, err := sponsorMsg.DelegateSessionCredit(delegateCtx, &vpnsponsorpb.MsgDelegateSessionCreditRequest{
		Delegation: &vpnsponsorpb.DelegatedSessionCredit{
			ReservationId:   delegationReservationInputID,
			SponsorId:       reservationSponsorInputID,
			AppId:           appInputID,
			EndUserId:       "  " + endUserTrimmed + "  ",
			SessionId:       "  " + sessionTrimmed + "  ",
			Credits:         220,
			AuthorizationId: authorizationMixedQueryID,
		},
	})
	if err != nil {
		t.Fatalf("sponsor delegate credit failed: %v", err)
	}
	if sponsorDelegateResp.GetDelegation().GetReservationId() != delegationReservationCanonicalID {
		t.Fatalf("expected canonical sponsor delegation reservation id %q, got %q", delegationReservationCanonicalID, sponsorDelegateResp.GetDelegation().GetReservationId())
	}
	if sponsorDelegateResp.GetDelegation().GetAuthorizationId() != authorizationCanonicalID {
		t.Fatalf("expected canonical sponsor delegation authorization id %q, got %q", authorizationCanonicalID, sponsorDelegateResp.GetDelegation().GetAuthorizationId())
	}
	if sponsorDelegateResp.GetDelegation().GetSponsorId() != reservationSponsorCanonicalID {
		t.Fatalf("expected canonical sponsor delegation sponsor id %q, got %q", reservationSponsorCanonicalID, sponsorDelegateResp.GetDelegation().GetSponsorId())
	}
	if sponsorDelegateResp.GetDelegation().GetAppId() != appCanonicalID {
		t.Fatalf("expected canonical sponsor delegation app id %q, got %q", appCanonicalID, sponsorDelegateResp.GetDelegation().GetAppId())
	}
	if sponsorDelegateResp.GetDelegation().GetEndUserId() != endUserTrimmed {
		t.Fatalf("expected trim-only sponsor delegation end user id %q, got %q", endUserTrimmed, sponsorDelegateResp.GetDelegation().GetEndUserId())
	}
	if sponsorDelegateResp.GetDelegation().GetSessionId() != sessionTrimmed {
		t.Fatalf("expected trim-only sponsor delegation session id %q, got %q", sessionTrimmed, sponsorDelegateResp.GetDelegation().GetSessionId())
	}

	sponsorGetDelegationByCanonicalResp, err := sponsorQuery.DelegatedSessionCredit(rpcCtx, &vpnsponsorpb.QueryDelegatedSessionCreditRequest{
		ReservationId: delegationReservationCanonicalID,
	})
	if err != nil {
		t.Fatalf("sponsor get delegation by canonical id failed: %v", err)
	}
	if !sponsorGetDelegationByCanonicalResp.GetFound() {
		t.Fatal("expected sponsor delegation found=true for canonical id")
	}
	if sponsorGetDelegationByCanonicalResp.GetDelegation().GetReservationId() != delegationReservationCanonicalID {
		t.Fatalf("expected canonical queried sponsor delegation reservation id %q, got %q", delegationReservationCanonicalID, sponsorGetDelegationByCanonicalResp.GetDelegation().GetReservationId())
	}
	if sponsorGetDelegationByCanonicalResp.GetDelegation().GetAuthorizationId() != authorizationCanonicalID {
		t.Fatalf("expected canonical queried sponsor delegation authorization id %q, got %q", authorizationCanonicalID, sponsorGetDelegationByCanonicalResp.GetDelegation().GetAuthorizationId())
	}
	if sponsorGetDelegationByCanonicalResp.GetDelegation().GetEndUserId() != endUserTrimmed {
		t.Fatalf("expected trim-only queried sponsor delegation end user id %q, got %q", endUserTrimmed, sponsorGetDelegationByCanonicalResp.GetDelegation().GetEndUserId())
	}
	if sponsorGetDelegationByCanonicalResp.GetDelegation().GetSessionId() != sessionTrimmed {
		t.Fatalf("expected trim-only queried sponsor delegation session id %q, got %q", sessionTrimmed, sponsorGetDelegationByCanonicalResp.GetDelegation().GetSessionId())
	}

	sponsorGetDelegationByMixedResp, err := sponsorQuery.DelegatedSessionCredit(rpcCtx, &vpnsponsorpb.QueryDelegatedSessionCreditRequest{
		ReservationId: delegationReservationMixedQueryID,
	})
	if err != nil {
		t.Fatalf("sponsor get delegation by mixed-case id failed: %v", err)
	}
	if !sponsorGetDelegationByMixedResp.GetFound() {
		t.Fatal("expected sponsor delegation found=true for mixed-case id")
	}
	if sponsorGetDelegationByMixedResp.GetDelegation().GetReservationId() != delegationReservationCanonicalID {
		t.Fatalf("expected mixed-case sponsor delegation query to resolve canonical reservation id %q, got %q", delegationReservationCanonicalID, sponsorGetDelegationByMixedResp.GetDelegation().GetReservationId())
	}

	sponsorListDelegationsResp, err := sponsorQuery.ListDelegatedSessionCredits(rpcCtx, &vpnsponsorpb.QueryListDelegatedSessionCreditsRequest{})
	if err != nil {
		t.Fatalf("sponsor list delegations failed: %v", err)
	}
	if !containsSponsorDelegationReservationID(sponsorListDelegationsResp.GetDelegations(), delegationReservationCanonicalID) {
		t.Fatalf("expected canonical sponsor delegation %q in list, got %v", delegationReservationCanonicalID, sponsorListDelegationsResp.GetDelegations())
	}
}

func TestIsLoopbackListenAddrWithLookupRequiresAllResolvedIPsLoopback(t *testing.T) {
	t.Parallel()

	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "loopback.local":
			return []net.IPAddr{
				{IP: net.ParseIP("127.0.0.1")},
				{IP: net.ParseIP("::1")},
			}, nil
		case "mixed.local":
			return []net.IPAddr{
				{IP: net.ParseIP("127.0.0.1")},
				{IP: net.ParseIP("203.0.113.10")},
			}, nil
		case "public.local":
			return []net.IPAddr{{IP: net.ParseIP("198.51.100.20")}}, nil
		case "empty.local":
			return []net.IPAddr{}, nil
		default:
			return nil, errors.New("lookup failed")
		}
	}

	testCases := []struct {
		name       string
		listenAddr string
		want       bool
	}{
		{name: "literal-ipv4-loopback", listenAddr: "127.0.0.1:7000", want: true},
		{name: "literal-ipv6-loopback", listenAddr: "[::1]:7000", want: true},
		{name: "ipv6-zone-loopback", listenAddr: "[::1%lo0]:7000", want: true},
		{name: "hostname-all-loopback", listenAddr: "loopback.local:7000", want: true},
		{name: "hostname-mixed-loopback-and-public", listenAddr: "mixed.local:7000", want: false},
		{name: "hostname-public", listenAddr: "public.local:7000", want: false},
		{name: "hostname-empty-resolution", listenAddr: "empty.local:7000", want: false},
		{name: "hostname-lookup-error", listenAddr: "missing.local:7000", want: false},
		{name: "wildcard-host", listenAddr: "*:7000", want: false},
		{name: "numeric-port-only", listenAddr: "7000", want: false},
		{name: "public-ip-without-port", listenAddr: "198.51.100.20", want: false},
		{name: "bufnet-short-circuit", listenAddr: "bufnet", want: true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isLoopbackListenAddrWithLookup(tc.listenAddr, lookup)
			if got != tc.want {
				t.Fatalf("isLoopbackListenAddrWithLookup(%q)=%v want=%v", tc.listenAddr, got, tc.want)
			}
		})
	}
}

func TestIsLoopbackPeerWithLookupRequiresAllResolvedIPsLoopback(t *testing.T) {
	t.Parallel()

	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "loopback.local":
			return []net.IPAddr{
				{IP: net.ParseIP("127.0.0.1")},
				{IP: net.ParseIP("::1")},
			}, nil
		case "mixed.local":
			return []net.IPAddr{
				{IP: net.ParseIP("127.0.0.1")},
				{IP: net.ParseIP("203.0.113.11")},
			}, nil
		default:
			return nil, errors.New("lookup failed")
		}
	}

	makePeerCtx := func(addr net.Addr) context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{Addr: addr})
	}

	testCases := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{name: "missing-peer", ctx: context.Background(), want: false},
		{name: "literal-loopback", ctx: makePeerCtx(namedAddr("127.0.0.1:40100")), want: true},
		{name: "hostname-all-loopback", ctx: makePeerCtx(namedAddr("loopback.local:40101")), want: true},
		{name: "hostname-mixed-loopback-and-public", ctx: makePeerCtx(namedAddr("mixed.local:40102")), want: false},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isLoopbackPeerWithLookup(tc.ctx, lookup)
			if got != tc.want {
				t.Fatalf("isLoopbackPeerWithLookup(%s)=%v want=%v", tc.name, got, tc.want)
			}
		})
	}
}

func TestMethodRequiresAuthDefaultDenyWithHealthAllowlist(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		fullMethod string
		want       bool
	}{
		{name: "health-check-open", fullMethod: grpcHealthCheckMethod, want: false},
		{name: "health-watch-auth-required", fullMethod: grpcHealthWatchMethod, want: true},
		{name: "tdpn-method-auth-required", fullMethod: "/tdpn.vpnbilling.v1.Msg/ReserveCredits", want: true},
		{name: "non-tdpn-method-auth-required", fullMethod: "/custom.service.v1.Query/Ping", want: true},
		{name: "empty-method-auth-required", fullMethod: "", want: true},
		{name: "trimmed-health-check-open", fullMethod: "  " + grpcHealthCheckMethod + "  ", want: false},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := methodRequiresAuth(tc.fullMethod); got != tc.want {
				t.Fatalf("methodRequiresAuth(%q)=%v want=%v", tc.fullMethod, got, tc.want)
			}
		})
	}
}

func TestAuthUnaryInterceptorDefaultDenyNonHealthMethods(t *testing.T) {
	t.Parallel()

	const authToken = "runtime-interceptor-token"
	interceptor := authUnaryInterceptor(authToken)
	handler := func(context.Context, any) (any, error) { return "ok", nil }

	healthResp, err := interceptor(
		context.Background(),
		struct{}{},
		&grpc.UnaryServerInfo{FullMethod: grpcHealthCheckMethod},
		handler,
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected health check without token to be unauthenticated, got %v", err)
	}

	healthTokenCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authToken))
	healthResp, err = interceptor(
		healthTokenCtx,
		struct{}{},
		&grpc.UnaryServerInfo{FullMethod: grpcHealthCheckMethod},
		handler,
	)
	if err != nil {
		t.Fatalf("expected health check with token to pass auth, got %v", err)
	}
	if healthResp != "ok" {
		t.Fatalf("expected health check handler response 'ok', got %#v", healthResp)
	}

	_, err = interceptor(
		context.Background(),
		struct{}{},
		&grpc.UnaryServerInfo{FullMethod: "/custom.service.v1.Query/Ping"},
		handler,
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected non-allowlisted method without token to be unauthenticated, got %v", err)
	}

	okTokenCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+authToken))
	authResp, err := interceptor(
		okTokenCtx,
		struct{}{},
		&grpc.UnaryServerInfo{FullMethod: "/custom.service.v1.Query/Ping"},
		handler,
	)
	if err != nil {
		t.Fatalf("expected non-allowlisted method with token to pass auth, got %v", err)
	}
	if authResp != "ok" {
		t.Fatalf("expected authorized handler response 'ok', got %#v", authResp)
	}
}

func containsBillingReservationID(records []*vpnbillingpb.CreditReservation, want string) bool {
	for _, record := range records {
		if record.GetReservationId() == want {
			return true
		}
	}
	return false
}

func containsBillingSettlementID(records []*vpnbillingpb.SettlementRecord, want string) bool {
	for _, record := range records {
		if record.GetSettlementId() == want {
			return true
		}
	}
	return false
}

func containsRewardAccrualID(records []*vpnrewardspb.RewardAccrual, want string) bool {
	for _, record := range records {
		if record.GetAccrualId() == want {
			return true
		}
	}
	return false
}

func containsRewardDistributionID(records []*vpnrewardspb.DistributionRecord, want string) bool {
	for _, record := range records {
		if record.GetDistributionId() == want {
			return true
		}
	}
	return false
}

func containsSponsorAuthorizationID(records []*vpnsponsorpb.SponsorAuthorization, want string) bool {
	for _, record := range records {
		if record.GetAuthorizationId() == want {
			return true
		}
	}
	return false
}

func containsSponsorDelegationReservationID(records []*vpnsponsorpb.DelegatedSessionCredit, want string) bool {
	for _, record := range records {
		if record.GetReservationId() == want {
			return true
		}
	}
	return false
}

func containsValidatorEligibilityID(records []*vpnvalidatorpb.ValidatorEligibility, want string) bool {
	for _, record := range records {
		if record.GetValidatorId() == want {
			return true
		}
	}
	return false
}

func containsValidatorStatusID(records []*vpnvalidatorpb.ValidatorStatusRecord, want string) bool {
	for _, record := range records {
		if record.GetStatusId() == want {
			return true
		}
	}
	return false
}

func containsGovernancePolicyID(records []*vpngovernancepb.GovernancePolicy, want string) bool {
	for _, record := range records {
		if record.GetPolicyId() == want {
			return true
		}
	}
	return false
}

func containsGovernanceDecisionID(records []*vpngovernancepb.GovernanceDecision, want string) bool {
	for _, record := range records {
		if record.GetDecisionId() == want {
			return true
		}
	}
	return false
}

func containsGovernanceActionID(records []*vpngovernancepb.GovernanceAuditAction, want string) bool {
	for _, record := range records {
		if record.GetActionId() == want {
			return true
		}
	}
	return false
}

func containsReflectionService(services []string, target string) bool {
	for _, service := range services {
		if service == target {
			return true
		}
	}
	return false
}
