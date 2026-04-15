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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	vpnbillingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	vpnrewardspb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1"
	vpnslashingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1"
	vpngovernancepb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpngovernance/v1"
	vpnsponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
	vpnvalidatorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnvalidator/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
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
	healthResp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
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
	assertQueryAuthParity("vpnrewards/ListRewardAccruals", func(callCtx context.Context) error {
		_, callErr := rewardsQuery.ListRewardAccruals(callCtx, &vpnrewardspb.QueryListRewardAccrualsRequest{})
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
	assertQueryAuthParity("vpnvalidator/ListValidatorEligibilities", func(callCtx context.Context) error {
		_, callErr := validatorQuery.ListValidatorEligibilities(callCtx, &vpnvalidatorpb.QueryListValidatorEligibilitiesRequest{})
		return callErr
	})
	assertQueryAuthParity("vpngovernance/ListGovernancePolicies", func(callCtx context.Context) error {
		_, callErr := governanceQuery.ListGovernancePolicies(callCtx, &vpngovernancepb.QueryListGovernancePoliciesRequest{})
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
	sponsorMsg := vpnsponsorpb.NewMsgClient(conn)
	sponsorQuery := vpnsponsorpb.NewQueryClient(conn)

	billingReserveResp, err := billingMsg.ReserveCredits(context.Background(), &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: "res-int-1",
			SponsorId:     "sponsor-int-1",
			SessionId:     "sess-int-1",
			AssetDenom:    "uusdc",
			Amount:        125,
		},
	})
	if err != nil {
		t.Fatalf("billing reserve credits failed: %v", err)
	}
	if billingReserveResp.GetReservation().GetReservationId() != "res-int-1" {
		t.Fatalf("unexpected billing reservation id %q", billingReserveResp.GetReservation().GetReservationId())
	}

	billingGetResp, err := billingQuery.CreditReservation(context.Background(), &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: "res-int-1",
	})
	if err != nil {
		t.Fatalf("billing get reservation failed: %v", err)
	}
	if !billingGetResp.GetFound() {
		t.Fatal("expected billing reservation found=true")
	}
	if billingGetResp.GetReservation().GetSessionId() != "sess-int-1" {
		t.Fatalf("unexpected billing reservation session id %q", billingGetResp.GetReservation().GetSessionId())
	}

	billingListResp, err := billingQuery.ListCreditReservations(context.Background(), &vpnbillingpb.QueryListCreditReservationsRequest{})
	if err != nil {
		t.Fatalf("billing list reservations failed: %v", err)
	}
	if !containsBillingReservationID(billingListResp.GetReservations(), "res-int-1") {
		t.Fatalf("expected reservation res-int-1 in billing list, got %v", billingListResp.GetReservations())
	}

	sponsorCreateResp, err := sponsorMsg.CreateAuthorization(context.Background(), &vpnsponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &vpnsponsorpb.SponsorAuthorization{
			AuthorizationId: "auth-int-1",
			SponsorId:       "sponsor-int-1",
			AppId:           "app-int-1",
			MaxCredits:      1000,
			ExpiresAtUnix:   4102444800,
		},
	})
	if err != nil {
		t.Fatalf("sponsor create authorization failed: %v", err)
	}
	if sponsorCreateResp.GetAuthorization().GetAuthorizationId() != "auth-int-1" {
		t.Fatalf("unexpected sponsor authorization id %q", sponsorCreateResp.GetAuthorization().GetAuthorizationId())
	}

	sponsorDelegateResp, err := sponsorMsg.DelegateSessionCredit(context.Background(), &vpnsponsorpb.MsgDelegateSessionCreditRequest{
		Delegation: &vpnsponsorpb.DelegatedSessionCredit{
			ReservationId:   "res-delegate-int-1",
			SponsorId:       "sponsor-int-1",
			AppId:           "app-int-1",
			EndUserId:       "user-int-1",
			SessionId:       "sess-delegate-int-1",
			Credits:         220,
			AuthorizationId: "auth-int-1",
		},
	})
	if err != nil {
		t.Fatalf("sponsor delegate credit failed: %v", err)
	}
	if sponsorDelegateResp.GetDelegation().GetReservationId() != "res-delegate-int-1" {
		t.Fatalf("unexpected sponsor delegation reservation id %q", sponsorDelegateResp.GetDelegation().GetReservationId())
	}

	sponsorGetAuthResp, err := sponsorQuery.SponsorAuthorization(context.Background(), &vpnsponsorpb.QuerySponsorAuthorizationRequest{
		AuthorizationId: "auth-int-1",
	})
	if err != nil {
		t.Fatalf("sponsor get authorization failed: %v", err)
	}
	if !sponsorGetAuthResp.GetFound() {
		t.Fatal("expected sponsor authorization found=true")
	}
	if sponsorGetAuthResp.GetAuthorization().GetAppId() != "app-int-1" {
		t.Fatalf("unexpected sponsor authorization app id %q", sponsorGetAuthResp.GetAuthorization().GetAppId())
	}

	sponsorGetDelegationResp, err := sponsorQuery.DelegatedSessionCredit(context.Background(), &vpnsponsorpb.QueryDelegatedSessionCreditRequest{
		ReservationId: "res-delegate-int-1",
	})
	if err != nil {
		t.Fatalf("sponsor get delegation failed: %v", err)
	}
	if !sponsorGetDelegationResp.GetFound() {
		t.Fatal("expected sponsor delegation found=true")
	}
	if sponsorGetDelegationResp.GetDelegation().GetAuthorizationId() != "auth-int-1" {
		t.Fatalf("unexpected sponsor delegation authorization id %q", sponsorGetDelegationResp.GetDelegation().GetAuthorizationId())
	}

	sponsorListAuthResp, err := sponsorQuery.ListSponsorAuthorizations(context.Background(), &vpnsponsorpb.QueryListSponsorAuthorizationsRequest{})
	if err != nil {
		t.Fatalf("sponsor list authorizations failed: %v", err)
	}
	if !containsSponsorAuthorizationID(sponsorListAuthResp.GetAuthorizations(), "auth-int-1") {
		t.Fatalf("expected auth-int-1 in sponsor authorizations list, got %v", sponsorListAuthResp.GetAuthorizations())
	}

	sponsorListDelegationsResp, err := sponsorQuery.ListDelegatedSessionCredits(context.Background(), &vpnsponsorpb.QueryListDelegatedSessionCreditsRequest{})
	if err != nil {
		t.Fatalf("sponsor list delegations failed: %v", err)
	}
	if !containsSponsorDelegationReservationID(sponsorListDelegationsResp.GetDelegations(), "res-delegate-int-1") {
		t.Fatalf("expected res-delegate-int-1 in sponsor delegations list, got %v", sponsorListDelegationsResp.GetDelegations())
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

	eligibilityID := "validator-runtime-rt-1"
	eligibilityResp, err := validatorMsg.SetValidatorEligibility(context.Background(), &vpnvalidatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &vpnvalidatorpb.ValidatorEligibility{
			ValidatorId:     eligibilityID,
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
	if eligibilityResp.GetEligibility().GetValidatorId() != eligibilityID {
		t.Fatalf("unexpected validator eligibility id %q", eligibilityResp.GetEligibility().GetValidatorId())
	}

	eligibilityByID, err := validatorQuery.ValidatorEligibility(context.Background(), &vpnvalidatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: eligibilityID,
	})
	if err != nil {
		t.Fatalf("query validator eligibility failed: %v", err)
	}
	if !eligibilityByID.GetFound() {
		t.Fatal("expected validator eligibility found=true")
	}
	if eligibilityByID.GetEligibility().GetOperatorAddress() != "tdpnvaloper1runtime1" {
		t.Fatalf("unexpected validator operator address %q", eligibilityByID.GetEligibility().GetOperatorAddress())
	}

	eligibilityList, err := validatorQuery.ListValidatorEligibilities(context.Background(), &vpnvalidatorpb.QueryListValidatorEligibilitiesRequest{})
	if err != nil {
		t.Fatalf("list validator eligibilities failed: %v", err)
	}
	if !containsValidatorEligibilityID(eligibilityList.GetEligibilities(), eligibilityID) {
		t.Fatalf("expected validator eligibility %q in list, got %v", eligibilityID, eligibilityList.GetEligibilities())
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
				ValidatorId:         eligibilityID,
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

	statusID := "validator-status-runtime-rt-1"
	statusResp, err := validatorMsg.RecordValidatorStatus(context.Background(), &vpnvalidatorpb.MsgRecordValidatorStatusRequest{
		Record: &vpnvalidatorpb.ValidatorStatusRecord{
			StatusId:         statusID,
			ValidatorId:      eligibilityID,
			ConsensusAddress: "tdpnvalcons1runtime1",
			LifecycleStatus:  "active",
			EvidenceHeight:   77,
			EvidenceRef:      "evidence://validator/runtime/77",
			RecordedAtUnix:   1713002002,
			Status:           vpnvalidatorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
		},
	})
	if err != nil {
		t.Fatalf("record validator status failed: %v", err)
	}
	if statusResp.GetRecord().GetStatusId() != statusID {
		t.Fatalf("unexpected validator status id %q", statusResp.GetRecord().GetStatusId())
	}

	statusByID, err := validatorQuery.ValidatorStatusRecord(context.Background(), &vpnvalidatorpb.QueryValidatorStatusRecordRequest{
		StatusId: statusID,
	})
	if err != nil {
		t.Fatalf("query validator status failed: %v", err)
	}
	if !statusByID.GetFound() {
		t.Fatal("expected validator status found=true")
	}
	if statusByID.GetRecord().GetLifecycleStatus() != "active" {
		t.Fatalf("unexpected validator lifecycle status %q", statusByID.GetRecord().GetLifecycleStatus())
	}

	statusList, err := validatorQuery.ListValidatorStatusRecords(context.Background(), &vpnvalidatorpb.QueryListValidatorStatusRecordsRequest{})
	if err != nil {
		t.Fatalf("list validator statuses failed: %v", err)
	}
	if !containsValidatorStatusID(statusList.GetRecords(), statusID) {
		t.Fatalf("expected validator status %q in list, got %v", statusID, statusList.GetRecords())
	}

	policyID := "governance-policy-runtime-rt-1"
	policyResp, err := governanceMsg.CreatePolicy(context.Background(), &vpngovernancepb.MsgCreatePolicyRequest{
		Policy: &vpngovernancepb.GovernancePolicy{
			PolicyId:        policyID,
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
	if policyResp.GetPolicy().GetPolicyId() != policyID {
		t.Fatalf("unexpected governance policy id %q", policyResp.GetPolicy().GetPolicyId())
	}
	if policyResp.GetIdempotentReplay() || policyResp.GetConflict() {
		t.Fatalf("unexpected governance policy replay/conflict flags: replay=%v conflict=%v", policyResp.GetIdempotentReplay(), policyResp.GetConflict())
	}

	policyByID, err := governanceQuery.GovernancePolicy(context.Background(), &vpngovernancepb.QueryGovernancePolicyRequest{
		PolicyId: policyID,
	})
	if err != nil {
		t.Fatalf("query governance policy failed: %v", err)
	}
	if !policyByID.GetFound() {
		t.Fatal("expected governance policy found=true")
	}
	if policyByID.GetPolicy().GetTitle() != "Runtime validator policy" {
		t.Fatalf("unexpected governance policy title %q", policyByID.GetPolicy().GetTitle())
	}

	policyList, err := governanceQuery.ListGovernancePolicies(context.Background(), &vpngovernancepb.QueryListGovernancePoliciesRequest{})
	if err != nil {
		t.Fatalf("list governance policies failed: %v", err)
	}
	if !containsGovernancePolicyID(policyList.GetPolicies(), policyID) {
		t.Fatalf("expected governance policy %q in list, got %v", policyID, policyList.GetPolicies())
	}

	decisionID := "governance-decision-runtime-rt-1"
	decisionResp, err := governanceMsg.RecordDecision(context.Background(), &vpngovernancepb.MsgRecordDecisionRequest{
		Decision: &vpngovernancepb.GovernanceDecision{
			DecisionId:    decisionID,
			PolicyId:      policyID,
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
	if decisionResp.GetDecision().GetDecisionId() != decisionID {
		t.Fatalf("unexpected governance decision id %q", decisionResp.GetDecision().GetDecisionId())
	}
	if decisionResp.GetIdempotentReplay() || decisionResp.GetConflict() {
		t.Fatalf("unexpected governance decision replay/conflict flags: replay=%v conflict=%v", decisionResp.GetIdempotentReplay(), decisionResp.GetConflict())
	}

	decisionByID, err := governanceQuery.GovernanceDecision(context.Background(), &vpngovernancepb.QueryGovernanceDecisionRequest{
		DecisionId: decisionID,
	})
	if err != nil {
		t.Fatalf("query governance decision failed: %v", err)
	}
	if !decisionByID.GetFound() {
		t.Fatal("expected governance decision found=true")
	}
	if decisionByID.GetDecision().GetPolicyId() != policyID {
		t.Fatalf("unexpected governance decision policy id %q", decisionByID.GetDecision().GetPolicyId())
	}

	decisionList, err := governanceQuery.ListGovernanceDecisions(context.Background(), &vpngovernancepb.QueryListGovernanceDecisionsRequest{})
	if err != nil {
		t.Fatalf("list governance decisions failed: %v", err)
	}
	if !containsGovernanceDecisionID(decisionList.GetDecisions(), decisionID) {
		t.Fatalf("expected governance decision %q in list, got %v", decisionID, decisionList.GetDecisions())
	}

	actionID := "governance-audit-runtime-rt-1"
	actionResp, err := governanceMsg.RecordAuditAction(context.Background(), &vpngovernancepb.MsgRecordAuditActionRequest{
		Action: &vpngovernancepb.GovernanceAuditAction{
			ActionId:        actionID,
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
	if actionResp.GetAction().GetActionId() != actionID {
		t.Fatalf("unexpected governance audit action id %q", actionResp.GetAction().GetActionId())
	}
	if actionResp.GetIdempotentReplay() || actionResp.GetConflict() {
		t.Fatalf("unexpected governance audit replay/conflict flags: replay=%v conflict=%v", actionResp.GetIdempotentReplay(), actionResp.GetConflict())
	}

	actionByID, err := governanceQuery.GovernanceAuditAction(context.Background(), &vpngovernancepb.QueryGovernanceAuditActionRequest{
		ActionId: actionID,
	})
	if err != nil {
		t.Fatalf("query governance audit action failed: %v", err)
	}
	if !actionByID.GetFound() {
		t.Fatal("expected governance audit action found=true")
	}
	if actionByID.GetAction().GetActor() != "bootstrap-admin" {
		t.Fatalf("unexpected governance audit actor %q", actionByID.GetAction().GetActor())
	}

	actionList, err := governanceQuery.ListGovernanceAuditActions(context.Background(), &vpngovernancepb.QueryListGovernanceAuditActionsRequest{})
	if err != nil {
		t.Fatalf("list governance audit actions failed: %v", err)
	}
	if !containsGovernanceActionID(actionList.GetActions(), actionID) {
		t.Fatalf("expected governance audit action %q in list, got %v", actionID, actionList.GetActions())
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

func containsBillingReservationID(records []*vpnbillingpb.CreditReservation, want string) bool {
	for _, record := range records {
		if record.GetReservationId() == want {
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
