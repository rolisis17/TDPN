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
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	vpnbillingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	vpnsponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
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
		modules: []string{"vpnbilling", "vpnrewards", "vpnslashing", "vpnsponsor"},
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

	expected := "tdpn-chain scaffold ready: vpnbilling, vpnrewards, vpnslashing, vpnsponsor\n"
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
		if sendErr != nil && status.Code(sendErr) != codes.Unimplemented {
			t.Fatalf("expected reflection send unimplemented in auth mode, got %v", sendErr)
		}
		if sendErr == nil {
			_, recvErr := reflectionStream.Recv()
			if status.Code(recvErr) != codes.Unimplemented {
				t.Fatalf("expected reflection recv unimplemented in auth mode, got %v", recvErr)
			}
		}
	} else if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected reflection unimplemented in auth mode, got %v", err)
	}

	billingMsg := vpnbillingpb.NewMsgClient(conn)

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
