package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	vpnbillingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	reflectionv1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type fakeCometRuntime struct {
	started    chan struct{}
	stopped    chan struct{}
	quitCh     chan struct{}
	stopOnce   sync.Once
	startErr   error
	stopErr    error
	startCalls int
	stopCalls  int
}

func newFakeCometRuntime() *fakeCometRuntime {
	return &fakeCometRuntime{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
		quitCh:  make(chan struct{}),
	}
}

func (f *fakeCometRuntime) Start() error {
	f.startCalls++
	close(f.started)
	return f.startErr
}

func (f *fakeCometRuntime) Stop() error {
	f.stopCalls++
	f.stopOnce.Do(func() {
		close(f.quitCh)
		close(f.stopped)
	})
	return f.stopErr
}

func (f *fakeCometRuntime) Quit() <-chan struct{} {
	return f.quitCh
}

func TestParseCometRuntimeConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		homeDir      string
		moniker      string
		p2pListen    string
		rpcListen    string
		proxyApp     string
		wantEnabled  bool
		wantErr      string
		wantHomeDir  string
		wantMoniker  string
		wantP2P      string
		wantRPC      string
		wantProxyApp string
	}{
		{
			name:        "disabled-when-empty",
			wantEnabled: false,
		},
		{
			name:         "trimmed-and-defaulted",
			homeDir:      "  runtime-home  ",
			moniker:      "\ttdpn-node\t",
			p2pListen:    " 127.0.0.1:26656 ",
			rpcListen:    "\n127.0.0.1:26657\n",
			wantEnabled:  true,
			wantHomeDir:  "runtime-home",
			wantMoniker:  "tdpn-node",
			wantP2P:      "127.0.0.1:26656",
			wantRPC:      "127.0.0.1:26657",
			wantProxyApp: defaultCometProxyApp,
		},
		{
			name:      "missing-home",
			moniker:   "tdpn-node",
			p2pListen: "127.0.0.1:26656",
			rpcListen: "127.0.0.1:26657",
			wantErr:   "--comet-home is required when comet mode is enabled",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, enabled, err := parseCometRuntimeConfig(tc.homeDir, tc.moniker, tc.p2pListen, tc.rpcListen, tc.proxyApp)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got cfg=%+v enabled=%v err=%v", tc.wantErr, cfg, enabled, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if enabled != tc.wantEnabled {
				t.Fatalf("expected enabled=%v, got %v", tc.wantEnabled, enabled)
			}
			if !enabled {
				return
			}
			if cfg.homeDir != tc.wantHomeDir {
				t.Fatalf("unexpected home dir %q", cfg.homeDir)
			}
			if cfg.moniker != tc.wantMoniker {
				t.Fatalf("unexpected moniker %q", cfg.moniker)
			}
			if cfg.p2pListen != tc.wantP2P {
				t.Fatalf("unexpected p2p listen %q", cfg.p2pListen)
			}
			if cfg.rpcListen != tc.wantRPC {
				t.Fatalf("unexpected rpc listen %q", cfg.rpcListen)
			}
			if cfg.proxyApp != tc.wantProxyApp {
				t.Fatalf("unexpected proxy app %q", cfg.proxyApp)
			}
		})
	}
}

func TestValidateCometRuntimeConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		cfg     cometRuntimeConfig
		wantErr string
	}{
		{
			name: "missing-home",
			cfg: cometRuntimeConfig{
				moniker:   "tdpn-node",
				p2pListen: "127.0.0.1:26656",
				rpcListen: "127.0.0.1:26657",
			},
			wantErr: "comet home is required",
		},
		{
			name: "missing-moniker",
			cfg: cometRuntimeConfig{
				homeDir:   "runtime-home",
				p2pListen: "127.0.0.1:26656",
				rpcListen: "127.0.0.1:26657",
			},
			wantErr: "comet moniker is required",
		},
		{
			name: "missing-p2p",
			cfg: cometRuntimeConfig{
				homeDir:   "runtime-home",
				moniker:   "tdpn-node",
				rpcListen: "127.0.0.1:26657",
			},
			wantErr: "comet p2p listen address is required",
		},
		{
			name: "missing-rpc",
			cfg: cometRuntimeConfig{
				homeDir:   "runtime-home",
				moniker:   "tdpn-node",
				p2pListen: "127.0.0.1:26656",
			},
			wantErr: "comet rpc listen address is required",
		},
		{
			name: "valid",
			cfg: cometRuntimeConfig{
				homeDir:   "runtime-home",
				moniker:   "tdpn-node",
				p2pListen: "127.0.0.1:26656",
				rpcListen: "127.0.0.1:26657",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateCometRuntimeConfig(tc.cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunTDPNDCometModeFlagValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing-moniker",
			args: []string{
				"--comet-home", "runtime-home",
				"--comet-p2p-laddr", "127.0.0.1:26656",
				"--comet-rpc-laddr", "127.0.0.1:26657",
			},
			want: "--comet-moniker is required",
		},
		{
			name: "missing-p2p",
			args: []string{
				"--comet-home", "runtime-home",
				"--comet-moniker", "tdpn-test",
				"--comet-rpc-laddr", "127.0.0.1:26657",
			},
			want: "--comet-p2p-laddr is required",
		},
		{
			name: "missing-rpc",
			args: []string{
				"--comet-home", "runtime-home",
				"--comet-moniker", "tdpn-test",
				"--comet-p2p-laddr", "127.0.0.1:26656",
			},
			want: "--comet-rpc-laddr is required",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			called := false
			err := runTDPND(
				context.Background(),
				tc.args,
				nil,
				func() chainScaffold { return &fakeScaffold{modules: []string{"vpnbilling"}} },
				runtimeDeps{
					NewCometRuntime: func(context.Context, cometRuntimeConfig, chainScaffold) (cometRuntime, error) {
						called = true
						return nil, errors.New("unexpected comet runtime creation")
					},
				},
			)
			if err == nil {
				t.Fatalf("expected comet validation error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
			if called {
				t.Fatalf("expected comet runtime factory not to be called for %s", tc.name)
			}
		})
	}
}

func TestRunTDPNDCometModeLifecycleOnCancel(t *testing.T) {
	scaffold := &fakeScaffold{modules: []string{"vpnbilling", "vpnrewards"}}
	runtime := newFakeCometRuntime()
	var captured cometRuntimeConfig

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--comet-home", "runtime-home",
				"--comet-moniker", "tdpn-test",
				"--comet-p2p-laddr", "127.0.0.1:26656",
				"--comet-rpc-laddr", "127.0.0.1:26657",
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				NewCometRuntime: func(_ context.Context, cfg cometRuntimeConfig, _ chainScaffold) (cometRuntime, error) {
					captured = cfg
					return runtime, nil
				},
			},
		)
	}()

	select {
	case <-runtime.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for comet runtime to start")
	}

	if captured.homeDir != "runtime-home" {
		t.Fatalf("unexpected comet home %q", captured.homeDir)
	}
	if captured.moniker != "tdpn-test" {
		t.Fatalf("unexpected comet moniker %q", captured.moniker)
	}
	if captured.p2pListen != "127.0.0.1:26656" {
		t.Fatalf("unexpected comet p2p listen %q", captured.p2pListen)
	}
	if captured.rpcListen != "127.0.0.1:26657" {
		t.Fatalf("unexpected comet rpc listen %q", captured.rpcListen)
	}
	if captured.proxyApp != defaultCometProxyApp {
		t.Fatalf("expected comet proxy app default %q, got %q", defaultCometProxyApp, captured.proxyApp)
	}

	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected clean comet shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for comet runtime shutdown")
	}

	select {
	case <-runtime.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("expected comet runtime Stop to be called")
	}

	if runtime.startCalls != 1 {
		t.Fatalf("expected one Start call, got %d", runtime.startCalls)
	}
	if runtime.stopCalls == 0 {
		t.Fatal("expected Stop to be called at least once")
	}
}

func TestRunCometModeStopsRuntimeOnStartError(t *testing.T) {
	t.Parallel()

	scaffold := &fakeScaffold{modules: []string{"vpnbilling"}}
	runtime := newFakeCometRuntime()
	runtime.startErr = errors.New("boom")

	err := runCometMode(
		context.Background(),
		scaffold,
		cometRuntimeConfig{
			homeDir:   "runtime-home",
			moniker:   "tdpn-node",
			p2pListen: "127.0.0.1:26656",
			rpcListen: "127.0.0.1:26657",
			proxyApp:  defaultCometProxyApp,
		},
		func(context.Context, cometRuntimeConfig, chainScaffold) (cometRuntime, error) {
			return runtime, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "start comet runtime") {
		t.Fatalf("expected wrapped start error, got %v", err)
	}

	select {
	case <-runtime.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("expected Stop to be called after start failure")
	}
	if runtime.stopCalls == 0 {
		t.Fatal("expected Stop to be called at least once after start failure")
	}
}

func TestRunTDPNDMixedCometGRPCSettlementLifecycle(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fakeRuntime := newFakeCometRuntime()
	grpcServer := newFakeGRPCServer()
	scaffold := app.NewChainScaffold()
	var captured cometRuntimeConfig

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--comet-home", "runtime-home",
				"--comet-moniker", "tdpn-node",
				"--comet-p2p-laddr", "127.0.0.1:26656",
				"--comet-rpc-laddr", "127.0.0.1:26657",
				"--grpc-listen", "grpc-mixed-test",
				"--settlement-http-listen", "settlement-mixed-test",
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, address string) (net.Listener, error) {
					if address != "grpc-mixed-test" {
						return nil, errors.New("unexpected grpc listen address")
					}
					return &fakeListener{}, nil
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-mixed-test" {
						return nil, errors.New("unexpected settlement listen address")
					}
					return httpListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					_ = opts
					return grpcServer
				},
				NewCometRuntime: func(_ context.Context, cfg cometRuntimeConfig, _ chainScaffold) (cometRuntime, error) {
					captured = cfg
					return fakeRuntime, nil
				},
			},
		)
	}()

	select {
	case <-fakeRuntime.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for comet runtime to start")
	}
	select {
	case <-grpcServer.serveStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for grpc runtime to start")
	}

	baseURL := "http://" + httpListener.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(baseURL + "/health")
		if err == nil {
			var payload map[string]any
			decodeErr := json.NewDecoder(resp.Body).Decode(&payload)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && decodeErr == nil && payload["status"] == "ok" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for settlement HTTP health on %s", baseURL)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if captured.homeDir != "runtime-home" {
		t.Fatalf("unexpected comet home %q", captured.homeDir)
	}
	if captured.moniker != "tdpn-node" {
		t.Fatalf("unexpected comet moniker %q", captured.moniker)
	}
	if captured.proxyApp != defaultCometProxyApp {
		t.Fatalf("expected default proxy app %q, got %q", defaultCometProxyApp, captured.proxyApp)
	}

	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected clean mixed-mode shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mixed-mode shutdown")
	}

	select {
	case <-fakeRuntime.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("expected comet runtime Stop to be called")
	}
	if fakeRuntime.stopCalls == 0 {
		t.Fatal("expected comet runtime Stop to be called at least once")
	}
	if grpcServer.gracefulCalls == 0 {
		t.Fatal("expected grpc GracefulStop to be called")
	}
}

func TestRunTDPNDMixedCometGRPCQueryDispatchAvailability(t *testing.T) {
	bufListener := bufconn.Listen(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fakeRuntime := newFakeCometRuntime()
	scaffold := app.NewChainScaffold()
	var captured cometRuntimeConfig

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--comet-home", "runtime-home",
				"--comet-moniker", "tdpn-node",
				"--comet-p2p-laddr", "127.0.0.1:26656",
				"--comet-rpc-laddr", "127.0.0.1:26657",
				"--grpc-listen", "bufnet",
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, address string) (net.Listener, error) {
					if address != "bufnet" {
						return nil, errors.New("unexpected grpc listen address")
					}
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
				NewCometRuntime: func(_ context.Context, cfg cometRuntimeConfig, _ chainScaffold) (cometRuntime, error) {
					captured = cfg
					return fakeRuntime, nil
				},
			},
		)
	}()

	select {
	case <-fakeRuntime.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for comet runtime to start")
	}

	if captured.homeDir != "runtime-home" {
		t.Fatalf("unexpected comet home %q", captured.homeDir)
	}
	if captured.moniker != "tdpn-node" {
		t.Fatalf("unexpected comet moniker %q", captured.moniker)
	}
	if captured.proxyApp != defaultCometProxyApp {
		t.Fatalf("expected default proxy app %q, got %q", defaultCometProxyApp, captured.proxyApp)
	}

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
		t.Fatalf("grpc health check failed: %v", err)
	}
	if healthResp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("expected grpc health status SERVING, got %v", healthResp.GetStatus())
	}

	billingMsg := vpnbillingpb.NewMsgClient(conn)
	billingQuery := vpnbillingpb.NewQueryClient(conn)

	const reservationID = "res-mixed-query-dispatch-1"
	if _, err := billingMsg.ReserveCredits(context.Background(), &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: reservationID,
			SponsorId:     "sponsor-mixed-query-dispatch-1",
			SessionId:     "sess-mixed-query-dispatch-1",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("billing reserve credits failed: %v", err)
	}

	billingGetResp, err := billingQuery.CreditReservation(context.Background(), &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: reservationID,
	})
	if err != nil {
		t.Fatalf("billing get reservation failed: %v", err)
	}
	if !billingGetResp.GetFound() {
		t.Fatal("expected billing reservation found=true")
	}
	if billingGetResp.GetReservation().GetReservationId() != reservationID {
		t.Fatalf("unexpected billing reservation id %q", billingGetResp.GetReservation().GetReservationId())
	}

	billingListResp, err := billingQuery.ListCreditReservations(context.Background(), &vpnbillingpb.QueryListCreditReservationsRequest{})
	if err != nil {
		t.Fatalf("billing list reservations failed: %v", err)
	}
	if !containsBillingReservationID(billingListResp.GetReservations(), reservationID) {
		t.Fatalf("expected reservation %q in billing list, got %v", reservationID, billingListResp.GetReservations())
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected clean mixed-mode shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mixed-mode shutdown")
	}

	select {
	case <-fakeRuntime.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("expected comet runtime Stop to be called")
	}
	if fakeRuntime.stopCalls == 0 {
		t.Fatal("expected comet runtime Stop to be called at least once")
	}
}

func TestRunTDPNDMixedCometGRPCAuthEnforcementAndHealth(t *testing.T) {
	const authToken = "tdpn-comet-mixed-auth-token"

	bufListener := bufconn.Listen(1024 * 1024)
	defer bufListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fakeRuntime := newFakeCometRuntime()
	scaffold := app.NewChainScaffold()
	var captured cometRuntimeConfig

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--comet-home", "runtime-home",
				"--comet-moniker", "tdpn-node",
				"--comet-p2p-laddr", "127.0.0.1:26656",
				"--comet-rpc-laddr", "127.0.0.1:26657",
				"--grpc-listen", "bufnet",
				"--grpc-auth-token", authToken,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, address string) (net.Listener, error) {
					if address != "bufnet" {
						return nil, errors.New("unexpected grpc listen address")
					}
					return bufListener, nil
				},
				NewGRPCServer: func(opts ...grpc.ServerOption) grpcRuntimeServer {
					return grpc.NewServer(opts...)
				},
				NewCometRuntime: func(_ context.Context, cfg cometRuntimeConfig, _ chainScaffold) (cometRuntime, error) {
					captured = cfg
					return fakeRuntime, nil
				},
			},
		)
	}()

	select {
	case <-fakeRuntime.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for comet runtime to start")
	}

	if captured.homeDir != "runtime-home" {
		t.Fatalf("unexpected comet home %q", captured.homeDir)
	}
	if captured.moniker != "tdpn-node" {
		t.Fatalf("unexpected comet moniker %q", captured.moniker)
	}
	if captured.proxyApp != defaultCometProxyApp {
		t.Fatalf("expected default proxy app %q, got %q", defaultCometProxyApp, captured.proxyApp)
	}

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
		t.Fatalf("grpc health check failed: %v", err)
	}
	if healthResp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("expected grpc health status SERVING, got %v", healthResp.GetStatus())
	}

	// Reflection must remain disabled in auth mode, including mixed comet+grpc runtime.
	reflectionClient := reflectionv1alpha.NewServerReflectionClient(conn)
	reflectionStream, err := reflectionClient.ServerReflectionInfo(context.Background())
	if err == nil {
		sendErr := reflectionStream.Send(&reflectionv1alpha.ServerReflectionRequest{
			MessageRequest: &reflectionv1alpha.ServerReflectionRequest_ListServices{
				ListServices: "*",
			},
		})
		if sendErr != nil && !isReflectionDisabledErr(sendErr) {
			t.Fatalf("expected reflection send disabled in mixed auth mode, got %v", sendErr)
		}
		if sendErr == nil {
			_, recvErr := reflectionStream.Recv()
			if !isReflectionDisabledErr(recvErr) {
				t.Fatalf("expected reflection recv disabled in mixed auth mode, got %v", recvErr)
			}
		}
	} else if !isReflectionDisabledErr(err) {
		t.Fatalf("expected reflection disabled in mixed auth mode, got %v", err)
	}

	billingQuery := vpnbillingpb.NewQueryClient(conn)
	billingMsg := vpnbillingpb.NewMsgClient(conn)
	_, err = billingQuery.ListCreditReservations(context.Background(), &vpnbillingpb.QueryListCreditReservationsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated vpnbilling query without token, got %v", err)
	}

	wrongTokenCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer wrong-token")
	_, err = billingQuery.ListCreditReservations(wrongTokenCtx, &vpnbillingpb.QueryListCreditReservationsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated vpnbilling query with wrong token, got %v", err)
	}

	authCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+authToken)
	const reservationID = "res-mixed-auth-enforcement-1"
	_, err = billingMsg.ReserveCredits(authCtx, &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: reservationID,
			SponsorId:     "sponsor-mixed-auth-enforcement-1",
			SessionId:     "sess-mixed-auth-enforcement-1",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	})
	if err != nil {
		t.Fatalf("expected authorized reserve success, got %v", err)
	}

	authorizedResp, err := billingQuery.ListCreditReservations(authCtx, &vpnbillingpb.QueryListCreditReservationsRequest{})
	if err != nil {
		t.Fatalf("expected authorized vpnbilling query success, got %v", err)
	}
	if authorizedResp == nil {
		t.Fatal("expected non-nil authorized vpnbilling query response")
	}
	foundReservation := false
	for _, record := range authorizedResp.GetReservations() {
		if record.GetReservationId() == reservationID {
			foundReservation = true
			break
		}
	}
	if !foundReservation {
		t.Fatalf("expected reservation %q in authorized vpnbilling list query, got %v", reservationID, authorizedResp.GetReservations())
	}

	_, err = billingQuery.CreditReservation(context.Background(), &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: reservationID,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated vpnbilling by-id query without token, got %v", err)
	}

	_, err = billingQuery.CreditReservation(wrongTokenCtx, &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: reservationID,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated vpnbilling by-id query with wrong token, got %v", err)
	}

	authorizedByIDResp, err := billingQuery.CreditReservation(authCtx, &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: reservationID,
	})
	if err != nil {
		t.Fatalf("expected authorized vpnbilling by-id query success, got %v", err)
	}
	if !authorizedByIDResp.GetFound() {
		t.Fatal("expected authorized vpnbilling by-id query found=true")
	}
	if authorizedByIDResp.GetReservation().GetReservationId() != reservationID {
		t.Fatalf("expected authorized vpnbilling by-id query reservation %q, got %q", reservationID, authorizedByIDResp.GetReservation().GetReservationId())
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close grpc conn: %v", err)
	}
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected clean mixed-mode shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mixed-mode shutdown")
	}

	select {
	case <-fakeRuntime.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("expected comet runtime Stop to be called")
	}
	if fakeRuntime.stopCalls == 0 {
		t.Fatal("expected comet runtime Stop to be called at least once")
	}
}

func TestTDPNCometApplicationComputeAppHashIgnoresHostLocalConfig(t *testing.T) {
	t.Parallel()

	appA := &tdpndCometApplication{
		moniker:  "node-a",
		homeDir:  "/tmp/node-a",
		proxyApp: "proxy-a",
		modules:  []string{"vpnbilling", "vpnsponsor"},
	}
	appB := &tdpndCometApplication{
		moniker:  "node-b",
		homeDir:  "/var/lib/node-b",
		proxyApp: "proxy-b",
		modules:  []string{"vpnbilling", "vpnsponsor"},
	}

	hashA := appA.computeAppHash(11)
	hashB := appB.computeAppHash(11)
	if !bytes.Equal(hashA, hashB) {
		t.Fatalf("expected app hash to ignore host-local config, got %X and %X", hashA, hashB)
	}
}

func TestTDPNCometApplicationComputeAppHashStableForModuleOrder(t *testing.T) {
	t.Parallel()

	appA := &tdpndCometApplication{modules: []string{"vpnbilling", "vpnsponsor", "vpnrewards"}}
	appB := &tdpndCometApplication{modules: []string{"vpnrewards", "vpnbilling", "vpnsponsor"}}

	hashA := appA.computeAppHash(19)
	hashB := appB.computeAppHash(19)
	if !bytes.Equal(hashA, hashB) {
		t.Fatalf("expected app hash to be order-independent for modules, got %X and %X", hashA, hashB)
	}
}

func TestTDPNCometApplicationComputeAppHashChangesWithHeight(t *testing.T) {
	t.Parallel()

	app := &tdpndCometApplication{modules: []string{"vpnbilling", "vpnsponsor"}}
	hashAtHeightOne := app.computeAppHash(1)
	hashAtHeightTwo := app.computeAppHash(2)
	if bytes.Equal(hashAtHeightOne, hashAtHeightTwo) {
		t.Fatalf("expected app hash to vary by height, got %X for both heights", hashAtHeightOne)
	}
}
