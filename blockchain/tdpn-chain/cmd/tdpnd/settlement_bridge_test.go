package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	urlpkg "net/url"
	"strings"
	"testing"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
	governancemodule "github.com/tdpn/tdpn-chain/x/vpngovernance/module"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
	rewardtypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
	validatormodule "github.com/tdpn/tdpn-chain/x/vpnvalidator/module"
	validatortypes "github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

func TestRunTDPNDSettlementHTTPHealth(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-test" {
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

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected health status 200, got %d", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode health payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected health payload status ok, got %v", payload["status"])
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

func TestRunTDPNDSettlementHTTPUnauthenticatedModeRejectsCrossOriginWrites(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-origin-guard-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-origin-guard-test" {
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

	payload := []byte(`{"EvidenceID":"ev-origin-guard-1","SubjectID":"provider-origin-guard-1","SessionID":"sess-origin-guard-1","ViolationType":"double-sign","EvidenceRef":"sha256:dcae4c8808ecbf9c1374201b09c7706b90df20b57e0aaf25e36a1053a421ea8a","ObservedAt":"2026-01-01T00:00:00Z"}`)
	crossOriginReq, err := http.NewRequest(http.MethodPost, baseURL+"/x/vpnslashing/evidence", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build cross-origin request: %v", err)
	}
	crossOriginReq.Header.Set("Content-Type", "application/json")
	crossOriginReq.Header.Set("Origin", "https://evil.example")
	crossOriginResp, err := http.DefaultClient.Do(crossOriginReq)
	if err != nil {
		t.Fatalf("cross-origin post failed: %v", err)
	}
	_ = crossOriginResp.Body.Close()
	if crossOriginResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected cross-origin unauthenticated POST to return 403, got %d", crossOriginResp.StatusCode)
	}

	localhostForeignPortReq, err := http.NewRequest(http.MethodPost, baseURL+"/x/vpnslashing/evidence", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build localhost foreign-port request: %v", err)
	}
	localhostForeignPortReq.Header.Set("Content-Type", "application/json")
	localhostForeignPortReq.Header.Set("Origin", "http://localhost:3000")
	localhostForeignPortResp, err := http.DefaultClient.Do(localhostForeignPortReq)
	if err != nil {
		t.Fatalf("localhost foreign-port post failed: %v", err)
	}
	_ = localhostForeignPortResp.Body.Close()
	if localhostForeignPortResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected localhost foreign-port origin to return 403, got %d", localhostForeignPortResp.StatusCode)
	}

	sameOriginReq, err := http.NewRequest(http.MethodPost, baseURL+"/x/vpnslashing/evidence", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build same-origin request: %v", err)
	}
	sameOriginReq.Header.Set("Content-Type", "application/json")
	sameOriginReq.Header.Set("Origin", baseURL)
	sameOriginResp, err := http.DefaultClient.Do(sameOriginReq)
	if err != nil {
		t.Fatalf("same-origin post failed: %v", err)
	}
	_ = sameOriginResp.Body.Close()
	if sameOriginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected same-origin unauthenticated POST to return 200, got %d", sameOriginResp.StatusCode)
	}

	cliReq, err := http.NewRequest(http.MethodPost, baseURL+"/x/vpnslashing/evidence", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build local request: %v", err)
	}
	cliReq.Header.Set("Content-Type", "application/json")
	cliResp, err := http.DefaultClient.Do(cliReq)
	if err != nil {
		t.Fatalf("local post failed: %v", err)
	}
	_ = cliResp.Body.Close()
	if cliResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected local unauthenticated POST without Origin to return 403, got %d", cliResp.StatusCode)
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

func TestSettlementBridgeAuthorizeRequestUnauthenticatedRequiresLoopbackRemote(t *testing.T) {
	handler := &settlementBridgeHandler{
		authToken:  "",
		listenAddr: "127.0.0.1:8081",
	}

	remoteReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081/x/vpnslashing/evidence", nil)
	remoteReq.RemoteAddr = "203.0.113.10:40000"
	remoteReq.Header.Set("Origin", "http://127.0.0.1:8081")
	remoteRR := httptest.NewRecorder()
	if handler.authorizeRequest(remoteRR, remoteReq) {
		t.Fatal("expected non-loopback unauthenticated request to be rejected")
	}
	if remoteRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback unauthenticated request, got %d", remoteRR.Code)
	}

	loopbackReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081/x/vpnslashing/evidence", nil)
	loopbackReq.RemoteAddr = "127.0.0.1:40001"
	loopbackReq.Header.Set("Origin", "http://127.0.0.1:8081")
	loopbackRR := httptest.NewRecorder()
	if !handler.authorizeRequest(loopbackRR, loopbackReq) {
		t.Fatalf("expected loopback unauthenticated request to be accepted, got status %d", loopbackRR.Code)
	}
}

func TestSettlementBridgeHealthBypassRequiresLoopbackWhenAuthEnabled(t *testing.T) {
	handler := &settlementBridgeHandler{
		authToken:  "bridge-secret-token",
		listenAddr: "127.0.0.1:8081",
	}
	routes := handler.routes()

	remoteReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/health", nil)
	remoteReq.RemoteAddr = "203.0.113.10:40100"
	remoteRR := httptest.NewRecorder()
	routes.ServeHTTP(remoteRR, remoteReq)
	if remoteRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected remote unauthenticated health request to return 401, got %d body=%s", remoteRR.Code, remoteRR.Body.String())
	}

	loopbackReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/health", nil)
	loopbackReq.RemoteAddr = "127.0.0.1:40101"
	loopbackRR := httptest.NewRecorder()
	routes.ServeHTTP(loopbackRR, loopbackReq)
	if loopbackRR.Code != http.StatusOK {
		t.Fatalf("expected loopback health request to bypass auth and return 200, got %d body=%s", loopbackRR.Code, loopbackRR.Body.String())
	}
}

func TestSettlementBridgeLoopbackHostCheckRequiresAllResolvedIPsLoopback(t *testing.T) {
	allLoopbackHostCheck := func(host string) bool {
		return isLoopbackHostWithLookup(host, func(_ context.Context, lookupHost string) ([]net.IPAddr, error) {
			switch strings.TrimSpace(strings.ToLower(lookupHost)) {
			case "localhost":
				return []net.IPAddr{
					{IP: net.ParseIP("127.0.0.1")},
					{IP: net.ParseIP("::1")},
				}, nil
			default:
				return nil, errors.New("lookup failed")
			}
		})
	}
	mixedHostCheck := func(host string) bool {
		return isLoopbackHostWithLookup(host, func(_ context.Context, lookupHost string) ([]net.IPAddr, error) {
			switch strings.TrimSpace(strings.ToLower(lookupHost)) {
			case "localhost":
				return []net.IPAddr{
					{IP: net.ParseIP("127.0.0.1")},
					{IP: net.ParseIP("203.0.113.20")},
				}, nil
			default:
				return nil, errors.New("lookup failed")
			}
		})
	}

	if !isAllowedUnauthenticatedOriginWithLoopbackCheck("http://localhost:8081", "localhost:8081", allLoopbackHostCheck) {
		t.Fatal("expected localhost origin/listen to be accepted when all resolved IPs are loopback")
	}
	if isAllowedUnauthenticatedOriginWithLoopbackCheck("http://localhost:8081", "localhost:8081", mixedHostCheck) {
		t.Fatal("expected localhost origin/listen to be rejected when any resolved IP is non-loopback")
	}
	if !isLoopbackRemoteAddrWithLoopbackCheck("localhost:40101", allLoopbackHostCheck) {
		t.Fatal("expected localhost remote addr to be loopback when all resolved IPs are loopback")
	}
	if isLoopbackRemoteAddrWithLoopbackCheck("localhost:40101", mixedHostCheck) {
		t.Fatal("expected localhost remote addr to be non-loopback when any resolved IP is non-loopback")
	}
	if got := listenAddressPortWithLoopbackCheck("localhost:8081", mixedHostCheck); got != "" {
		t.Fatalf("expected no listen port when localhost resolves to mixed addresses, got %q", got)
	}
}

func TestSettlementBridgeAuthorizeRequestUnauthenticatedAllowsLocalhostOrigin(t *testing.T) {
	handler := &settlementBridgeHandler{
		authToken:  "",
		listenAddr: "localhost:8081",
	}

	localhostReq := httptest.NewRequest(http.MethodPost, "http://localhost:8081/x/vpnslashing/evidence", nil)
	localhostReq.RemoteAddr = "localhost:40111"
	localhostReq.Header.Set("Origin", "http://localhost:8081")
	localhostRR := httptest.NewRecorder()
	if !handler.authorizeRequest(localhostRR, localhostReq) {
		t.Fatalf("expected localhost unauthenticated request to be accepted, got status %d", localhostRR.Code)
	}
}

func TestSettlementBridgeHealthBypassAllowsLocalhostWhenAuthEnabled(t *testing.T) {
	handler := &settlementBridgeHandler{
		authToken:  "bridge-secret-token",
		listenAddr: "localhost:8081",
	}
	routes := handler.routes()

	localhostReq := httptest.NewRequest(http.MethodGet, "http://localhost:8081/health", nil)
	localhostReq.RemoteAddr = "localhost:40112"
	localhostRR := httptest.NewRecorder()
	routes.ServeHTTP(localhostRR, localhostReq)
	if localhostRR.Code != http.StatusOK {
		t.Fatalf("expected localhost health request to bypass auth and return 200, got %d body=%s", localhostRR.Code, localhostRR.Body.String())
	}
}

func TestRunTDPNDSettlementHTTPAuthRequiredOnPOST(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const authToken = "bridge-secret"

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-auth-test",
				"--settlement-http-auth-token", authToken,
			},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-auth-test" {
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

	healthResp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	_ = healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected health status 200 with auth enabled, got %d", healthResp.StatusCode)
	}

	payload := []byte(`{"EvidenceID":"ev-auth-1","SubjectID":"provider-auth-1","SessionID":"sess-auth-1","ViolationType":"double-sign","EvidenceRef":"sha256:dcae4c8808ecbf9c1374201b09c7706b90df20b57e0aaf25e36a1053a421ea8a","ObservedAt":"2026-01-01T00:00:00Z"}`)
	unauthResp, err := http.Post(baseURL+"/x/vpnslashing/evidence", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("unauth post failed: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated POST, got %d", unauthResp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/x/vpnslashing/evidence", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	authResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authenticated post failed: %v", err)
	}
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for authenticated POST, got %d", authResp.StatusCode)
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

func TestRunTDPNDSettlementHTTPAuthContractGETAndPOSTBearerRequired(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const authToken = "bridge-contract-secret"
	const finalityToken = "bridge-contract-finality-secret"
	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-auth-contract-test",
				"--settlement-http-auth-token", authToken,
				"--settlement-http-finality-auth-token", finalityToken,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-auth-contract-test" {
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

	status, payload := doJSONRequest(t, http.MethodGet, baseURL+"/health", "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected health endpoint to remain open in auth mode, got %d payload=%v", status, payload)
	}

	authGetPaths := []string{
		"/x/vpnbilling/reservations",
		"/x/vpnbilling/settlements",
		"/x/vpnrewards/accruals",
		"/x/vpnrewards/distributions",
		"/x/vpnsponsor/authorizations",
		"/x/vpnsponsor/delegations",
		"/x/vpnslashing/evidence",
		"/x/vpnslashing/penalties",
		"/x/vpnvalidator/eligibilities",
		"/x/vpnvalidator/status-records",
		"/x/vpngovernance/policies",
		"/x/vpngovernance/decisions",
		"/x/vpngovernance/audit-actions",
	}
	validHeaders := settlementFinalityHeaders(authToken, finalityToken)
	seedBillingReservation(t, scaffold, "res-auth-contract-1", "sess-auth-contract-1", "subject-auth-contract-1", "uusdc", 250)
	rewardAuthProofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-auth-contract-1",
		"reward-auth-contract-1",
		"provider-auth-contract-1",
		"sess-auth-contract-1",
		100,
		"uusdc",
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Time{},
		time.Time{},
	)
	for _, path := range authGetPaths {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+path, "", nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("expected unauthenticated GET %s to return 401 in auth mode, got %d payload=%v", path, status, payload)
		}
		status, payload = doJSONRequest(t, http.MethodGet, baseURL+path, "", validHeaders)
		if status != http.StatusOK {
			t.Fatalf("expected authenticated GET %s to return 200 in auth mode, got %d payload=%v", path, status, payload)
		}
	}

	testCases := []struct {
		name      string
		postPath  string
		postBody  string
		verifyGET string
	}{
		{
			name:      "billing-reservation",
			postPath:  "/x/vpnbilling/reservations",
			postBody:  `{"ReservationID":"res-auth-contract-create-1","SessionID":"sess-auth-contract-create-1","SubjectID":"subject-auth-contract-create-1","AmountMicros":250,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z"}`,
			verifyGET: "/x/vpnbilling/reservations/res-auth-contract-create-1",
		},
		{
			name:      "billing",
			postPath:  "/x/vpnbilling/settlements",
			postBody:  `{"SettlementID":"set-auth-contract-1","ReservationID":"res-auth-contract-1","SessionID":"sess-auth-contract-1","SubjectID":"subject-auth-contract-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
			verifyGET: "/x/vpnbilling/settlements/set-auth-contract-1",
		},
		{
			name:      "rewards",
			postPath:  "/x/vpnrewards/issues",
			postBody:  `{"RewardID":"reward-auth-contract-1","ProviderSubjectID":"provider-auth-contract-1","SessionID":"sess-auth-contract-1","SettlementReferenceID":"set-auth-contract-1","TrafficProofRef":"` + rewardAuthProofRef + `","PayoutPeriodStart":"2025-12-29T00:00:00Z","PayoutPeriodEnd":"2026-01-05T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
			verifyGET: "/x/vpnrewards/accruals/reward-auth-contract-1",
		},
		{
			name:      "sponsor",
			postPath:  "/x/vpnsponsor/reservations",
			postBody:  `{"ReservationID":"sponsor-res-auth-contract-1","SponsorID":"sponsor-auth-contract-1","SubjectID":"app-auth-contract-1","SessionID":"sess-auth-contract-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
			verifyGET: "/x/vpnsponsor/delegations/sponsor-res-auth-contract-1",
		},
		{
			name:      "slashing",
			postPath:  "/x/vpnslashing/evidence",
			postBody:  `{"EvidenceID":"ev-auth-contract-1","SubjectID":"provider-auth-contract-1","SessionID":"sess-auth-contract-1","ViolationType":"double-sign","EvidenceRef":"sha256:688aac5bfff82af2d92ef98edb1a7d98e963b9ed60d96cf66145d29cec3a1d28","ObservedAt":"2026-01-01T00:00:00Z"}`,
			verifyGET: "/x/vpnslashing/evidence/ev-auth-contract-1",
		},
		{
			name:      "validator-eligibility",
			postPath:  "/x/vpnvalidator/eligibilities",
			postBody:  `{"ValidatorID":"val-auth-contract-1","OperatorAddress":"op-auth-contract-1","Eligible":true,"PolicyReason":"bootstrap","UpdatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
			verifyGET: "/x/vpnvalidator/eligibilities/val-auth-contract-1",
		},
		{
			name:      "validator-status",
			postPath:  "/x/vpnvalidator/status-records",
			postBody:  `{"StatusID":"status-auth-contract-1","ValidatorID":"val-auth-contract-1","ConsensusAddress":"cons-auth-contract-1","LifecycleStatus":"active","EvidenceHeight":123,"EvidenceRef":"sha256:762cf93d891338985757d904c8cb5abbf5b8834c16aa526f807c45e3377efdde","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}`,
			verifyGET: "/x/vpnvalidator/status-records/status-auth-contract-1",
		},
		{
			name:      "governance-policy",
			postPath:  "/x/vpngovernance/policies",
			postBody:  `{"PolicyID":"policy-auth-contract-1","Title":"auth-contract-policy","Description":"auth contract test policy","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
			verifyGET: "/x/vpngovernance/policies/policy-auth-contract-1",
		},
		{
			name:      "governance-decision",
			postPath:  "/x/vpngovernance/decisions",
			postBody:  `{"DecisionID":"decision-auth-contract-1","PolicyID":"policy-auth-contract-1","ProposalID":"proposal-auth-contract-1","Outcome":"approve","Decider":"bootstrap-multisig","Reason":"auth contract decision","DecidedAt":"2026-01-01T00:00:02Z","Status":"submitted"}`,
			verifyGET: "/x/vpngovernance/decisions/decision-auth-contract-1",
		},
		{
			name:      "governance-audit-action",
			postPath:  "/x/vpngovernance/audit-actions",
			postBody:  `{"ActionID":"action-auth-contract-1","Action":"admin_set_policy","Actor":"bootstrap-multisig","Reason":"auth contract audit","EvidencePointer":"obj://audit/action-auth-contract-1","Timestamp":"2026-01-01T00:00:03Z"}`,
			verifyGET: "/x/vpngovernance/audit-actions/action-auth-contract-1",
		},
	}

	wrongHeaders := map[string]string{"Authorization": "Bearer wrong-token"}

	for _, tc := range testCases {
		status, payload := doJSONRequest(t, http.MethodPost, baseURL+tc.postPath, tc.postBody, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("[%s] expected unauthenticated POST to return 401, got %d payload=%v", tc.name, status, payload)
		}

		status, payload = doJSONRequest(t, http.MethodPost, baseURL+tc.postPath, tc.postBody, wrongHeaders)
		if status != http.StatusUnauthorized {
			t.Fatalf("[%s] expected wrong bearer POST to return 401, got %d payload=%v", tc.name, status, payload)
		}

		status, payload = doJSONRequest(t, http.MethodPost, baseURL+tc.postPath, tc.postBody, validHeaders)
		if status != http.StatusOK {
			t.Fatalf("[%s] expected valid bearer POST to return 200, got %d payload=%v", tc.name, status, payload)
		}

		status, payload = doJSONRequest(t, http.MethodGet, baseURL+tc.verifyGET, "", nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("[%s] expected unauthenticated GET %s to return 401 after write, got %d payload=%v",
				tc.name, tc.verifyGET, status, payload)
		}
		status, payload = doJSONRequest(t, http.MethodGet, baseURL+tc.verifyGET, "", validHeaders)
		if status != http.StatusOK {
			t.Fatalf("[%s] expected authenticated GET %s to return 200 after write, got %d payload=%v",
				tc.name, tc.verifyGET, status, payload)
		}
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

func TestRunTDPNDSettlementHTTPAuthPrincipalBindsIdentityFields(t *testing.T) {
	const authToken = "bridge-principal-token"
	const finalityToken = "bridge-principal-finality-token"
	const authPrincipal = "Bridge-Principal-1"
	const canonicalPrincipal = "bridge-principal-1"

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-auth-principal-test",
				"--settlement-http-auth-token", authToken,
				"--settlement-http-finality-auth-token", finalityToken,
				"--settlement-http-auth-principal", authPrincipal,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-auth-principal-test" {
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
	authHeaders := settlementFinalityHeaders(authToken, finalityToken)

	sponsorMismatchBody := `{"ReservationID":"sponsor-res-principal-mismatch-1","SponsorID":"other-sponsor","SubjectID":"app-principal-1","SessionID":"sess-principal-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2030-12-31T00:00:00Z"}`
	status, payload := doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnsponsor/reservations", sponsorMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected sponsor caller mismatch to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "SponsorID must match authenticated caller" {
		t.Fatalf("expected sponsor mismatch error, got %q", got)
	}

	sponsorAutofillBody := `{"ReservationID":"sponsor-res-principal-ok-1","SubjectID":"app-principal-1","SessionID":"sess-principal-2","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2030-12-31T00:00:00Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnsponsor/reservations", sponsorAutofillBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected sponsor caller autofill to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/sponsor-res-principal-ok-1", "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected sponsor delegation by-id get to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "delegation", "SponsorID", canonicalPrincipal)

	billingReservationMismatchBody := `{"ReservationID":"billing-res-principal-mismatch-1","SubjectID":"other-principal","SessionID":"sess-principal-reservation-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", billingReservationMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected billing reservation caller mismatch to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "SubjectID must match authenticated caller" {
		t.Fatalf("expected billing reservation subject mismatch error, got %q", got)
	}

	billingReservationAutofillBody := `{"ReservationID":"billing-res-principal-autofill-1","SessionID":"sess-principal-reservation-2","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", billingReservationAutofillBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected billing reservation caller autofill to return 200, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/reservations/billing-res-principal-autofill-1", "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected billing reservation by-id get to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "reservation", "SponsorID", canonicalPrincipal)

	_, err = scaffold.BillingMsgServer().CreateReservation(context.Background(), app.BillingCreateReservationRequest{
		Record: billingtypes.CreditReservation{
			ReservationID: "billing-res-principal-1",
			SponsorID:     canonicalPrincipal,
			SessionID:     "sess-principal-2",
			AssetDenom:    "uusdc",
			Amount:        500,
			Status:        chaintypes.ReconciliationConfirmed,
			CreatedAtUnix: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
		},
	})
	if err != nil {
		t.Fatalf("seed billing reservation: %v", err)
	}

	settlementMismatchBody := `{"SettlementID":"settlement-principal-mismatch-1","ReservationID":"billing-res-principal-1","SessionID":"sess-principal-2","SubjectID":"other-principal","ChargedMicros":500,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:01Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/settlements", settlementMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected settlement subject caller mismatch to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "SubjectID must match authenticated caller" {
		t.Fatalf("expected settlement subject mismatch error, got %q", got)
	}

	settlementAutofillBody := `{"SettlementID":"settlement-principal-ok-1","ReservationID":"billing-res-principal-1","SessionID":"sess-principal-2","ChargedMicros":500,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:02Z","Status":"confirmed"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/settlements", settlementAutofillBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected settlement subject caller autofill to return 200, got %d payload=%v", status, payload)
	}

	rewardMismatchBody := `{"RewardID":"reward-principal-mismatch-1","ProviderSubjectID":"other-principal","SessionID":"sess-principal-3","SettlementReferenceID":"set-principal-mismatch-1","RewardMicros":50,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:03Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnrewards/issues", rewardMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected reward provider caller mismatch to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "ProviderSubjectID must match authenticated caller" {
		t.Fatalf("expected reward provider mismatch error, got %q", got)
	}

	rewardAutofillIssuedAt := time.Date(2026, 1, 1, 0, 0, 4, 0, time.UTC)
	rewardAutofillProofRef := seedVerifiedRewardProof(t, scaffold, "traffic-proof/reward-principal-ok-1", "reward-principal-ok-1", canonicalPrincipal, "sess-principal-4", 51, "uusdc", rewardAutofillIssuedAt, time.Time{}, time.Time{})
	rewardAutofillBody := `{"RewardID":"reward-principal-ok-1","SessionID":"sess-principal-4","TrafficProofRef":"` + rewardAutofillProofRef + `","PayoutPeriodStart":"2025-12-29T00:00:00Z","PayoutPeriodEnd":"2026-01-05T00:00:00Z","RewardMicros":51,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:04Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnrewards/issues", rewardAutofillBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected reward provider caller autofill to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnrewards/accruals/reward-principal-ok-1", "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected reward accrual by-id get to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "accrual", "ProviderID", canonicalPrincipal)

	slashingMismatchBody := `{"EvidenceID":"ev-principal-mismatch-1","SubjectID":"other-principal","SessionID":"sess-principal-5","ViolationType":"double-sign","EvidenceRef":"sha256:ab2607bc705f27357f7b1dd2089fbb6f9d33af74d05574f2d2f9c1ca4f31e22c","ObservedAt":"2026-01-01T00:00:05Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnslashing/evidence", slashingMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected slashing subject caller mismatch to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "SubjectID must match authenticated caller" {
		t.Fatalf("expected slashing subject mismatch error, got %q", got)
	}

	slashingAutofillBody := `{"EvidenceID":"ev-principal-ok-1","SessionID":"sess-principal-6","ViolationType":"double-sign","EvidenceRef":"sha256:ce1ad56555311a8b138899bc99700d80aa1b55950daeab84a859a0c9f5fca6db","ObservedAt":"2026-01-01T00:00:06Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnslashing/evidence", slashingAutofillBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected slashing subject caller autofill to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnslashing/evidence/ev-principal-ok-1", "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected slashing evidence by-id get to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "evidence", "ProviderID", canonicalPrincipal)

	policyBody := `{"PolicyID":"policy-principal-1","Title":"auth-principal-policy","Description":"identity binding policy seed","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpngovernance/policies", policyBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected governance policy seed to return 200, got %d payload=%v", status, payload)
	}

	decisionMismatchBody := `{"DecisionID":"decision-principal-mismatch-1","PolicyID":"policy-principal-1","ProposalID":"proposal-principal-1","Outcome":"approve","Decider":"other-principal","Reason":"mismatch","DecidedAt":"2026-01-01T00:00:01Z","Status":"submitted"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpngovernance/decisions", decisionMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected governance decision caller mismatch to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "Decider must match authenticated caller" {
		t.Fatalf("expected decision mismatch error, got %q", got)
	}

	decisionAutofillBody := `{"DecisionID":"decision-principal-ok-1","PolicyID":"policy-principal-1","ProposalID":"proposal-principal-2","Outcome":"approve","Reason":"autofill","DecidedAt":"2026-01-01T00:00:02Z","Status":"submitted"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpngovernance/decisions", decisionAutofillBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected governance decision caller autofill to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpngovernance/decisions/decision-principal-ok-1", "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected governance decision by-id get to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "decision", "Decider", canonicalPrincipal)

	actionMismatchBody := `{"ActionID":"action-principal-mismatch-1","Action":"admin_set_policy","Actor":"other-principal","Reason":"mismatch","EvidencePointer":"obj://audit/action-principal-mismatch-1","Timestamp":"2026-01-01T00:00:03Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpngovernance/audit-actions", actionMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected governance audit caller mismatch to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "Actor must match authenticated caller" {
		t.Fatalf("expected audit mismatch error, got %q", got)
	}

	actionAutofillBody := `{"ActionID":"action-principal-ok-1","Action":"admin_set_policy","Reason":"autofill","EvidencePointer":"obj://audit/action-principal-ok-1","Timestamp":"2026-01-01T00:00:04Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpngovernance/audit-actions", actionAutofillBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected governance audit caller autofill to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpngovernance/audit-actions/action-principal-ok-1", "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected governance audit by-id get to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "action", "Actor", canonicalPrincipal)

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

func TestRunTDPNDSettlementHTTPAuthPrincipalSettlementAndSlashEdgeCases(t *testing.T) {
	const authToken = "bridge-edge-token"
	const finalityToken = "bridge-edge-finality-token"
	const authPrincipal = "  Bridge-Edge-Principal  "
	const canonicalPrincipal = "bridge-edge-principal"

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-auth-principal-edge-test",
				"--settlement-http-auth-token", authToken,
				"--settlement-http-finality-auth-token", finalityToken,
				"--settlement-http-auth-principal", authPrincipal,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-auth-principal-edge-test" {
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
	authHeaders := settlementFinalityHeaders(authToken, finalityToken)

	seedBillingReservation(t, scaffold, "billing-res-edge-1", "sess-edge-1", canonicalPrincipal, "uusdc", 700)

	settlementMismatchBody := `{"SettlementID":"settlement-edge-mismatch-1","ReservationID":"billing-res-edge-1","SessionID":"sess-edge-1","SubjectID":"  BRIDGE-EDGE-OTHER  ","ChargedMicros":700,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`
	status, payload := doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/settlements", settlementMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected settlement subject mismatch edge case to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "SubjectID must match authenticated caller" {
		t.Fatalf("expected settlement subject mismatch error, got %q", got)
	}

	settlementWhitespaceAutofillBody := `{"SettlementID":"settlement-edge-autofill-1","ReservationID":"billing-res-edge-1","SessionID":"sess-edge-1","SubjectID":"   ","ChargedMicros":700,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:01Z","Status":"confirmed"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/settlements", settlementWhitespaceAutofillBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected settlement whitespace subject autofill to return 200, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/settlements/settlement-edge-autofill-1", "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected settlement by-id get after whitespace autofill to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "settlement", "SettlementID", "settlement-edge-autofill-1")

	slashingMismatchBody := `{"EvidenceID":"ev-edge-mismatch-1","SubjectID":"  BRIDGE-EDGE-OTHER  ","SessionID":"sess-edge-2","ViolationType":"double-sign","EvidenceRef":"sha256:ab2607bc705f27357f7b1dd2089fbb6f9d33af74d05574f2d2f9c1ca4f31e22c","ObservedAt":"2026-01-01T00:00:02Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnslashing/evidence", slashingMismatchBody, authHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("expected slashing subject mismatch edge case to return 403, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "SubjectID must match authenticated caller" {
		t.Fatalf("expected slashing subject mismatch error, got %q", got)
	}

	slashingWhitespaceAutofillWithObjProofBody := `{"EvidenceID":"ev-edge-autofill-1","SubjectID":"   ","SessionID":"sess-edge-3","ViolationType":"  DOWNTIME-PROOF  ","EvidenceRef":"   obj://bridge/edge/proof-1   ","ObservedAt":"2026-01-01T00:00:03Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnslashing/evidence", slashingWhitespaceAutofillWithObjProofBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected slashing whitespace subject autofill with objective proof to return 200, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnslashing/evidence/ev-edge-autofill-1", "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected slashing evidence by-id get after whitespace autofill to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "evidence", "ProviderID", canonicalPrincipal)
	expectJSONStringField(t, payload, "evidence", "ProofHash", "obj://bridge/edge/proof-1")
	expectJSONStringField(t, payload, "evidence", "ViolationType", "downtime-proof")
	expectJSONStringField(t, payload, "evidence", "Kind", slashingtypes.EvidenceKindObjective)

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

func TestRunTDPNDSettlementHTTPSlashEvidenceRejectsInvalidObjectiveRef(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-invalid-evidence-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-invalid-evidence-test" {
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

	cases := []struct {
		name string
		body string
	}{
		{
			name: "invalid prefix",
			body: `{"EvidenceID":"ev-invalid-ref-1","SubjectID":"provider-invalid-ref-1","SessionID":"sess-invalid-ref-1","ViolationType":"double-sign","EvidenceRef":"proof-invalid-ref-1","ObservedAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			name: "short sha256",
			body: `{"EvidenceID":"ev-invalid-ref-short-sha","SubjectID":"provider-invalid-ref-1","SessionID":"sess-invalid-ref-1","ViolationType":"double-sign","EvidenceRef":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde","ObservedAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			name: "object path contains whitespace",
			body: `{"EvidenceID":"ev-invalid-ref-obj-space","SubjectID":"provider-invalid-ref-1","SessionID":"sess-invalid-ref-1","ViolationType":"double-sign","EvidenceRef":"obj://bucket/key with-space","ObservedAt":"2026-01-01T00:00:00Z"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, payload := doJSONRequest(
				t,
				http.MethodPost,
				baseURL+"/x/vpnslashing/evidence",
				tc.body,
				nil,
			)
			if status != http.StatusBadRequest {
				t.Fatalf("expected invalid evidence_ref to return 400, got %d payload=%v", status, payload)
			}

			errorText, _ := payload["error"].(string)
			if !strings.Contains(errorText, "proof hash must use objective format") {
				t.Fatalf("expected invalid format error, got payload=%v", payload)
			}
		})
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

func TestRunTDPNDSettlementHTTPSlashEvidenceValidatesViolationTypesAndRequiredFields(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-violation-type-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-violation-type-test" {
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

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnslashing/evidence",
		`{"EvidenceID":"ev-violation-type-valid-1","SubjectID":"provider-violation-type-valid-1","SessionID":"sess-violation-type-valid-1","ViolationType":"  SESSION-REPLAY-PROOF  ","EvidenceRef":"sha256:ab2607bc705f27357f7b1dd2089fbb6f9d33af74d05574f2d2f9c1ca4f31e22c","ObservedAt":"2026-01-01T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected allowed violation type to return 200, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(
		t,
		http.MethodGet,
		baseURL+"/x/vpnslashing/evidence/ev-violation-type-valid-1",
		"",
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected slash evidence GET to return 200, got %d payload=%v", status, payload)
	}
	evidenceObj, ok := payload["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("expected evidence object in GET payload, got payload=%v", payload)
	}
	violationType, _ := evidenceObj["ViolationType"].(string)
	if violationType != "session-replay-proof" {
		t.Fatalf("expected normalized violation type %q in stored evidence, got %q", "session-replay-proof", violationType)
	}

	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnslashing/evidence",
		`{"EvidenceID":"ev-violation-type-invalid-1","SubjectID":"provider-violation-type-invalid-1","SessionID":"sess-violation-type-invalid-1","ViolationType":"objective","EvidenceRef":"sha256:fe39d73ac24f4539ff3321f981523019db52fbe5931f0f5edcc26e83e136c1b8","ObservedAt":"2026-01-01T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid violation type to return 400, got %d payload=%v", status, payload)
	}
	errorText, _ := payload["error"].(string)
	if !strings.Contains(errorText, bridgeObjectiveViolationTypeError) {
		t.Fatalf("expected invalid violation type message, got payload=%v", payload)
	}

	requiredFieldCases := []struct {
		name        string
		body        string
		errorSubstr string
	}{
		{
			name:        "missing evidence id",
			body:        `{"SubjectID":"provider-required-fields-1","SessionID":"sess-required-fields-1","ViolationType":"double-sign","EvidenceRef":"sha256:0dd2e95d6d937280c0f5e1f5654c0f7938c735fbb2bcb966d587a20e23757eeb","ObservedAt":"2026-01-01T00:00:00Z"}`,
			errorSubstr: "evidence_id is required",
		},
		{
			name:        "missing subject id",
			body:        `{"EvidenceID":"ev-required-fields-2","SessionID":"sess-required-fields-2","ViolationType":"double-sign","EvidenceRef":"sha256:cb87e9274d6f6641f4f0a8b86095f978035b1af2d8fda072ebf9a6ea1df42d76","ObservedAt":"2026-01-01T00:00:00Z"}`,
			errorSubstr: "subject_id is required",
		},
		{
			name:        "missing session id",
			body:        `{"EvidenceID":"ev-required-fields-3","SubjectID":"provider-required-fields-3","ViolationType":"double-sign","EvidenceRef":"sha256:c9dd2ccd8a8996f2fef2b51d20adcd20582c7648b8b3d2f0b4c7a95c6c45c744","ObservedAt":"2026-01-01T00:00:00Z"}`,
			errorSubstr: "session_id is required",
		},
		{
			name:        "missing violation type",
			body:        `{"EvidenceID":"ev-required-fields-4","SubjectID":"provider-required-fields-4","SessionID":"sess-required-fields-4","EvidenceRef":"sha256:ee5417ea68cf8fd5ce62f24d75e78387880865c95e9ca05477305f18ff8db9bf","ObservedAt":"2026-01-01T00:00:00Z"}`,
			errorSubstr: "violation_type is required",
		},
		{
			name:        "missing evidence ref",
			body:        `{"EvidenceID":"ev-required-fields-5","SubjectID":"provider-required-fields-5","SessionID":"sess-required-fields-5","ViolationType":"double-sign","ObservedAt":"2026-01-01T00:00:00Z"}`,
			errorSubstr: "evidence_ref is required",
		},
	}

	for _, tc := range requiredFieldCases {
		t.Run(tc.name, func(t *testing.T) {
			status, payload := doJSONRequest(
				t,
				http.MethodPost,
				baseURL+"/x/vpnslashing/evidence",
				tc.body,
				nil,
			)
			if status != http.StatusBadRequest {
				t.Fatalf("expected missing required fields to return 400, got %d payload=%v", status, payload)
			}

			errorText, _ := payload["error"].(string)
			if !strings.Contains(errorText, tc.errorSubstr) {
				t.Fatalf("expected error to contain %q, got payload=%v", tc.errorSubstr, payload)
			}
		})
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

func TestRunTDPNDSettlementHTTPSlashEvidenceDuplicateIncidentReturnsConflict(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-duplicate-incident-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-duplicate-incident-test" {
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

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnslashing/evidence",
		`{"EvidenceID":"ev-dup-incident-a","SubjectID":"provider-dup-incident-1","SessionID":"sess-dup-incident-1","ViolationType":"double-sign","EvidenceRef":"sha256:7e70f58fa8f4eb44ef6ceb8fd9b3550a8fd2fb208f5baf5f4f3fd95f078aaafd","ObservedAt":"2026-01-01T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected first slashing evidence POST to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnslashing/evidence",
		`{"EvidenceID":"ev-dup-incident-b","SubjectID":"provider-dup-incident-1","SessionID":"sess-dup-incident-1","ViolationType":"double-sign","EvidenceRef":"sha256:7e70f58fa8f4eb44ef6ceb8fd9b3550a8fd2fb208f5baf5f4f3fd95f078aaafd","ObservedAt":"2026-01-01T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusConflict {
		t.Fatalf("expected duplicate objective incident POST to return 409, got %d payload=%v", status, payload)
	}
	if errText, _ := payload["error"].(string); !strings.Contains(errText, "duplicates already-recorded evidence") {
		t.Fatalf("expected duplicate evidence conflict details, got %q", errText)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnslashing/evidence/ev-dup-incident-b", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected duplicate evidence id lookup to return 404 after conflict, got %d payload=%v", status, payload)
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

func TestRunTDPNDSettlementHTTPValidatorStatusRejectsInvalidObjectiveEvidenceRef(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-invalid-validator-status-ref-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-invalid-validator-status-ref-test" {
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

	cases := []struct {
		name string
		body string
	}{
		{
			name: "short sha256",
			body: `{"StatusID":"status-invalid-ref-short-sha","ValidatorID":"val-invalid-ref-1","ConsensusAddress":"cons-invalid-ref-1","LifecycleStatus":"active","EvidenceHeight":9,"EvidenceRef":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}`,
		},
		{
			name: "object path contains whitespace",
			body: `{"StatusID":"status-invalid-ref-obj-space","ValidatorID":"val-invalid-ref-1","ConsensusAddress":"cons-invalid-ref-1","LifecycleStatus":"active","EvidenceHeight":9,"EvidenceRef":"obj://validator/status with-space","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, payload := doJSONRequest(
				t,
				http.MethodPost,
				baseURL+"/x/vpnvalidator/status-records",
				tc.body,
				nil,
			)
			if status != http.StatusBadRequest {
				t.Fatalf("expected invalid evidence_ref to return 400, got %d payload=%v", status, payload)
			}

			errorText, _ := payload["error"].(string)
			if !strings.Contains(errorText, "evidence ref must use objective format") {
				t.Fatalf("expected invalid format error, got payload=%v", payload)
			}
		})
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

func TestRunTDPNDSettlementHTTPRejectsMalformedJSONPayloads(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-json-hardening-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-json-hardening-test" {
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

	oversizedBody := fmt.Sprintf(
		`{"SettlementID":"set-json-oversized-1","ReservationID":"res-json-oversized-1","SessionID":"sess-json-oversized-1","SubjectID":"%s","ChargedMicros":1,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		strings.Repeat("a", int(settlementBridgeMaxJSONBodyBytes)),
	)
	validSettlementBody := `{"SettlementID":"set-json-base-1","ReservationID":"res-json-base-1","SessionID":"sess-json-base-1","SubjectID":"subject-json-base-1","ChargedMicros":1,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`

	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown field rejected",
			body: `{"SettlementID":"set-json-unknown-1","ReservationID":"res-json-unknown-1","SessionID":"sess-json-unknown-1","SubjectID":"subject-json-unknown-1","ChargedMicros":1,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Unexpected":"field"}`,
		},
		{
			name: "oversized body rejected",
			body: oversizedBody,
		},
		{
			name: "trailing json token rejected",
			body: validSettlementBody + "\n{}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, payload := doJSONRequest(
				t,
				http.MethodPost,
				baseURL+"/x/vpnbilling/settlements",
				tc.body,
				nil,
			)
			if status != http.StatusBadRequest {
				t.Fatalf("expected malformed json case %q to return 400, got %d payload=%v", tc.name, status, payload)
			}
			errText, _ := payload["error"].(string)
			if !strings.Contains(strings.ToLower(errText), "invalid json payload") {
				t.Fatalf("expected malformed json case %q to include invalid JSON payload error, got payload=%v", tc.name, payload)
			}
		})
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

func TestSettlementBridgeRewardIssueAcceptsEnrichedPayload(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}
	seedBillingReservation(t, scaffold, "res-enriched-1", "sess-enriched-1", "provider-enriched-1", "uusdc", 100)
	_, err := scaffold.BillingMsgServer().FinalizeSettlement(context.Background(), app.BillingFinalizeSettlementRequest{
		Record: billingtypes.SettlementRecord{
			SettlementID:   "set-enriched-1",
			ReservationID:  "res-enriched-1",
			SessionID:      "sess-enriched-1",
			BilledAmount:   100,
			AssetDenom:     "uusdc",
			SettledAtUnix:  time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC).Unix(),
			OperationState: chaintypes.ReconciliationConfirmed,
		},
	})
	if err != nil {
		t.Fatalf("seed enriched settlement ref: %v", err)
	}
	issuedAt := time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC)
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-enriched-1",
		"reward-enriched-1",
		"provider-enriched-1",
		"sess-enriched-1",
		100,
		"uusdc",
		issuedAt,
		periodStart,
		periodEnd,
	)
	body := `{"RewardID":"reward-enriched-1","ProviderSubjectID":"provider-enriched-1","SessionID":"sess-enriched-1","SettlementReferenceID":"set-enriched-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`

	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected enriched reward payload to be accepted, got %d body=%s", rr.Code, rr.Body.String())
	}

	resp, err := scaffold.RewardsQueryServer().GetDistribution(context.Background(), app.RewardsGetDistributionRequest{
		DistributionID: "dist:reward-enriched-1",
	})
	if err != nil {
		t.Fatalf("query reward distribution: %v", err)
	}
	if !resp.Found {
		t.Fatal("expected reward distribution to be persisted")
	}
	accrualResp, err := scaffold.RewardsQueryServer().GetAccrual(context.Background(), app.RewardsGetAccrualRequest{
		AccrualID: "reward-enriched-1",
	})
	if err != nil {
		t.Fatalf("query reward accrual: %v", err)
	}
	if !accrualResp.Found {
		t.Fatal("expected reward accrual to be persisted")
	}
	expectedAccruedAt := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC).Unix()
	if accrualResp.Accrual.AccruedAtUnix != expectedAccruedAt {
		t.Fatalf("expected payout-period accrual time %d, got %d", expectedAccruedAt, accrualResp.Accrual.AccruedAtUnix)
	}

	var payoutRef struct {
		RewardID              string `json:"RewardID"`
		SettlementReferenceID string `json:"SettlementReferenceID"`
		TrafficProofRef       string `json:"TrafficProofRef"`
		PayoutPeriodStart     string `json:"PayoutPeriodStart"`
		PayoutPeriodEnd       string `json:"PayoutPeriodEnd"`
	}
	if err := json.Unmarshal([]byte(resp.Distribution.PayoutRef), &payoutRef); err != nil {
		t.Fatalf("expected enriched payout ref JSON, got %q: %v", resp.Distribution.PayoutRef, err)
	}
	if payoutRef.RewardID != "reward-enriched-1" ||
		payoutRef.SettlementReferenceID != "set-enriched-1" ||
		payoutRef.TrafficProofRef != proofRef ||
		payoutRef.PayoutPeriodStart != "2026-04-20T00:00:00Z" ||
		payoutRef.PayoutPeriodEnd != "2026-04-27T00:00:00Z" {
		t.Fatalf("unexpected enriched payout ref: %#v", payoutRef)
	}
}

func TestSettlementBridgeRewardProofRegistryQueriesOnlyExplicitVerifiedProofs(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}
	server := httptest.NewServer(handler.routes())
	defer server.Close()

	authHeaders := map[string]string{"Authorization": "Bearer bridge-secret"}
	proofPath := "traffic-proof/reward-proof-registry-1"
	proofRef := "obj://" + proofPath
	proofRoute := "/x/vpnrewards/proofs/" + urlpkg.PathEscape(proofPath)
	issuedAt := time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC)
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)

	rewardBody := `{"RewardID":"reward-proof-registry-1","ProviderSubjectID":"provider-proof-registry-1","SessionID":"session-proof-registry-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":777,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`
	status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", rewardBody, authHeaders)
	if status != http.StatusConflict {
		t.Fatalf("expected reward issue with missing verified proof to return 409, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, server.URL+proofRoute, "", authHeaders)
	if status != http.StatusNotFound {
		t.Fatalf("expected missing proof registry record to be hidden, got %d payload=%v", status, payload)
	}

	unverifiedProof := rewardtypes.RewardProofRecord{
		ProofPath:         proofPath,
		TrafficProofRef:   proofRef,
		TrustContract:     rewardtypes.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "reward-proof-registry-1",
		ProviderSubjectID: "provider-proof-registry-1",
		SessionID:         "session-proof-registry-1",
		PayoutStartUnix:   periodStart.Unix(),
		PayoutEndUnix:     periodEnd.Unix(),
		RewardMicros:      777,
		Currency:          "uusdc",
		IssuedAtUnix:      issuedAt.Unix(),
		Verified:          false,
	}
	if err := scaffold.RewardsModule.Keeper.UpsertProofWithError(unverifiedProof); err != nil {
		t.Fatalf("seed unverified proof: %v", err)
	}

	status, payload = doJSONRequest(t, http.MethodGet, server.URL+proofRoute, "", authHeaders)
	if status != http.StatusNotFound {
		t.Fatalf("expected unverified proof registry record to be hidden, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", rewardBody, authHeaders)
	if status != http.StatusConflict {
		t.Fatalf("expected reward issue with unverified proof to return 409, got %d payload=%v", status, payload)
	}

	verifiedProofPath := "traffic-proof/reward-proof-registry-verified-1"
	verifiedProofRef := "obj://" + verifiedProofPath
	verifiedProofRoute := "/x/vpnrewards/proofs/" + urlpkg.PathEscape(verifiedProofPath)
	verifiedRewardBody := `{"RewardID":"reward-proof-registry-verified-1","ProviderSubjectID":"provider-proof-registry-1","SessionID":"session-proof-registry-1","TrafficProofRef":"` + verifiedProofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":777,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`
	verifiedProof := rewardtypes.RewardProofRecord{
		ProofPath:         verifiedProofPath,
		TrafficProofRef:   verifiedProofRef,
		TrustContract:     rewardtypes.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "reward-proof-registry-verified-1",
		ProviderSubjectID: "provider-proof-registry-1",
		SessionID:         "session-proof-registry-1",
		PayoutStartUnix:   periodStart.Unix(),
		PayoutEndUnix:     periodEnd.Unix(),
		RewardMicros:      777,
		Currency:          "uusdc",
		IssuedAtUnix:      issuedAt.Unix(),
		Verified:          true,
	}
	verifiedProof.VerifierID = "objective-proof-registry"
	verifiedProof.VerifiedAtUnix = issuedAt.Add(time.Minute).Unix()
	if err := scaffold.RewardsModule.Keeper.UpsertProofWithError(verifiedProof); err != nil {
		t.Fatalf("seed verified proof: %v", err)
	}

	status, payload = doJSONRequest(t, http.MethodGet, server.URL+verifiedProofRoute, "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected verified proof registry lookup to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "proof", "traffic_proof_ref", verifiedProofRef)
	expectJSONStringField(t, payload, "proof", "trust_contract", rewardtypes.RewardProofTrustContractObjectiveTrafficV1)
	expectJSONStringField(t, payload, "proof", "reward_id", "reward-proof-registry-verified-1")
	expectJSONStringField(t, payload, "proof", "provider_subject_id", "provider-proof-registry-1")
	expectJSONStringField(t, payload, "proof", "session_id", "session-proof-registry-1")
	expectJSONStringField(t, payload, "proof", "currency", "uusdc")
	expectJSONStringField(t, payload, "proof", "verifier_id", "objective-proof-registry")

	proof, ok := payload["proof"].(map[string]any)
	if !ok {
		t.Fatalf("expected proof object, got %#v", payload["proof"])
	}
	if verified, ok := proof["verified"].(bool); !ok || !verified {
		t.Fatalf("expected proof.verified=true, got %#v", proof["verified"])
	}
	if micros, ok := proof["reward_micros"].(float64); !ok || micros != 777 {
		t.Fatalf("expected proof.reward_micros=777, got %#v", proof["reward_micros"])
	}

	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", verifiedRewardBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected reward issue with verified proof to be accepted, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, server.URL+"/x/vpnrewards/proofs/"+urlpkg.PathEscape("traffic-proof/missing"), "", authHeaders)
	if status != http.StatusNotFound {
		t.Fatalf("expected missing proof registry lookup to return 404, got %d payload=%v", status, payload)
	}
}

func TestSettlementBridgeRewardProofRegistrationEnablesRewardIssue(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:              scaffold,
		authToken:             "bridge-secret",
		authPrincipal:         "provider-proof-post-1",
		rewardProofAuthToken:  "proof-secret",
		finalityAuthToken:     "finality-secret",
		rewardProofVerifierID: "objective-proof-post",
	}
	server := httptest.NewServer(handler.routes())
	defer server.Close()

	authHeaders := map[string]string{"Authorization": "Bearer bridge-secret"}
	proofHeaders := map[string]string{"Authorization": "Bearer bridge-secret", rewardProofAuthorizationHeader: "Bearer proof-secret"}
	finalityHeaders := map[string]string{"Authorization": "Bearer bridge-secret", finalityAuthorizationHeader: "Bearer finality-secret"}
	proofPath := "traffic-proof/reward-proof-post-1"
	proofRef := "obj://" + proofPath
	proofBody := `{"TrafficProofRef":"` + proofRef + `","TrustContract":"` + rewardtypes.RewardProofTrustContractObjectiveTrafficV1 + `","RewardID":"reward-proof-post-1","SessionID":"session-proof-post-1","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":321,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z","Verified":true,"VerifierID":"objective-proof-post","VerifiedAt":"2026-04-27T00:00:02Z"}`
	status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/proofs", proofBody, proofHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected proof registration to return 200, got %d payload=%v", status, payload)
	}
	if got, ok := payload["id"].(string); !ok || got != proofPath {
		t.Fatalf("expected proof registration id=%q, got %#v", proofPath, payload["id"])
	}

	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/proofs", proofBody, proofHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected idempotent proof registration replay to return 200, got %d payload=%v", status, payload)
	}
	if replay, ok := payload["replay"].(bool); !ok || !replay {
		t.Fatalf("expected proof registration replay=true, got %#v", payload["replay"])
	}

	status, payload = doJSONRequest(t, http.MethodGet, server.URL+"/x/vpnrewards/proofs/"+urlpkg.PathEscape(proofPath), "", authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected proof lookup to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "proof", "provider_subject_id", "provider-proof-post-1")
	expectJSONStringField(t, payload, "proof", "traffic_proof_ref", proofRef)

	rewardBody := `{"RewardID":"reward-proof-post-1","ProviderSubjectID":"provider-proof-post-1","SessionID":"session-proof-post-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":321,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z","Status":"confirmed"}`
	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", rewardBody, finalityHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected reward issue with bridge-registered proof to be accepted, got %d payload=%v", status, payload)
	}
	accrual, err := scaffold.RewardsQueryServer().GetAccrual(context.Background(), app.RewardsGetAccrualRequest{AccrualID: "reward-proof-post-1"})
	if err != nil {
		t.Fatalf("query accrual after confirmed reward issue: %v", err)
	}
	if !accrual.Found || accrual.Accrual.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected confirmed accrual after trusted bridge reward issue, got found=%v accrual=%+v", accrual.Found, accrual.Accrual)
	}
}

func TestSettlementBridgeRewardIssueFinalityReplayTransitionsSubmittedReward(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:              scaffold,
		authToken:             "bridge-secret",
		finalityAuthToken:     "finality-secret",
		rewardProofVerifierID: "settlement-bridge-test-verifier",
	}
	server := httptest.NewServer(handler.routes())
	defer server.Close()

	authHeaders := map[string]string{"Authorization": "Bearer bridge-secret"}
	finalityHeaders := map[string]string{
		"Authorization":             "Bearer bridge-secret",
		finalityAuthorizationHeader: "Bearer finality-secret",
	}
	issuedAt := time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC)
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-finality-replay-1",
		"reward-finality-replay-1",
		"provider-finality-replay-1",
		"session-finality-replay-1",
		654,
		"uusdc",
		issuedAt,
		periodStart,
		periodEnd,
	)
	submittedBody := `{"RewardID":"reward-finality-replay-1","ProviderSubjectID":"provider-finality-replay-1","SessionID":"session-finality-replay-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":654,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`
	confirmedBody := `{"RewardID":"reward-finality-replay-1","ProviderSubjectID":"provider-finality-replay-1","SessionID":"session-finality-replay-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":654,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z","Status":"confirmed"}`

	status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", submittedBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected submitted reward issue to succeed, got %d payload=%v", status, payload)
	}
	distribution, err := scaffold.RewardsQueryServer().GetDistribution(context.Background(), app.RewardsGetDistributionRequest{DistributionID: "dist:reward-finality-replay-1"})
	if err != nil {
		t.Fatalf("query submitted distribution: %v", err)
	}
	if !distribution.Found || distribution.Distribution.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected submitted distribution, got found=%v distribution=%+v", distribution.Found, distribution.Distribution)
	}

	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", confirmedBody, authHeaders)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected missing finality token to fail, got %d payload=%v", status, payload)
	}
	distribution, err = scaffold.RewardsQueryServer().GetDistribution(context.Background(), app.RewardsGetDistributionRequest{DistributionID: "dist:reward-finality-replay-1"})
	if err != nil {
		t.Fatalf("query distribution after rejected finality: %v", err)
	}
	if distribution.Distribution.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected distribution to remain submitted after rejected finality, got %q", distribution.Distribution.Status)
	}

	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", confirmedBody, finalityHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected authorized finality replay to succeed, got %d payload=%v", status, payload)
	}
	if replay, _ := payload["replay"].(bool); replay {
		t.Fatalf("expected first finality transition replay=false, got payload=%v", payload)
	}
	distribution, err = scaffold.RewardsQueryServer().GetDistribution(context.Background(), app.RewardsGetDistributionRequest{DistributionID: "dist:reward-finality-replay-1"})
	if err != nil {
		t.Fatalf("query confirmed distribution: %v", err)
	}
	if !distribution.Found || distribution.Distribution.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected confirmed distribution, got found=%v distribution=%+v", distribution.Found, distribution.Distribution)
	}
	accrual, err := scaffold.RewardsQueryServer().GetAccrual(context.Background(), app.RewardsGetAccrualRequest{AccrualID: "reward-finality-replay-1"})
	if err != nil {
		t.Fatalf("query confirmed accrual: %v", err)
	}
	if !accrual.Found || accrual.Accrual.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected confirmed accrual, got found=%v accrual=%+v", accrual.Found, accrual.Accrual)
	}

	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", confirmedBody, finalityHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected authorized finality replay to remain idempotent, got %d payload=%v", status, payload)
	}
	if replay, ok := payload["replay"].(bool); !ok || !replay {
		t.Fatalf("expected terminal finality replay=true, got payload=%v", payload)
	}
}

func TestSettlementBridgeRewardProofRegistrationRequiresConfiguredVerifier(t *testing.T) {
	scaffold := app.NewChainScaffold()
	proofHeaders := map[string]string{"Authorization": "Bearer bridge-secret", rewardProofAuthorizationHeader: "Bearer proof-secret"}
	proofBody := `{"TrafficProofRef":"obj://traffic-proof/reward-proof-verifier-required-1","TrustContract":"` + rewardtypes.RewardProofTrustContractObjectiveTrafficV1 + `","RewardID":"reward-proof-verifier-required-1","ProviderSubjectID":"provider-proof-verifier-required-1","SessionID":"session-proof-verifier-required-1","RewardMicros":321,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z","Verified":true,"VerifierID":"objective-proof-post","VerifiedAt":"2026-04-27T00:00:02Z"}`

	t.Run("missing verifier config fails closed", func(t *testing.T) {
		handler := &settlementBridgeHandler{
			scaffold:             scaffold,
			authToken:            "bridge-secret",
			rewardProofAuthToken: "proof-secret",
		}
		server := httptest.NewServer(handler.routes())
		defer server.Close()

		status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/proofs", proofBody, proofHeaders)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("expected missing verifier to return 503, got %d payload=%v", status, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "verifier id is not configured") {
			t.Fatalf("expected verifier config guidance, got payload=%v", payload)
		}
	})

	t.Run("missing scoped proof token fails closed", func(t *testing.T) {
		handler := &settlementBridgeHandler{
			scaffold:              scaffold,
			authToken:             "bridge-secret",
			rewardProofVerifierID: "configured-proof-verifier",
		}
		server := httptest.NewServer(handler.routes())
		defer server.Close()

		status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/proofs", proofBody, map[string]string{"Authorization": "Bearer bridge-secret"})
		if status != http.StatusServiceUnavailable {
			t.Fatalf("expected missing scoped proof token config to return 503, got %d payload=%v", status, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "reward proof verifier token") {
			t.Fatalf("expected scoped proof token guidance, got payload=%v", payload)
		}
	})

	t.Run("regular bridge token alone cannot register verified proof", func(t *testing.T) {
		handler := &settlementBridgeHandler{
			scaffold:              scaffold,
			authToken:             "bridge-secret",
			rewardProofAuthToken:  "proof-secret",
			rewardProofVerifierID: "configured-proof-verifier",
		}
		server := httptest.NewServer(handler.routes())
		defer server.Close()

		status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/proofs", proofBody, map[string]string{"Authorization": "Bearer bridge-secret"})
		if status != http.StatusUnauthorized {
			t.Fatalf("expected missing scoped proof bearer to return 401, got %d payload=%v", status, payload)
		}
	})

	t.Run("payload verifier cannot override configured verifier", func(t *testing.T) {
		handler := &settlementBridgeHandler{
			scaffold:              scaffold,
			authToken:             "bridge-secret",
			rewardProofAuthToken:  "proof-secret",
			rewardProofVerifierID: "configured-proof-verifier",
		}
		server := httptest.NewServer(handler.routes())
		defer server.Close()

		status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/proofs", proofBody, proofHeaders)
		if status != http.StatusForbidden {
			t.Fatalf("expected verifier mismatch to return 403, got %d payload=%v", status, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "VerifierID must match") {
			t.Fatalf("expected verifier mismatch guidance, got payload=%v", payload)
		}
	})
}

func TestSettlementBridgeRewardIssueRequiresConfiguredProofVerifier(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:              scaffold,
		authToken:             "bridge-secret",
		finalityAuthToken:     "finality-secret",
		rewardProofVerifierID: "configured-verifier",
	}
	server := httptest.NewServer(handler.routes())
	defer server.Close()

	issuedAt := time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC)
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofPath := "traffic-proof/reward-proof-wrong-verifier-1"
	proofRef := "obj://" + proofPath
	if err := scaffold.RewardsModule.Keeper.UpsertProofWithError(rewardtypes.RewardProofRecord{
		ProofPath:         proofPath,
		TrafficProofRef:   proofRef,
		TrustContract:     rewardtypes.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "reward-wrong-verifier-1",
		ProviderSubjectID: "provider-wrong-verifier-1",
		SessionID:         "session-wrong-verifier-1",
		PayoutStartUnix:   periodStart.Unix(),
		PayoutEndUnix:     periodEnd.Unix(),
		RewardMicros:      777,
		Currency:          "uusdc",
		IssuedAtUnix:      issuedAt.Unix(),
		Verified:          true,
		VerifierID:        "wrong-verifier",
		VerifiedAtUnix:    issuedAt.Add(time.Second).Unix(),
	}); err != nil {
		t.Fatalf("seed verified proof with wrong verifier: %v", err)
	}

	rewardBody := `{"RewardID":"reward-wrong-verifier-1","ProviderSubjectID":"provider-wrong-verifier-1","SessionID":"session-wrong-verifier-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":777,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z","Status":"confirmed"}`
	status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", rewardBody, map[string]string{"Authorization": "Bearer bridge-secret", finalityAuthorizationHeader: "Bearer finality-secret"})
	if status != http.StatusConflict {
		t.Fatalf("expected verifier mismatch to reject reward issue, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "verifier") {
		t.Fatalf("expected verifier mismatch guidance, got payload=%v", payload)
	}
	accrual, err := scaffold.RewardsQueryServer().GetAccrual(context.Background(), app.RewardsGetAccrualRequest{AccrualID: "reward-wrong-verifier-1"})
	if err != nil {
		t.Fatalf("query accrual after rejected reward: %v", err)
	}
	if accrual.Found {
		t.Fatalf("rejected reward issue should not create accrual: %+v", accrual.Accrual)
	}
}

func TestSettlementBridgeRewardIssueValidatesStatusBeforeAccrualWrite(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:              scaffold,
		authToken:             "bridge-secret",
		rewardProofVerifierID: "objective-proof-status",
	}
	server := httptest.NewServer(handler.routes())
	defer server.Close()

	issuedAt := time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC)
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofPath := "traffic-proof/reward-proof-invalid-status-1"
	proofRef := "obj://" + proofPath
	if err := scaffold.RewardsModule.Keeper.UpsertProofWithError(rewardtypes.RewardProofRecord{
		ProofPath:         proofPath,
		TrafficProofRef:   proofRef,
		TrustContract:     rewardtypes.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "reward-invalid-status-1",
		ProviderSubjectID: "provider-invalid-status-1",
		SessionID:         "session-invalid-status-1",
		PayoutStartUnix:   periodStart.Unix(),
		PayoutEndUnix:     periodEnd.Unix(),
		RewardMicros:      777,
		Currency:          "uusdc",
		IssuedAtUnix:      issuedAt.Unix(),
		Verified:          true,
		VerifierID:        "objective-proof-status",
		VerifiedAtUnix:    issuedAt.Add(time.Second).Unix(),
	}); err != nil {
		t.Fatalf("seed verified proof: %v", err)
	}

	rewardBody := `{"RewardID":"reward-invalid-status-1","ProviderSubjectID":"provider-invalid-status-1","SessionID":"session-invalid-status-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":777,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z","Status":"nonsense"}`
	status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", rewardBody, map[string]string{"Authorization": "Bearer bridge-secret"})
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid status to reject reward issue, got %d payload=%v", status, payload)
	}
	accrual, err := scaffold.RewardsQueryServer().GetAccrual(context.Background(), app.RewardsGetAccrualRequest{AccrualID: "reward-invalid-status-1"})
	if err != nil {
		t.Fatalf("query accrual after invalid status: %v", err)
	}
	if accrual.Found {
		t.Fatalf("invalid reward status should not create accrual: %+v", accrual.Accrual)
	}
}

func TestSettlementBridgeRewardIssueFinalityConfigCheckedBeforeAccrualWrite(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:          scaffold,
		authToken:         "bridge-secret",
		finalityAuthToken: "finality-secret",
	}
	server := httptest.NewServer(handler.routes())
	defer server.Close()

	issuedAt := time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC)
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofPath := "traffic-proof/reward-proof-missing-finality-config-1"
	proofRef := "obj://" + proofPath
	if err := scaffold.RewardsModule.Keeper.UpsertProofWithError(rewardtypes.RewardProofRecord{
		ProofPath:         proofPath,
		TrafficProofRef:   proofRef,
		TrustContract:     rewardtypes.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "reward-missing-finality-config-1",
		ProviderSubjectID: "provider-missing-finality-config-1",
		SessionID:         "session-missing-finality-config-1",
		PayoutStartUnix:   periodStart.Unix(),
		PayoutEndUnix:     periodEnd.Unix(),
		RewardMicros:      777,
		Currency:          "uusdc",
		IssuedAtUnix:      issuedAt.Unix(),
		Verified:          true,
		VerifierID:        "some-verifier",
		VerifiedAtUnix:    issuedAt.Add(time.Second).Unix(),
	}); err != nil {
		t.Fatalf("seed verified proof: %v", err)
	}

	rewardBody := `{"RewardID":"reward-missing-finality-config-1","ProviderSubjectID":"provider-missing-finality-config-1","SessionID":"session-missing-finality-config-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":777,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z","Status":"confirmed"}`
	status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnrewards/issues", rewardBody, map[string]string{"Authorization": "Bearer bridge-secret", finalityAuthorizationHeader: "Bearer finality-secret"})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("expected missing finality verifier config to reject reward issue, got %d payload=%v", status, payload)
	}
	accrual, err := scaffold.RewardsQueryServer().GetAccrual(context.Background(), app.RewardsGetAccrualRequest{AccrualID: "reward-missing-finality-config-1"})
	if err != nil {
		t.Fatalf("query accrual after missing finality config: %v", err)
	}
	if accrual.Found {
		t.Fatalf("missing finality config should not create accrual: %+v", accrual.Accrual)
	}
}

func TestSettlementBridgeRewardIssueRejectsInvalidEnrichedPayload(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing proof path",
			body: `{"RewardID":"reward-missing-proof-1","ProviderSubjectID":"provider-missing-proof-1","SessionID":"sess-missing-proof-1","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`,
		},
		{
			name: "invalid traffic proof ref",
			body: `{"RewardID":"reward-invalid-proof-1","ProviderSubjectID":"provider-invalid-proof-1","SessionID":"sess-invalid-proof-1","TrafficProofRef":"legacy-proof","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`,
		},
		{
			name: "sha256 traffic proof ref is not a verified proof reference",
			body: `{"RewardID":"reward-sha256-proof-1","ProviderSubjectID":"provider-sha256-proof-1","SessionID":"sess-sha256-proof-1","TrafficProofRef":"sha256:570557014837233ea50f09f62316d47cdaff2c615d55ab83d843b00c6f53d49b","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`,
		},
		{
			name: "payout start is not monday utc midnight",
			body: `{"RewardID":"reward-invalid-period-1","ProviderSubjectID":"provider-invalid-period-1","SessionID":"sess-invalid-period-1","TrafficProofRef":"obj://traffic/proof-1","PayoutPeriodStart":"2026-04-21T00:00:00Z","PayoutPeriodEnd":"2026-04-28T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-28T00:00:01Z"}`,
		},
		{
			name: "payout end is not exactly seven days",
			body: `{"RewardID":"reward-invalid-end-1","ProviderSubjectID":"provider-invalid-end-1","SessionID":"sess-invalid-end-1","TrafficProofRef":"obj://traffic/proof-2","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-26T23:59:59Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`,
		},
		{
			name: "payout period is incomplete",
			body: `{"RewardID":"reward-invalid-incomplete-1","ProviderSubjectID":"provider-invalid-incomplete-1","SessionID":"sess-invalid-incomplete-1","TrafficProofRef":"obj://traffic/proof-3","PayoutPeriodStart":"2026-04-20T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scaffold := app.NewChainScaffold()
			handler := &settlementBridgeHandler{
				scaffold:          scaffold,
				authToken:         "bridge-secret",
				finalityAuthToken: "finality-secret",
			}
			req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer bridge-secret")
			req.Header.Set(finalityAuthorizationHeader, "Bearer finality-secret")
			rr := httptest.NewRecorder()
			handler.routes().ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected invalid enriched reward payload to return 400, got %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestSettlementBridgeRewardIssueRejectsVerifiedProofForDifferentRewardMaterial(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}
	issuedAt := time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC)
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	proofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-material-mismatch-1",
		"reward-material-mismatch-1",
		"provider-material-mismatch-1",
		"sess-material-mismatch-1",
		100,
		"uusdc",
		issuedAt,
		periodStart,
		periodEnd,
	)

	body := `{"RewardID":"reward-material-mismatch-1","ProviderSubjectID":"provider-material-mismatch-1","SessionID":"sess-material-mismatch-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":101,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`
	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected mismatched verified reward proof to return 409, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "traffic_proof_ref does not match reward payload") {
		t.Fatalf("expected reward proof mismatch response, got body=%s", rr.Body.String())
	}
}

func TestSettlementBridgeRewardIssueValidatesSettlementReferenceWithTrafficProof(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}

	noProofBody := `{"RewardID":"reward-no-traffic-proof-1","ProviderSubjectID":"provider-ref-1","SessionID":"sess-ref-1","SettlementReferenceID":"set-missing-ref-1","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`
	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(noProofBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected settlement-ref-only reward to return 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "traffic_proof_ref is required") {
		t.Fatalf("expected missing traffic_proof_ref response, got body=%s", rr.Body.String())
	}

	missingRefBody := `{"RewardID":"reward-missing-settlement-ref-1","ProviderSubjectID":"provider-ref-1","SessionID":"sess-ref-1","SettlementReferenceID":"set-missing-ref-1","TrafficProofRef":"obj://traffic-proof/reward-missing-settlement-ref-1","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`
	req = httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(missingRefBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected missing settlement ref to return 404, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "settlement_reference_id not found") {
		t.Fatalf("expected missing settlement ref response, got body=%s", rr.Body.String())
	}

	seedBillingReservation(t, scaffold, "res-reward-ref-1", "sess-reward-ref-1", "subject-reward-ref-1", "uusdc", 100)
	_, err := scaffold.BillingMsgServer().FinalizeSettlement(context.Background(), app.BillingFinalizeSettlementRequest{
		Record: billingtypes.SettlementRecord{
			SettlementID:   "set-reward-ref-1",
			ReservationID:  "res-reward-ref-1",
			SessionID:      "sess-reward-ref-1",
			BilledAmount:   100,
			AssetDenom:     "uusdc",
			SettledAtUnix:  time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC).Unix(),
			OperationState: chaintypes.ReconciliationConfirmed,
		},
	})
	if err != nil {
		t.Fatalf("seed settlement ref: %v", err)
	}

	mismatchBody := `{"RewardID":"reward-mismatched-settlement-ref-1","ProviderSubjectID":"provider-ref-1","SessionID":"sess-reward-ref-other","SettlementReferenceID":"set-reward-ref-1","TrafficProofRef":"obj://traffic-proof/reward-mismatched-settlement-ref-1","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:02Z"}`
	req = httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(mismatchBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected mismatched settlement ref to return 409, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "settlement_reference_id session mismatch") {
		t.Fatalf("expected mismatched settlement ref response, got body=%s", rr.Body.String())
	}

	mismatchWithTrafficProofBody := `{"RewardID":"reward-mismatched-settlement-ref-proof-1","ProviderSubjectID":"provider-ref-1","SessionID":"sess-reward-ref-other","SettlementReferenceID":"set-reward-ref-1","TrafficProofRef":"obj://traffic-proof/reward-mismatched-settlement-ref-proof-1","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:02Z"}`
	req = httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(mismatchWithTrafficProofBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected settlement ref mismatch with traffic proof to return 409, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "settlement_reference_id session mismatch") {
		t.Fatalf("expected mismatched settlement ref with traffic proof response, got body=%s", rr.Body.String())
	}

	seedBillingReservation(t, scaffold, "res-reward-ref-unconfirmed-1", "sess-reward-ref-unconfirmed-1", "subject-reward-ref-unconfirmed-1", "uusdc", 100)
	err = scaffold.BillingModule.Keeper.UpsertSettlementWithError(billingtypes.SettlementRecord{
		SettlementID:   "set-reward-ref-unconfirmed-1",
		ReservationID:  "res-reward-ref-unconfirmed-1",
		SessionID:      "sess-reward-ref-unconfirmed-1",
		BilledAmount:   100,
		AssetDenom:     "uusdc",
		SettledAtUnix:  time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC).Unix(),
		OperationState: chaintypes.ReconciliationSubmitted,
	})
	if err != nil {
		t.Fatalf("seed unconfirmed settlement ref: %v", err)
	}
	unconfirmedBody := `{"RewardID":"reward-unconfirmed-settlement-ref-1","ProviderSubjectID":"provider-ref-1","SessionID":"sess-reward-ref-unconfirmed-1","SettlementReferenceID":"set-reward-ref-unconfirmed-1","TrafficProofRef":"obj://traffic-proof/reward-unconfirmed-settlement-ref-1","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:03Z"}`
	req = httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(unconfirmedBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected unconfirmed settlement ref to return 409, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "settlement_reference_id is not confirmed") {
		t.Fatalf("expected unconfirmed settlement ref response, got body=%s", rr.Body.String())
	}

	validNoProofBody := `{"RewardID":"reward-backed-settlement-ref-no-proof-1","ProviderSubjectID":"provider-ref-no-proof-1","SessionID":"sess-reward-ref-1","SettlementReferenceID":"set-reward-ref-1","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:03Z"}`
	req = httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(validNoProofBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected confirmed settlement-ref-only reward to return 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "traffic_proof_ref is required") {
		t.Fatalf("expected confirmed settlement-ref-only reward to require traffic proof, got body=%s", rr.Body.String())
	}

	validProofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-backed-settlement-ref-1",
		"reward-backed-settlement-ref-1",
		"provider-ref-1",
		"sess-reward-ref-1",
		100,
		"uusdc",
		time.Date(2026, 4, 27, 0, 0, 3, 0, time.UTC),
		time.Time{},
		time.Time{},
	)
	validBody := `{"RewardID":"reward-backed-settlement-ref-1","ProviderSubjectID":"provider-ref-1","SessionID":"sess-reward-ref-1","SettlementReferenceID":"set-reward-ref-1","TrafficProofRef":"` + validProofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:03Z"}`
	req = httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(validBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected backed settlement ref reward to return 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSettlementBridgeRewardIssueHeldBySlashEvidence(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}

	seedBillingReservation(t, scaffold, "res-reward-slash-hold-1", "sess-reward-slash-hold-1", "provider-slash-hold-1", "uusdc", 100)
	_, err := scaffold.BillingMsgServer().FinalizeSettlement(context.Background(), app.BillingFinalizeSettlementRequest{
		Record: billingtypes.SettlementRecord{
			SettlementID:   "set-reward-slash-hold-1",
			ReservationID:  "res-reward-slash-hold-1",
			SessionID:      "sess-reward-slash-hold-1",
			BilledAmount:   100,
			AssetDenom:     "uusdc",
			SettledAtUnix:  time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC).Unix(),
			OperationState: chaintypes.ReconciliationConfirmed,
		},
	})
	if err != nil {
		t.Fatalf("seed settlement ref: %v", err)
	}
	proofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-slash-held-1",
		"reward-slash-held-1",
		"provider-slash-hold-1",
		"sess-reward-slash-hold-1",
		100,
		"uusdc",
		time.Date(2026, 4, 27, 0, 0, 3, 0, time.UTC),
		time.Time{},
		time.Time{},
	)
	_, err = scaffold.SlashingMsgServer().SubmitEvidence(context.Background(), app.SlashingSubmitEvidenceRequest{
		Record: slashingtypes.SlashEvidence{
			EvidenceID:      "evidence-reward-slash-hold-1",
			ProviderID:      "provider-slash-hold-1",
			SessionID:       "sess-reward-slash-hold-1",
			Kind:            slashingtypes.EvidenceKindObjective,
			ProofHash:       "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ViolationType:   "invalid-settlement-proof",
			SubmittedAtUnix: time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC).Unix(),
		},
	})
	if err != nil {
		t.Fatalf("seed slash evidence: %v", err)
	}

	body := `{"RewardID":"reward-slash-held-1","ProviderSubjectID":"provider-slash-hold-1","SessionID":"sess-reward-slash-hold-1","SettlementReferenceID":"set-reward-slash-hold-1","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:03Z"}`
	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected slash-held reward to return 409, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "reward payout is held by slash evidence") {
		t.Fatalf("expected slash hold response, got body=%s", rr.Body.String())
	}
}

func TestSettlementBridgeWeeklyRewardIssueHeldBySlashEvidenceInPayoutWindow(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}

	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	issuedAt := periodEnd.Add(time.Second)
	proofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-weekly-slash-hold-1",
		"reward-weekly-slash-held-1",
		"provider-weekly-slash-hold-1",
		"weekly-provider-provider-weekly-slash-hold-1-20260420",
		700,
		"uusdc",
		issuedAt,
		periodStart,
		periodEnd,
	)
	_, err := scaffold.SlashingMsgServer().SubmitEvidence(context.Background(), app.SlashingSubmitEvidenceRequest{
		Record: slashingtypes.SlashEvidence{
			EvidenceID:      "evidence-weekly-slash-hold-1",
			ProviderID:      "provider-weekly-slash-hold-1",
			SessionID:       "real-session-weekly-slash-hold-1",
			Kind:            slashingtypes.EvidenceKindObjective,
			ProofHash:       "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			ViolationType:   "invalid-settlement-proof",
			SubmittedAtUnix: periodStart.Add(48 * time.Hour).Unix(),
		},
	})
	if err != nil {
		t.Fatalf("seed slash evidence: %v", err)
	}

	body := `{"RewardID":"reward-weekly-slash-held-1","ProviderSubjectID":"provider-weekly-slash-hold-1","SessionID":"weekly-provider-provider-weekly-slash-hold-1-20260420","TrafficProofRef":"` + proofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":700,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`
	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected weekly slash-held reward to return 409, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "reward payout is held by slash evidence for provider/week") {
		t.Fatalf("expected weekly slash hold response, got body=%s", rr.Body.String())
	}
}

func TestSettlementBridgeRewardIssueRejectsDuplicatePayoutPeriodDespiteIssuedAtChange(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}

	issuedAt := time.Date(2026, 4, 27, 0, 0, 1, 0, time.UTC)
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	firstProofRef := seedVerifiedRewardProof(t, scaffold, "traffic-proof/reward-period-dup-1", "reward-period-dup-1", "provider-period-dup-1", "sess-period-dup-1", 100, "uusdc", issuedAt, periodStart, periodEnd)
	firstBody := `{"RewardID":"reward-period-dup-1","ProviderSubjectID":"provider-period-dup-1","SessionID":"sess-period-dup-1","TrafficProofRef":"` + firstProofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-27T00:00:01Z"}`
	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(firstBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected first reward period payload to be accepted, got %d body=%s", rr.Code, rr.Body.String())
	}

	duplicateIssuedAt := time.Date(2026, 5, 4, 0, 0, 1, 0, time.UTC)
	duplicateProofRef := seedVerifiedRewardProof(t, scaffold, "traffic-proof/reward-period-dup-2", "reward-period-dup-2", "provider-period-dup-1", "sess-period-dup-2", 101, "uusdc", duplicateIssuedAt, periodStart, periodEnd)
	duplicateBody := `{"RewardID":"reward-period-dup-2","ProviderSubjectID":"provider-period-dup-1","SessionID":"sess-period-dup-2","TrafficProofRef":"` + duplicateProofRef + `","PayoutPeriodStart":"2026-04-20T00:00:00Z","PayoutPeriodEnd":"2026-04-27T00:00:00Z","RewardMicros":101,"Currency":"uusdc","IssuedAt":"2026-05-04T00:00:01Z"}`
	req = httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(duplicateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected duplicate reward period payload to return 409, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "weekly epoch") {
		t.Fatalf("expected duplicate reward period response to mention weekly epoch, got body=%s", rr.Body.String())
	}
}

func TestSettlementBridgeRewardIssueRejectsMissingPayoutPeriod(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}

	firstIssuedAt := time.Date(2026, 4, 21, 0, 0, 1, 0, time.UTC)
	firstProofRef := seedVerifiedRewardProof(t, scaffold, "traffic-proof/reward-session-week-1", "reward-session-week-1", "provider-session-week-1", "sess-session-week-1", 100, "uusdc", firstIssuedAt, time.Time{}, time.Time{})
	firstBody := `{"RewardID":"reward-session-week-1","ProviderSubjectID":"provider-session-week-1","SessionID":"sess-session-week-1","TrafficProofRef":"` + firstProofRef + `","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-04-21T00:00:01Z"}`
	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnrewards/issues", strings.NewReader(firstBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected missing payout period to return 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "payout_period_start and payout_period_end are required") {
		t.Fatalf("expected missing payout period response, got body=%s", rr.Body.String())
	}
}

func TestSettlementBridgeSlashEvidenceAcceptsAmountCurrencyPayload(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}
	body := `{"EvidenceID":"ev-amount-currency-1","SubjectID":"provider-amount-currency-1","SessionID":"sess-amount-currency-1","ViolationType":"double-sign","EvidenceRef":"sha256:efe6bdb3f85eea1e7297c7e86b586adceffd36245ed995dd8c6cf846d5f8ec1c","SlashMicros":2500,"Currency":"uusdc","ObservedAt":"2026-04-27T00:00:00Z"}`

	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnslashing/evidence", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected slash amount/currency payload to be accepted, got %d body=%s", rr.Code, rr.Body.String())
	}

	resp, err := scaffold.SlashingQueryServer().GetEvidence(context.Background(), app.SlashingGetEvidenceRequest{
		EvidenceID: "ev-amount-currency-1",
	})
	if err != nil {
		t.Fatalf("query slash evidence: %v", err)
	}
	if !resp.Found {
		t.Fatal("expected slash evidence to be persisted")
	}
	expectedProofHash := "obj://settlement-slash/ev-amount-currency-1?currency=uusdc&evidence_ref=sha256%3Aefe6bdb3f85eea1e7297c7e86b586adceffd36245ed995dd8c6cf846d5f8ec1c&slash_micros=2500"
	if resp.Evidence.ProofHash != expectedProofHash {
		t.Fatalf("expected slash amount/currency to be encoded into proof hash %q, got %q", expectedProofHash, resp.Evidence.ProofHash)
	}
	if resp.Evidence.SlashAmount != 2500 {
		t.Fatalf("expected typed slash amount 2500, got %d", resp.Evidence.SlashAmount)
	}
	if resp.Evidence.SlashDenom != "uusdc" {
		t.Fatalf("expected typed slash denom %q, got %q", "uusdc", resp.Evidence.SlashDenom)
	}
}

func TestSettlementBridgeSlashEvidenceConfirmThenPenaltyPost(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:          scaffold,
		authToken:         "bridge-secret",
		finalityAuthToken: "finality-secret",
	}
	server := httptest.NewServer(handler.routes())
	defer server.Close()
	authHeaders := map[string]string{"Authorization": "Bearer bridge-secret"}
	finalityHeaders := map[string]string{"Authorization": "Bearer bridge-secret", finalityAuthorizationHeader: "Bearer finality-secret"}

	evidenceBody := `{"EvidenceID":"ev-confirm-penalty-1","SubjectID":"provider-confirm-penalty-1","SessionID":"sess-confirm-penalty-1","ViolationType":"double-sign","EvidenceRef":"sha256:12a91cd7490fa78e48a12080428198f24fc2d99b1e34923ceb87af10231ac7bc","SlashMicros":2500,"Currency":"uusdc","ObservedAt":"2026-04-27T00:00:00Z"}`
	status, payload := doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnslashing/evidence", evidenceBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected slash evidence post to return 200, got %d payload=%v", status, payload)
	}

	penaltyBody := `{"PenaltyID":"pen-confirm-penalty-1","EvidenceID":"ev-confirm-penalty-1","SlashBasisPoint":25,"SlashMicros":2500,"Currency":"uusdc"}`
	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnslashing/penalties", penaltyBody, authHeaders)
	if status != http.StatusBadRequest {
		t.Fatalf("expected penalty before confirmation to fail closed with 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "non-final evidence") {
		t.Fatalf("expected non-final evidence error before confirmation, got %q", got)
	}

	status, payload = doJSONRequest(t, http.MethodPatch, server.URL+"/x/vpnslashing/evidence/ev-confirm-penalty-1", `{"Status":"confirmed"}`, finalityHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected slash evidence confirmation to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodPost, server.URL+"/x/vpnslashing/penalties", penaltyBody, authHeaders)
	if status != http.StatusOK {
		t.Fatalf("expected penalty after confirmation to return 200, got %d payload=%v", status, payload)
	}
	if got, _ := payload["id"].(string); got != "pen-confirm-penalty-1" {
		t.Fatalf("expected penalty id in response, got %q payload=%v", got, payload)
	}

	penaltyResp, err := scaffold.SlashingQueryServer().GetPenalty(context.Background(), app.SlashingGetPenaltyRequest{
		PenaltyID: "pen-confirm-penalty-1",
	})
	if err != nil {
		t.Fatalf("query penalty: %v", err)
	}
	if !penaltyResp.Found {
		t.Fatal("expected confirmed evidence penalty to be persisted")
	}
	if penaltyResp.Penalty.SlashAmount != 2500 || penaltyResp.Penalty.SlashDenom != "uusdc" {
		t.Fatalf("unexpected typed penalty fields: %+v", penaltyResp.Penalty)
	}
}

func TestSettlementBridgeSlashEvidenceFinalityRequiresAuthenticatedMode(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:   scaffold,
		listenAddr: "127.0.0.1:8081",
	}

	evidenceBody := `{"EvidenceID":"ev-finality-auth-required-1","SubjectID":"provider-finality-auth-required-1","SessionID":"sess-finality-auth-required-1","ViolationType":"double-sign","EvidenceRef":"sha256:3a39bd990a402ab0d0704f0aa7e7a4663f523cc37c3f64e19033b5720f2caea3","SlashMicros":2500,"Currency":"uusdc","ObservedAt":"2026-04-27T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081/x/vpnslashing/evidence", strings.NewReader(evidenceBody))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected unauthenticated loopback evidence post to return 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPatch, "http://127.0.0.1:8081/x/vpnslashing/evidence/ev-finality-auth-required-1", strings.NewReader(`{"Status":"confirmed"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unauthenticated slash finality to fail closed with 503, got %d body=%s", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode slash finality response: %v body=%s", err, rr.Body.String())
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "slash evidence finality requires authenticated settlement bridge mode") {
		t.Fatalf("expected authenticated-mode error, got %q", got)
	}

	resp, err := scaffold.SlashingQueryServer().GetEvidence(context.Background(), app.SlashingGetEvidenceRequest{
		EvidenceID: "ev-finality-auth-required-1",
	})
	if err != nil {
		t.Fatalf("query slash evidence: %v", err)
	}
	if !resp.Found {
		t.Fatal("expected slash evidence to remain persisted after failed finality")
	}
	if resp.Evidence.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected slash evidence to remain submitted after failed finality, got %q", resp.Evidence.Status)
	}
}

func TestSettlementBridgeSlashEvidenceRejectsDuplicateAmountWrappedIncident(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}

	firstBody := `{"EvidenceID":"ev-amount-dup-a","SubjectID":"provider-amount-dup-1","SessionID":"sess-amount-dup-1","ViolationType":"double-sign","EvidenceRef":"sha256:2d7c1f8fe2aa2abf4f18115c23f52654044cfdb8458c602b6f85f63362ab6be6","SlashMicros":100,"Currency":"uusdc","ObservedAt":"2026-04-27T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnslashing/evidence", strings.NewReader(firstBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected first amount-wrapped slash evidence to be accepted, got %d body=%s", rr.Code, rr.Body.String())
	}

	duplicateBody := `{"EvidenceID":"ev-amount-dup-b","SubjectID":"provider-amount-dup-1","SessionID":"sess-amount-dup-1","ViolationType":"double-sign","EvidenceRef":"sha256:2d7c1f8fe2aa2abf4f18115c23f52654044cfdb8458c602b6f85f63362ab6be6","SlashMicros":200,"Currency":"uusdc","ObservedAt":"2026-04-27T00:00:01Z"}`
	req = httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnslashing/evidence", strings.NewReader(duplicateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr = httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected duplicate amount-wrapped slash evidence to return 409, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "duplicates already-recorded evidence") {
		t.Fatalf("expected duplicate amount-wrapped slash response to mention replay, got body=%s", rr.Body.String())
	}
}

func TestSettlementBridgeSlashEvidenceRejectsNegativeSlashMicros(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}
	body := `{"EvidenceID":"ev-negative-slash-1","SubjectID":"provider-negative-slash-1","SessionID":"sess-negative-slash-1","ViolationType":"double-sign","EvidenceRef":"sha256:7b4b6df9a278abfdc9222ca89c4df8a9a0a79f901bb850fbf82a5d33f684450a","SlashMicros":-1,"Currency":"uusdc","ObservedAt":"2026-04-27T00:00:00Z"}`

	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnslashing/evidence", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected negative slash_micros to return 400, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSettlementBridgeSlashEvidenceRejectsInvalidCurrencyToken(t *testing.T) {
	scaffold := app.NewChainScaffold()
	handler := &settlementBridgeHandler{
		scaffold:  scaffold,
		authToken: "bridge-secret",
	}
	body := `{"EvidenceID":"ev-invalid-slash-currency-1","SubjectID":"provider-invalid-slash-currency-1","SessionID":"sess-invalid-slash-currency-1","ViolationType":"double-sign","EvidenceRef":"sha256:460b8c43644ff1b271ca55d3ec0858e1a422861123cf27e0bcc32e089bc04968","SlashMicros":100,"Currency":"uu sdc","ObservedAt":"2026-04-27T00:00:00Z"}`

	req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnslashing/evidence", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bridge-secret")
	rr := httptest.NewRecorder()
	handler.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid slash currency to return 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Currency must be a canonical non-empty token") {
		t.Fatalf("expected canonical currency error, got body=%s", rr.Body.String())
	}
}

func TestRunTDPNDSettlementHTTPHappyPathPerEndpoint(t *testing.T) {
	const authToken = "bridge-happy-token"
	const finalityToken = "bridge-happy-finality-token"

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-happy-test",
				"--settlement-http-auth-token", authToken,
				"--settlement-http-finality-auth-token", finalityToken,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-happy-test" {
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
	headers := settlementFinalityHeaders(authToken, finalityToken)
	seedBillingReservation(t, scaffold, "res-http-1", "sess-http-1", "subject-http-1", "uusdc", 250)
	rewardHTTPProofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-http-1",
		"reward-http-1",
		"provider-http-1",
		"sess-http-1",
		100,
		"uusdc",
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Time{},
		time.Time{},
	)

	cases := []struct {
		path       string
		body       string
		verifyGET  string
		objectKey  string
		idField    string
		idValue    string
		envelopeID string
	}{
		{
			path:      "/x/vpnbilling/settlements",
			body:      `{"SettlementID":"set-http-1","ReservationID":"res-http-1","SessionID":"sess-http-1","SubjectID":"subject-http-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
			verifyGET: "/x/vpnbilling/settlements/set-http-1",
			objectKey: "settlement",
			idField:   "SettlementID",
			idValue:   "set-http-1",
		},
		{
			path:       "/x/vpnrewards/issues",
			body:       `{"RewardID":"reward-http-1","ProviderSubjectID":"provider-http-1","SessionID":"sess-http-1","SettlementReferenceID":"set-http-1","TrafficProofRef":"` + rewardHTTPProofRef + `","PayoutPeriodStart":"2025-12-29T00:00:00Z","PayoutPeriodEnd":"2026-01-05T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
			verifyGET:  "/x/vpnrewards/accruals/reward-http-1",
			objectKey:  "accrual",
			idField:    "AccrualID",
			idValue:    "reward-http-1",
			envelopeID: "dist:reward-http-1",
		},
		{
			path:      "/x/vpnsponsor/reservations",
			body:      `{"ReservationID":"res-http-1","SponsorID":"sponsor-http-1","SubjectID":"app-http-1","SessionID":"sess-http-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
			verifyGET: "/x/vpnsponsor/delegations/res-http-1",
			objectKey: "delegation",
			idField:   "ReservationID",
			idValue:   "res-http-1",
		},
		{
			path:      "/x/vpnslashing/evidence",
			body:      `{"EvidenceID":"ev-http-1","SubjectID":"provider-http-1","SessionID":"sess-http-1","ViolationType":"double-sign","EvidenceRef":"sha256:d15cf66aff24713d226c1cfc45c9056acdb396b8e24da71c57d1e5a34efd2d08","ObservedAt":"2026-01-01T00:00:00Z"}`,
			verifyGET: "/x/vpnslashing/evidence/ev-http-1",
			objectKey: "evidence",
			idField:   "EvidenceID",
			idValue:   "ev-http-1",
		},
		{
			path:      "/x/vpnvalidator/eligibilities",
			body:      `{"ValidatorID":"val-http-1","OperatorAddress":"op-http-1","Eligible":true,"PolicyReason":"bootstrap policy","UpdatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
			verifyGET: "/x/vpnvalidator/eligibilities/val-http-1",
			objectKey: "eligibility",
			idField:   "ValidatorID",
			idValue:   "val-http-1",
		},
		{
			path:      "/x/vpnvalidator/status-records",
			body:      `{"StatusID":"status-http-1","ValidatorID":"val-http-1","ConsensusAddress":"cons-http-1","LifecycleStatus":"active","EvidenceHeight":7,"EvidenceRef":"sha256:afb8c2cf33cde95de5436ea939cae4a1a45c9c64938524ec7bb3d850a0b59497","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}`,
			verifyGET: "/x/vpnvalidator/status-records/status-http-1",
			objectKey: "status",
			idField:   "StatusID",
			idValue:   "status-http-1",
		},
		{
			path:      "/x/vpngovernance/policies",
			body:      `{"PolicyID":"policy-http-1","Title":"policy-http-title","Description":"policy-http-description","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}`,
			verifyGET: "/x/vpngovernance/policies/policy-http-1",
			objectKey: "policy",
			idField:   "PolicyID",
			idValue:   "policy-http-1",
		},
		{
			path:      "/x/vpngovernance/decisions",
			body:      `{"DecisionID":"decision-http-1","PolicyID":"policy-http-1","ProposalID":"proposal-http-1","Outcome":"approve","Decider":"bootstrap-multisig","Reason":"happy path","DecidedAt":"2026-01-01T00:00:02Z","Status":"confirmed"}`,
			verifyGET: "/x/vpngovernance/decisions/decision-http-1",
			objectKey: "decision",
			idField:   "DecisionID",
			idValue:   "decision-http-1",
		},
		{
			path:      "/x/vpngovernance/audit-actions",
			body:      `{"ActionID":"action-http-1","Action":"admin_set_policy","Actor":"bootstrap-multisig","Reason":"happy path audit","EvidencePointer":"obj://audit/action-http-1","Timestamp":"2026-01-01T00:00:03Z"}`,
			verifyGET: "/x/vpngovernance/audit-actions/action-http-1",
			objectKey: "action",
			idField:   "ActionID",
			idValue:   "action-http-1",
		},
	}

	for _, tc := range cases {
		status, payload := doJSONRequest(t, http.MethodPost, baseURL+tc.path, tc.body, headers)
		if status != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d payload=%v", tc.path, status, payload)
		}

		id, ok := payload["id"].(string)
		if !ok {
			t.Fatalf("expected POST %s to return id string, got payload=%v", tc.path, payload)
		}
		expectedEnvelopeID := tc.envelopeID
		if expectedEnvelopeID == "" {
			expectedEnvelopeID = tc.idValue
		}
		if id != expectedEnvelopeID {
			t.Fatalf("expected POST %s to return id=%s, got %s", tc.path, expectedEnvelopeID, id)
		}

		status, payload = doJSONRequest(t, http.MethodGet, baseURL+tc.verifyGET, "", headers)
		if status != http.StatusOK {
			t.Fatalf("expected GET %s to return 200, got %d payload=%v", tc.verifyGET, status, payload)
		}
		expectJSONIDField(t, payload, tc.objectKey, tc.idField, tc.idValue)
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

func TestRunTDPNDSettlementHTTPValidatorGovernanceWriteMethodContract(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-validator-governance-write-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-validator-governance-write-test" {
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

	cases := []struct {
		name      string
		path      string
		postBody  string
		verifyGET string
		objectKey string
		idField   string
		idValue   string
	}{
		{
			name:      "validator-eligibility",
			path:      "/x/vpnvalidator/eligibilities",
			postBody:  `{"ValidatorID":"val-method-1","OperatorAddress":"op-method-1","Eligible":true,"PolicyReason":"method test","UpdatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
			verifyGET: "/x/vpnvalidator/eligibilities/val-method-1",
			objectKey: "eligibility",
			idField:   "ValidatorID",
			idValue:   "val-method-1",
		},
		{
			name:      "validator-status",
			path:      "/x/vpnvalidator/status-records",
			postBody:  `{"StatusID":"status-method-1","ValidatorID":"val-method-1","ConsensusAddress":"cons-method-1","LifecycleStatus":"active","EvidenceHeight":9,"EvidenceRef":"sha256:522e9fc34dbba0963cd8af8f4194114f4e5badaf138b95477bed0a3bbd5fd6ad","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}`,
			verifyGET: "/x/vpnvalidator/status-records/status-method-1",
			objectKey: "status",
			idField:   "StatusID",
			idValue:   "status-method-1",
		},
		{
			name:      "governance-policy",
			path:      "/x/vpngovernance/policies",
			postBody:  `{"PolicyID":"policy-method-1","Title":"method policy","Description":"method policy description","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
			verifyGET: "/x/vpngovernance/policies/policy-method-1",
			objectKey: "policy",
			idField:   "PolicyID",
			idValue:   "policy-method-1",
		},
		{
			name:      "governance-decision",
			path:      "/x/vpngovernance/decisions",
			postBody:  `{"DecisionID":"decision-method-1","PolicyID":"policy-method-1","ProposalID":"proposal-method-1","Outcome":"approve","Decider":"bootstrap-multisig","Reason":"method decision","DecidedAt":"2026-01-01T00:00:02Z","Status":"submitted"}`,
			verifyGET: "/x/vpngovernance/decisions/decision-method-1",
			objectKey: "decision",
			idField:   "DecisionID",
			idValue:   "decision-method-1",
		},
		{
			name:      "governance-audit-action",
			path:      "/x/vpngovernance/audit-actions",
			postBody:  `{"ActionID":"action-method-1","Action":"admin_set_policy","Actor":"bootstrap-multisig","Reason":"method audit","EvidencePointer":"obj://audit/action-method-1","Timestamp":"2026-01-01T00:00:03Z"}`,
			verifyGET: "/x/vpngovernance/audit-actions/action-method-1",
			objectKey: "action",
			idField:   "ActionID",
			idValue:   "action-method-1",
		},
	}

	for _, tc := range cases {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+tc.path, "", nil)
		if status != http.StatusOK {
			t.Fatalf("[%s] expected GET list before write to return 200, got %d payload=%v", tc.name, status, payload)
		}

		status, payload = doJSONRequest(t, http.MethodPut, baseURL+tc.path, tc.postBody, nil)
		if status != http.StatusMethodNotAllowed {
			t.Fatalf("[%s] expected PUT to return 405, got %d payload=%v", tc.name, status, payload)
		}
		if payload["error"] != "method not allowed" {
			t.Fatalf("[%s] expected PUT payload error=method not allowed, got %v", tc.name, payload["error"])
		}

		status, payload = doJSONRequest(t, http.MethodPost, baseURL+tc.path, tc.postBody, nil)
		if status != http.StatusOK {
			t.Fatalf("[%s] expected POST to return 200, got %d payload=%v", tc.name, status, payload)
		}

		status, payload = doJSONRequest(t, http.MethodGet, baseURL+tc.verifyGET, "", nil)
		if status != http.StatusOK {
			t.Fatalf("[%s] expected GET by-id %s to return 200, got %d payload=%v", tc.name, tc.verifyGET, status, payload)
		}
		expectJSONIDField(t, payload, tc.objectKey, tc.idField, tc.idValue)
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

func TestRunTDPNDSettlementHTTPBillingRejectsNonPositiveCharge(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-zero-charge-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-zero-charge-test" {
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

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-zero-charge-1","ReservationID":"res-zero-charge-1","SessionID":"sess-zero-charge-1","SubjectID":"subject-zero-charge-1","ChargedMicros":0,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"submitted"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected zero-charge settlement POST to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "ChargedMicros must be > 0" {
		t.Fatalf("error=%q want=ChargedMicros must be > 0", got)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/reservations/res-zero-charge-1", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected reservation GET to return 404, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/settlements/set-zero-charge-1", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected settlement GET to return 404, got %d payload=%v", status, payload)
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

func TestRunTDPNDSettlementHTTPBillingReservationCreateQueryReplayConflictAndBlocksNonFinalSettle(t *testing.T) {
	const authToken = "bridge-reservation-create-token"
	const finalityToken = "bridge-reservation-create-finality-token"

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-reservation-create-test",
				"--settlement-http-auth-token", authToken,
				"--settlement-http-finality-auth-token", finalityToken,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-reservation-create-test" {
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
	headers := settlementFinalityHeaders(authToken, finalityToken)

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/reservations",
		`{"ReservationID":"res-invalid-create-1","SessionID":"sess-invalid-create-1","SubjectID":"subject-invalid-create-1","AmountMicros":0,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z"}`,
		headers,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid reservation POST to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "AmountMicros must be > 0" {
		t.Fatalf("error=%q want=AmountMicros must be > 0", got)
	}

	reservationBody := `{"ReservationID":"res-create-1","SessionID":"sess-create-1","SubjectID":"subject-create-1","AmountMicros":300,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", reservationBody, headers)
	if status != http.StatusOK {
		t.Fatalf("expected reservation POST to return 200, got %d payload=%v", status, payload)
	}
	if got, _ := payload["id"].(string); got != "res-create-1" {
		t.Fatalf("expected reservation POST id res-create-1, got %q", got)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/reservations/res-create-1", "", headers)
	if status != http.StatusOK {
		t.Fatalf("expected reservation GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "reservation", "ReservationID", "res-create-1")
	expectJSONStringField(t, payload, "reservation", "SponsorID", "subject-create-1")
	expectJSONStringField(t, payload, "reservation", "Status", string(chaintypes.ReconciliationSubmitted))
	expectJSONIntField(t, payload, "reservation", "Amount", 300)

	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", reservationBody, headers)
	if status != http.StatusOK {
		t.Fatalf("expected reservation replay POST to return 200, got %d payload=%v", status, payload)
	}
	if replay, _ := payload["replay"].(bool); !replay {
		t.Fatalf("expected reservation replay=true, got payload=%v", payload)
	}

	confirmBody := `{"ReservationID":"res-create-1","SessionID":"sess-create-1","SubjectID":"subject-create-1","AmountMicros":300,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", confirmBody, headers)
	if status != http.StatusOK {
		t.Fatalf("expected reservation confirmation POST to return 200, got %d payload=%v", status, payload)
	}
	if replay, _ := payload["replay"].(bool); replay {
		t.Fatalf("expected first confirmation replay=false, got payload=%v", payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/reservations/res-create-1", "", headers)
	if status != http.StatusOK {
		t.Fatalf("expected confirmed reservation GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "reservation", "Status", string(chaintypes.ReconciliationConfirmed))

	conflictBody := `{"ReservationID":"res-create-1","SessionID":"sess-create-1","SubjectID":"subject-create-1","AmountMicros":301,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", conflictBody, headers)
	if status != http.StatusConflict {
		t.Fatalf("expected reservation conflict POST to return 409, got %d payload=%v", status, payload)
	}

	settlementBody := `{"SettlementID":"set-create-1","ReservationID":"res-create-1","SessionID":"sess-create-1","SubjectID":"subject-create-1","ChargedMicros":275,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:01Z","Status":"confirmed"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/settlements", settlementBody, headers)
	if status != http.StatusOK {
		t.Fatalf("expected settlement POST against confirmed reservation to return 200, got %d payload=%v", status, payload)
	}
	if got, _ := payload["id"].(string); got != "set-create-1" {
		t.Fatalf("expected settlement id set-create-1, got %q payload=%v", got, payload)
	}

	upperCurrencyReservationBody := `{"ReservationID":"res-create-upper-currency-1","SessionID":"sess-create-upper-currency-1","SubjectID":"subject-create-upper-currency-1","AmountMicros":300,"Currency":"TDPNC","CreatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", upperCurrencyReservationBody, headers)
	if status != http.StatusOK {
		t.Fatalf("expected uppercase-currency reservation POST to return 200, got %d payload=%v", status, payload)
	}
	upperCurrencyConfirmBody := `{"ReservationID":"res-create-upper-currency-1","SessionID":"sess-create-upper-currency-1","SubjectID":"subject-create-upper-currency-1","AmountMicros":300,"Currency":"TDPNC","CreatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", upperCurrencyConfirmBody, headers)
	if status != http.StatusOK {
		t.Fatalf("expected uppercase-currency reservation confirmation POST to return 200, got %d payload=%v", status, payload)
	}
	upperCurrencySettlementBody := `{"SettlementID":"set-create-upper-currency-1","ReservationID":"res-create-upper-currency-1","SessionID":"sess-create-upper-currency-1","SubjectID":"subject-create-upper-currency-1","ChargedMicros":275,"Currency":"TDPNC","SettledAt":"2026-01-01T00:00:02Z","Status":"confirmed"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/settlements", upperCurrencySettlementBody, headers)
	if status != http.StatusOK {
		t.Fatalf("expected uppercase-currency settlement POST against confirmed reservation to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/settlements/set-create-1", "", headers)
	if status != http.StatusOK {
		t.Fatalf("expected settlement GET to return 200, got %d payload=%v", status, payload)
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

func TestSettlementBridgeBillingReservationPostRejectsConfirmedStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{
			name:   "literal confirmed",
			status: "confirmed",
		},
		{
			name:   "proto-style confirmed",
			status: "RECONCILIATION_STATUS_CONFIRMED",
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scaffold := app.NewChainScaffold()
			handler := &settlementBridgeHandler{
				scaffold:          scaffold,
				authToken:         "bridge-secret",
				finalityAuthToken: "finality-secret",
			}
			reservationID := fmt.Sprintf("res-reject-confirmed-%d", i+1)
			body := fmt.Sprintf(
				`{"ReservationID":%q,"SessionID":"sess-reject-confirmed-1","SubjectID":"subject-reject-confirmed-1","AmountMicros":300,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","Status":%q}`,
				reservationID,
				tc.status,
			)
			req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnbilling/reservations", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer bridge-secret")
			req.Header.Set(finalityAuthorizationHeader, "Bearer finality-secret")
			rr := httptest.NewRecorder()

			handler.routes().ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected confirmed reservation POST to return 400, got %d body=%s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "confirmed requires an existing pending or submitted reservation") {
				t.Fatalf("expected existing-reservation confirmation error, got body=%s", rr.Body.String())
			}
			resp, err := scaffold.BillingQueryServer().GetReservation(context.Background(), app.BillingGetReservationRequest{
				ReservationID: reservationID,
			})
			if err != nil {
				t.Fatalf("query rejected reservation %q: %v", reservationID, err)
			}
			if resp.Found {
				t.Fatalf("expected confirmed reservation POST not to persist, got %#v", resp.Reservation)
			}
		})
	}
}

func TestSettlementBridgeBillingSettlementStatusDoesNotPromoteSubmittedBroadcastAcceptance(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		omitStatus bool
		wantState  chaintypes.ReconciliationStatus
		wantStatus int
	}{
		{
			name:       "omitted finality is rejected",
			omitStatus: true,
			wantState:  chaintypes.ReconciliationSubmitted,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "submitted is rejected because settlement finality must be explicit",
			status:     "submitted",
			wantState:  chaintypes.ReconciliationSubmitted,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "confirmed remains final",
			status:     "confirmed",
			wantState:  chaintypes.ReconciliationConfirmed,
			wantStatus: http.StatusOK,
		},
		{
			name:       "proto-style submitted is rejected",
			status:     "RECONCILIATION_STATUS_SUBMITTED",
			wantState:  chaintypes.ReconciliationSubmitted,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "invalid explicit status rejected",
			status:     "broadcast-accepted",
			wantStatus: http.StatusBadRequest,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scaffold := app.NewChainScaffold()
			handler := &settlementBridgeHandler{
				scaffold:          scaffold,
				authToken:         "bridge-secret",
				finalityAuthToken: "finality-secret",
			}
			suffix := fmt.Sprintf("%d", i+1)
			reservationID := "res-status-finality-" + suffix
			settlementID := "set-status-finality-" + suffix
			sessionID := "sess-status-finality-" + suffix
			subjectID := "subject-status-finality-" + suffix
			seedBillingReservation(t, scaffold, reservationID, sessionID, subjectID, "uusdc", 250)

			body := fmt.Sprintf(
				`{"SettlementID":%q,"ReservationID":%q,"SessionID":%q,"SubjectID":%q,"ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"`,
				settlementID,
				reservationID,
				sessionID,
				subjectID,
			)
			if !tc.omitStatus {
				body += fmt.Sprintf(`,"Status":%q`, tc.status)
			}
			body += `}`
			req := httptest.NewRequest(http.MethodPost, "http://bridge.local/x/vpnbilling/settlements", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer bridge-secret")
			req.Header.Set(finalityAuthorizationHeader, "Bearer finality-secret")
			rr := httptest.NewRecorder()
			handler.routes().ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("expected settlement POST status %d, got %d body=%s", tc.wantStatus, rr.Code, rr.Body.String())
			}

			resp, err := scaffold.BillingQueryServer().GetSettlement(context.Background(), app.BillingGetSettlementRequest{
				SettlementID: settlementID,
			})
			if err != nil {
				t.Fatalf("query settlement %q: %v", settlementID, err)
			}
			if tc.wantStatus != http.StatusOK {
				if resp.Found {
					t.Fatalf("expected invalid status settlement not to be persisted, got %#v", resp.Settlement)
				}
				return
			}
			if !resp.Found {
				t.Fatalf("expected settlement %q to be persisted", settlementID)
			}
			if resp.Settlement.OperationState != tc.wantState {
				t.Fatalf("expected operation state %q, got %q", tc.wantState, resp.Settlement.OperationState)
			}
		})
	}
}

func TestRunTDPNDSettlementHTTPBillingFinalizeRequiresExistingMatchingReservation(t *testing.T) {
	const authToken = "bridge-reservation-enforcement-token"
	const finalityToken = "bridge-reservation-enforcement-finality-token"

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-reservation-enforcement-test",
				"--settlement-http-auth-token", authToken,
				"--settlement-http-finality-auth-token", finalityToken,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-reservation-enforcement-test" {
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
	headers := settlementFinalityHeaders(authToken, finalityToken)

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-missing-reservation-id-1","SessionID":"sess-missing-reservation-id-1","SubjectID":"subject-missing-reservation-id-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		headers,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected missing ReservationID to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "SettlementID, ReservationID, SessionID, SubjectID, and Currency are required" {
		t.Fatalf("error=%q want=SettlementID, ReservationID, SessionID, SubjectID, and Currency are required", got)
	}

	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-missing-reservation-1","ReservationID":"res-missing-reservation-1","SessionID":"sess-missing-reservation-1","SubjectID":"subject-missing-reservation-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		headers,
	)
	if status != http.StatusNotFound {
		t.Fatalf("expected missing reservation to return 404, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "reservation not found" {
		t.Fatalf("error=%q want=reservation not found", got)
	}

	seedBillingReservation(t, scaffold, "res-mismatch-1", "sess-mismatch-1", "subject-mismatch-1", "uusdc", 250)
	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-mismatch-1","ReservationID":"res-mismatch-1","SessionID":"sess-mismatch-1","SubjectID":"subject-mismatch-wrong-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		headers,
	)
	if status != http.StatusConflict {
		t.Fatalf("expected mismatched reservation fields to return 409, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "reservation fields do not match settlement" {
		t.Fatalf("error=%q want=reservation fields do not match settlement", got)
	}

	seedBillingReservation(t, scaffold, "res-session-mismatch-1", "sess-session-mismatch-1", "subject-session-mismatch-1", "uusdc", 250)
	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-session-mismatch-1","ReservationID":"res-session-mismatch-1","SessionID":"sess-session-mismatch-wrong-1","SubjectID":"subject-session-mismatch-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		headers,
	)
	if status != http.StatusConflict {
		t.Fatalf("expected session-mismatched reservation fields to return 409, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "reservation fields do not match settlement" {
		t.Fatalf("error=%q want=reservation fields do not match settlement", got)
	}

	seedBillingReservation(t, scaffold, "res-currency-mismatch-1", "sess-currency-mismatch-1", "subject-currency-mismatch-1", "uusdc", 250)
	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-currency-mismatch-1","ReservationID":"res-currency-mismatch-1","SessionID":"sess-currency-mismatch-1","SubjectID":"subject-currency-mismatch-1","ChargedMicros":250,"Currency":"utdpn","SettledAt":"2026-01-01T00:00:00Z"}`,
		headers,
	)
	if status != http.StatusConflict {
		t.Fatalf("expected currency-mismatched reservation fields to return 409, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "reservation fields do not match settlement" {
		t.Fatalf("error=%q want=reservation fields do not match settlement", got)
	}

	seedBillingReservation(t, scaffold, "res-overcharge-1", "sess-overcharge-1", "subject-overcharge-1", "uusdc", 250)
	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-overcharge-1","ReservationID":"res-overcharge-1","SessionID":"sess-overcharge-1","SubjectID":"subject-overcharge-1","ChargedMicros":251,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		headers,
	)
	if status != http.StatusConflict {
		t.Fatalf("expected overcharged reservation settlement to return 409, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "charged amount exceeds reserved amount" {
		t.Fatalf("error=%q want=charged amount exceeds reserved amount", got)
	}

	seedBillingReservation(t, scaffold, "res-ok-1", "sess-ok-1", "subject-ok-1", "uusdc", 250)
	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-ok-1","ReservationID":"res-ok-1","SessionID":"sess-ok-1","SubjectID":"subject-ok-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
		headers,
	)
	if status != http.StatusOK {
		t.Fatalf("expected matching reservation settlement to return 200, got %d payload=%v", status, payload)
	}

	seedBillingReservation(t, scaffold, "res-partial-1", "sess-partial-1", "subject-partial-1", "uusdc", 300)
	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-partial-1","ReservationID":"res-partial-1","SessionID":"sess-partial-1","SubjectID":"subject-partial-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
		headers,
	)
	if status != http.StatusOK {
		t.Fatalf("expected partial reservation settlement to return 200, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(
		t,
		http.MethodGet,
		baseURL+"/x/vpnbilling/settlements/set-partial-1",
		"",
		headers,
	)
	if status != http.StatusOK {
		t.Fatalf("expected partial settlement GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONIntField(t, payload, "settlement", "BilledAmount", 250)

	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-ok-1","ReservationID":"res-ok-1","SessionID":"sess-ok-1","SubjectID":"subject-ok-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
		headers,
	)
	if status != http.StatusOK {
		t.Fatalf("expected duplicate settlement replay to return 200, got %d payload=%v", status, payload)
	}
	if replay, _ := payload["replay"].(bool); !replay {
		t.Fatalf("expected duplicate settlement replay=true, got payload=%v", payload)
	}

	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-ok-1","ReservationID":"res-ok-1","SessionID":"sess-ok-1","SubjectID":"subject-ok-1","ChargedMicros":200,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
		headers,
	)
	if status != http.StatusConflict {
		t.Fatalf("expected conflicting settlement replay to return 409, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "conflicting fields") {
		t.Fatalf("error=%q want conflicting fields", got)
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

func TestRunTDPNDSettlementHTTPSponsorReservationRejectsInvalidCreditsOrExpiry(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-sponsor-validation-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-sponsor-validation-test" {
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

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"sponsor-res-invalid-amount-1","SponsorID":"sponsor-invalid-amount-1","SubjectID":"app-invalid-amount-1","SessionID":"sess-invalid-amount-1","AmountMicros":0,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid amount sponsor POST to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "AmountMicros must be > 0" {
		t.Fatalf("error=%q want=AmountMicros must be > 0", got)
	}

	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"sponsor-res-expired-1","SponsorID":"sponsor-expired-1","SubjectID":"app-expired-1","SessionID":"sess-expired-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2020-01-01T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected expired sponsor POST to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "ExpiresAt must be in the future" {
		t.Fatalf("error=%q want=ExpiresAt must be in the future", got)
	}

	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"sponsor-res-blank-currency-1","SponsorID":"sponsor-blank-currency-1","SubjectID":"app-blank-currency-1","SessionID":"sess-blank-currency-1","AmountMicros":500,"Currency":"   ","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected blank currency sponsor POST to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "Currency is required" {
		t.Fatalf("error=%q want=Currency is required", got)
	}

	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"sponsor-res-invalid-currency-1","SponsorID":"sponsor-invalid-currency-1","SubjectID":"app-invalid-currency-1","SessionID":"sess-invalid-currency-1","AmountMicros":500,"Currency":"uu sdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid currency sponsor POST to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "Currency must be a canonical non-empty token" {
		t.Fatalf("error=%q want=Currency must be a canonical non-empty token", got)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/authorizations/auth:sponsor-res-invalid-amount-1", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected invalid-amount authorization GET to return 404, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/sponsor-res-invalid-amount-1", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected invalid-amount delegation GET to return 404, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/authorizations/auth:sponsor-res-expired-1", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected expired authorization GET to return 404, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/sponsor-res-expired-1", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected expired delegation GET to return 404, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/authorizations/auth:sponsor-res-blank-currency-1", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected blank-currency authorization GET to return 404, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/sponsor-res-invalid-currency-1", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected invalid-currency delegation GET to return 404, got %d payload=%v", status, payload)
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

func TestRunTDPNDSettlementHTTPSponsorReservationRejectsInvalidSponsorOperationWithoutMetadata(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-sponsor-operation-validation-test"},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-sponsor-operation-validation-test" {
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

	const invalidAuthorizationReservationID = "sponsor-res-invalid-auth-operation-1"
	longAppID := strings.Repeat("a", 129)
	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"`+invalidAuthorizationReservationID+`","SponsorID":"sponsor-invalid-auth-operation-1","AppID":"`+longAppID+`","EndUserID":"user-invalid-auth-operation-1","SessionID":"sess-invalid-auth-operation-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid authorization sponsor POST to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "app id exceeds 128 characters" {
		t.Fatalf("error=%q want=app id exceeds 128 characters", got)
	}
	assertSponsorCurrencyMetadataAbsent(t, scaffold, invalidAuthorizationReservationID)
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/authorizations/auth:"+invalidAuthorizationReservationID, "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected invalid authorization record to be absent, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/"+invalidAuthorizationReservationID, "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected invalid authorization delegation to be absent, got %d payload=%v", status, payload)
	}

	const invalidDelegationReservationID = "sponsor-res-invalid-delegation-operation-1"
	longEndUserID := strings.Repeat("u", 129)
	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"`+invalidDelegationReservationID+`","SponsorID":"sponsor-invalid-delegation-operation-1","AppID":"app-invalid-delegation-operation-1","EndUserID":"`+longEndUserID+`","SessionID":"sess-invalid-delegation-operation-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid delegation sponsor POST to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "end user id exceeds 128 characters" {
		t.Fatalf("error=%q want=end user id exceeds 128 characters", got)
	}
	assertSponsorCurrencyMetadataAbsent(t, scaffold, invalidDelegationReservationID)
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/authorizations/auth:"+invalidDelegationReservationID, "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected invalid delegation authorization to be absent, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/"+invalidDelegationReservationID, "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected invalid delegation record to be absent, got %d payload=%v", status, payload)
	}

	const conflictingAuthorizationReservationID = "sponsor-res-conflicting-auth-operation-1"
	_, err = scaffold.SponsorMsgServer().CreateAuthorization(context.Background(), app.SponsorCreateAuthorizationRequest{
		Record: sponsortypes.SponsorAuthorization{
			AuthorizationID: "auth:" + conflictingAuthorizationReservationID,
			SponsorID:       "existing-conflict-sponsor-1",
			AppID:           "existing-conflict-app-1",
			MaxCredits:      500,
			ExpiresAtUnix:   1798675200,
			Status:          chaintypes.ReconciliationPending,
		},
	})
	if err != nil {
		t.Fatalf("seed conflicting sponsor authorization: %v", err)
	}
	status, payload = doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"`+conflictingAuthorizationReservationID+`","SponsorID":"new-conflict-sponsor-1","AppID":"new-conflict-app-1","EndUserID":"new-conflict-user-1","SessionID":"sess-conflicting-auth-operation-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusConflict {
		t.Fatalf("expected conflicting authorization sponsor POST to return 409, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "vpnsponsor: authorization conflict" {
		t.Fatalf("error=%q want=vpnsponsor: authorization conflict", got)
	}
	assertSponsorCurrencyMetadataAbsent(t, scaffold, conflictingAuthorizationReservationID)
	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/"+conflictingAuthorizationReservationID, "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected conflicting authorization delegation to be absent, got %d payload=%v", status, payload)
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

func TestRunTDPNDSettlementHTTPSponsorReservationCurrencyRoundTrips(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-sponsor-currency-test"},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-sponsor-currency-test" {
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

	const reservationID = "sponsor-res-currency-1"
	const authorizationID = "auth:" + reservationID
	body := `{"ReservationID":"` + reservationID + `","SponsorID":"sponsor-currency-1","SubjectID":"app-currency-1","SessionID":"sess-currency-1","AmountMicros":500,"Currency":" TDPNC ","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`

	status, payload := doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnsponsor/reservations", body, nil)
	if status != http.StatusOK {
		t.Fatalf("expected sponsor reservation POST to return 200, got %d payload=%v", status, payload)
	}
	if got, _ := payload["id"].(string); got != reservationID {
		t.Fatalf("expected sponsor reservation id %q, got %q", reservationID, got)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/authorizations/"+authorizationID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected sponsor authorization GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "authorization", "Currency", "tdpnc")

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/"+reservationID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected sponsor delegation GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "delegation", "Currency", "tdpnc")

	metaResp, err := scaffold.BillingQueryServer().GetReservation(context.Background(), app.BillingGetReservationRequest{
		ReservationID: sponsorReservationCurrencyMetadataID(reservationID),
	})
	if err != nil {
		t.Fatalf("query persisted sponsor currency metadata: %v", err)
	}
	if !metaResp.Found {
		t.Fatal("expected sponsor currency metadata reservation to be persisted")
	}
	if metaResp.Reservation.AssetDenom != "tdpnc" {
		t.Fatalf("expected persisted sponsor currency %q, got %q", "tdpnc", metaResp.Reservation.AssetDenom)
	}

	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnsponsor/reservations", body, nil)
	if status != http.StatusOK {
		t.Fatalf("expected sponsor reservation replay POST to return 200, got %d payload=%v", status, payload)
	}
	if replay, _ := payload["replay"].(bool); !replay {
		t.Fatalf("expected sponsor reservation replay=true, got payload=%v", payload)
	}

	conflictBody := `{"ReservationID":"` + reservationID + `","SponsorID":"sponsor-currency-1","SubjectID":"app-currency-1","SessionID":"sess-currency-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnsponsor/reservations", conflictBody, nil)
	if status != http.StatusConflict {
		t.Fatalf("expected sponsor reservation currency conflict to return 409, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); got != "sponsor reservation currency does not match existing reservation" {
		t.Fatalf("error=%q want=sponsor reservation currency does not match existing reservation", got)
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

func TestRunTDPNDSettlementHTTPRejectsReservedSponsorCurrencyMetadataReservationIDs(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-reserved-metadata-id-test"},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-reserved-metadata-id-test" {
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

	reservedID := sponsorReservationCurrencyMetadataID("sponsor-res-user-visible-1")
	billingBody := `{"ReservationID":"` + reservedID + `","SessionID":"sess-reserved-metadata-billing-1","SubjectID":"subject-reserved-metadata-1","AmountMicros":300,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z"}`
	status, payload := doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnbilling/reservations", billingBody, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("reserved billing id status=%d want=%d payload=%v", status, http.StatusBadRequest, payload)
	}
	if got, _ := payload["error"].(string); got != "ReservationID uses a reserved bridge metadata prefix" {
		t.Fatalf("reserved billing error=%q payload=%v", got, payload)
	}

	sponsorBody := `{"ReservationID":"` + reservedID + `","SponsorID":"sponsor-reserved-metadata-1","SubjectID":"app-reserved-metadata-1","SessionID":"sess-reserved-metadata-sponsor-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`
	status, payload = doJSONRequest(t, http.MethodPost, baseURL+"/x/vpnsponsor/reservations", sponsorBody, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("reserved sponsor id status=%d want=%d payload=%v", status, http.StatusBadRequest, payload)
	}
	if got, _ := payload["error"].(string); got != "ReservationID uses a reserved bridge metadata prefix" {
		t.Fatalf("reserved sponsor error=%q payload=%v", got, payload)
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

func TestRunTDPNDSettlementHTTPSponsorIdentityMappingDistinctAppAndEndUser(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-sponsor-identity-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-sponsor-identity-test" {
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

	const reservationID = "sponsor-res-ident-1"
	const authorizationID = "auth:" + reservationID
	const appID = "app-ident-1"
	const endUserID = "enduser-ident-1"

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"`+reservationID+`","SponsorID":"sponsor-ident-1","SubjectID":"legacy-subject-ident-1","AppID":"`+appID+`","EndUserID":"`+endUserID+`","SessionID":"sess-ident-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected sponsor POST to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/authorizations/"+authorizationID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected authorization GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "authorization", "AppID", appID)

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/"+reservationID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected delegation GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "delegation", "AppID", appID)
	expectJSONStringField(t, payload, "delegation", "EndUserID", endUserID)

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

func TestRunTDPNDSettlementHTTPSponsorIdentityMappingLegacySubjectFallback(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-sponsor-legacy-fallback-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-sponsor-legacy-fallback-test" {
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

	const reservationID = "sponsor-res-legacy-1"
	const authorizationID = "auth:" + reservationID
	const subjectID = "legacy-subject-1"

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnsponsor/reservations",
		`{"ReservationID":"`+reservationID+`","SponsorID":"sponsor-legacy-1","SubjectID":"`+subjectID+`","SessionID":"sess-legacy-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("expected sponsor POST to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/authorizations/"+authorizationID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected authorization GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "authorization", "AppID", subjectID)

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnsponsor/delegations/"+reservationID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected delegation GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONStringField(t, payload, "delegation", "AppID", subjectID)
	expectJSONStringField(t, payload, "delegation", "EndUserID", subjectID)

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

func TestRunTDPNDSettlementHTTPQueryHappyPathAndLists(t *testing.T) {
	const authToken = "bridge-query-token"
	const finalityToken = "bridge-query-finality-token"

	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-query-test",
				"--settlement-http-auth-token", authToken,
				"--settlement-http-finality-auth-token", finalityToken,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-query-test" {
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
	headers := settlementFinalityHeaders(authToken, finalityToken)
	seedBillingReservation(t, scaffold, "res-query-1", "sess-query-1", "subject-query-1", "uusdc", 250)
	rewardQueryProofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-query-1",
		"reward-query-1",
		"provider-query-1",
		"sess-query-1",
		100,
		"uusdc",
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Time{},
		time.Time{},
	)

	seedCases := []struct {
		path string
		body string
	}{
		{
			path: "/x/vpnbilling/settlements",
			body: `{"SettlementID":"set-query-1","ReservationID":"res-query-1","SessionID":"sess-query-1","SubjectID":"subject-query-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
		},
		{
			path: "/x/vpnrewards/issues",
			body: `{"RewardID":"reward-query-1","ProviderSubjectID":"provider-query-1","SessionID":"sess-query-1","SettlementReferenceID":"set-query-1","TrafficProofRef":"` + rewardQueryProofRef + `","PayoutPeriodStart":"2025-12-29T00:00:00Z","PayoutPeriodEnd":"2026-01-05T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnsponsor/reservations",
			body: `{"ReservationID":"sponsor-res-query-1","SponsorID":"sponsor-query-1","SubjectID":"app-query-1","SessionID":"sess-query-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		},
		{
			path: "/x/vpnslashing/evidence",
			body: `{"EvidenceID":"ev-query-1","SubjectID":"provider-query-1","SessionID":"sess-query-1","ViolationType":"double-sign","EvidenceRef":"sha256:98c28e7336b1709232b3cf6d5a5af8c4d0a779fe32360f37d8a1c832f03e5cbf","SlashMicros":25,"Currency":"uusdc","ObservedAt":"2026-01-01T00:00:00Z"}`,
		},
	}

	for _, tc := range seedCases {
		status, payload := doJSONRequest(t, http.MethodPost, baseURL+tc.path, tc.body, headers)
		if status != http.StatusOK {
			t.Fatalf("expected POST %s to return 200, got %d payload=%v", tc.path, status, payload)
		}
	}
	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnslashing/evidence",
		`{"EvidenceID":"ev-query-other","SubjectID":"provider-query-other","SessionID":"sess-query-1","ViolationType":"double-sign","EvidenceRef":"sha256:045e4f6d4216a2ae8d2e69d92f8db88c0333bf81ba69647753d5b127ae83836b","ObservedAt":"2026-01-01T00:00:00Z"}`,
		headers,
	)
	if status != http.StatusOK {
		t.Fatalf("expected extra slash evidence seed to return 200, got %d payload=%v", status, payload)
	}
	status, payload = doJSONRequest(
		t,
		http.MethodGet,
		baseURL+"/x/vpnslashing/evidence?subject_id=provider-query-1&session_id=sess-query-1&observed_at_or_after=2026-01-01T00:00:00Z&observed_before=2026-01-08T00:00:00Z",
		"",
		headers,
	)
	if status != http.StatusOK {
		t.Fatalf("expected filtered slash evidence list to return 200, got %d payload=%v", status, payload)
	}
	evidenceItems, ok := payload["evidence"].([]any)
	if !ok || len(evidenceItems) != 1 {
		t.Fatalf("filtered evidence=%#v want one item payload=%v", payload["evidence"], payload)
	}
	evidenceRecord, ok := evidenceItems[0].(map[string]any)
	if !ok {
		t.Fatalf("filtered evidence[0]=%#v want object", evidenceItems[0])
	}
	if got, _ := evidenceRecord["EvidenceID"].(string); got != "ev-query-1" {
		t.Fatalf("filtered EvidenceID=%q want ev-query-1 payload=%v", got, payload)
	}

	scaffold.SlashingModule.Keeper.UpsertEvidence(slashingtypes.SlashEvidence{
		EvidenceID:      "ev-query-failed",
		ProviderID:      "provider-query-1",
		SessionID:       "sess-query-1",
		Kind:            slashingtypes.EvidenceKindObjective,
		ViolationType:   "double-sign",
		ProofHash:       "sha256:4ce6a4b234c807e9ef2696a6dd8fa72a7f41e93c76e7db3fba6258c124b92373",
		SubmittedAtUnix: 1767225600,
		Status:          "failed",
	})
	status, payload = doJSONRequest(
		t,
		http.MethodGet,
		baseURL+"/x/vpnslashing/evidence?subject_id=provider-query-1&session_id=sess-query-1",
		"",
		headers,
	)
	if status != http.StatusOK {
		t.Fatalf("expected default failed-inclusive slash evidence list to return 200, got %d payload=%v", status, payload)
	}
	evidenceItems, ok = payload["evidence"].([]any)
	if !ok || len(evidenceItems) != 2 {
		t.Fatalf("default evidence=%#v want submitted+failed payload=%v", payload["evidence"], payload)
	}
	status, payload = doJSONRequest(
		t,
		http.MethodGet,
		baseURL+"/x/vpnslashing/evidence?subject_id=provider-query-1&session_id=sess-query-1&include_failed=false",
		"",
		headers,
	)
	if status != http.StatusOK {
		t.Fatalf("expected explicit failed-exclusive slash evidence list to return 200, got %d payload=%v", status, payload)
	}
	evidenceItems, ok = payload["evidence"].([]any)
	if !ok || len(evidenceItems) != 1 {
		t.Fatalf("explicit-false evidence=%#v want only submitted payload=%v", payload["evidence"], payload)
	}
	evidenceRecord, ok = evidenceItems[0].(map[string]any)
	if !ok {
		t.Fatalf("explicit-false evidence[0]=%#v want object", evidenceItems[0])
	}
	if got, _ := evidenceRecord["EvidenceID"].(string); got == "ev-query-failed" {
		t.Fatalf("include_failed=false returned failed evidence payload=%v", payload)
	}
	status, payload = doJSONRequest(
		t,
		http.MethodGet,
		baseURL+"/x/vpnslashing/evidence?subject_id=provider-query-1&session_id=sess-query-1&include_failed=tru",
		"",
		headers,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid include_failed to return 400, got %d payload=%v", status, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "invalid include_failed") {
		t.Fatalf("expected invalid include_failed error, got payload=%v", payload)
	}

	confirmedEvidence, ok := scaffold.SlashingModule.Keeper.GetEvidence("ev-query-1")
	if !ok {
		t.Fatal("expected slash evidence ev-query-1 to exist before penalty seed")
	}
	confirmedEvidence.Status = chaintypes.ReconciliationConfirmed
	scaffold.SlashingModule.Keeper.UpsertEvidence(confirmedEvidence)

	_, err = scaffold.SlashingMsgServer().ApplyPenalty(context.Background(), app.SlashingApplyPenaltyRequest{
		Record: slashingtypes.PenaltyDecision{
			PenaltyID:       "pen-query-1",
			EvidenceID:      "ev-query-1",
			SlashBasisPoint: 25,
			SlashAmount:     25,
			SlashDenom:      "uusdc",
			Jailed:          false,
			AppliedAtUnix:   1735689600,
		},
	})
	if err != nil {
		t.Fatalf("apply penalty seed: %v", err)
	}

	validatorMsg := validatormodule.NewMsgServer(scaffold.ValidatorModule.Keeper)
	if _, err := validatorMsg.SetValidatorEligibility(validatormodule.SetValidatorEligibilityRequest{
		Eligibility: validatortypes.ValidatorEligibility{
			ValidatorID:     "val-query-1",
			OperatorAddress: "op-query-1",
			Eligible:        true,
			PolicyReason:    "bootstrap policy",
		},
	}); err != nil {
		t.Fatalf("set validator eligibility seed: %v", err)
	}
	if _, err := validatorMsg.RecordValidatorStatus(validatormodule.RecordValidatorStatusRequest{
		Record: validatortypes.ValidatorStatusRecord{
			StatusID:        "status-query-1",
			ValidatorID:     "val-query-1",
			LifecycleStatus: validatortypes.ValidatorLifecycleActive,
			EvidenceHeight:  99,
			EvidenceRef:     "sha256:ce1ad56555311a8b138899bc99700d80aa1b55950daeab84a859a0c9f5fca6db",
		},
	}); err != nil {
		t.Fatalf("record validator status seed: %v", err)
	}

	governanceMsg := governancemodule.NewMsgServer(scaffold.GovernanceModule.Keeper)
	if _, err := governanceMsg.CreatePolicy(governancemodule.CreatePolicyRequest{
		Policy: governancetypes.GovernancePolicy{
			PolicyID:        "policy-query-1",
			Title:           "bootstrap-policy",
			Description:     "phase 6 governance seed",
			Version:         1,
			ActivatedAtUnix: 1735689600,
		},
	}); err != nil {
		t.Fatalf("create governance policy seed: %v", err)
	}
	if _, err := governanceMsg.RecordDecision(governancemodule.RecordDecisionRequest{
		Decision: governancetypes.GovernanceDecision{
			DecisionID:    "decision-query-1",
			PolicyID:      "policy-query-1",
			ProposalID:    "proposal-query-1",
			Outcome:       governancetypes.DecisionOutcomeApprove,
			Decider:       "bootstrap-multisig",
			Reason:        "objective thresholds met",
			DecidedAtUnix: 1735689601,
		},
	}); err != nil {
		t.Fatalf("record governance decision seed: %v", err)
	}
	if _, err := governanceMsg.RecordAuditAction(governancemodule.RecordAuditActionRequest{
		Action: governancetypes.GovernanceAuditAction{
			ActionID:        "action-query-1",
			Action:          "admin_set_policy",
			Actor:           "bootstrap-multisig",
			Reason:          "initialization",
			EvidencePointer: "obj://audit/action-query-1",
			TimestampUnix:   1735689602,
		},
	}); err != nil {
		t.Fatalf("record governance audit action seed: %v", err)
	}

	getByIDChecks := []struct {
		path      string
		objectKey string
		idField   string
		idValue   string
	}{
		{path: "/x/vpnbilling/reservations/res-query-1", objectKey: "reservation", idField: "ReservationID", idValue: "res-query-1"},
		{path: "/x/vpnbilling/settlements/set-query-1", objectKey: "settlement", idField: "SettlementID", idValue: "set-query-1"},
		{path: "/x/vpnrewards/accruals/reward-query-1", objectKey: "accrual", idField: "AccrualID", idValue: "reward-query-1"},
		{path: "/x/vpnrewards/distributions/dist:reward-query-1", objectKey: "distribution", idField: "DistributionID", idValue: "dist:reward-query-1"},
		{path: "/x/vpnsponsor/authorizations/auth:sponsor-res-query-1", objectKey: "authorization", idField: "AuthorizationID", idValue: "auth:sponsor-res-query-1"},
		{path: "/x/vpnsponsor/delegations/sponsor-res-query-1", objectKey: "delegation", idField: "ReservationID", idValue: "sponsor-res-query-1"},
		{path: "/x/vpnslashing/evidence/ev-query-1", objectKey: "evidence", idField: "EvidenceID", idValue: "ev-query-1"},
		{path: "/x/vpnslashing/penalties/pen-query-1", objectKey: "penalty", idField: "PenaltyID", idValue: "pen-query-1"},
		{path: "/x/vpnvalidator/eligibilities/val-query-1", objectKey: "eligibility", idField: "ValidatorID", idValue: "val-query-1"},
		{path: "/x/vpnvalidator/status-records/status-query-1", objectKey: "status", idField: "StatusID", idValue: "status-query-1"},
		{path: "/x/vpngovernance/policies/policy-query-1", objectKey: "policy", idField: "PolicyID", idValue: "policy-query-1"},
		{path: "/x/vpngovernance/decisions/decision-query-1", objectKey: "decision", idField: "DecisionID", idValue: "decision-query-1"},
		{path: "/x/vpngovernance/audit-actions/action-query-1", objectKey: "action", idField: "ActionID", idValue: "action-query-1"},
	}

	for _, tc := range getByIDChecks {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+tc.path, "", headers)
		if status != http.StatusOK {
			t.Fatalf("expected GET %s to return 200, got %d payload=%v", tc.path, status, payload)
		}
		expectJSONIDField(t, payload, tc.objectKey, tc.idField, tc.idValue)
	}

	listChecks := []struct {
		path    string
		listKey string
	}{
		{path: "/x/vpnbilling/reservations", listKey: "reservations"},
		{path: "/x/vpnbilling/settlements", listKey: "settlements"},
		{path: "/x/vpnrewards/accruals", listKey: "accruals"},
		{path: "/x/vpnrewards/distributions", listKey: "distributions"},
		{path: "/x/vpnsponsor/authorizations", listKey: "authorizations"},
		{path: "/x/vpnsponsor/delegations", listKey: "delegations"},
		{path: "/x/vpnslashing/evidence", listKey: "evidence"},
		{path: "/x/vpnslashing/penalties", listKey: "penalties"},
		{path: "/x/vpnvalidator/eligibilities", listKey: "eligibilities"},
		{path: "/x/vpnvalidator/status-records", listKey: "records"},
		{path: "/x/vpngovernance/policies", listKey: "policies"},
		{path: "/x/vpngovernance/decisions", listKey: "decisions"},
		{path: "/x/vpngovernance/audit-actions", listKey: "actions"},
	}
	for _, tc := range listChecks {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+tc.path, "", headers)
		if status != http.StatusOK {
			t.Fatalf("expected GET %s to return 200, got %d payload=%v", tc.path, status, payload)
		}
		expectJSONArrayNonEmpty(t, payload, tc.listKey)
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

func TestRunTDPNDSettlementHTTPQueryNotFoundByID(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--settlement-http-listen", "settlement-notfound-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-notfound-test" {
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

	missingPaths := []string{
		"/x/vpnbilling/reservations/missing-reservation",
		"/x/vpnbilling/settlements/missing-settlement",
		"/x/vpnrewards/accruals/missing-accrual",
		"/x/vpnrewards/distributions/missing-distribution",
		"/x/vpnsponsor/authorizations/missing-authorization",
		"/x/vpnsponsor/delegations/missing-delegation",
		"/x/vpnslashing/evidence/missing-evidence",
		"/x/vpnslashing/penalties/missing-penalty",
		"/x/vpnvalidator/eligibilities/missing-validator",
		"/x/vpnvalidator/status-records/missing-status",
		"/x/vpngovernance/policies/missing-policy",
		"/x/vpngovernance/decisions/missing-decision",
		"/x/vpngovernance/audit-actions/missing-action",
	}
	for _, path := range missingPaths {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+path, "", nil)
		if status != http.StatusNotFound {
			t.Fatalf("expected GET %s to return 404, got %d payload=%v", path, status, payload)
		}
		if payload["error"] != "not found" {
			t.Fatalf("expected GET %s payload error=not found, got %v", path, payload["error"])
		}
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

func TestRunTDPNDSettlementHTTPGETQueriesRequireAuthWithAuth(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const authToken = "bridge-open-get-secret"
	const finalityToken = "bridge-open-get-finality-secret"
	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-get-open-test",
				"--settlement-http-auth-token", authToken,
				"--settlement-http-finality-auth-token", finalityToken,
			},
			nil,
			func() chainScaffold { return scaffold },
			runtimeDeps{
				Listen: func(_, _ string) (net.Listener, error) {
					return nil, errors.New("grpc listener should not be used")
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-get-open-test" {
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

	unauthStatus, _ := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnbilling/settlements",
		`{"SettlementID":"set-auth-open-denied-1","SessionID":"sess-auth-open-1","SubjectID":"subject-auth-open-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		nil,
	)
	if unauthStatus != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated POST to remain blocked with 401, got %d", unauthStatus)
	}

	authHeaders := settlementFinalityHeaders(authToken, finalityToken)
	seedBillingReservation(t, scaffold, "res-auth-open-1", "sess-auth-open-1", "subject-auth-open-1", "uusdc", 250)
	rewardAuthOpenProofRef := seedVerifiedRewardProof(
		t,
		scaffold,
		"traffic-proof/reward-auth-open-1",
		"reward-auth-open-1",
		"provider-auth-open-1",
		"sess-auth-open-1",
		100,
		"uusdc",
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Time{},
		time.Time{},
	)
	seedCases := []struct {
		path string
		body string
	}{
		{
			path: "/x/vpnbilling/settlements",
			body: `{"SettlementID":"set-auth-open-1","ReservationID":"res-auth-open-1","SessionID":"sess-auth-open-1","SubjectID":"subject-auth-open-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
		},
		{
			path: "/x/vpnrewards/issues",
			body: `{"RewardID":"reward-auth-open-1","ProviderSubjectID":"provider-auth-open-1","SessionID":"sess-auth-open-1","SettlementReferenceID":"set-auth-open-1","TrafficProofRef":"` + rewardAuthOpenProofRef + `","PayoutPeriodStart":"2025-12-29T00:00:00Z","PayoutPeriodEnd":"2026-01-05T00:00:00Z","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnsponsor/reservations",
			body: `{"ReservationID":"sponsor-res-auth-open-1","SponsorID":"sponsor-auth-open-1","SubjectID":"app-auth-open-1","SessionID":"sess-auth-open-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		},
		{
			path: "/x/vpnslashing/evidence",
			body: `{"EvidenceID":"ev-auth-open-1","SubjectID":"provider-auth-open-1","SessionID":"sess-auth-open-1","ViolationType":"double-sign","EvidenceRef":"sha256:9bbf13c7bdf221673b5d927e27af94491bef49ed1f623c05e2e9206ea0f21934","SlashMicros":30,"Currency":"uusdc","ObservedAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnvalidator/eligibilities",
			body: `{"ValidatorID":"val-auth-open-1","OperatorAddress":"op-auth-open-1","Eligible":true,"PolicyReason":"bootstrap policy","UpdatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}`,
		},
		{
			path: "/x/vpnvalidator/status-records",
			body: `{"StatusID":"status-auth-open-1","ValidatorID":"val-auth-open-1","ConsensusAddress":"cons-auth-open-1","LifecycleStatus":"active","EvidenceHeight":99,"EvidenceRef":"sha256:0550eb9cd962ce3f3362e46ba082d65e6c8708386b4acc14ab4ead4915c78fe8","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}`,
		},
		{
			path: "/x/vpngovernance/policies",
			body: `{"PolicyID":"policy-auth-open-1","Title":"auth-open-policy","Description":"auth open read query","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}`,
		},
		{
			path: "/x/vpngovernance/decisions",
			body: `{"DecisionID":"decision-auth-open-1","PolicyID":"policy-auth-open-1","ProposalID":"proposal-auth-open-1","Outcome":"approve","Decider":"bootstrap-multisig","Reason":"contract auth-open coverage","DecidedAt":"2026-01-01T00:00:01Z","Status":"confirmed"}`,
		},
		{
			path: "/x/vpngovernance/audit-actions",
			body: `{"ActionID":"action-auth-open-1","Action":"admin_set_policy","Actor":"bootstrap-multisig","Reason":"auth-open query coverage","EvidencePointer":"obj://audit/action-auth-open-1","Timestamp":"2026-01-01T00:00:02Z"}`,
		},
	}

	for _, tc := range seedCases {
		status, payload := doJSONRequest(t, http.MethodPost, baseURL+tc.path, tc.body, authHeaders)
		if status != http.StatusOK {
			t.Fatalf("expected authenticated POST %s to return 200, got %d payload=%v", tc.path, status, payload)
		}
	}

	confirmedEvidence, ok := scaffold.SlashingModule.Keeper.GetEvidence("ev-auth-open-1")
	if !ok {
		t.Fatal("expected slash evidence ev-auth-open-1 to exist before penalty seed")
	}
	confirmedEvidence.Status = chaintypes.ReconciliationConfirmed
	scaffold.SlashingModule.Keeper.UpsertEvidence(confirmedEvidence)

	_, err = scaffold.SlashingMsgServer().ApplyPenalty(context.Background(), app.SlashingApplyPenaltyRequest{
		Record: slashingtypes.PenaltyDecision{
			PenaltyID:       "pen-auth-open-1",
			EvidenceID:      "ev-auth-open-1",
			SlashBasisPoint: 30,
			SlashAmount:     30,
			SlashDenom:      "uusdc",
			Jailed:          true,
			AppliedAtUnix:   1735689600,
		},
	})
	if err != nil {
		t.Fatalf("apply penalty seed in auth mode: %v", err)
	}

	openGETChecks := []string{
		"/x/vpnbilling/reservations/res-auth-open-1",
		"/x/vpnbilling/settlements/set-auth-open-1",
		"/x/vpnrewards/accruals/reward-auth-open-1",
		"/x/vpnrewards/distributions/dist:reward-auth-open-1",
		"/x/vpnsponsor/authorizations/auth:sponsor-res-auth-open-1",
		"/x/vpnsponsor/delegations/sponsor-res-auth-open-1",
		"/x/vpnslashing/evidence/ev-auth-open-1",
		"/x/vpnslashing/penalties/pen-auth-open-1",
		"/x/vpnvalidator/eligibilities/val-auth-open-1",
		"/x/vpnvalidator/status-records/status-auth-open-1",
		"/x/vpngovernance/policies/policy-auth-open-1",
		"/x/vpngovernance/decisions/decision-auth-open-1",
		"/x/vpngovernance/audit-actions/action-auth-open-1",
	}

	for _, path := range openGETChecks {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+path, "", nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("expected unauthenticated GET %s to return 401, got %d payload=%v", path, status, payload)
		}
		status, payload = doJSONRequest(t, http.MethodGet, baseURL+path, "", authHeaders)
		if status != http.StatusOK {
			t.Fatalf("expected authenticated GET %s to return 200, got %d payload=%v", path, status, payload)
		}
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

func TestRunTDPNDGRPCAndSettlementHTTPTogether(t *testing.T) {
	grpcListener := bufconn.Listen(1024 * 1024)
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{"--grpc-listen", "bufnet-combo", "--settlement-http-listen", "settlement-combo"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
			runtimeDeps{
				Listen: func(_, address string) (net.Listener, error) {
					if address != "bufnet-combo" {
						return nil, errors.New("unexpected grpc listen address")
					}
					return grpcListener, nil
				},
				ListenHTTP: func(_, address string) (net.Listener, error) {
					if address != "settlement-combo" {
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

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	conn, err := grpc.DialContext(
		dialCtx,
		"bufnet-combo",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return grpcListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	grpcHealth := healthpb.NewHealthClient(conn)
	healthResp, err := grpcHealth.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("grpc health check failed: %v", err)
	}
	if healthResp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("expected grpc health SERVING, got %v", healthResp.GetStatus())
	}

	httpURL := "http://" + httpListener.Addr().String() + "/health"
	waitForHTTPReady(t, httpURL)

	httpHealthResp, err := http.Get(httpURL)
	if err != nil {
		t.Fatalf("http health check failed: %v", err)
	}
	_ = httpHealthResp.Body.Close()
	if httpHealthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected settlement health 200, got %d", httpHealthResp.StatusCode)
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

func TestBindIdentityFieldToAuthenticatedCallerEdgeCases(t *testing.T) {
	tests := []struct {
		name                   string
		rawFieldValue          string
		authenticatedPrincipal string
		wantBoundValue         string
		wantAllowed            bool
	}{
		{
			name:                   "no authenticated principal returns trimmed field",
			rawFieldValue:          "  Raw-Subject  ",
			authenticatedPrincipal: "",
			wantBoundValue:         "Raw-Subject",
			wantAllowed:            true,
		},
		{
			name:                   "empty field autofills canonical principal",
			rawFieldValue:          "   ",
			authenticatedPrincipal: "  Bridge-Subject-1  ",
			wantBoundValue:         "bridge-subject-1",
			wantAllowed:            true,
		},
		{
			name:                   "case-insensitive principal match canonicalizes output",
			rawFieldValue:          " BRIDGE-SUBJECT-1 ",
			authenticatedPrincipal: " bridge-subject-1 ",
			wantBoundValue:         "bridge-subject-1",
			wantAllowed:            true,
		},
		{
			name:                   "mismatched principal is rejected",
			rawFieldValue:          "bridge-subject-2",
			authenticatedPrincipal: "bridge-subject-1",
			wantBoundValue:         "",
			wantAllowed:            false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotBoundValue, gotAllowed := bindIdentityFieldToAuthenticatedCaller(tc.rawFieldValue, tc.authenticatedPrincipal)
			if gotAllowed != tc.wantAllowed {
				t.Fatalf("expected allowed=%t, got %t (boundValue=%q)", tc.wantAllowed, gotAllowed, gotBoundValue)
			}
			if gotBoundValue != tc.wantBoundValue {
				t.Fatalf("expected bound value %q, got %q", tc.wantBoundValue, gotBoundValue)
			}
		})
	}
}

func TestValidateBridgeSlashEvidenceRefEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		proofHash string
		wantErr   bool
	}{
		{
			name:      "accepts sha256 objective proof",
			proofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr:   false,
		},
		{
			name:      "accepts obj objective proof",
			proofHash: "obj://bridge/edge/proof-2",
			wantErr:   false,
		},
		{
			name:      "rejects legacy proof format",
			proofHash: "legacy-proof-format",
			wantErr:   true,
		},
		{
			name:      "rejects obj proof with whitespace in path",
			proofHash: "obj://bridge/edge/proof with-space",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBridgeSlashEvidenceRef(tc.proofHash)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for proof hash %q", tc.proofHash)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for proof hash %q, got %v", tc.proofHash, err)
			}
		})
	}
}

func seedBillingReservation(
	t *testing.T,
	scaffold *app.ChainScaffold,
	reservationID string,
	sessionID string,
	subjectID string,
	currency string,
	amount int64,
) {
	t.Helper()

	_, err := scaffold.BillingMsgServer().CreateReservation(context.Background(), app.BillingCreateReservationRequest{
		Record: billingtypes.CreditReservation{
			ReservationID: strings.TrimSpace(reservationID),
			SponsorID:     strings.TrimSpace(subjectID),
			SessionID:     strings.TrimSpace(sessionID),
			AssetDenom:    strings.TrimSpace(currency),
			Amount:        amount,
			CreatedAtUnix: 1735689600,
			Status:        chaintypes.ReconciliationConfirmed,
		},
	})
	if err != nil {
		t.Fatalf("seed billing reservation %q: %v", reservationID, err)
	}
}

func seedVerifiedRewardProof(
	t *testing.T,
	scaffold *app.ChainScaffold,
	proofPath string,
	rewardID string,
	providerSubjectID string,
	sessionID string,
	rewardMicros int64,
	currency string,
	issuedAt time.Time,
	periodStart time.Time,
	periodEnd time.Time,
) string {
	t.Helper()

	proofRef := "obj://" + strings.TrimSpace(proofPath)
	verifiedAt := issuedAt.Add(time.Minute)
	if issuedAt.IsZero() {
		verifiedAt = time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	}
	if periodStart.IsZero() && periodEnd.IsZero() && !issuedAt.IsZero() {
		periodStart = defaultRewardTestPeriodStart(issuedAt)
		periodEnd = periodStart.AddDate(0, 0, 7)
	}
	record := rewardtypes.RewardProofRecord{
		ProofPath:         proofPath,
		TrafficProofRef:   proofRef,
		TrustContract:     rewardtypes.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          rewardID,
		ProviderSubjectID: providerSubjectID,
		SessionID:         sessionID,
		PayoutStartUnix:   unixOrZero(periodStart),
		PayoutEndUnix:     unixOrZero(periodEnd),
		RewardMicros:      rewardMicros,
		Currency:          currency,
		IssuedAtUnix:      unixOrZero(issuedAt),
		Verified:          true,
		VerifierID:        "settlement-bridge-test-verifier",
		VerifiedAtUnix:    verifiedAt.UTC().Unix(),
	}
	if err := scaffold.RewardsModule.Keeper.UpsertProofWithError(record); err != nil {
		t.Fatalf("seed verified reward proof %q: %v", proofPath, err)
	}
	return proofRef
}

func defaultRewardTestPeriodStart(issuedAt time.Time) time.Time {
	issuedUTC := issuedAt.UTC()
	start := time.Date(issuedUTC.Year(), issuedUTC.Month(), issuedUTC.Day(), 0, 0, 0, 0, time.UTC)
	daysSinceMonday := (int(start.Weekday()) + 6) % 7
	start = start.AddDate(0, 0, -daysSinceMonday)
	if issuedUTC.Weekday() == time.Monday && issuedUTC.Sub(start) <= time.Minute {
		start = start.AddDate(0, 0, -7)
	}
	return start
}

func assertSponsorCurrencyMetadataAbsent(t *testing.T, scaffold *app.ChainScaffold, reservationID string) {
	t.Helper()

	metaResp, err := scaffold.BillingQueryServer().GetReservation(context.Background(), app.BillingGetReservationRequest{
		ReservationID: sponsorReservationCurrencyMetadataID(reservationID),
	})
	if err != nil {
		t.Fatalf("query sponsor currency metadata for %q: %v", reservationID, err)
	}
	if metaResp.Found {
		t.Fatalf("expected no sponsor currency metadata for %q, found %#v", reservationID, metaResp.Reservation)
	}
}

func doJSONRequest(t *testing.T, method, url, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()

	var requestBody io.Reader
	if body != "" {
		requestBody = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if req.Header.Get("Origin") == "" && req.URL != nil && req.URL.Host != "" &&
		(req.URL.Scheme == "http" || req.URL.Scheme == "https") {
		req.Header.Set("Origin", req.URL.Scheme+"://"+req.URL.Host)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("perform request %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body for %s %s: %v", method, url, err)
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return resp.StatusCode, map[string]any{}
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode json body for %s %s: %v body=%s", method, url, err, trimmed)
	}
	return resp.StatusCode, payload
}

func settlementAuthHeaders(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func settlementFinalityHeaders(token, finalityToken string) map[string]string {
	return map[string]string{
		"Authorization":             "Bearer " + token,
		finalityAuthorizationHeader: "Bearer " + finalityToken,
	}
}

func expectJSONIDField(t *testing.T, payload map[string]any, objectKey, idField, expectedID string) {
	t.Helper()

	record, ok := payload[objectKey].(map[string]any)
	if !ok {
		t.Fatalf("expected payload[%s] to be object, got %#v", objectKey, payload[objectKey])
	}
	got, ok := record[idField].(string)
	if !ok {
		t.Fatalf("expected payload[%s][%s] to be string, got %#v", objectKey, idField, record[idField])
	}
	if got != expectedID {
		t.Fatalf("expected payload[%s][%s]=%s, got %s", objectKey, idField, expectedID, got)
	}
}

func expectJSONStringField(t *testing.T, payload map[string]any, objectKey, field, expected string) {
	t.Helper()

	record, ok := payload[objectKey].(map[string]any)
	if !ok {
		t.Fatalf("expected payload[%s] to be object, got %#v", objectKey, payload[objectKey])
	}
	got, ok := record[field].(string)
	if !ok {
		t.Fatalf("expected payload[%s][%s] to be string, got %#v", objectKey, field, record[field])
	}
	if got != expected {
		t.Fatalf("expected payload[%s][%s]=%s, got %s", objectKey, field, expected, got)
	}
}

func expectJSONIntField(t *testing.T, payload map[string]any, objectKey, field string, expected int64) {
	t.Helper()

	record, ok := payload[objectKey].(map[string]any)
	if !ok {
		t.Fatalf("expected payload[%s] to be object, got %#v", objectKey, payload[objectKey])
	}

	raw, ok := record[field]
	if !ok {
		t.Fatalf("expected payload[%s][%s] to be present", objectKey, field)
	}

	gotFloat, ok := raw.(float64)
	if !ok {
		t.Fatalf("expected payload[%s][%s] to be number, got %#v", objectKey, field, raw)
	}

	got := int64(gotFloat)
	if float64(got) != gotFloat {
		t.Fatalf("expected payload[%s][%s] to be integer-compatible number, got %v", objectKey, field, gotFloat)
	}
	if got != expected {
		t.Fatalf("expected payload[%s][%s]=%d, got %d", objectKey, field, expected, got)
	}
}

func expectJSONArrayNonEmpty(t *testing.T, payload map[string]any, listKey string) {
	t.Helper()

	items, ok := payload[listKey].([]any)
	if !ok {
		t.Fatalf("expected payload[%s] to be array, got %#v", listKey, payload[listKey])
	}
	if len(items) == 0 {
		t.Fatalf("expected payload[%s] to be non-empty", listKey)
	}
}

func waitForHTTPReady(t *testing.T, url string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for http readiness at %s: %v", url, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
