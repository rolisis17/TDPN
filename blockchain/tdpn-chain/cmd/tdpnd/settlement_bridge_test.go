package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
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

	payload := []byte(`{"EvidenceID":"ev-auth-1","SubjectID":"provider-auth-1","SessionID":"sess-auth-1","EvidenceRef":"sha256:proof-auth-1","ObservedAt":"2026-01-01T00:00:00Z"}`)
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

func TestRunTDPNDSettlementHTTPAuthContractGETOpenPOSTBearerRequired(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const authToken = "bridge-contract-secret"
	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-auth-contract-test",
				"--settlement-http-auth-token", authToken,
			},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
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

	// Auth mode must keep query GET endpoints open (never 401-gated).
	openGetPaths := []string{
		"/health",
		"/x/vpnbilling/reservations",
		"/x/vpnbilling/settlements",
		"/x/vpnrewards/accruals",
		"/x/vpnrewards/distributions",
		"/x/vpnsponsor/authorizations",
		"/x/vpnsponsor/delegations",
		"/x/vpnslashing/evidence",
		"/x/vpnslashing/penalties",
	}
	for _, path := range openGetPaths {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+path, "", nil)
		if status != http.StatusOK {
			t.Fatalf("expected unauthenticated GET %s to return 200 in auth mode, got %d payload=%v", path, status, payload)
		}
	}

	testCases := []struct {
		name      string
		postPath  string
		postBody  string
		verifyGET string
	}{
		{
			name:      "billing",
			postPath:  "/x/vpnbilling/settlements",
			postBody:  `{"SettlementID":"set-auth-contract-1","ReservationID":"res-auth-contract-1","SessionID":"sess-auth-contract-1","SubjectID":"subject-auth-contract-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
			verifyGET: "/x/vpnbilling/settlements/set-auth-contract-1",
		},
		{
			name:      "rewards",
			postPath:  "/x/vpnrewards/issues",
			postBody:  `{"RewardID":"reward-auth-contract-1","ProviderSubjectID":"provider-auth-contract-1","SessionID":"sess-auth-contract-1","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
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
			postBody:  `{"EvidenceID":"ev-auth-contract-1","SubjectID":"provider-auth-contract-1","SessionID":"sess-auth-contract-1","ViolationType":"objective","EvidenceRef":"sha256:proof-auth-contract-1","ObservedAt":"2026-01-01T00:00:00Z"}`,
			verifyGET: "/x/vpnslashing/evidence/ev-auth-contract-1",
		},
	}

	validHeaders := map[string]string{"Authorization": "Bearer " + authToken}
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
		if status != http.StatusOK {
			t.Fatalf("[%s] expected unauthenticated GET %s to remain open after write, got %d payload=%v",
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

	status, payload := doJSONRequest(
		t,
		http.MethodPost,
		baseURL+"/x/vpnslashing/evidence",
		`{"EvidenceID":"ev-invalid-ref-1","SubjectID":"provider-invalid-ref-1","SessionID":"sess-invalid-ref-1","ViolationType":"double-sign","EvidenceRef":"proof-invalid-ref-1","ObservedAt":"2026-01-01T00:00:00Z"}`,
		nil,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid evidence_ref to return 400, got %d payload=%v", status, payload)
	}

	errorText, _ := payload["error"].(string)
	if !strings.Contains(errorText, "proof hash must use objective format") {
		t.Fatalf("expected invalid format error, got payload=%v", payload)
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

func TestRunTDPNDSettlementHTTPHappyPathPerEndpoint(t *testing.T) {
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
			[]string{"--settlement-http-listen", "settlement-happy-test"},
			nil,
			func() chainScaffold { return app.NewChainScaffold() },
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

	cases := []struct {
		path string
		body string
	}{
		{
			path: "/x/vpnbilling/settlements",
			body: `{"SettlementID":"set-http-1","SessionID":"sess-http-1","SubjectID":"subject-http-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnrewards/issues",
			body: `{"RewardID":"reward-http-1","ProviderSubjectID":"provider-http-1","SessionID":"sess-http-1","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnsponsor/reservations",
			body: `{"ReservationID":"res-http-1","SponsorID":"sponsor-http-1","SubjectID":"app-http-1","SessionID":"sess-http-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		},
		{
			path: "/x/vpnslashing/evidence",
			body: `{"EvidenceID":"ev-http-1","SubjectID":"provider-http-1","SessionID":"sess-http-1","ViolationType":"objective","EvidenceRef":"sha256:proof-http-1","ObservedAt":"2026-01-01T00:00:00Z"}`,
		},
	}

	for _, tc := range cases {
		resp, err := http.Post(baseURL+tc.path, "application/json", bytes.NewReader([]byte(tc.body)))
		if err != nil {
			t.Fatalf("post %s failed: %v", tc.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d body=%s", tc.path, resp.StatusCode, strings.TrimSpace(string(body)))
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

func TestRunTDPNDSettlementHTTPBillingZeroChargeSettlementContract(t *testing.T) {
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
	if status != http.StatusOK {
		t.Fatalf("expected zero-charge settlement POST to return 200, got %d payload=%v", status, payload)
	}

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/reservations/res-zero-charge-1", "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected reservation GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONIntField(t, payload, "reservation", "Amount", 1)
	expectJSONStringField(t, payload, "reservation", "ReservationID", "res-zero-charge-1")

	status, payload = doJSONRequest(t, http.MethodGet, baseURL+"/x/vpnbilling/settlements/set-zero-charge-1", "", nil)
	if status != http.StatusOK {
		t.Fatalf("expected settlement GET to return 200, got %d payload=%v", status, payload)
	}
	expectJSONIntField(t, payload, "settlement", "BilledAmount", 0)
	expectJSONStringField(t, payload, "settlement", "ReservationID", "res-zero-charge-1")

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
			[]string{"--settlement-http-listen", "settlement-query-test"},
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

	seedCases := []struct {
		path string
		body string
	}{
		{
			path: "/x/vpnbilling/settlements",
			body: `{"SettlementID":"set-query-1","ReservationID":"res-query-1","SessionID":"sess-query-1","SubjectID":"subject-query-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnrewards/issues",
			body: `{"RewardID":"reward-query-1","ProviderSubjectID":"provider-query-1","SessionID":"sess-query-1","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnsponsor/reservations",
			body: `{"ReservationID":"sponsor-res-query-1","SponsorID":"sponsor-query-1","SubjectID":"app-query-1","SessionID":"sess-query-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		},
		{
			path: "/x/vpnslashing/evidence",
			body: `{"EvidenceID":"ev-query-1","SubjectID":"provider-query-1","SessionID":"sess-query-1","ViolationType":"objective","EvidenceRef":"sha256:proof-query-1","ObservedAt":"2026-01-01T00:00:00Z"}`,
		},
	}

	for _, tc := range seedCases {
		status, payload := doJSONRequest(t, http.MethodPost, baseURL+tc.path, tc.body, nil)
		if status != http.StatusOK {
			t.Fatalf("expected POST %s to return 200, got %d payload=%v", tc.path, status, payload)
		}
	}

	_, err = scaffold.SlashingMsgServer().ApplyPenalty(context.Background(), app.SlashingApplyPenaltyRequest{
		Record: slashingtypes.PenaltyDecision{
			PenaltyID:       "pen-query-1",
			EvidenceID:      "ev-query-1",
			SlashBasisPoint: 25,
			Jailed:          false,
			AppliedAtUnix:   1735689600,
		},
	})
	if err != nil {
		t.Fatalf("apply penalty seed: %v", err)
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
	}

	for _, tc := range getByIDChecks {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+tc.path, "", nil)
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
	}
	for _, tc := range listChecks {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+tc.path, "", nil)
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

func TestRunTDPNDSettlementHTTPGETQueriesRemainOpenWithAuth(t *testing.T) {
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	defer httpListener.Close()

	scaffold := app.NewChainScaffold()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const authToken = "bridge-open-get-secret"
	runDone := make(chan error, 1)
	go func() {
		runDone <- runTDPND(
			ctx,
			[]string{
				"--settlement-http-listen", "settlement-get-open-test",
				"--settlement-http-auth-token", authToken,
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

	authHeaders := map[string]string{"Authorization": "Bearer " + authToken}
	seedCases := []struct {
		path string
		body string
	}{
		{
			path: "/x/vpnbilling/settlements",
			body: `{"SettlementID":"set-auth-open-1","ReservationID":"res-auth-open-1","SessionID":"sess-auth-open-1","SubjectID":"subject-auth-open-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnrewards/issues",
			body: `{"RewardID":"reward-auth-open-1","ProviderSubjectID":"provider-auth-open-1","SessionID":"sess-auth-open-1","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
		},
		{
			path: "/x/vpnsponsor/reservations",
			body: `{"ReservationID":"sponsor-res-auth-open-1","SponsorID":"sponsor-auth-open-1","SubjectID":"app-auth-open-1","SessionID":"sess-auth-open-1","AmountMicros":500,"Currency":"uusdc","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}`,
		},
		{
			path: "/x/vpnslashing/evidence",
			body: `{"EvidenceID":"ev-auth-open-1","SubjectID":"provider-auth-open-1","SessionID":"sess-auth-open-1","ViolationType":"objective","EvidenceRef":"sha256:proof-auth-open-1","ObservedAt":"2026-01-01T00:00:00Z"}`,
		},
	}

	for _, tc := range seedCases {
		status, payload := doJSONRequest(t, http.MethodPost, baseURL+tc.path, tc.body, authHeaders)
		if status != http.StatusOK {
			t.Fatalf("expected authenticated POST %s to return 200, got %d payload=%v", tc.path, status, payload)
		}
	}

	_, err = scaffold.SlashingMsgServer().ApplyPenalty(context.Background(), app.SlashingApplyPenaltyRequest{
		Record: slashingtypes.PenaltyDecision{
			PenaltyID:       "pen-auth-open-1",
			EvidenceID:      "ev-auth-open-1",
			SlashBasisPoint: 30,
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
	}

	for _, path := range openGETChecks {
		status, payload := doJSONRequest(t, http.MethodGet, baseURL+path, "", nil)
		if status != http.StatusOK {
			t.Fatalf("expected unauthenticated GET %s to return 200, got %d payload=%v", path, status, payload)
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
