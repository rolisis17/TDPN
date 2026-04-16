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
	governancemodule "github.com/tdpn/tdpn-chain/x/vpngovernance/module"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
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

	payload := []byte(`{"EvidenceID":"ev-auth-1","SubjectID":"provider-auth-1","SessionID":"sess-auth-1","EvidenceRef":"sha256:dcae4c8808ecbf9c1374201b09c7706b90df20b57e0aaf25e36a1053a421ea8a","ObservedAt":"2026-01-01T00:00:00Z"}`)
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
		"/x/vpnvalidator/eligibilities",
		"/x/vpnvalidator/status-records",
		"/x/vpngovernance/policies",
		"/x/vpngovernance/decisions",
		"/x/vpngovernance/audit-actions",
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
			postBody:  `{"EvidenceID":"ev-auth-contract-1","SubjectID":"provider-auth-contract-1","SessionID":"sess-auth-contract-1","ViolationType":"objective","EvidenceRef":"sha256:688aac5bfff82af2d92ef98edb1a7d98e963b9ed60d96cf66145d29cec3a1d28","ObservedAt":"2026-01-01T00:00:00Z"}`,
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
			postBody:  `{"ActionID":"action-auth-contract-1","Action":"policy.bootstrap","Actor":"bootstrap-multisig","Reason":"auth contract audit","EvidencePointer":"obj://audit/action-auth-contract-1","Timestamp":"2026-01-01T00:00:03Z"}`,
			verifyGET: "/x/vpngovernance/audit-actions/action-auth-contract-1",
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
			body:      `{"SettlementID":"set-http-1","SessionID":"sess-http-1","SubjectID":"subject-http-1","ChargedMicros":250,"Currency":"uusdc","SettledAt":"2026-01-01T00:00:00Z"}`,
			verifyGET: "/x/vpnbilling/settlements/set-http-1",
			objectKey: "settlement",
			idField:   "SettlementID",
			idValue:   "set-http-1",
		},
		{
			path:       "/x/vpnrewards/issues",
			body:       `{"RewardID":"reward-http-1","ProviderSubjectID":"provider-http-1","SessionID":"sess-http-1","RewardMicros":100,"Currency":"uusdc","IssuedAt":"2026-01-01T00:00:00Z"}`,
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
			body:      `{"EvidenceID":"ev-http-1","SubjectID":"provider-http-1","SessionID":"sess-http-1","ViolationType":"objective","EvidenceRef":"sha256:d15cf66aff24713d226c1cfc45c9056acdb396b8e24da71c57d1e5a34efd2d08","ObservedAt":"2026-01-01T00:00:00Z"}`,
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
			body:      `{"ActionID":"action-http-1","Action":"policy.bootstrap","Actor":"bootstrap-multisig","Reason":"happy path audit","EvidencePointer":"obj://audit/action-http-1","Timestamp":"2026-01-01T00:00:03Z"}`,
			verifyGET: "/x/vpngovernance/audit-actions/action-http-1",
			objectKey: "action",
			idField:   "ActionID",
			idValue:   "action-http-1",
		},
	}

	for _, tc := range cases {
		status, payload := doJSONRequest(t, http.MethodPost, baseURL+tc.path, tc.body, nil)
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

		status, payload = doJSONRequest(t, http.MethodGet, baseURL+tc.verifyGET, "", nil)
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
			postBody:  `{"ActionID":"action-method-1","Action":"policy.bootstrap","Actor":"bootstrap-multisig","Reason":"method audit","EvidencePointer":"obj://audit/action-method-1","Timestamp":"2026-01-01T00:00:03Z"}`,
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
			body: `{"EvidenceID":"ev-query-1","SubjectID":"provider-query-1","SessionID":"sess-query-1","ViolationType":"objective","EvidenceRef":"sha256:98c28e7336b1709232b3cf6d5a5af8c4d0a779fe32360f37d8a1c832f03e5cbf","ObservedAt":"2026-01-01T00:00:00Z"}`,
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

	validatorMsg := validatormodule.NewMsgServer(&scaffold.ValidatorModule.Keeper)
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

	governanceMsg := governancemodule.NewMsgServer(&scaffold.GovernanceModule.Keeper)
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
			Action:          "policy.bootstrap",
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
		{path: "/x/vpnvalidator/eligibilities", listKey: "eligibilities"},
		{path: "/x/vpnvalidator/status-records", listKey: "records"},
		{path: "/x/vpngovernance/policies", listKey: "policies"},
		{path: "/x/vpngovernance/decisions", listKey: "decisions"},
		{path: "/x/vpngovernance/audit-actions", listKey: "actions"},
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
			body: `{"EvidenceID":"ev-auth-open-1","SubjectID":"provider-auth-open-1","SessionID":"sess-auth-open-1","ViolationType":"objective","EvidenceRef":"sha256:9bbf13c7bdf221673b5d927e27af94491bef49ed1f623c05e2e9206ea0f21934","ObservedAt":"2026-01-01T00:00:00Z"}`,
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
			body: `{"ActionID":"action-auth-open-1","Action":"policy.bootstrap","Actor":"bootstrap-multisig","Reason":"auth-open query coverage","EvidencePointer":"obj://audit/action-auth-open-1","Timestamp":"2026-01-01T00:00:02Z"}`,
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
		"/x/vpnvalidator/eligibilities/val-auth-open-1",
		"/x/vpnvalidator/status-records/status-auth-open-1",
		"/x/vpngovernance/policies/policy-auth-open-1",
		"/x/vpngovernance/decisions/decision-auth-open-1",
		"/x/vpngovernance/audit-actions/action-auth-open-1",
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
