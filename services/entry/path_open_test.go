package entry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pncrypto "privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func strictExitRouteFixture() exitRoute {
	return exitRoute{
		controlURL: "https://exit.example",
		dataAddr:   "exit.example:51821",
		operatorID: "op-exit",
		fetchedAt:  time.Now(),
		validUntil: time.Now().Add(time.Minute),
	}
}

func TestHandlePathOpenLiveModeRejectsNonWireGuardTransport(t *testing.T) {
	exitCalls := 0
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exitCalls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer exitSrv.Close()

	s := &Service{
		liveWGMode:     true,
		dataAddr:       "127.0.0.1:51820",
		exitControlURL: exitSrv.URL,
		exitDataAddr:   "127.0.0.1:51821",
		httpClient:     exitSrv.Client(),
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{},
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
		routeTTL:       time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		Transport:  "policy-json",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40000"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open in live mode for non-wireguard transport")
	}
	if out.Reason != "transport must be wireguard-udp in entry live mode" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenStrictRequiresTokenProofNonce(t *testing.T) {
	s := &Service{betaStrict: true}
	reqBody, err := json.Marshal(proto.PathOpenRequest{
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40000"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open without nonce in strict mode")
	}
	if out.Reason != "token-proof-nonce-required" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
}

func TestHandlePathOpenStrictRejectsMalformedTokenProof(t *testing.T) {
	s := &Service{betaStrict: true}
	reqBody, err := json.Marshal(proto.PathOpenRequest{
		TokenProof:      "not-base64",
		TokenProofNonce: "nonce-a",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40000"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open for malformed proof in strict mode")
	}
	if out.Reason != "token-proof-invalid" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
}

func TestHandlePathOpenStrictRejectsEmptyExitIDBeforeForwarding(t *testing.T) {
	exitCalls := 0
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exitCalls++
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: true})
	}))
	defer exitSrv.Close()

	s := &Service{
		betaStrict:     true,
		dataAddr:       "127.0.0.1:51820",
		exitControlURL: exitSrv.URL,
		exitDataAddr:   "127.0.0.1:51821",
		httpClient:     exitSrv.Client(),
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{},
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
		routeTTL:       time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		TokenProof:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SignatureSize)),
		TokenProofNonce: "nonce-strict-empty-exit",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40002"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open without exit id in strict mode")
	}
	if out.Reason != "unknown-exit" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit when strict empty exit id is rejected, got %d", exitCalls)
	}
}

func TestHandlePathOpenStrictRejectsMissingMiddleRelayBeforeForwarding(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-b",
			Role:       "exit",
			OperatorID: "op-exit",
			Endpoint:   "exit.example:51821",
			ControlURL: "https://exit.example",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["https://exit.example/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{Accepted: true, SessionExp: time.Now().Add(5 * time.Minute).Unix(), Transport: "wireguard-udp"})(nil)
	}

	s := &Service{
		betaStrict:            true,
		requireMiddleRelay:    true,
		dataAddr:              "127.0.0.1:51820",
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:              map[string]sessionState{},
		exitRouteCache:        map[string]exitRoute{"exit-b": strictExitRouteFixture()},
		directoryURLs:         []string{durl},
		buckets:               map[string]rateBucket{},
		abuse:                 map[string]abuseState{},
		openRPS:               100,
		routeTTL:              time.Minute,
		requireDistinctExitOp: false,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:          "exit-b",
		TokenProof:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SignatureSize)),
		TokenProofNonce: "nonce-strict-missing-middle",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41008"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected strict mode to reject missing middle relay")
	}
	if out.Reason != "middle-relay-required" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit when middle relay is required, got %d", exitCalls)
	}
}

func TestHandlePathOpenRequireMiddleRelayRejectsMissingMiddleRelayBeforeForwarding(t *testing.T) {
	exitCalls := 0
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exitCalls++
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: true})
	}))
	defer exitSrv.Close()

	s := &Service{
		requireMiddleRelay: true,
		dataAddr:           "127.0.0.1:51820",
		httpClient:         exitSrv.Client(),
		sessions:           map[string]sessionState{},
		exitRouteCache:     map[string]exitRoute{"exit-b": {controlURL: exitSrv.URL, dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		buckets:            map[string]rateBucket{},
		abuse:              map[string]abuseState{},
		openRPS:            100,
		routeTTL:           time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:     "exit-b",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41009"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected require-middle-relay mode to reject missing middle relay")
	}
	if out.Reason != "middle-relay-required" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit when middle relay is required, got %d", exitCalls)
	}
}

func TestHandlePathOpenDefaultAllowsMissingMiddleRelay(t *testing.T) {
	exitCalls := 0
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exitCalls++
		resp := proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer exitSrv.Close()

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		httpClient:     exitSrv.Client(),
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: exitSrv.URL, dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
		routeTTL:       time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:     "exit-b",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41010"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected default mode to allow missing middle relay, reason=%q", out.Reason)
	}
	if exitCalls != 1 {
		t.Fatalf("expected one call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenLiveModeAllowsWireGuardTransport(t *testing.T) {
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/path/open" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var in proto.PathOpenRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if in.Transport != "wireguard-udp" {
			t.Fatalf("expected wireguard-udp transport, got %q", in.Transport)
		}
		resp := proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer exitSrv.Close()

	s := &Service{
		liveWGMode:     true,
		dataAddr:       "127.0.0.1:51820",
		exitControlURL: exitSrv.URL,
		exitDataAddr:   "127.0.0.1:51821",
		httpClient:     exitSrv.Client(),
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{},
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
		routeTTL:       time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		Transport:  "wireguard-udp",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40001"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected accepted response, got reason=%q", out.Reason)
	}
	if out.Transport != "wireguard-udp" {
		t.Fatalf("expected transport echoed as wireguard-udp, got %q", out.Transport)
	}
	if out.SessionID == "" || out.EntryDataAddr == "" {
		t.Fatalf("expected session details in response, got %+v", out)
	}
}

func TestHandlePathOpenLiveModeRejectsExitTransportDowngrade(t *testing.T) {
	openCalls := 0
	closeCalls := 0
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/path/open":
			openCalls++
			resp := proto.PathOpenResponse{
				Accepted:     true,
				SessionExp:   time.Now().Add(5 * time.Minute).Unix(),
				Transport:    "policy-json",
				SessionKeyID: "sk-downgrade-basic",
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/v1/path/close":
			closeCalls++
			_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer exitSrv.Close()

	s := &Service{
		liveWGMode: true,
		dataAddr:   "127.0.0.1:51820",
		httpClient: exitSrv.Client(),
		sessions:   map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{
			"exit-live": {
				controlURL: exitSrv.URL,
				dataAddr:   "127.0.0.1:51821",
				operatorID: "op-exit",
				fetchedAt:  time.Now(),
			},
		},
		buckets:  map[string]rateBucket{},
		abuse:    map[string]abuseState{},
		openRPS:  100,
		routeTTL: time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:     "exit-live",
		Transport:  "wireguard-udp",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40002"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open when exit downgrades live transport")
	}
	if out.Reason != "transport must be wireguard-udp in entry live mode" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if openCalls != 1 {
		t.Fatalf("expected one open call to exit, got %d", openCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("expected one close cleanup call to exit, got %d", closeCalls)
	}
	if len(s.sessions) != 0 {
		t.Fatalf("expected no session recorded on transport downgrade, got %d", len(s.sessions))
	}
}

func TestHandlePathOpenLiveModeRejectsExitTransportDowngradeAndClosesRemoteSession(t *testing.T) {
	openCalls := 0
	closeCalls := 0
	openedSessionID := ""
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/path/open":
			openCalls++
			var in proto.PathOpenRequest
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Fatalf("decode open request: %v", err)
			}
			if strings.TrimSpace(in.SessionID) == "" {
				t.Fatalf("expected generated session id in forwarded open request")
			}
			openedSessionID = in.SessionID
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{
				Accepted:     true,
				SessionExp:   time.Now().Add(5 * time.Minute).Unix(),
				Transport:    "policy-json",
				SessionKeyID: "sk-downgrade-close",
			})
		case "/v1/path/close":
			closeCalls++
			var in proto.PathCloseRequest
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Fatalf("decode close request: %v", err)
			}
			if in.SessionID != openedSessionID {
				t.Fatalf("expected close for opened session id=%q, got %q", openedSessionID, in.SessionID)
			}
			if in.SessionKeyID != "sk-downgrade-close" {
				t.Fatalf("expected close request to include exit session key id, got %q", in.SessionKeyID)
			}
			_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer exitSrv.Close()

	s := &Service{
		liveWGMode: true,
		dataAddr:   "127.0.0.1:51820",
		httpClient: exitSrv.Client(),
		sessions:   map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{
			"exit-live-close": {
				controlURL: exitSrv.URL,
				dataAddr:   "127.0.0.1:51821",
				operatorID: "op-exit",
				fetchedAt:  time.Now(),
			},
		},
		buckets:  map[string]rateBucket{},
		abuse:    map[string]abuseState{},
		openRPS:  100,
		routeTTL: time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:     "exit-live-close",
		Transport:  "wireguard-udp",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40003"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open when exit downgrades live transport")
	}
	if out.Reason != "transport must be wireguard-udp in entry live mode" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if openCalls != 1 {
		t.Fatalf("expected one open call to exit, got %d", openCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("expected one best-effort close call after downgrade rejection, got %d", closeCalls)
	}
	if len(s.sessions) != 0 {
		t.Fatalf("expected no local session recorded on transport downgrade, got %d", len(s.sessions))
	}
}

func TestHandlePathOpenRejectsWhenSessionCapacityReached(t *testing.T) {
	exitCalls := 0
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exitCalls++
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})
	}))
	defer exitSrv.Close()

	s := &Service{
		dataAddr:              "127.0.0.1:51820",
		httpClient:            exitSrv.Client(),
		maxSessions:           1,
		sessions:              map[string]sessionState{"existing": {expiresUnix: time.Now().Add(5 * time.Minute).Unix()}},
		exitRouteCache:        map[string]exitRoute{"exit-a": {controlURL: exitSrv.URL, dataAddr: "127.0.0.1:51821", operatorID: "op-b", fetchedAt: time.Now()}},
		buckets:               map[string]rateBucket{},
		abuse:                 map[string]abuseState{},
		openRPS:               100,
		routeTTL:              time.Minute,
		requireDistinctExitOp: false,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:     "exit-a",
		Transport:  "wireguard-udp",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40102"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open when session capacity is reached")
	}
	if out.Reason != "entry-capacity-exceeded" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no exit call when at session capacity, got %d", exitCalls)
	}
}

func TestHandlePathOpenConcurrentCapacityReservesSessionSlot(t *testing.T) {
	var exitCallsMu sync.Mutex
	exitCalls := 0
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://exit.local/v1/path/open": func(req *http.Request) (*http.Response, error) {
			exitCallsMu.Lock()
			exitCalls++
			exitCallsMu.Unlock()
			entered <- struct{}{}
			<-release
			return jsonResp(proto.PathOpenResponse{
				Accepted:   true,
				SessionExp: time.Now().Add(5 * time.Minute).Unix(),
				Transport:  "wireguard-udp",
			})(req)
		},
	}
	s := &Service{
		dataAddr:              "127.0.0.1:51820",
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		maxSessions:           1,
		sessions:              map[string]sessionState{},
		exitRouteCache:        map[string]exitRoute{"exit-a": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-b", fetchedAt: time.Now()}},
		buckets:               map[string]rateBucket{},
		abuse:                 map[string]abuseState{},
		openRPS:               100,
		routeTTL:              time.Minute,
		requireDistinctExitOp: false,
	}

	type openResult struct {
		code int
		resp proto.PathOpenResponse
		err  error
	}
	openOnce := func(remoteAddr string) openResult {
		reqBody, err := json.Marshal(proto.PathOpenRequest{
			ExitID:     "exit-a",
			Transport:  "wireguard-udp",
			TokenProof: "proof",
		})
		if err != nil {
			return openResult{err: err}
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
		req.RemoteAddr = remoteAddr
		rr := httptest.NewRecorder()
		s.handlePathOpen(rr, req)
		var out proto.PathOpenResponse
		if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
			return openResult{code: rr.Code, err: err}
		}
		return openResult{code: rr.Code, resp: out}
	}

	results := make([]openResult, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	remotes := []string{"127.0.0.1:41101", "127.0.0.1:41102"}
	for i := range remotes {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = openOnce(remotes[idx])
		}(i)
	}
	close(start)

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first forwarded path open")
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	accepted := 0
	capacityRejected := 0
	for i, res := range results {
		if res.err != nil {
			t.Fatalf("result %d error: %v", i, res.err)
		}
		if res.code != http.StatusOK {
			t.Fatalf("result %d expected status 200, got %d", i, res.code)
		}
		if res.resp.Accepted {
			accepted++
		}
		if res.resp.Reason == "entry-capacity-exceeded" {
			capacityRejected++
		}
	}
	if accepted != 1 {
		t.Fatalf("expected exactly one accepted open under maxSessions=1, got %d", accepted)
	}
	if capacityRejected != 1 {
		t.Fatalf("expected exactly one entry-capacity-exceeded rejection, got %d", capacityRejected)
	}

	s.mu.RLock()
	sessionCount := len(s.sessions)
	pendingCount := s.pendingSessions
	s.mu.RUnlock()
	if sessionCount != 1 {
		t.Fatalf("expected exactly one recorded session, got %d", sessionCount)
	}
	if pendingCount != 0 {
		t.Fatalf("expected no pending session reservations after completion, got %d", pendingCount)
	}

	exitCallsMu.Lock()
	recordedExitCalls := exitCalls
	exitCallsMu.Unlock()
	if recordedExitCalls != 1 {
		t.Fatalf("expected exactly one forwarded exit open call, got %d", recordedExitCalls)
	}
}

func TestHandlePathOpenChecksBanBeforeDirectoryFetch(t *testing.T) {
	durl := "http://directory.local"
	directoryCalls := 0
	handlers := map[string]func(*http.Request) (*http.Response, error){
		durl + "/v1/pubkeys": func(req *http.Request) (*http.Response, error) {
			directoryCalls++
			return jsonResp(proto.DirectoryPubKeysResponse{
				Operator: "op-dir",
				PubKeys:  []string{"invalid"},
			})(req)
		},
	}
	now := time.Now()
	s := &Service{
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		directoryURLs:         []string{durl},
		directoryMinSources:   1,
		directoryMinOperators: 1,
		directoryMinVotes:     1,
		sessions:              map[string]sessionState{},
		exitRouteCache:        map[string]exitRoute{},
		buckets:               map[string]rateBucket{},
		abuse: map[string]abuseState{
			"127.0.0.1": {
				lastSeenSec:    now.Unix(),
				bannedUntilSec: now.Add(time.Minute).Unix(),
			},
		},
		openRPS:  100,
		routeTTL: time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:     "exit-unknown",
		Transport:  "wireguard-udp",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41006"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open for banned source")
	}
	if out.Reason != "source-temporarily-blocked" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if directoryCalls != 0 {
		t.Fatalf("expected ban check to short-circuit before directory fetch, got calls=%d", directoryCalls)
	}
}

func TestHandlePathOpenRejectsSameOperatorWhenDistinctRequired(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-a",
			Role:       "exit",
			OperatorID: "op-a",
			Endpoint:   "127.0.0.1:51821",
			ControlURL: "http://exit.local",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(nil)
	}

	s := &Service{
		dataAddr:              "127.0.0.1:51820",
		operatorID:            "op-a",
		requireDistinctExitOp: true,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:              map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{
			"exit-a": {
				controlURL: "http://exit.local",
				dataAddr:   "127.0.0.1:51821",
				operatorID: "op-b",
				fetchedAt:  time.Now(),
			},
		},
		directoryURLs: []string{durl},
		buckets:       map[string]rateBucket{},
		abuse:         map[string]abuseState{},
		openRPS:       100,
		routeTTL:      time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:     "exit-a",
		Transport:  "wireguard-udp",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40101"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open for same entry/exit operator")
	}
	if out.Reason != "entry-exit-operator-collision" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenAllowsDistinctOperatorWhenRequired(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-b",
			Role:       "exit",
			OperatorID: "op-b",
			Endpoint:   "127.0.0.1:51821",
			ControlURL: "http://exit.local",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(nil)
	}

	s := &Service{
		dataAddr:              "127.0.0.1:51820",
		operatorID:            "op-a",
		requireDistinctExitOp: true,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:              map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{
			"exit-b": {
				controlURL: "http://exit.local",
				dataAddr:   "127.0.0.1:51821",
				operatorID: "op-a",
				fetchedAt:  time.Now(),
			},
		},
		directoryURLs: []string{durl},
		buckets:       map[string]rateBucket{},
		abuse:         map[string]abuseState{},
		openRPS:       100,
		routeTTL:      time.Minute,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:     "exit-b",
		Transport:  "wireguard-udp",
		TokenProof: "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:40102"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected accepted open for distinct operators, reason=%q", out.Reason)
	}
	if exitCalls == 0 {
		t.Fatalf("expected call to exit when operators are distinct")
	}
}

func TestHandlePathOpenRejectsUnknownMiddleRelay(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "middle-known", Role: "middle", OperatorID: "op-middle", Endpoint: "127.0.0.1:51822", ValidUntil: time.Now().Add(time.Minute)},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{Accepted: true, SessionExp: time.Now().Add(5 * time.Minute).Unix()})(nil)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-missing",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41001"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open for unknown middle relay")
	}
	if out.Reason != "unknown-middle-relay" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenStrictModeBypassesStaleMiddleRelayCache(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-b",
			Role:       "exit",
			OperatorID: "op-exit",
			Endpoint:   "exit.example:51821",
			ControlURL: "https://exit.example",
			ValidUntil: time.Now().Add(time.Minute),
		},
		{RelayID: "middle-stale", Role: "exit", OperatorID: "op-middle", Endpoint: "127.0.0.1:51822", ValidUntil: time.Now().Add(time.Minute)},
	})
	relayCalls := 0
	baseRelaysHandler := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		relayCalls++
		return baseRelaysHandler(req)
	}

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{Accepted: true, SessionExp: time.Now().Add(5 * time.Minute).Unix()})(nil)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		betaStrict:     true,
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": strictExitRouteFixture()},
		relayDescCache: map[string]cachedRelayDescriptor{
			"middle-stale": {
				desc: proto.RelayDescriptor{
					RelayID:    "middle-stale",
					Role:       "micro-relay",
					OperatorID: "op-middle",
					Endpoint:   "127.0.0.1:51822",
					ValidUntil: time.Now().Add(time.Minute),
				},
				fetchedAt: time.Now(),
			},
		},
		directoryURLs: []string{durl},
		routeTTL:      time.Minute,
		buckets:       map[string]rateBucket{},
		abuse:         map[string]abuseState{},
		openRPS:       100,
	}

	tokenProof := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:          "exit-b",
		MiddleRelayID:   "middle-stale",
		Transport:       "wireguard-udp",
		TokenProof:      tokenProof,
		TokenProofNonce: "nonce-strict-cache-bypass",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41042"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected strict mode to reject stale cached middle relay descriptor")
	}
	if out.Reason != "middle-relay-role-invalid" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if relayCalls == 0 {
		t.Fatalf("expected strict mode to bypass cache and fetch directory relay descriptor")
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenRequireMiddleRelayBypassesStaleMiddleRelayCache(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "middle-stale", Role: "exit", OperatorID: "op-middle", Endpoint: "127.0.0.1:51822", ValidUntil: time.Now().Add(time.Minute)},
	})
	relayCalls := 0
	baseRelaysHandler := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		relayCalls++
		return baseRelaysHandler(req)
	}

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{Accepted: true, SessionExp: time.Now().Add(5 * time.Minute).Unix()})(nil)
	}

	s := &Service{
		requireMiddleRelay: true,
		dataAddr:           "127.0.0.1:51820",
		operatorID:         "op-entry",
		httpClient:         &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:           map[string]sessionState{},
		exitRouteCache:     map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		relayDescCache: map[string]cachedRelayDescriptor{
			"middle-stale": {
				desc: proto.RelayDescriptor{
					RelayID:    "middle-stale",
					Role:       "micro-relay",
					OperatorID: "op-middle",
					Endpoint:   "127.0.0.1:51822",
					ValidUntil: time.Now().Add(time.Minute),
				},
				fetchedAt: time.Now(),
			},
		},
		directoryURLs: []string{durl},
		routeTTL:      time.Minute,
		buckets:       map[string]rateBucket{},
		abuse:         map[string]abuseState{},
		openRPS:       100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-stale",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41044"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected require-middle-relay mode to reject stale cached middle relay descriptor")
	}
	if out.Reason != "middle-relay-role-invalid" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if relayCalls == 0 {
		t.Fatalf("expected require-middle-relay mode to bypass cache and fetch directory relay descriptor")
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenNonStrictModeUsesStaleMiddleRelayCache(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "middle-stale", Role: "exit", OperatorID: "op-middle", Endpoint: "127.0.0.1:51822", ValidUntil: time.Now().Add(time.Minute)},
	})
	relayCalls := 0
	baseRelaysHandler := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		relayCalls++
		return baseRelaysHandler(req)
	}

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{Accepted: true, SessionExp: time.Now().Add(5 * time.Minute).Unix()})(nil)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		relayDescCache: map[string]cachedRelayDescriptor{
			"middle-stale": {
				desc: proto.RelayDescriptor{
					RelayID:    "middle-stale",
					Role:       "micro-relay",
					OperatorID: "op-middle",
					Endpoint:   "127.0.0.1:51822",
					ValidUntil: time.Now().Add(time.Minute),
				},
				fetchedAt: time.Now(),
			},
		},
		directoryURLs: []string{durl},
		routeTTL:      time.Minute,
		buckets:       map[string]rateBucket{},
		abuse:         map[string]abuseState{},
		openRPS:       100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-stale",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41043"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected non-strict mode to use cached middle relay descriptor, reason=%q", out.Reason)
	}
	if relayCalls != 0 {
		t.Fatalf("expected non-strict mode to use cache without fetching relay descriptor, calls=%d", relayCalls)
	}
	if exitCalls != 1 {
		t.Fatalf("expected one call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenNonStrictModeBypassesExpiredMiddleRelayCache(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "middle-expired", Role: "exit", OperatorID: "op-middle", Endpoint: "127.0.0.1:51822", ValidUntil: time.Now().Add(time.Minute)},
	})
	relayCalls := 0
	baseRelaysHandler := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		relayCalls++
		return baseRelaysHandler(req)
	}

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{Accepted: true, SessionExp: time.Now().Add(5 * time.Minute).Unix()})(nil)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		relayDescCache: map[string]cachedRelayDescriptor{
			"middle-expired": {
				desc: proto.RelayDescriptor{
					RelayID:    "middle-expired",
					Role:       "micro-relay",
					OperatorID: "op-middle",
					Endpoint:   "127.0.0.1:51822",
					ValidUntil: time.Now().Add(-time.Minute),
				},
				fetchedAt: time.Now(),
			},
		},
		directoryURLs: []string{durl},
		routeTTL:      time.Minute,
		buckets:       map[string]rateBucket{},
		abuse:         map[string]abuseState{},
		openRPS:       100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-expired",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41045"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected non-strict mode to reject expired cached middle relay descriptor")
	}
	if out.Reason != "middle-relay-role-invalid" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if relayCalls == 0 {
		t.Fatalf("expected non-strict mode to bypass expired cache and fetch directory relay descriptor")
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenRejectsMiddleRelayEqualsExit(t *testing.T) {
	exitCalls := 0
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		exitCalls++
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: true, SessionExp: time.Now().Add(5 * time.Minute).Unix()})
	}))
	defer exitSrv.Close()

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		httpClient:     exitSrv.Client(),
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: exitSrv.URL, dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "exit-b",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41002"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open when middle relay equals exit relay")
	}
	if out.Reason != "middle-relay-equals-exit" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenRejectsMiddleExitOperatorCollision(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "middle-collide", Role: "middle", OperatorID: "op-exit", Endpoint: "127.0.0.1:51822", ValidUntil: time.Now().Add(time.Minute)},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(_ *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{Accepted: true, SessionExp: time.Now().Add(5 * time.Minute).Unix()})(nil)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-collide",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41003"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected denied open for middle/exit operator collision")
	}
	if out.Reason != "middle-exit-operator-collision" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenAllowsValidMiddleRelayAndForwards(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "middle-ok",
			Role:       "entry",
			HopRoles:   []string{"middle"},
			OperatorID: "op-middle",
			Endpoint:   "127.0.0.1:51822",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		var in proto.PathOpenRequest
		if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
			t.Fatalf("decode forwarded request: %v", err)
		}
		if in.MiddleRelayID != "middle-ok" {
			t.Fatalf("expected forwarded middle relay id, got %q", in.MiddleRelayID)
		}
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-ok",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41004"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected accepted open with valid middle relay, reason=%q", out.Reason)
	}
	if exitCalls != 1 {
		t.Fatalf("expected one call to exit, got %d", exitCalls)
	}
}

func TestRelaySupportsMiddleDescriptorRoleAliases(t *testing.T) {
	aliases := []string{
		"middle",
		"relay",
		"micro-relay",
		"micro_relay",
		"transit",
		"three-hop-middle",
	}

	for _, alias := range aliases {
		alias := alias
		t.Run(alias, func(t *testing.T) {
			if !relaySupportsMiddleDescriptor(proto.RelayDescriptor{Role: alias}) {
				t.Fatalf("expected role %q to be accepted as middle descriptor", alias)
			}
		})
	}
}

func TestRelaySupportsMiddleDescriptorForPolicyStrictRejectsRoleAliases(t *testing.T) {
	aliases := []string{
		"middle",
		"relay",
		"micro_relay",
		"transit",
		"three-hop-middle",
	}

	for _, alias := range aliases {
		alias := alias
		t.Run(alias, func(t *testing.T) {
			if relaySupportsMiddleDescriptorForPolicy(proto.RelayDescriptor{Role: alias}, true) {
				t.Fatalf("expected strict policy to reject alias role %q", alias)
			}
		})
	}

	if !relaySupportsMiddleDescriptorForPolicy(proto.RelayDescriptor{
		Role:         "micro-relay",
		Reputation:   0.9,
		Uptime:       0.9,
		Capacity:     0.9,
		AbusePenalty: 0.1,
	}, true) {
		t.Fatal("expected strict policy to accept canonical micro-relay role")
	}
}

func TestHandlePathOpenAllowsMiddleRelayMicroRelayRoleWithoutHopRoles(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "middle-micro-role",
			Role:       "micro-relay",
			OperatorID: "op-middle",
			Endpoint:   "127.0.0.1:51822",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		var in proto.PathOpenRequest
		if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
			t.Fatalf("decode forwarded request: %v", err)
		}
		if in.MiddleRelayID != "middle-micro-role" {
			t.Fatalf("expected forwarded middle relay id, got %q", in.MiddleRelayID)
		}
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-micro-role",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41041"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected accepted open with micro-relay role descriptor, reason=%q", out.Reason)
	}
	if exitCalls != 1 {
		t.Fatalf("expected one call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenStrictRejectsMiddleRelayWithConflictingRoleMetadata(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-b",
			Role:       "exit",
			OperatorID: "op-exit",
			Endpoint:   "exit.example:51821",
			ControlURL: "https://exit.example",
			ValidUntil: time.Now().Add(time.Minute),
		},
		{
			RelayID:    "middle-conflict-strict",
			Role:       "exit",
			HopRoles:   []string{"middle"},
			OperatorID: "op-middle",
			Endpoint:   "127.0.0.1:51822",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		betaStrict:     true,
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": strictExitRouteFixture()},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	tokenProof := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:          "exit-b",
		MiddleRelayID:   "middle-conflict-strict",
		Transport:       "wireguard-udp",
		TokenProof:      tokenProof,
		TokenProofNonce: "nonce-middle-conflict-strict",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41047"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected strict mode to reject conflicting middle relay role metadata")
	}
	if out.Reason != "middle-relay-role-invalid" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenRequireMiddleRelayRejectsMiddleRelayWithConflictingRoleMetadata(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "middle-conflict-required",
			Role:       "exit",
			HopRoles:   []string{"middle"},
			OperatorID: "op-middle",
			Endpoint:   "127.0.0.1:51822",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		requireMiddleRelay: true,
		dataAddr:           "127.0.0.1:51820",
		operatorID:         "op-entry",
		httpClient:         &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:           map[string]sessionState{},
		exitRouteCache:     map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		directoryURLs:      []string{durl},
		routeTTL:           time.Minute,
		buckets:            map[string]rateBucket{},
		abuse:              map[string]abuseState{},
		openRPS:            100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-conflict-required",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41050"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected require-middle-relay mode to reject conflicting middle relay role metadata")
	}
	if out.Reason != "middle-relay-role-invalid" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenStrictRejectsMiddleRelayWithInvalidRuntimeAdmissionMetadata(t *testing.T) {
	tests := []struct {
		name string
		desc proto.RelayDescriptor
	}{
		{
			name: "non-middle hop role",
			desc: proto.RelayDescriptor{
				RelayID:      "middle-runtime-invalid-hop",
				Role:         "micro-relay",
				HopRoles:     []string{"middle", "entry"},
				OperatorID:   "op-middle",
				Reputation:   0.9,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.1,
				Endpoint:     "127.0.0.1:51822",
				ValidUntil:   time.Now().Add(time.Minute),
			},
		},
		{
			name: "disallowed capability",
			desc: proto.RelayDescriptor{
				RelayID:      "middle-runtime-invalid-cap",
				Role:         "micro-relay",
				HopRoles:     []string{"middle"},
				Capabilities: []string{"wg", "tiered-policy"},
				OperatorID:   "op-middle",
				Reputation:   0.9,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.1,
				Endpoint:     "127.0.0.1:51822",
				ValidUntil:   time.Now().Add(time.Minute),
			},
		},
		{
			name: "missing quality scores",
			desc: proto.RelayDescriptor{
				RelayID:    "middle-runtime-missing-scores",
				Role:       "micro-relay",
				HopRoles:   []string{"middle"},
				OperatorID: "op-middle",
				Endpoint:   "127.0.0.1:51822",
				ValidUntil: time.Now().Add(time.Minute),
			},
		},
		{
			name: "under-threshold quality score",
			desc: proto.RelayDescriptor{
				RelayID:      "middle-runtime-under-threshold",
				Role:         "micro-relay",
				HopRoles:     []string{"middle"},
				OperatorID:   "op-middle",
				Reputation:   0.49,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.1,
				Endpoint:     "127.0.0.1:51822",
				ValidUntil:   time.Now().Add(time.Minute),
			},
		},
		{
			name: "abuse penalty above max",
			desc: proto.RelayDescriptor{
				RelayID:      "middle-runtime-high-abuse",
				Role:         "micro-relay",
				HopRoles:     []string{"middle"},
				OperatorID:   "op-middle",
				Reputation:   0.9,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.51,
				Endpoint:     "127.0.0.1:51822",
				ValidUntil:   time.Now().Add(time.Minute),
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			durl := "http://directory.local"
			handlers := make(map[string]func(*http.Request) (*http.Response, error))
			addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
				{
					RelayID:    "exit-b",
					Role:       "exit",
					OperatorID: "op-exit",
					Endpoint:   "exit.example:51821",
					ControlURL: "https://exit.example",
					ValidUntil: time.Now().Add(time.Minute),
				},
				tc.desc,
			})

			exitCalls := 0
			handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
				exitCalls++
				return jsonResp(proto.PathOpenResponse{
					Accepted:   true,
					SessionExp: time.Now().Add(5 * time.Minute).Unix(),
					Transport:  "wireguard-udp",
				})(req)
			}

			s := &Service{
				dataAddr:       "127.0.0.1:51820",
				operatorID:     "op-entry",
				betaStrict:     true,
				httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
				sessions:       map[string]sessionState{},
				exitRouteCache: map[string]exitRoute{"exit-b": strictExitRouteFixture()},
				directoryURLs:  []string{durl},
				routeTTL:       time.Minute,
				buckets:        map[string]rateBucket{},
				abuse:          map[string]abuseState{},
				openRPS:        100,
			}

			tokenProof := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			reqBody, err := json.Marshal(proto.PathOpenRequest{
				ExitID:          "exit-b",
				MiddleRelayID:   tc.desc.RelayID,
				Transport:       "wireguard-udp",
				TokenProof:      tokenProof,
				TokenProofNonce: "nonce-middle-runtime-invalid",
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
			req.RemoteAddr = "127.0.0.1:41050"
			rr := httptest.NewRecorder()
			s.handlePathOpen(rr, req)

			var out proto.PathOpenResponse
			if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if out.Accepted {
				t.Fatalf("expected strict mode to reject invalid middle runtime admission metadata")
			}
			if out.Reason != "middle-relay-role-invalid" {
				t.Fatalf("unexpected reason: %q", out.Reason)
			}
			if exitCalls != 0 {
				t.Fatalf("expected no call to exit, got %d", exitCalls)
			}
		})
	}
}

func TestHandlePathOpenStrictAllowsCanonicalMiddleRelayRole(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-b",
			Role:       "exit",
			OperatorID: "op-exit",
			Endpoint:   "exit.example:51821",
			ControlURL: "https://exit.example",
			ValidUntil: time.Now().Add(time.Minute),
		},
		{
			RelayID:      "middle-canonical-strict",
			Role:         "micro-relay",
			OperatorID:   "op-middle",
			Reputation:   0.9,
			Uptime:       0.9,
			Capacity:     0.9,
			AbusePenalty: 0.1,
			Endpoint:     "127.0.0.1:51822",
			ValidUntil:   time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["https://exit.example/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		var in proto.PathOpenRequest
		if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
			t.Fatalf("decode forwarded request: %v", err)
		}
		if in.MiddleRelayID != "middle-canonical-strict" {
			t.Fatalf("expected forwarded middle relay id, got %q", in.MiddleRelayID)
		}
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		betaStrict:     true,
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "https://exit.example", dataAddr: "exit.example:51821", operatorID: "op-middle", fetchedAt: time.Now(), validUntil: time.Now().Add(time.Minute)}},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	tokenProof := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:          "exit-b",
		MiddleRelayID:   "middle-canonical-strict",
		Transport:       "wireguard-udp",
		TokenProof:      tokenProof,
		TokenProofNonce: "nonce-middle-canonical-strict",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41048"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected strict mode to allow canonical middle role descriptor, reason=%q", out.Reason)
	}
	if exitCalls != 1 {
		t.Fatalf("expected one call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenNonStrictAllowsMiddleRelayWithConflictingRoleMetadata(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "middle-conflict-nonstrict",
			Role:       "exit",
			HopRoles:   []string{"middle"},
			OperatorID: "op-middle",
			Endpoint:   "127.0.0.1:51822",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		var in proto.PathOpenRequest
		if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
			t.Fatalf("decode forwarded request: %v", err)
		}
		if in.MiddleRelayID != "middle-conflict-nonstrict" {
			t.Fatalf("expected forwarded middle relay id, got %q", in.MiddleRelayID)
		}
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-conflict-nonstrict",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41049"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected non-strict mode to allow conflicting middle relay metadata via compatibility path, reason=%q", out.Reason)
	}
	if exitCalls != 1 {
		t.Fatalf("expected one call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenStrictRejectsMiddleRelayWithoutOperatorID(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-b",
			Role:       "exit",
			OperatorID: "op-exit",
			Endpoint:   "exit.example:51821",
			ControlURL: "https://exit.example",
			ValidUntil: time.Now().Add(time.Minute),
		},
		{
			RelayID:      "middle-no-operator",
			Role:         "micro-relay",
			OperatorID:   "",
			Reputation:   0.9,
			Uptime:       0.9,
			Capacity:     0.9,
			AbusePenalty: 0.1,
			Endpoint:     "127.0.0.1:51822",
			ValidUntil:   time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		betaStrict:     true,
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": strictExitRouteFixture()},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	tokenProof := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:          "exit-b",
		MiddleRelayID:   "middle-no-operator",
		Transport:       "wireguard-udp",
		TokenProof:      tokenProof,
		TokenProofNonce: "nonce-middle-operator-missing",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41044"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected strict mode to reject middle relay without operator id")
	}
	if out.Reason != "middle-relay-operator-missing" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenDistinctModeRejectsMiddleRelayWithoutOperatorID(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-b",
			Role:       "exit",
			OperatorID: "op-exit",
			Endpoint:   "127.0.0.1:51821",
			ControlURL: "http://exit.local",
			ValidUntil: time.Now().Add(time.Minute),
		},
		{
			RelayID:    "middle-no-operator-distinct",
			Role:       "middle",
			OperatorID: "",
			Endpoint:   "127.0.0.1:51822",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:              "127.0.0.1:51820",
		operatorID:            "op-entry",
		requireDistinctExitOp: true,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:              map[string]sessionState{},
		exitRouteCache:        map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-entry", fetchedAt: time.Now()}},
		directoryURLs:         []string{durl},
		routeTTL:              time.Minute,
		buckets:               map[string]rateBucket{},
		abuse:                 map[string]abuseState{},
		openRPS:               100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-no-operator-distinct",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41046"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected distinct operator mode to reject middle relay without operator id")
	}
	if out.Reason != "middle-relay-operator-missing" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenRequireMiddleRelayRejectsMiddleRelayWithoutOperatorID(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:      "middle-no-operator-required",
			Role:         "micro-relay",
			OperatorID:   "",
			Reputation:   0.9,
			Uptime:       0.9,
			Capacity:     0.9,
			AbusePenalty: 0.1,
			Endpoint:     "127.0.0.1:51822",
			ValidUntil:   time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:           "127.0.0.1:51820",
		operatorID:         "op-entry",
		requireMiddleRelay: true,
		httpClient:         &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:           map[string]sessionState{},
		exitRouteCache:     map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		directoryURLs:      []string{durl},
		routeTTL:           time.Minute,
		buckets:            map[string]rateBucket{},
		abuse:              map[string]abuseState{},
		openRPS:            100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-no-operator-required",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41048"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Accepted {
		t.Fatalf("expected require-middle-relay mode to reject middle relay without operator id")
	}
	if out.Reason != "middle-relay-operator-missing" {
		t.Fatalf("unexpected reason: %q", out.Reason)
	}
	if exitCalls != 0 {
		t.Fatalf("expected no call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenNonStrictAllowsMiddleRelayWithoutOperatorID(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "middle-no-operator",
			Role:       "middle",
			OperatorID: "",
			Endpoint:   "127.0.0.1:51822",
			ValidUntil: time.Now().Add(time.Minute),
		},
	})

	exitCalls := 0
	handlers["http://exit.local/v1/path/open"] = func(req *http.Request) (*http.Response, error) {
		exitCalls++
		var in proto.PathOpenRequest
		if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
			t.Fatalf("decode forwarded request: %v", err)
		}
		if in.MiddleRelayID != "middle-no-operator" {
			t.Fatalf("expected forwarded middle relay id, got %q", in.MiddleRelayID)
		}
		return jsonResp(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  "wireguard-udp",
		})(req)
	}

	s := &Service{
		dataAddr:       "127.0.0.1:51820",
		operatorID:     "op-entry",
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions:       map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{"exit-b": {controlURL: "http://exit.local", dataAddr: "127.0.0.1:51821", operatorID: "op-exit", fetchedAt: time.Now()}},
		directoryURLs:  []string{durl},
		routeTTL:       time.Minute,
		buckets:        map[string]rateBucket{},
		abuse:          map[string]abuseState{},
		openRPS:        100,
	}

	reqBody, err := json.Marshal(proto.PathOpenRequest{
		ExitID:        "exit-b",
		MiddleRelayID: "middle-no-operator",
		Transport:     "wireguard-udp",
		TokenProof:    "proof",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41045"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected non-strict mode to allow middle relay without operator id, reason=%q", out.Reason)
	}
	if exitCalls != 1 {
		t.Fatalf("expected one call to exit, got %d", exitCalls)
	}
}

func TestHandlePathOpenPreservesProofBoundTransportForForwarding(t *testing.T) {
	issuerPub, issuerPriv, err := pncrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generate issuer keypair: %v", err)
	}
	popPub, popPriv, err := pncrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("generate pop keypair: %v", err)
	}

	claims := pncrypto.CapabilityClaims{
		Audience:   "exit",
		TokenType:  pncrypto.TokenTypeClientAccess,
		CNFEd25519: pncrypto.EncodeEd25519PublicKey(popPub),
		Tier:       1,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "tok-forward-proof",
		ExitScope:  []string{"exit-b"},
	}
	token, err := pncrypto.SignClaims(claims, issuerPriv)
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}

	openReq := proto.PathOpenRequest{
		ExitID:          "exit-b",
		Token:           token,
		TokenProofNonce: "nonce-forward-proof",
		Transport:       "",
		RequestedMTU:    1280,
		RequestedRegion: "ap-southeast",
	}
	proof, err := pncrypto.SignPathOpenProof(popPriv, pncrypto.PathOpenProofInput{
		Token:           openReq.Token,
		ExitID:          openReq.ExitID,
		MiddleRelayID:   openReq.MiddleRelayID,
		TokenProofNonce: openReq.TokenProofNonce,
		ClientInnerPub:  openReq.ClientInnerPub,
		Transport:       openReq.Transport,
		RequestedMTU:    openReq.RequestedMTU,
		RequestedRegion: openReq.RequestedRegion,
	})
	if err != nil {
		t.Fatalf("sign token proof: %v", err)
	}
	openReq.TokenProof = proof

	exitCalls := 0
	forwardedTransport := "unset"
	exitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exitCalls++
		var in proto.PathOpenRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode forwarded request: %v", err)
		}
		forwardedTransport = in.Transport
		gotClaims, err := pncrypto.VerifyClaims(in.Token, issuerPub)
		if err != nil {
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token verification failed"})
			return
		}
		popVerify, err := pncrypto.ParseEd25519PublicKey(gotClaims.CNFEd25519)
		if err != nil {
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token proof key invalid"})
			return
		}
		if err := pncrypto.VerifyPathOpenProof(in.TokenProof, popVerify, pncrypto.PathOpenProofInput{
			Token:           in.Token,
			ExitID:          in.ExitID,
			MiddleRelayID:   in.MiddleRelayID,
			TokenProofNonce: in.TokenProofNonce,
			ClientInnerPub:  in.ClientInnerPub,
			Transport:       in.Transport,
			RequestedMTU:    in.RequestedMTU,
			RequestedRegion: in.RequestedRegion,
		}); err != nil {
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token proof invalid"})
			return
		}
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{
			Accepted:   true,
			SessionExp: time.Now().Add(5 * time.Minute).Unix(),
			Transport:  in.Transport,
		})
	}))
	defer exitSrv.Close()

	s := &Service{
		dataAddr:   "127.0.0.1:51820",
		httpClient: exitSrv.Client(),
		sessions:   map[string]sessionState{},
		exitRouteCache: map[string]exitRoute{
			"exit-b": {
				controlURL: exitSrv.URL,
				dataAddr:   "127.0.0.1:51821",
				operatorID: "op-exit",
				fetchedAt:  time.Now(),
			},
		},
		buckets:  map[string]rateBucket{},
		abuse:    map[string]abuseState{},
		openRPS:  100,
		routeTTL: time.Minute,
	}

	reqBody, err := json.Marshal(openReq)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:41005"
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, req)

	var out proto.PathOpenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected accepted open with preserved proof-bound fields, reason=%q", out.Reason)
	}
	if exitCalls != 1 {
		t.Fatalf("expected one call to exit, got %d", exitCalls)
	}
	if forwardedTransport != "" {
		t.Fatalf("expected empty transport to be forwarded unchanged, got %q", forwardedTransport)
	}
	if out.Transport != "policy-json" {
		t.Fatalf("expected entry response transport to normalize to policy-json, got %q", out.Transport)
	}
}

func TestHandlePathOpenRejectsUnknownFieldJSON(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(`{"token_proof":"proof","unexpected":true}`))
	rr := httptest.NewRecorder()

	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid json") {
		t.Fatalf("expected invalid json error body, got %q", rr.Body.String())
	}
}

func TestHandlePathOpenRejectsTrailingJSON(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(`{"token_proof":"proof"}{"extra":1}`))
	rr := httptest.NewRecorder()

	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid json") {
		t.Fatalf("expected invalid json error body, got %q", rr.Body.String())
	}
}

func TestHandlePathOpenRejectsOversizedJSON(t *testing.T) {
	s := &Service{}
	body := `{"token_proof":"` + strings.Repeat("a", 70*1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(body))
	rr := httptest.NewRecorder()

	s.handlePathOpen(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid json") {
		t.Fatalf("expected invalid json error body, got %q", rr.Body.String())
	}
}

func TestDecodeBoundedJSONResponseRejectsOversizedBody(t *testing.T) {
	body := strings.NewReader(`{"value":"` + strings.Repeat("a", int(remoteResponseMaxBodyBytes)+1024) + `"}`)
	var out map[string]string
	if err := decodeBoundedJSONResponse(body, &out, remoteResponseMaxBodyBytes); err == nil {
		t.Fatalf("expected oversized response rejection")
	}
}
