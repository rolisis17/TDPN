package entry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacynode/pkg/proto"
)

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
