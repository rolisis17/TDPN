package entry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacynode/pkg/proto"
)

func TestHandlePathCloseSessionKeyMismatchDoesNotDeleteSession(t *testing.T) {
	t.Parallel()

	s := &Service{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: map[string]func(*http.Request) (*http.Response, error){}}},
		sessions: map[string]sessionState{
			"sess-1": {
				exitControlURL: "http://exit.local",
				sessionKeyID:   "expected-key",
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sess-1","session_key_id":"wrong-key"}`))
	rr := httptest.NewRecorder()
	s.handlePathClose(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathCloseResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Reason != "session-key-id-mismatch" {
		t.Fatalf("reason=%q want=session-key-id-mismatch", resp.Reason)
	}
	if _, ok := s.sessions["sess-1"]; !ok {
		t.Fatal("expected session to be retained on key mismatch")
	}
}

func TestHandlePathCloseDeletesSessionAfterSuccessfulForward(t *testing.T) {
	t.Parallel()

	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://exit.local/v1/path/close": jsonResp(proto.PathCloseResponse{Closed: true}),
	}
	s := &Service{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions: map[string]sessionState{
			"sess-2": {
				exitControlURL: "http://exit.local",
				sessionKeyID:   "good-key",
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sess-2","session_key_id":"good-key"}`))
	rr := httptest.NewRecorder()
	s.handlePathClose(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathCloseResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Closed {
		t.Fatalf("expected closed response, got %+v", resp)
	}
	if _, ok := s.sessions["sess-2"]; ok {
		t.Fatal("expected session to be deleted after successful close")
	}
}

func TestHandlePathCloseRetainsSessionOnForwardFailure(t *testing.T) {
	t.Parallel()

	s := &Service{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: map[string]func(*http.Request) (*http.Response, error){}}},
		sessions: map[string]sessionState{
			"sess-3": {
				exitControlURL: "http://exit.local",
				sessionKeyID:   "good-key",
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sess-3","session_key_id":"good-key"}`))
	rr := httptest.NewRecorder()
	s.handlePathClose(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := s.sessions["sess-3"]; !ok {
		t.Fatal("expected session to remain when close forwarding fails")
	}
}

func TestHandlePathCloseRetainsSessionWhenExitReportsUnclosed(t *testing.T) {
	t.Parallel()

	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://exit.local/v1/path/close": jsonResp(proto.PathCloseResponse{Closed: false, Reason: "wg remove failed"}),
	}
	s := &Service{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		sessions: map[string]sessionState{
			"sess-4": {
				exitControlURL: "http://exit.local",
				sessionKeyID:   "good-key",
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sess-4","session_key_id":"good-key"}`))
	rr := httptest.NewRecorder()
	s.handlePathClose(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathCloseResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Closed {
		t.Fatalf("expected unclosed response propagated, got %+v", resp)
	}
	if _, ok := s.sessions["sess-4"]; !ok {
		t.Fatal("expected session retained when exit reports close failure")
	}
}
