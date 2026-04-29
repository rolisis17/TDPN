package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestPacketNonceGeneratorIsMonotonic(t *testing.T) {
	g := &packetNonceGenerator{next: 41}
	if got := g.Next(); got != 41 {
		t.Fatalf("first nonce=%d want 41", got)
	}
	if got := g.Next(); got != 42 {
		t.Fatalf("second nonce=%d want 42", got)
	}

	const maxUint64 = ^uint64(0)
	g = &packetNonceGenerator{next: maxUint64}
	if got := g.Next(); got != maxUint64 {
		t.Fatalf("max nonce=%d want %d", got, maxUint64)
	}
	if got := g.Next(); got != 1 {
		t.Fatalf("wrapped nonce=%d want 1", got)
	}
}

func TestOpenPathWithChallengeRetries(t *testing.T) {
	entryURL := "http://entry.local"
	calls := 0
	handlers := map[string]func(*http.Request) (*http.Response, error){
		entryURL + "/v1/path/open": func(req *http.Request) (*http.Response, error) {
			calls++
			var in proto.PathOpenRequest
			_ = json.NewDecoder(req.Body).Decode(&in)
			if in.MiddleRelayID != "middle-a" {
				return jsonResponse(proto.PathOpenResponse{Accepted: false, Reason: "missing middle relay id"})(req)
			}
			if calls == 1 {
				return jsonResponse(proto.PathOpenResponse{
					Accepted:   false,
					Reason:     "challenge-required",
					Challenge:  "abc",
					Difficulty: 1,
				})(req)
			}
			if in.PuzzleNonce == "" || in.PuzzleDigest == "" {
				return jsonResponse(proto.PathOpenResponse{Accepted: false, Reason: "missing puzzle"})(req)
			}
			return jsonResponse(proto.PathOpenResponse{
				Accepted:      true,
				SessionID:     "s1",
				EntryDataAddr: "127.0.0.1:51820",
				Transport:     "policy-json",
			})(req)
		},
	}
	c := &Client{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	resp, err := c.openPathWithChallenge(context.Background(), entryURL, proto.PathOpenRequest{
		ExitID:        "exit-a",
		MiddleRelayID: "middle-a",
		Token:         "tok",
		Transport:     "policy-json",
		SessionID:     "unused",
		RequestedMTU:  1280,
	})
	if err != nil {
		t.Fatalf("openPathWithChallenge failed: %v", err)
	}
	if !resp.Accepted || resp.SessionID != "s1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if calls != 2 {
		t.Fatalf("expected two open calls, got %d", calls)
	}
}

func TestOpenPathWithChallengeDenied(t *testing.T) {
	entryURL := "http://entry.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		entryURL + "/v1/path/open": jsonResponse(proto.PathOpenResponse{
			Accepted: false,
			Reason:   "exit scope denied",
		}),
	}
	c := &Client{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	_, err := c.openPathWithChallenge(context.Background(), entryURL, proto.PathOpenRequest{
		ExitID:    "exit-a",
		Token:     "tok",
		Transport: "policy-json",
	})
	if err == nil || !strings.Contains(err.Error(), "path open denied") {
		t.Fatalf("expected denied error, got %v", err)
	}
}

func TestClientRouteAssertionForPairBindsSelectedPath(t *testing.T) {
	pair := relayPair{
		entry:     proto.RelayDescriptor{RelayID: "entry-a"},
		middle:    proto.RelayDescriptor{RelayID: "middle-a"},
		hasMiddle: true,
		exit:      proto.RelayDescriptor{RelayID: "exit-a"},
	}

	assertion := clientRouteAssertionForPair(pair, "3hop", pair.middle.RelayID, "res-a", "res-session-a", "cosmos1subject")
	if assertion == nil {
		t.Fatalf("expected route assertion")
	}
	if assertion.PathProfile != "3hop" {
		t.Fatalf("path profile=%q want 3hop", assertion.PathProfile)
	}
	if assertion.EntryRelayID != "entry-a" || assertion.MiddleRelayID != "middle-a" || assertion.ExitRelayID != "exit-a" {
		t.Fatalf("unexpected assertion: %+v", assertion)
	}
	if assertion.ReservationID != "res-a" || assertion.ReservationSessionID != "res-session-a" || assertion.ReservationSubjectID != "cosmos1subject" || assertion.SessionID != "res-session-a" {
		t.Fatalf("expected reservation-bound assertion, got %+v", assertion)
	}
}

func TestBindClientRouteAssertionToRequestBindsProofFields(t *testing.T) {
	assertion := &proto.PathRouteAssertion{
		PathProfile:  "2hop",
		EntryRelayID: "entry-a",
		ExitRelayID:  "exit-a",
	}
	req := proto.PathOpenRequest{
		Token:                "tok-a",
		TokenProofNonce:      "nonce-a",
		SessionID:            "session-a",
		ReservationID:        "res-a",
		ReservationSessionID: "session-a",
		ReservationSubjectID: "cosmos1subject",
		ClientInnerPub:       "client-pub-a",
		Transport:            "wireguard-udp",
		RequestedMTU:         1280,
		RequestedRegion:      "us-east",
	}
	bindClientRouteAssertionToRequest(assertion, req)
	if assertion.SessionID != "session-a" ||
		assertion.TokenProofNonce != "nonce-a" ||
		assertion.ClientInnerPub != "client-pub-a" ||
		assertion.Transport != "wireguard-udp" ||
		assertion.RequestedMTU != 1280 ||
		assertion.RequestedRegion != "us-east" ||
		assertion.TokenSHA256 != crypto.PathRouteAssertionBindingHash("tok-a") {
		t.Fatalf("assertion not request-bound: %+v", assertion)
	}
}

func TestOpenPathRejectsTrailingJSON(t *testing.T) {
	entryURL := "http://entry.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		entryURL + "/v1/path/open": func(_ *http.Request) (*http.Response, error) {
			body := `{"accepted":true,"session_id":"s1","entry_data_addr":"127.0.0.1:51820","transport":"policy-json"}{"extra":1}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	}
	c := &Client{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	_, err := c.openPath(context.Background(), entryURL, proto.PathOpenRequest{
		ExitID:    "exit-a",
		Token:     "tok",
		Transport: "policy-json",
	})
	if err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing-json decode error, got %v", err)
	}
}

func TestOpenPathRejectsOversizedResponse(t *testing.T) {
	entryURL := "http://entry.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		entryURL + "/v1/path/open": func(_ *http.Request) (*http.Response, error) {
			oversizedChallenge := strings.Repeat("a", int(clientPathControlResponseMaxBytes))
			body := fmt.Sprintf(`{"accepted":false,"reason":"challenge-required","challenge":"%s","difficulty":1}`, oversizedChallenge)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	}
	c := &Client{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	_, err := c.openPath(context.Background(), entryURL, proto.PathOpenRequest{
		ExitID:    "exit-a",
		Token:     "tok",
		Transport: "policy-json",
	})
	if err == nil || (!strings.Contains(err.Error(), "exceeds") && !strings.Contains(err.Error(), "EOF")) {
		t.Fatalf("expected oversized decode error, got %v", err)
	}
}

func TestOpenPathWithChallengeRejectsDifficultyOverCap(t *testing.T) {
	entryURL := "http://entry.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		entryURL + "/v1/path/open": jsonResponse(proto.PathOpenResponse{
			Accepted:   false,
			Reason:     "challenge-required",
			Challenge:  "abc",
			Difficulty: clientMaxPuzzleDifficulty + 1,
		}),
	}
	c := &Client{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	_, err := c.openPathWithChallenge(context.Background(), entryURL, proto.PathOpenRequest{
		ExitID:        "exit-a",
		MiddleRelayID: "middle-a",
		Token:         "tok",
		Transport:     "policy-json",
		SessionID:     "unused",
		RequestedMTU:  1280,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("expected difficulty cap error, got %v", err)
	}
}

func jsonResponse(v interface{}) func(*http.Request) (*http.Response, error) {
	return func(_ *http.Request) (*http.Response, error) {
		b, _ := json.Marshal(v)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(b)),
		}, nil
	}
}
