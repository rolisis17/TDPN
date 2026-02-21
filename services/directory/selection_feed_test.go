package directory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestHandleSelectionFeedSignsResponse(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	t.Setenv("EXIT_REPUTATION_SCORE", "0.9")
	t.Setenv("EXIT_UPTIME_SCORE", "0.8")
	t.Setenv("EXIT_CAPACITY_SCORE", "0.7")
	t.Setenv("EXIT_ABUSE_PENALTY", "0.1")

	s := &Service{
		pubKey:            pub,
		privKey:           priv,
		entryEndpoints:    []string{"127.0.0.1:51820"},
		endpointRotateSec: 30,
		selectionFeedTTL:  20 * time.Second,
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/selection-feed", nil)
	rr := httptest.NewRecorder()
	s.handleSelectionFeed(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	var feed proto.RelaySelectionFeedResponse
	if err := json.NewDecoder(rr.Body).Decode(&feed); err != nil {
		t.Fatalf("decode feed: %v", err)
	}
	if len(feed.Scores) != 1 {
		t.Fatalf("expected one score entry, got %d", len(feed.Scores))
	}
	score := feed.Scores[0]
	if score.RelayID != "exit-local-1" || score.Role != "exit" {
		t.Fatalf("unexpected score target: %+v", score)
	}
	if score.Reputation != 0.9 || score.Uptime != 0.8 || score.Capacity != 0.7 || score.AbusePenalty != 0.1 {
		t.Fatalf("unexpected score values: %+v", score)
	}
	if err := crypto.VerifyRelaySelectionFeed(feed, pub, time.Now()); err != nil {
		t.Fatalf("verify selection feed: %v", err)
	}
}

func TestHandleSelectionFeedIncludesPeerScores(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := &Service{
		pubKey:            pub,
		privKey:           priv,
		operatorID:        "operator-local",
		entryEndpoints:    []string{"127.0.0.1:51820"},
		endpointRotateSec: 30,
		selectionFeedTTL:  20 * time.Second,
		peerScores: map[string]proto.RelaySelectionScore{
			relayKey("exit-local-1", "exit"): {
				RelayID:      "exit-local-1",
				Role:         "exit",
				Reputation:   0.8,
				Uptime:       0.9,
				Capacity:     0.7,
				AbusePenalty: 0.1,
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/selection-feed", nil)
	rr := httptest.NewRecorder()
	s.handleSelectionFeed(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	var feed proto.RelaySelectionFeedResponse
	if err := json.NewDecoder(rr.Body).Decode(&feed); err != nil {
		t.Fatalf("decode feed: %v", err)
	}
	if len(feed.Scores) != 1 {
		t.Fatalf("expected one merged score entry, got %d", len(feed.Scores))
	}
	got := feed.Scores[0]
	if got.Reputation <= 0 {
		t.Fatalf("expected non-zero merged reputation from peer feed")
	}
}

func TestHandleTrustAttestationsSignsResponse(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	t.Setenv("EXIT_REPUTATION_SCORE", "0.85")
	t.Setenv("EXIT_UPTIME_SCORE", "0.8")
	t.Setenv("EXIT_CAPACITY_SCORE", "0.75")
	t.Setenv("EXIT_ABUSE_PENALTY", "0.05")
	t.Setenv("EXIT_BOND_SCORE", "0.7")
	t.Setenv("EXIT_STAKE_SCORE", "0.6")

	s := &Service{
		pubKey:            pub,
		privKey:           priv,
		operatorID:        "operator-local",
		entryEndpoints:    []string{"127.0.0.1:51820"},
		endpointRotateSec: 30,
		trustFeedTTL:      20 * time.Second,
		trustEpoch:        5 * time.Second,
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/trust-attestations", nil)
	rr := httptest.NewRecorder()
	s.handleTrustAttestations(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	var feed proto.RelayTrustAttestationFeedResponse
	if err := json.NewDecoder(rr.Body).Decode(&feed); err != nil {
		t.Fatalf("decode trust feed: %v", err)
	}
	if len(feed.Attestations) != 1 {
		t.Fatalf("expected one trust attestation, got %d", len(feed.Attestations))
	}
	att := feed.Attestations[0]
	if att.RelayID != "exit-local-1" || att.Role != "exit" {
		t.Fatalf("unexpected trust attestation target: %+v", att)
	}
	if att.BondScore != 0.7 || att.StakeScore != 0.6 {
		t.Fatalf("unexpected bond/stake scores: %+v", att)
	}
	if err := crypto.VerifyRelayTrustAttestationFeed(feed, pub, time.Now()); err != nil {
		t.Fatalf("verify trust feed: %v", err)
	}
}

func TestWriteJSONWithETagSupportsNotModified(t *testing.T) {
	req1 := httptest.NewRequest(http.MethodGet, "/v1/relays", nil)
	rr1 := httptest.NewRecorder()
	if err := writeJSONWithETag(rr1, req1, map[string]string{"x": "1"}); err != nil {
		t.Fatalf("writeJSONWithETag first: %v", err)
	}
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first status 200, got %d", rr1.Code)
	}
	etag := rr1.Header().Get("ETag")
	if strings.TrimSpace(etag) == "" {
		t.Fatalf("expected etag header")
	}
	req2 := httptest.NewRequest(http.MethodGet, "/v1/relays", nil)
	req2.Header.Set("If-None-Match", etag)
	rr2 := httptest.NewRecorder()
	if err := writeJSONWithETag(rr2, req2, map[string]string{"x": "1"}); err != nil {
		t.Fatalf("writeJSONWithETag second: %v", err)
	}
	if rr2.Code != http.StatusNotModified {
		t.Fatalf("expected 304 for matching etag, got %d", rr2.Code)
	}
}
