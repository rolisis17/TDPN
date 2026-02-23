package directory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestHandleSyncStatusRequiresAdminToken(t *testing.T) {
	s := &Service{adminToken: "secret"}
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/sync-status", nil)
	rr := httptest.NewRecorder()
	s.handleSyncStatus(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleSyncStatusReturnsSnapshot(t *testing.T) {
	s := &Service{adminToken: "secret"}
	s.setPeerSyncStatus(proto.DirectorySyncRunStatus{
		LastRunAt:         100,
		Success:           true,
		SuccessSources:    2,
		SourceOperators:   []string{"op-a", "op-b"},
		RequiredOperators: 2,
		QuorumMet:         true,
	})
	s.setIssuerSyncStatus(proto.DirectorySyncRunStatus{
		LastRunAt:         110,
		Success:           false,
		SuccessSources:    1,
		SourceOperators:   []string{"issuer-a"},
		RequiredOperators: 2,
		QuorumMet:         false,
		Error:             "issuer operator quorum not met",
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/sync-status", nil)
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	s.handleSyncStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var out proto.DirectorySyncStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Peer.Success || out.Peer.SuccessSources != 2 || !out.Peer.QuorumMet {
		t.Fatalf("unexpected peer sync status: %+v", out.Peer)
	}
	if out.Issuer.Success || out.Issuer.Error == "" || out.Issuer.QuorumMet {
		t.Fatalf("unexpected issuer sync status: %+v", out.Issuer)
	}
}

func TestSyncPeerRelaysUpdatesStatusFailure(t *testing.T) {
	s := &Service{
		peerURLs:          []string{"http://peer-down.local"},
		peerMinVotes:      1,
		peerMinOperators:  1,
		peerRelayETags:    make(map[string]string),
		peerRelayCache:    make(map[string][]proto.RelayDescriptor),
		peerScoreETags:    make(map[string]string),
		peerScoreCache:    make(map[string]map[string]proto.RelaySelectionScore),
		peerTrustETags:    make(map[string]string),
		peerTrustCache:    make(map[string]map[string]proto.RelayTrustAttestation),
		issuerTrustETags:  make(map[string]string),
		issuerTrustCache:  make(map[string]map[string]proto.RelayTrustAttestation),
		peerHintPubKeys:   make(map[string]string),
		peerHintOperators: make(map[string]string),
		httpClient:        &http.Client{Transport: mockRoundTripper{handlers: map[string]func(*http.Request) (*http.Response, error){}}},
	}
	err := s.syncPeerRelays(context.Background())
	if err == nil {
		t.Fatalf("expected syncPeerRelays failure")
	}
	peer, _ := s.snapshotSyncStatus()
	if peer.Success {
		t.Fatalf("expected peer status failure: %+v", peer)
	}
	if peer.SuccessSources != 0 || peer.QuorumMet {
		t.Fatalf("unexpected peer failure summary: %+v", peer)
	}
	if strings.TrimSpace(peer.Error) == "" {
		t.Fatalf("expected peer failure error message")
	}
}

func TestSyncIssuerTrustUpdatesStatusSuccess(t *testing.T) {
	urlA := "http://issuer-a.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	now := time.Now()
	trustA := proto.RelayTrustAttestationFeedResponse{
		Operator:    "issuer-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:    "exit-shared",
				Role:       "exit",
				OperatorID: "op-shared",
				Reputation: 0.8,
				Confidence: 0.9,
			},
		},
	}
	sigA, err := crypto.SignRelayTrustAttestationFeed(trustA, privA)
	if err != nil {
		t.Fatalf("sign trustA: %v", err)
	}
	trustA.Signature = sigA
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-a", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubA)}}),
		urlA + "/v1/trust/relays": jsonResp(trustA),
	}
	s := &Service{
		issuerTrustURLs:     []string{urlA},
		issuerMinOperators:  1,
		issuerTrustMinVotes: 1,
		issuerTrustETags:    make(map[string]string),
		issuerTrustCache:    make(map[string]map[string]proto.RelayTrustAttestation),
		issuerTrust:         make(map[string]proto.RelayTrustAttestation),
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if err := s.syncIssuerTrust(context.Background()); err != nil {
		t.Fatalf("syncIssuerTrust: %v", err)
	}
	_, issuer := s.snapshotSyncStatus()
	if !issuer.Success || issuer.SuccessSources != 1 || !issuer.QuorumMet {
		t.Fatalf("unexpected issuer sync status: %+v", issuer)
	}
	if len(issuer.SourceOperators) != 1 || issuer.SourceOperators[0] != "issuer-a" {
		t.Fatalf("expected issuer source operator tracking, got %+v", issuer.SourceOperators)
	}
}
