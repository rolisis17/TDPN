package issuer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestHandleRelayTrustSupportsETag304(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := &Service{
		pubKey:       pub,
		privKey:      priv,
		trustFeedTTL: 30 * time.Second,
		subjects: map[string]proto.SubjectProfile{
			"exit-a": {Subject: "exit-a", Reputation: 0.9, Bond: 100},
		},
	}

	firstReq := httptest.NewRequest(http.MethodGet, "/v1/trust/relays", nil)
	firstRR := httptest.NewRecorder()
	s.handleRelayTrust(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", firstRR.Code)
	}
	etag := firstRR.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("expected ETag header")
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/v1/trust/relays", nil)
	secondReq.Header.Set("If-None-Match", etag)
	secondRR := httptest.NewRecorder()
	s.handleRelayTrust(secondRR, secondReq)
	if secondRR.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", secondRR.Code)
	}
}

func TestHandleRevocationsSupportsETag304(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := &Service{
		pubKey:            pub,
		privKey:           priv,
		issuerID:          "issuer-local",
		revocationFeedTTL: 30 * time.Second,
		revocations: map[string]int64{
			"tok-1": time.Now().Add(time.Hour).Unix(),
		},
		keyEpoch:      1,
		minTokenEpoch: 1,
	}

	firstReq := httptest.NewRequest(http.MethodGet, "/v1/revocations", nil)
	firstRR := httptest.NewRecorder()
	s.handleRevocations(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", firstRR.Code)
	}
	etag := firstRR.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("expected ETag header")
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/v1/revocations", nil)
	secondReq.Header.Set("If-None-Match", etag)
	secondRR := httptest.NewRecorder()
	s.handleRevocations(secondRR, secondReq)
	if secondRR.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", secondRR.Code)
	}
}
