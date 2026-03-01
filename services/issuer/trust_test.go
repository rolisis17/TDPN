package issuer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestHandleRelayTrustSignsAndNormalizes(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := &Service{
		issuerID:        "issuer-local",
		pubKey:          pub,
		privKey:         priv,
		trustFeedTTL:    20 * time.Second,
		trustConfidence: 0.8,
		trustBondMax:    500,
		trustOperatorID: "op-main",
		subjects: map[string]proto.SubjectProfile{
			"exit-a": {Subject: "exit-a", Kind: proto.SubjectKindRelayExit, Reputation: 0.9, Bond: 250},
			"exit-b": {Subject: "exit-b", Kind: proto.SubjectKindRelayExit, Reputation: 1.2, Bond: 800},
			"exit-c": {
				Subject:      "exit-c",
				Kind:         proto.SubjectKindRelayExit,
				Reputation:   0.95,
				Bond:         300,
				TierCap:      1,
				DisputeUntil: time.Now().Add(time.Hour).Unix(),
			},
			"exit-d": {Subject: "exit-d", Kind: proto.SubjectKindRelayExit, Reputation: 0.85, Bond: 0, Stake: 400},
			"client-alice": {
				Subject:    "client-alice",
				Kind:       proto.SubjectKindClient,
				Reputation: 0.99,
				Bond:       700,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/trust/relays", nil)
	rr := httptest.NewRecorder()
	s.handleRelayTrust(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	var out proto.RelayTrustAttestationFeedResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode trust feed: %v", err)
	}
	if len(out.Attestations) != 4 {
		t.Fatalf("expected 4 relay attestations, got %d", len(out.Attestations))
	}
	if err := crypto.VerifyRelayTrustAttestationFeed(out, pub, time.Now()); err != nil {
		t.Fatalf("verify trust feed: %v", err)
	}

	a := out.Attestations[0]
	b := out.Attestations[1]
	c := out.Attestations[2]
	d := out.Attestations[3]
	if a.RelayID != "exit-a" || b.RelayID != "exit-b" || c.RelayID != "exit-c" || d.RelayID != "exit-d" {
		t.Fatalf("expected sorted relay ids, got %s, %s, %s, %s", a.RelayID, b.RelayID, c.RelayID, d.RelayID)
	}
	if a.BondScore < 0.49 || a.BondScore > 0.51 {
		t.Fatalf("expected normalized bond score ~0.5, got %f", a.BondScore)
	}
	if b.BondScore != 1 {
		t.Fatalf("expected clamped bond score 1, got %f", b.BondScore)
	}
	if b.Reputation != 1 {
		t.Fatalf("expected clamped reputation 1, got %f", b.Reputation)
	}
	if a.OperatorID != "op-main" || b.OperatorID != "op-main" {
		t.Fatalf("expected operator id propagated")
	}
	if a.Confidence != 0.8 || b.Confidence != 0.8 {
		t.Fatalf("expected confidence 0.8 propagated")
	}
	if c.Confidence >= 0.8 {
		t.Fatalf("expected dispute to lower confidence, got %f", c.Confidence)
	}
	if c.AbusePenalty <= 0.6 {
		t.Fatalf("expected elevated abuse penalty for disputed relay, got %f", c.AbusePenalty)
	}
	if d.StakeScore < 0.79 || d.StakeScore > 0.81 {
		t.Fatalf("expected stake score from explicit stake ~0.8, got %f", d.StakeScore)
	}
}
