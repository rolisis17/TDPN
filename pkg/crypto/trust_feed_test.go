package crypto

import (
	"testing"
	"time"

	"privacynode/pkg/proto"
)

func TestSignAndVerifyRelayTrustAttestationFeed(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelayTrustAttestationFeedResponse{
		Operator:    "operator-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:      "exit-a",
				Role:         "exit",
				Reputation:   0.9,
				Uptime:       0.95,
				Capacity:     0.8,
				AbusePenalty: 0.1,
				BondScore:    0.7,
				StakeScore:   0.6,
				Confidence:   0.9,
			},
		},
	}
	sig, err := SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelayTrustAttestationFeed(feed, pub, now); err != nil {
		t.Fatalf("verify trust feed: %v", err)
	}
}

func TestVerifyRelayTrustAttestationFeedRejectsTamper(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelayTrustAttestationFeedResponse{
		GeneratedAt:  now.Unix(),
		ExpiresAt:    now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{{RelayID: "exit-a", Role: "exit", BondScore: 0.4}},
	}
	sig, err := SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	feed.Signature = sig
	feed.Attestations[0].BondScore = 0.9

	if err := VerifyRelayTrustAttestationFeed(feed, pub, now); err == nil {
		t.Fatalf("expected tampered trust feed verification failure")
	}
}

func TestVerifyRelayTrustAttestationFeedRejectsExpired(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelayTrustAttestationFeedResponse{
		GeneratedAt:  now.Add(-120 * time.Second).Unix(),
		ExpiresAt:    now.Add(-10 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{{RelayID: "exit-a", Role: "exit", StakeScore: 0.5}},
	}
	sig, err := SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelayTrustAttestationFeed(feed, pub, now); err == nil {
		t.Fatalf("expected expired trust feed verification failure")
	}
}
