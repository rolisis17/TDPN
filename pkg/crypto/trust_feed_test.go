package crypto

import (
	"crypto/ed25519"
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

func TestVerifyRelayTrustAttestationFeedRejectsMissingTimestamps(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)

	testCases := []struct {
		name        string
		generatedAt int64
		expiresAt   int64
	}{
		{name: "missing_generated_at", generatedAt: 0, expiresAt: now.Add(30 * time.Second).Unix()},
		{name: "missing_expires_at", generatedAt: now.Unix(), expiresAt: 0},
		{name: "expires_at_not_after_generated_at", generatedAt: now.Unix(), expiresAt: now.Unix()},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			feed := proto.RelayTrustAttestationFeedResponse{
				GeneratedAt:  tc.generatedAt,
				ExpiresAt:    tc.expiresAt,
				Attestations: []proto.RelayTrustAttestation{{RelayID: "exit-a", Role: "exit", StakeScore: 0.5}},
			}
			sig, err := SignRelayTrustAttestationFeed(feed, priv)
			if err != nil {
				t.Fatalf("sign trust feed: %v", err)
			}
			feed.Signature = sig

			if err := VerifyRelayTrustAttestationFeed(feed, pub, now); err == nil {
				t.Fatalf("expected verification failure for %s", tc.name)
			}
		})
	}
}

func TestVerifyRelayTrustAttestationFeedRejectsStaleReplay(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelayTrustAttestationFeedResponse{
		GeneratedAt:  now.Add(-relayFeedMaxAge - time.Second).Unix(),
		ExpiresAt:    now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{{RelayID: "exit-a", Role: "exit", StakeScore: 0.5}},
	}
	sig, err := SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelayTrustAttestationFeed(feed, pub, now); err == nil {
		t.Fatalf("expected stale trust feed verification failure")
	}
}

func TestVerifyRelayTrustAttestationFeedRejectsExcessiveLifetime(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelayTrustAttestationFeedResponse{
		GeneratedAt:  now.Unix(),
		ExpiresAt:    now.Add(relayFeedMaxLifetime + time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{{RelayID: "exit-a", Role: "exit", StakeScore: 0.5}},
	}
	sig, err := SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelayTrustAttestationFeed(feed, pub, now); err == nil {
		t.Fatalf("expected excessive-lifetime trust feed verification failure")
	}
}

func TestVerifyRelayTrustAttestationFeedAllowsMaxFutureExpiryWindow(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelayTrustAttestationFeedResponse{
		GeneratedAt:  now.Add(relayFeedMaxFutureSkew).Unix(),
		ExpiresAt:    now.Add(relayFeedMaxFutureSkew + relayFeedMaxLifetime).Unix(),
		Attestations: []proto.RelayTrustAttestation{{RelayID: "exit-a", Role: "exit", StakeScore: 0.5}},
	}
	sig, err := SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelayTrustAttestationFeed(feed, pub, now); err != nil {
		t.Fatalf("expected max bounded future-expiry trust feed to verify, got %v", err)
	}
}

func TestSignRelayTrustAttestationFeedRejectsMalformedPrivateKey(t *testing.T) {
	now := time.Unix(1771576000, 0)
	feed := proto.RelayTrustAttestationFeedResponse{
		GeneratedAt:  now.Unix(),
		ExpiresAt:    now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{{RelayID: "exit-a", Role: "exit", BondScore: 0.4}},
	}
	if _, err := SignRelayTrustAttestationFeed(feed, ed25519.PrivateKey("bad-key")); err == nil {
		t.Fatalf("expected malformed private key to fail signing")
	}
}
