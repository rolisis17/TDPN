package crypto

import (
	"crypto/ed25519"
	"testing"
	"time"

	"privacynode/pkg/proto"
)

func TestSignAndVerifyRelaySelectionFeed(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelaySelectionFeedResponse{
		Operator:    "operator-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Scores: []proto.RelaySelectionScore{
			{
				RelayID:      "exit-a",
				Role:         "exit",
				Reputation:   0.9,
				Uptime:       0.95,
				Capacity:     0.8,
				AbusePenalty: 0.1,
			},
		},
	}
	sig, err := SignRelaySelectionFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelaySelectionFeed(feed, pub, now); err != nil {
		t.Fatalf("verify feed: %v", err)
	}
}

func TestVerifyRelaySelectionFeedRejectsTamper(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelaySelectionFeedResponse{
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Scores:      []proto.RelaySelectionScore{{RelayID: "exit-a", Role: "exit", Reputation: 0.6}},
	}
	sig, err := SignRelaySelectionFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign feed: %v", err)
	}
	feed.Signature = sig
	feed.Scores[0].Reputation = 0.99

	if err := VerifyRelaySelectionFeed(feed, pub, now); err == nil {
		t.Fatalf("expected tampered feed verification failure")
	}
}

func TestVerifyRelaySelectionFeedRejectsExpired(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelaySelectionFeedResponse{
		GeneratedAt: now.Add(-120 * time.Second).Unix(),
		ExpiresAt:   now.Add(-10 * time.Second).Unix(),
		Scores:      []proto.RelaySelectionScore{{RelayID: "exit-a", Role: "exit", Reputation: 0.6}},
	}
	sig, err := SignRelaySelectionFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelaySelectionFeed(feed, pub, now); err == nil {
		t.Fatalf("expected expired feed verification failure")
	}
}

func TestVerifyRelaySelectionFeedRejectsMissingTimestamps(t *testing.T) {
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
			feed := proto.RelaySelectionFeedResponse{
				GeneratedAt: tc.generatedAt,
				ExpiresAt:   tc.expiresAt,
				Scores:      []proto.RelaySelectionScore{{RelayID: "exit-a", Role: "exit", Reputation: 0.6}},
			}
			sig, err := SignRelaySelectionFeed(feed, priv)
			if err != nil {
				t.Fatalf("sign feed: %v", err)
			}
			feed.Signature = sig

			if err := VerifyRelaySelectionFeed(feed, pub, now); err == nil {
				t.Fatalf("expected verification failure for %s", tc.name)
			}
		})
	}
}

func TestVerifyRelaySelectionFeedRejectsStaleReplay(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelaySelectionFeedResponse{
		GeneratedAt: now.Add(-relayFeedMaxAge - time.Second).Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Scores:      []proto.RelaySelectionScore{{RelayID: "exit-a", Role: "exit", Reputation: 0.6}},
	}
	sig, err := SignRelaySelectionFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelaySelectionFeed(feed, pub, now); err == nil {
		t.Fatalf("expected stale feed verification failure")
	}
}

func TestVerifyRelaySelectionFeedRejectsExcessiveLifetime(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelaySelectionFeedResponse{
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(relayFeedMaxLifetime + time.Second).Unix(),
		Scores:      []proto.RelaySelectionScore{{RelayID: "exit-a", Role: "exit", Reputation: 0.6}},
	}
	sig, err := SignRelaySelectionFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelaySelectionFeed(feed, pub, now); err == nil {
		t.Fatalf("expected excessive-lifetime feed verification failure")
	}
}

func TestVerifyRelaySelectionFeedAllowsMaxFutureExpiryWindow(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1771576000, 0)
	feed := proto.RelaySelectionFeedResponse{
		GeneratedAt: now.Add(relayFeedMaxFutureSkew).Unix(),
		ExpiresAt:   now.Add(relayFeedMaxFutureSkew + relayFeedMaxLifetime).Unix(),
		Scores:      []proto.RelaySelectionScore{{RelayID: "exit-a", Role: "exit", Reputation: 0.6}},
	}
	sig, err := SignRelaySelectionFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign feed: %v", err)
	}
	feed.Signature = sig

	if err := VerifyRelaySelectionFeed(feed, pub, now); err != nil {
		t.Fatalf("expected max bounded future-expiry feed to verify, got %v", err)
	}
}

func TestSignRelaySelectionFeedRejectsMalformedPrivateKey(t *testing.T) {
	now := time.Unix(1771576000, 0)
	feed := proto.RelaySelectionFeedResponse{
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Scores:      []proto.RelaySelectionScore{{RelayID: "exit-a", Role: "exit", Reputation: 0.6}},
	}
	if _, err := SignRelaySelectionFeed(feed, ed25519.PrivateKey("bad-key")); err == nil {
		t.Fatalf("expected malformed private key to fail signing")
	}
}
