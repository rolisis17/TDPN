package crypto

import (
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
