package issuer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestBuildRevocationFeedSigned(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	s := &Service{
		issuerID:          "issuer-local",
		privKey:           priv,
		revocationFeedTTL: 20 * time.Second,
		keyEpoch:          3,
		minTokenEpoch:     2,
		revocationVersion: 9,
		revocations: map[string]int64{
			"jti-old": now.Add(-5 * time.Second).Unix(),
			"jti-a":   now.Add(60 * time.Second).Unix(),
			"jti-b":   now.Add(120 * time.Second).Unix(),
		},
	}

	feed, err := s.buildRevocationFeed(now)
	if err != nil {
		t.Fatalf("build feed: %v", err)
	}
	if feed.Issuer != "issuer-local" {
		t.Fatalf("unexpected issuer: %s", feed.Issuer)
	}
	if feed.GeneratedAt != now.Unix() {
		t.Fatalf("unexpected generated_at: %d", feed.GeneratedAt)
	}
	if feed.ExpiresAt != now.Add(20*time.Second).Unix() {
		t.Fatalf("unexpected expires_at: %d", feed.ExpiresAt)
	}
	if feed.KeyEpoch != 3 || feed.MinTokenEpoch != 2 || feed.Version != 10 {
		t.Fatalf("unexpected epoch/version fields: key=%d min=%d version=%d", feed.KeyEpoch, feed.MinTokenEpoch, feed.Version)
	}
	if len(feed.Revocations) != 2 {
		t.Fatalf("expected pruned revocations length=2 got=%d", len(feed.Revocations))
	}
	if feed.Revocations[0].JTI != "jti-a" || feed.Revocations[1].JTI != "jti-b" {
		t.Fatalf("expected sorted revocations, got %+v", feed.Revocations)
	}
	if !verifyFeedSignature(t, feed, pub) {
		t.Fatalf("expected valid signature")
	}
}

func verifyFeedSignature(t *testing.T, feed proto.RevocationListResponse, pub ed25519.PublicKey) bool {
	t.Helper()
	sigRaw, err := base64.RawURLEncoding.DecodeString(feed.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return ed25519.Verify(pub, payload, sigRaw)
}
