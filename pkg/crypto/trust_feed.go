package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"privacynode/pkg/proto"
)

func SignRelayTrustAttestationFeed(feed proto.RelayTrustAttestationFeedResponse, priv ed25519.PrivateKey) (string, error) {
	if len(priv) == 0 {
		return "", fmt.Errorf("missing trust feed private key")
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return "", fmt.Errorf("marshal trust feed: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyRelayTrustAttestationFeed(feed proto.RelayTrustAttestationFeedResponse, pub ed25519.PublicKey, now time.Time) error {
	if feed.Signature == "" {
		return fmt.Errorf("trust feed missing signature")
	}
	nowUnix := now.Unix()
	if feed.ExpiresAt > 0 && nowUnix >= feed.ExpiresAt {
		return fmt.Errorf("trust feed expired")
	}
	if feed.GeneratedAt > 0 && feed.GeneratedAt > nowUnix+60 {
		return fmt.Errorf("trust feed generated_at too far in future")
	}

	sigRaw, err := base64.RawURLEncoding.DecodeString(feed.Signature)
	if err != nil {
		return fmt.Errorf("decode trust feed signature: %w", err)
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("marshal trust feed: %w", err)
	}
	if !ed25519.Verify(pub, payload, sigRaw) {
		return fmt.Errorf("trust feed signature invalid")
	}
	return nil
}
