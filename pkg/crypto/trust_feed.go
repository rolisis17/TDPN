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
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
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
	if err := verifySignedFeedFreshness("trust feed", feed.GeneratedAt, feed.ExpiresAt, now); err != nil {
		return err
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
