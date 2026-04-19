package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"privacynode/pkg/proto"
)

func SignRelaySelectionFeed(feed proto.RelaySelectionFeedResponse, priv ed25519.PrivateKey) (string, error) {
	if len(priv) == 0 {
		return "", fmt.Errorf("missing selection feed private key")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return "", fmt.Errorf("marshal selection feed: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyRelaySelectionFeed(feed proto.RelaySelectionFeedResponse, pub ed25519.PublicKey, now time.Time) error {
	if feed.Signature == "" {
		return fmt.Errorf("selection feed missing signature")
	}
	if err := verifySignedFeedFreshness("selection feed", feed.GeneratedAt, feed.ExpiresAt, now); err != nil {
		return err
	}

	sigRaw, err := base64.RawURLEncoding.DecodeString(feed.Signature)
	if err != nil {
		return fmt.Errorf("decode selection feed signature: %w", err)
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("marshal selection feed: %w", err)
	}
	if !ed25519.Verify(pub, payload, sigRaw) {
		return fmt.Errorf("selection feed signature invalid")
	}
	return nil
}
