package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"privacynode/pkg/proto"
)

const maxRelayDescriptorFutureValidity = 24 * time.Hour

func VerifyRelayDescriptor(desc proto.RelayDescriptor, pub ed25519.PublicKey) error {
	if desc.ValidUntil.IsZero() {
		return fmt.Errorf("descriptor valid_until missing")
	}
	now := time.Now()
	if now.After(desc.ValidUntil) {
		return fmt.Errorf("descriptor expired")
	}
	if desc.ValidUntil.After(now.Add(maxRelayDescriptorFutureValidity)) {
		return fmt.Errorf("descriptor valid_until too far in future")
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(desc.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	clone := desc
	clone.Signature = ""
	payload, err := json.Marshal(clone)
	if err != nil {
		return fmt.Errorf("marshal descriptor: %w", err)
	}
	if !ed25519.Verify(pub, payload, sigRaw) {
		return fmt.Errorf("descriptor signature invalid")
	}
	return nil
}
