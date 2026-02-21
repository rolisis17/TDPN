package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"privacynode/pkg/proto"
)

func VerifyRelayDescriptor(desc proto.RelayDescriptor, pub ed25519.PublicKey) error {
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
