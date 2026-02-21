package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"privacynode/pkg/proto"
)

func TestVerifyRelayDescriptor(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	d := proto.RelayDescriptor{
		RelayID:    "r1",
		Role:       "entry",
		Endpoint:   "127.0.0.1:1",
		ValidUntil: time.Now().Add(time.Minute),
	}
	clone := d
	b, _ := json.Marshal(clone)
	sig := ed25519.Sign(priv, b)
	d.Signature = base64.RawURLEncoding.EncodeToString(sig)
	if err := VerifyRelayDescriptor(d, pub); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}
