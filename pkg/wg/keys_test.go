package wg

import (
	"encoding/base64"
	"testing"
)

func TestKeyValidation(t *testing.T) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	k := base64.StdEncoding.EncodeToString(b)
	if !IsValidPublicKey(k) {
		t.Fatalf("expected key to validate")
	}
}

func TestKeyValidationRejectsBadLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	if IsValidPublicKey(short) {
		t.Fatalf("expected short key to fail")
	}
}
