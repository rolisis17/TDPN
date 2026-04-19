package app

import (
	crand "crypto/rand"
	"errors"
	"testing"
)

type failingRandomReader struct{}

func (failingRandomReader) Read(_ []byte) (int, error) {
	return 0, errors.New("rng unavailable")
}

func TestRandomNonceFailsClosedOnRandomReadError(t *testing.T) {
	prev := crand.Reader
	crand.Reader = failingRandomReader{}
	t.Cleanup(func() { crand.Reader = prev })

	if _, err := randomNonce(); err == nil {
		t.Fatalf("expected randomNonce to fail when random reader fails")
	}
}

func TestRandomProofNonceFailsClosedOnRandomReadError(t *testing.T) {
	prev := crand.Reader
	crand.Reader = failingRandomReader{}
	t.Cleanup(func() { crand.Reader = prev })

	if _, err := randomProofNonce(); err == nil {
		t.Fatalf("expected randomProofNonce to fail when random reader fails")
	}
}

func TestRandomWGPublicKeyLikeFailsClosedOnRandomReadError(t *testing.T) {
	prev := crand.Reader
	crand.Reader = failingRandomReader{}
	t.Cleanup(func() { crand.Reader = prev })

	if _, err := randomWGPublicKeyLike(); err == nil {
		t.Fatalf("expected randomWGPublicKeyLike to fail when random reader fails")
	}
}
