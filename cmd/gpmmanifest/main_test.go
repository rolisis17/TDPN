package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func TestWriteOwnerOnlyPrivateKeyCanBeReadBack(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "manifest_ed25519.key")
	encoded := base64.RawURLEncoding.EncodeToString(priv) + "\n"
	if err := writeFileWithMode(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("write owner-only key: %v", err)
	}
	got, err := readPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if !bytes.Equal(got, priv) {
		t.Fatalf("private key round trip mismatch")
	}
}
