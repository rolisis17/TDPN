package directory

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestHandlePubKeysIncludesCurrentAndPrevious(t *testing.T) {
	pubCurrent, privCurrent, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen current: %v", err)
	}
	pubPrev, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen previous: %v", err)
	}
	file := filepath.Join(t.TempDir(), "previous.txt")
	prevB64 := base64.RawURLEncoding.EncodeToString(pubPrev)
	if err := os.WriteFile(file, []byte(prevB64+"\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	s := &Service{
		operatorID:          "op-main",
		pubKey:              pubCurrent,
		privKey:             privCurrent,
		previousPubKeysFile: file,
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/pubkeys", nil)
	rr := httptest.NewRecorder()
	s.handlePubKeys(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.DirectoryPubKeysResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Operator != "op-main" {
		t.Fatalf("unexpected operator: %s", out.Operator)
	}
	if len(out.PubKeys) != 2 {
		t.Fatalf("expected 2 pubkeys, got %d", len(out.PubKeys))
	}
}

func TestRotateSigningKeyUpdatesCurrentAndPrevious(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "directory.key")
	prevPath := filepath.Join(dir, "previous.txt")
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	oldPub := base64.RawURLEncoding.EncodeToString(pub)
	s := &Service{
		pubKey:              pub,
		privKey:             priv,
		privateKeyPath:      privPath,
		previousPubKeysFile: prevPath,
	}
	if err := s.rotateSigningKey(); err != nil {
		t.Fatalf("rotateSigningKey: %v", err)
	}
	newPub, _ := s.currentKeypair()
	if base64.RawURLEncoding.EncodeToString(newPub) == oldPub {
		t.Fatalf("expected pubkey to change after rotation")
	}
	if _, err := os.Stat(privPath); err != nil {
		t.Fatalf("expected private key persisted: %v", err)
	}
	prev, err := loadPreviousPubKeys(prevPath)
	if err != nil {
		t.Fatalf("load previous pubkeys: %v", err)
	}
	if len(prev) == 0 || prev[0] != oldPub {
		t.Fatalf("expected old key present in previous pubkeys")
	}
}
