package issuer

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

func TestLoadPreviousPubKeys(t *testing.T) {
	pubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	file := filepath.Join(t.TempDir(), "previous.txt")
	content := base64.RawURLEncoding.EncodeToString(pubA) + "\n" + base64.RawURLEncoding.EncodeToString(pubB) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	keys, err := loadPreviousPubKeys(file)
	if err != nil {
		t.Fatalf("loadPreviousPubKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestHandlePubKeysIncludesCurrentAndPrevious(t *testing.T) {
	pubCurrent, _, err := crypto.GenerateEd25519Keypair()
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
	s := &Service{pubKey: pubCurrent, previousPubKeysFile: file}
	req := httptest.NewRequest(http.MethodGet, "/v1/pubkeys", nil)
	rr := httptest.NewRecorder()
	s.handlePubKeys(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.IssuerPubKeysResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.PubKeys) != 2 {
		t.Fatalf("expected 2 pubkeys, got %d", len(out.PubKeys))
	}
}
