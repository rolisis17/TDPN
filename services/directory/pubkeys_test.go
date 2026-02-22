package directory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestHandlePubKeysRespectsHistoryLimit(t *testing.T) {
	pubCurrent, privCurrent, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen current: %v", err)
	}
	pubPrevA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen prev a: %v", err)
	}
	pubPrevB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen prev b: %v", err)
	}
	pubPrevC, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen prev c: %v", err)
	}
	file := filepath.Join(t.TempDir(), "previous.txt")
	lines := []string{
		base64.RawURLEncoding.EncodeToString(pubPrevA),
		base64.RawURLEncoding.EncodeToString(pubPrevB),
		base64.RawURLEncoding.EncodeToString(pubPrevC),
	}
	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	s := &Service{
		operatorID:          "op-main",
		pubKey:              pubCurrent,
		privKey:             privCurrent,
		previousPubKeysFile: file,
		keyHistory:          2,
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
	if len(out.PubKeys) != 3 {
		t.Fatalf("expected current + 2 previous keys, got %d", len(out.PubKeys))
	}
	if out.PubKeys[1] != lines[0] || out.PubKeys[2] != lines[1] {
		t.Fatalf("expected oldest previous key trimmed, got %v", out.PubKeys)
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

func TestRotateSigningKeyRespectsHistoryLimit(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "directory.key")
	prevPath := filepath.Join(dir, "previous.txt")
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := &Service{
		pubKey:              pub,
		privKey:             priv,
		privateKeyPath:      privPath,
		previousPubKeysFile: prevPath,
		keyHistory:          2,
	}
	oldPubs := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		curPub, _ := s.currentKeypair()
		oldPubs = append(oldPubs, base64.RawURLEncoding.EncodeToString(curPub))
		if err := s.rotateSigningKey(); err != nil {
			t.Fatalf("rotateSigningKey iteration %d: %v", i, err)
		}
	}
	prev, err := loadPreviousPubKeys(prevPath)
	if err != nil {
		t.Fatalf("load previous pubkeys: %v", err)
	}
	if len(prev) != 2 {
		t.Fatalf("expected previous key history trimmed to 2, got %d", len(prev))
	}
	if prev[0] != oldPubs[3] || prev[1] != oldPubs[2] {
		t.Fatalf("unexpected trimmed previous key order got=%v want=[%s %s]", prev, oldPubs[3], oldPubs[2])
	}
}

func TestRunKeyRotationAutoRotates(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "directory.key")
	prevPath := filepath.Join(dir, "previous.txt")
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	initialPub := base64.RawURLEncoding.EncodeToString(pub)
	s := &Service{
		pubKey:              pub,
		privKey:             priv,
		privateKeyPath:      privPath,
		previousPubKeysFile: prevPath,
		keyRotateEvery:      15 * time.Millisecond,
		keyHistory:          2,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.runKeyRotation(ctx)

	deadline := time.Now().Add(600 * time.Millisecond)
	rotated := false
	for time.Now().Before(deadline) {
		curPub, _ := s.currentKeypair()
		if base64.RawURLEncoding.EncodeToString(curPub) != initialPub {
			rotated = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !rotated {
		t.Fatalf("expected auto key rotation to change current key")
	}

	time.Sleep(20 * time.Millisecond)
	prev, err := loadPreviousPubKeys(prevPath)
	if err != nil {
		t.Fatalf("load previous pubkeys: %v", err)
	}
	if len(prev) == 0 {
		t.Fatalf("expected at least one previous key after auto rotation")
	}
	if prev[0] != initialPub && (len(prev) < 2 || prev[1] != initialPub) {
		t.Fatalf("expected initial key retained in previous key history, got=%v", prev)
	}
}
