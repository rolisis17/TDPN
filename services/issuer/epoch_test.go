package issuer

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"privacynode/pkg/crypto"
)

func TestLoadOrCreateEpochState(t *testing.T) {
	file := filepath.Join(t.TempDir(), "epochs.json")
	s := &Service{
		epochStateFile: file,
		keyEpoch:       1,
		minTokenEpoch:  1,
	}
	if err := s.loadOrCreateEpochState(); err != nil {
		t.Fatalf("loadOrCreateEpochState: %v", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("expected epoch file created: %v", err)
	}
}

func TestRotateSigningKeyIncrementsEpochAndStoresPrevious(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "issuer.key")
	prevPath := filepath.Join(dir, "prev.txt")
	epochPath := filepath.Join(dir, "epochs.json")
	revPath := filepath.Join(dir, "revocations.json")

	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := &Service{
		pubKey:              pub,
		privKey:             priv,
		privateKeyPath:      privPath,
		previousPubKeysFile: prevPath,
		epochStateFile:      epochPath,
		revocationsFile:     revPath,
		keyHistory:          3,
		keyEpoch:            1,
		minTokenEpoch:       1,
		revocations:         map[string]int64{"jti-a": time.Now().Add(time.Minute).Unix()},
	}
	oldPub := base64.RawURLEncoding.EncodeToString(pub)
	if err := s.rotateSigningKey(); err != nil {
		t.Fatalf("rotateSigningKey: %v", err)
	}
	if s.keyEpoch != 2 {
		t.Fatalf("expected key epoch incremented to 2, got %d", s.keyEpoch)
	}
	if s.minTokenEpoch < 2 {
		t.Fatalf("expected min token epoch advanced, got %d", s.minTokenEpoch)
	}
	if _, err := os.Stat(privPath); err != nil {
		t.Fatalf("expected private key persisted: %v", err)
	}
	prev, err := loadPreviousPubKeys(prevPath)
	if err != nil {
		t.Fatalf("loadPreviousPubKeys: %v", err)
	}
	if len(prev) == 0 || prev[0] != oldPub {
		t.Fatalf("expected previous pubkey to contain old key")
	}
}

func TestSaveLoadRevocationsStoreFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.json")
	s := &Service{
		revocationsFile:   path,
		revocations:       map[string]int64{"jti-a": 111},
		keyEpoch:          7,
		minTokenEpoch:     6,
		revocationVersion: 9,
	}
	if err := s.saveRevocations(); err != nil {
		t.Fatalf("saveRevocations: %v", err)
	}
	s2 := &Service{
		revocationsFile: path,
		revocations:     map[string]int64{},
		keyEpoch:        1,
		minTokenEpoch:   1,
	}
	if err := s2.loadRevocations(); err != nil {
		t.Fatalf("loadRevocations: %v", err)
	}
	if got := s2.revocationVersion; got != 9 {
		t.Fatalf("expected revocation version 9, got %d", got)
	}
	if got := s2.keyEpoch; got != 7 {
		t.Fatalf("expected key epoch 7, got %d", got)
	}
	if got := s2.minTokenEpoch; got != 6 {
		t.Fatalf("expected min token epoch 6, got %d", got)
	}
	if until := s2.revocations["jti-a"]; until != 111 {
		t.Fatalf("expected revocation persisted, got %d", until)
	}
}
