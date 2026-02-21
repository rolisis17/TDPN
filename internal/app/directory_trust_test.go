package app

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTrustedKeysAndTOFU(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "trusted.txt")

	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	key := base64.RawURLEncoding.EncodeToString(keyBytes)

	c := &Client{trustStrict: true, trustTOFU: true, trustFile: file}
	if err := c.enforceDirectoryTrust(key); err != nil {
		t.Fatalf("expected TOFU trust pinning, got err: %v", err)
	}

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read pinned file: %v", err)
	}
	if len(content) == 0 {
		t.Fatalf("expected pinned key in file")
	}

	keys, err := loadTrustedKeys(file)
	if err != nil {
		t.Fatalf("load trusted keys: %v", err)
	}
	if _, ok := keys[key]; !ok {
		t.Fatalf("expected key in trusted map")
	}
}

func TestStrictTrustRejectsUnknown(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "trusted.txt")

	knownBytes := make([]byte, 32)
	unknownBytes := make([]byte, 32)
	for i := range knownBytes {
		knownBytes[i] = byte(i + 1)
		unknownBytes[i] = byte(i + 2)
	}
	known := base64.RawURLEncoding.EncodeToString(knownBytes)
	unknown := base64.RawURLEncoding.EncodeToString(unknownBytes)
	if err := os.WriteFile(file, []byte(known+"\n"), 0o644); err != nil {
		t.Fatalf("write trusted file: %v", err)
	}

	c := &Client{trustStrict: true, trustTOFU: false, trustFile: file}
	if err := c.enforceDirectoryTrust(unknown); err == nil {
		t.Fatalf("expected unknown key to be rejected")
	}
}

func TestStrictTrustAcceptsKeysetWhenOnePinnedAndPinsNew(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "trusted.txt")

	keyABytes := make([]byte, 32)
	keyBBytes := make([]byte, 32)
	for i := range keyABytes {
		keyABytes[i] = byte(i + 1)
		keyBBytes[i] = byte(i + 3)
	}
	keyA := base64.RawURLEncoding.EncodeToString(keyABytes)
	keyB := base64.RawURLEncoding.EncodeToString(keyBBytes)

	if err := os.WriteFile(file, []byte(keyA+"\n"), 0o644); err != nil {
		t.Fatalf("write trusted file: %v", err)
	}
	c := &Client{trustStrict: true, trustTOFU: false, trustFile: file}
	if err := c.enforceDirectoryTrustSet([]string{keyB, keyA}); err != nil {
		t.Fatalf("expected keyset trust when one key already pinned: %v", err)
	}
	keys, err := loadTrustedKeys(file)
	if err != nil {
		t.Fatalf("load trusted keys: %v", err)
	}
	if _, ok := keys[keyB]; !ok {
		t.Fatalf("expected new key pinned from trusted keyset")
	}
}
