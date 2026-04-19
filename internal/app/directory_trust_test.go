package app

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"privacynode/pkg/proto"
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

func TestStrictTrustAcceptsKeysetWhenOnePinnedWithoutAutoPin(t *testing.T) {
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
	if _, ok := keys[keyB]; ok {
		t.Fatalf("unexpected implicit pinning of untrusted key from keyset")
	}
}

func TestStrictTrustTOFURejectsMalformedKeysetWithoutPersisting(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "trusted.txt")

	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	valid := base64.RawURLEncoding.EncodeToString(keyBytes)

	c := &Client{trustStrict: true, trustTOFU: true, trustFile: file}
	if err := c.enforceDirectoryTrustSet([]string{valid, "not-valid-base64"}); err == nil {
		t.Fatalf("expected malformed keyset to be rejected")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("expected no trust file write on malformed keyset, stat err=%v", err)
	}
}

func TestFetchDirectoryPubKeysFromRejectsMalformedKeysetWithoutPersisting(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "trusted.txt")

	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	valid := base64.RawURLEncoding.EncodeToString(keyBytes)

	url := "http://directory.local"
	c := &Client{
		trustStrict: true,
		trustTOFU:   true,
		trustFile:   file,
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: map[string]func(*http.Request) (*http.Response, error){
			url + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
				PubKeys: []string{valid, "invalid-key"},
			}),
		}}},
	}

	if _, _, err := c.fetchDirectoryPubKeysFrom(context.Background(), url); err == nil {
		t.Fatalf("expected malformed pubkey response to fail")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("expected no trust file write on malformed pubkey response, stat err=%v", err)
	}
}

func TestFetchDirectoryPubKeysFromStrictFiltersUntrustedKeys(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "trusted.txt")

	trustedBytes := make([]byte, 32)
	untrustedBytes := make([]byte, 32)
	for i := range trustedBytes {
		trustedBytes[i] = byte(i + 1)
		untrustedBytes[i] = byte(i + 41)
	}
	trustedKey := base64.RawURLEncoding.EncodeToString(trustedBytes)
	untrustedKey := base64.RawURLEncoding.EncodeToString(untrustedBytes)
	if err := os.WriteFile(file, []byte(trustedKey+"\n"), 0o644); err != nil {
		t.Fatalf("write trusted file: %v", err)
	}

	url := "http://directory.local"
	c := &Client{
		trustStrict: true,
		trustTOFU:   false,
		trustFile:   file,
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: map[string]func(*http.Request) (*http.Response, error){
			url + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
				PubKeys: []string{untrustedKey, trustedKey},
			}),
		}}},
	}

	keys, _, err := c.fetchDirectoryPubKeysFrom(context.Background(), url)
	if err != nil {
		t.Fatalf("fetchDirectoryPubKeysFrom: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected exactly one trusted verification key, got %d", len(keys))
	}
	if got := base64.RawURLEncoding.EncodeToString(keys[0]); got != trustedKey {
		t.Fatalf("expected trusted key %s, got %s", trustedKey, got)
	}
}

func TestLoadTrustedKeysRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "trusted-target.txt")
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	key := base64.RawURLEncoding.EncodeToString(keyBytes)
	if err := os.WriteFile(target, []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write target trust file: %v", err)
	}
	link := filepath.Join(dir, "trusted.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := loadTrustedKeys(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink trust file rejection, got %v", err)
	}
}

func TestLoadTrustedKeysRejectsOversizedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "trusted.txt")
	oversized := strings.Repeat("a", int(clientTrustedKeysFileMaxBytes)+1)
	if err := os.WriteFile(file, []byte(oversized), 0o600); err != nil {
		t.Fatalf("write oversized trust file: %v", err)
	}
	if _, err := loadTrustedKeys(file); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized trust file rejection, got %v", err)
	}
}

func TestAppendTrustedKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "trusted-target.txt")
	if err := os.WriteFile(target, []byte{}, 0o600); err != nil {
		t.Fatalf("write target trust file: %v", err)
	}
	link := filepath.Join(dir, "trusted.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	key := base64.RawURLEncoding.EncodeToString(keyBytes)
	if err := appendTrustedKey(link, key); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected appendTrustedKey symlink rejection, got %v", err)
	}
}
