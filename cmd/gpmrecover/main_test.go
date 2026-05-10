package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"privacynode/pkg/accesspack"
	"privacynode/pkg/adminauth"
)

func TestGPMRecoverSignVerifyRoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	privateKey := filepath.Join(dir, "recovery.key")
	publicKey := filepath.Join(dir, "recovery.pub")
	unsignedPack := filepath.Join(dir, "pack.json")
	signedPack := filepath.Join(dir, "pack.signed.json")
	trustStore := filepath.Join(dir, "trust-store.json")

	if err := runGen([]string{"--private-key-out", privateKey, "--public-key-out", publicKey}); err != nil {
		t.Fatalf("gen: %v", err)
	}
	body, err := json.MarshalIndent(testRecoveryPack(server.URL), "", "  ")
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	if err := os.WriteFile(unsignedPack, body, 0o644); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	if err := runSign([]string{"--pack", unsignedPack, "--private-key-file", privateKey, "--out", signedPack}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := runVerify([]string{"--pack", signedPack, "--public-key-file", publicKey, "--show-paths"}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := runCheck([]string{"--pack", signedPack, "--public-key-file", publicKey, "--timeout-sec", "2"}); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := runTrustAdd([]string{"--trust-store", trustStore, "--org-id", "cli-org", "--org-name", "CLI Org", "--public-key-file", publicKey, "--source", "test"}); err != nil {
		t.Fatalf("trust-add: %v", err)
	}
	if err := runTrustList([]string{"--trust-store", trustStore}); err != nil {
		t.Fatalf("trust-list: %v", err)
	}
	if err := runVerify([]string{"--pack", signedPack, "--trust-store", trustStore, "--show-paths"}); err != nil {
		t.Fatalf("verify with trust store: %v", err)
	}
	if err := runCheck([]string{"--pack", signedPack, "--trust-store", trustStore, "--timeout-sec", "2"}); err != nil {
		t.Fatalf("check with trust store: %v", err)
	}
	packEnvelope := filepath.Join(dir, "pack.txt")
	importedPack := filepath.Join(dir, "pack.imported.json")
	if err := runTextExport([]string{"--kind", "access-pack", "--in", signedPack, "--out", packEnvelope}); err != nil {
		t.Fatalf("text-export pack: %v", err)
	}
	packQR := filepath.Join(dir, "pack.png")
	if err := runQRPNG([]string{"--text-file", packEnvelope, "--out", packQR, "--size", "256"}); err != nil {
		t.Fatalf("qr-png pack: %v", err)
	}
	qrBody, err := os.ReadFile(packQR)
	if err != nil {
		t.Fatalf("read qr png: %v", err)
	}
	if !bytes.HasPrefix(qrBody, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		t.Fatal("qr-png output is not a png")
	}
	if err := runTextImport([]string{"--text-file", packEnvelope, "--expect-kind", "access-pack", "--out", importedPack}); err != nil {
		t.Fatalf("text-import pack: %v", err)
	}
	if err := runVerify([]string{"--pack", importedPack, "--trust-store", trustStore}); err != nil {
		t.Fatalf("verify imported pack: %v", err)
	}
	storeEnvelope := filepath.Join(dir, "store.txt")
	importedStore := filepath.Join(dir, "store.imported.json")
	if err := runTextExport([]string{"--kind", "trust-store", "--in", trustStore, "--out", storeEnvelope}); err != nil {
		t.Fatalf("text-export store: %v", err)
	}
	if err := runTextImport([]string{"--text-file", storeEnvelope, "--expect-kind", "trust-store", "--out", importedStore}); err != nil {
		t.Fatalf("text-import store: %v", err)
	}
	if err := runVerify([]string{"--pack", signedPack, "--trust-store", importedStore}); err != nil {
		t.Fatalf("verify imported store: %v", err)
	}
	pubBody, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	pub, err := adminauth.ParsePublicKey(string(pubBody))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	keyID := adminauth.KeyIDFromPublicKey(pub)
	if err := runTrustRemove([]string{"--trust-store", trustStore, "--org-id", "cli-org", "--key-id", keyID}); err != nil {
		t.Fatalf("trust-remove: %v", err)
	}
	if err := runVerify([]string{"--pack", signedPack, "--trust-store", trustStore}); err == nil {
		t.Fatal("expected verify with empty trust store to fail")
	}
}

func testRecoveryPack(serverURL string) accesspack.Pack {
	return accesspack.Pack{
		SchemaVersion: accesspack.SchemaVersion,
		PackID:        "arp-test-cli",
		Organization: accesspack.Organization{
			OrgID:   "cli-org",
			Name:    "CLI Org",
			HomeURL: "https://cli.example",
		},
		IssuedAtUTC:      "2026-05-10T00:00:00Z",
		ExpiresAtUTC:     "2099-01-01T00:00:00Z",
		IntendedAudience: "CLI test users",
		Sources: []accesspack.Source{
			{SourceID: "official", Kind: "official", URL: serverURL, Priority: 10},
		},
		AccessPaths: []accesspack.AccessPath{
			{PathID: "main", Kind: "website", URL: serverURL, Priority: 10},
		},
	}
}
