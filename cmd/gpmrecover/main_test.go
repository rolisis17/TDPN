package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	unsignedBridge := filepath.Join(dir, "bridge.json")
	signedBridge := filepath.Join(dir, "bridge.signed.json")
	helperRegistry := filepath.Join(dir, "bridge-helper-registry.json")
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
	bridgeBody, err := json.MarshalIndent(testBridgeInvite(server.URL), "", "  ")
	if err != nil {
		t.Fatalf("marshal bridge invite: %v", err)
	}
	if err := os.WriteFile(unsignedBridge, bridgeBody, 0o644); err != nil {
		t.Fatalf("write bridge invite: %v", err)
	}
	if err := runBridgeSign([]string{"--invite", unsignedBridge, "--private-key-file", privateKey, "--out", signedBridge}); err != nil {
		t.Fatalf("bridge-sign: %v", err)
	}
	if err := writeBridgeHelperRegistryFile(helperRegistry, testCLIBridgeHelperRegistry(server.URL)); err != nil {
		t.Fatalf("write helper registry: %v", err)
	}
	if err := runBridgeVerify([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--show-paths"}); err != nil {
		t.Fatalf("bridge-verify: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--helper-registry", helperRegistry}); err != nil {
		t.Fatalf("bridge-policy: %v", err)
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
	if err := runBridgeVerify([]string{"--invite", signedBridge, "--trust-store", trustStore, "--show-paths"}); err != nil {
		t.Fatalf("bridge-verify with trust store: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--trust-store", trustStore, "--helper-registry", helperRegistry}); err != nil {
		t.Fatalf("bridge-policy with trust store: %v", err)
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
	bridgeEnvelope := filepath.Join(dir, "bridge.txt")
	importedBridge := filepath.Join(dir, "bridge.imported.json")
	if err := runTextExport([]string{"--kind", "bridge-invite", "--in", signedBridge, "--out", bridgeEnvelope}); err != nil {
		t.Fatalf("text-export bridge invite: %v", err)
	}
	if err := runTextImport([]string{"--text-file", bridgeEnvelope, "--expect-kind", "bridge-invite", "--out", importedBridge}); err != nil {
		t.Fatalf("text-import bridge invite: %v", err)
	}
	if err := runBridgeVerify([]string{"--invite", importedBridge, "--trust-store", importedStore}); err != nil {
		t.Fatalf("bridge-verify imported bridge invite: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", importedBridge, "--trust-store", importedStore, "--helper-registry", helperRegistry}); err != nil {
		t.Fatalf("bridge-policy imported bridge invite: %v", err)
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
	if err := runBridgeVerify([]string{"--invite", signedBridge, "--trust-store", trustStore}); err == nil {
		t.Fatal("expected bridge verify with empty trust store to fail")
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--trust-store", trustStore}); err == nil {
		t.Fatal("expected bridge policy with empty trust store to fail")
	}
}

func TestGPMRecoverDemoBundle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	dir := filepath.Join(t.TempDir(), "demo")
	if err := runDemoBundle([]string{"--out-dir", dir, "--base-url", server.URL, "--helper-url", server.URL + "/bridge"}); err != nil {
		t.Fatalf("demo-bundle: %v", err)
	}
	manifestPath := filepath.Join(dir, "demo-manifest.json")
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest demoBundleOutput
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.BridgePolicy.Status != "pass" {
		t.Fatalf("expected manifest bridge policy pass, got %+v", manifest.BridgePolicy)
	}
	for _, key := range []string{
		"private_key",
		"public_key",
		"trust_store",
		"access_pack_signed",
		"bridge_invite_signed",
		"bridge_helper_registry",
		"access_pack_text",
		"bridge_invite_text",
		"trust_store_text",
		"access_pack_qr",
		"bridge_invite_qr",
	} {
		if manifest.Files[key] == "" {
			t.Fatalf("manifest missing %s", key)
		}
		assertFileExists(t, manifest.Files[key])
	}
	if err := runVerify([]string{"--pack", manifest.Files["access_pack_signed"], "--trust-store", manifest.Files["trust_store"], "--show-paths"}); err != nil {
		t.Fatalf("verify generated pack: %v", err)
	}
	if err := runBridgeVerify([]string{"--invite", manifest.Files["bridge_invite_signed"], "--trust-store", manifest.Files["trust_store"], "--show-paths"}); err != nil {
		t.Fatalf("verify generated bridge invite: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", manifest.Files["bridge_invite_signed"], "--trust-store", manifest.Files["trust_store"], "--helper-registry", manifest.Files["bridge_helper_registry"]}); err != nil {
		t.Fatalf("policy generated bridge invite: %v", err)
	}
	for _, key := range []string{"access_pack_qr", "bridge_invite_qr"} {
		qrBody, err := os.ReadFile(manifest.Files[key])
		if err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if !bytes.HasPrefix(qrBody, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
			t.Fatalf("%s is not a png", key)
		}
	}
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%s is not a regular file", path)
	}
	if info.Size() == 0 {
		t.Fatalf("%s is empty", path)
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

func testBridgeInvite(serverURL string) accesspack.BridgeInvite {
	issuedAt := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	return accesspack.BridgeInvite{
		SchemaVersion: accesspack.SchemaVersion,
		InviteID:      "bri-test-cli",
		Organization: accesspack.Organization{
			OrgID:   "cli-org",
			Name:    "CLI Org",
			HomeURL: "https://cli.example",
		},
		IssuedAtUTC:      issuedAt.Format(time.RFC3339),
		ExpiresAtUTC:     issuedAt.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		IntendedAudience: "CLI test users blocked from the main site",
		Helper: accesspack.BridgeHelper{
			HelperID:    "helper-cli",
			DisplayName: "CLI Helper",
			ContactURL:  serverURL + "/contact",
			Description: "Temporary bridge helper",
		},
		AccessPaths: []accesspack.AccessPath{
			{PathID: "bridge-main", Kind: "bridge", URL: serverURL + "/bridge", Priority: 10},
			{PathID: "bridge-contact", Kind: "instructions", URL: "mailto:bridge-helper@example.com", Priority: 20, RequiresExternalApp: true},
		},
	}
}

func testCLIBridgeHelperRegistry(serverURL string) accesspack.BridgeHelperRegistry {
	now := time.Now().UTC().Truncate(time.Second)
	return accesspack.BridgeHelperRegistry{
		Version: accesspack.BridgeHelperRegistryVersion,
		Helpers: []accesspack.BridgeHelperRegistration{
			{
				HelperID:       "helper-cli",
				DisplayName:    "CLI Helper",
				Status:         accesspack.BridgeHelperStatusActive,
				OrgIDs:         []string{"cli-org"},
				ContactURL:     serverURL + "/contact",
				ActiveFromUTC:  now.Add(-2 * time.Hour).Format(time.RFC3339),
				ActiveUntilUTC: now.Add(8 * 24 * time.Hour).Format(time.RFC3339),
				UpdatedAtUTC:   now.Format(time.RFC3339),
			},
		},
	}
}
