package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
	signedRegistry := filepath.Join(dir, "bridge-helper-registry.signed.json")
	verifiedRegistry := filepath.Join(dir, "bridge-helper-registry.verified.json")
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
	if err := runBridgeRegistrySign([]string{
		"--helper-registry", helperRegistry,
		"--org-id", "cli-org",
		"--org-name", "CLI Org",
		"--private-key-file", privateKey,
		"--registry-id", "cli-registry",
		"--out", signedRegistry,
	}); err != nil {
		t.Fatalf("bridge-registry-sign: %v", err)
	}
	if err := runBridgeRegistryVerify([]string{"--signed-registry", signedRegistry, "--public-key-file", publicKey, "--out-registry", verifiedRegistry, "--show-registry"}); err != nil {
		t.Fatalf("bridge-registry-verify: %v", err)
	}
	if err := runBridgeRegistryCheck([]string{"--helper-registry", verifiedRegistry, "--helper-id", "helper-cli", "--org-id", "cli-org", "--require-active"}); err != nil {
		t.Fatalf("bridge-registry-check verified registry: %v", err)
	}
	if err := runBridgeRegistryCheck([]string{"--helper-registry", helperRegistry, "--helper-id", "helper-cli", "--org-id", "cli-org", "--require-active"}); err != nil {
		t.Fatalf("bridge-registry-check: %v", err)
	}
	upsertedRegistry := filepath.Join(dir, "bridge-helper-registry.upserted.json")
	if err := runBridgeRegistryUpsertHelper([]string{
		"--helper-registry", helperRegistry,
		"--helper-id", "helper-cli-2",
		"--org-ids", "cli-org,cli-org-alt",
		"--display-name", "CLI Helper Two",
		"--contact-url", server.URL + "/contact-two",
		"--abuse-report-url", server.URL + "/abuse-two",
		"--rate-limit-policy", "beta cap: per-user and per-source limits enforced",
		"--out", upsertedRegistry,
	}); err != nil {
		t.Fatalf("bridge-registry-upsert-helper: %v", err)
	}
	if err := runBridgeRegistryCheck([]string{"--helper-registry", upsertedRegistry, "--helper-id", "helper-cli-2", "--org-id", "cli-org-alt", "--require-active"}); err != nil {
		t.Fatalf("bridge-registry-check upserted helper: %v", err)
	}
	quarantinedRegistry := filepath.Join(dir, "bridge-helper-registry.quarantined.json")
	if err := runBridgeRegistrySetStatus([]string{"--helper-registry", helperRegistry, "--helper-id", "helper-cli", "--status", "quarantined", "--reason", "maintenance window", "--out", quarantinedRegistry}); err != nil {
		t.Fatalf("bridge-registry-set-status quarantine: %v", err)
	}
	if err := runBridgeRegistryCheck([]string{"--helper-registry", quarantinedRegistry, "--helper-id", "helper-cli", "--require-active"}); err == nil {
		t.Fatal("expected quarantined helper to fail active registry check")
	}
	if err := runBridgeVerify([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--show-paths"}); err != nil {
		t.Fatalf("bridge-verify: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--helper-registry", helperRegistry, "--require-helper-registry"}); err != nil {
		t.Fatalf("bridge-policy: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--signed-helper-registry", signedRegistry, "--require-helper-registry"}); err != nil {
		t.Fatalf("bridge-policy signed helper registry: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--require-helper-registry"}); err == nil {
		t.Fatal("expected bridge-policy to fail when helper registry is required but missing")
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
	if err := runBridgeRegistryVerify([]string{"--signed-registry", signedRegistry, "--trust-store", trustStore}); err != nil {
		t.Fatalf("bridge-registry-verify with trust store: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--trust-store", trustStore, "--helper-registry", helperRegistry, "--require-helper-registry"}); err != nil {
		t.Fatalf("bridge-policy with trust store: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--trust-store", trustStore, "--signed-helper-registry", signedRegistry, "--require-helper-registry"}); err != nil {
		t.Fatalf("bridge-policy signed helper registry with trust store: %v", err)
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
	registryEnvelope := filepath.Join(dir, "registry.txt")
	importedRegistry := filepath.Join(dir, "registry.imported.json")
	if err := runTextExport([]string{"--kind", "trust-store", "--in", trustStore, "--out", storeEnvelope}); err != nil {
		t.Fatalf("text-export store: %v", err)
	}
	if err := runTextImport([]string{"--text-file", storeEnvelope, "--expect-kind", "trust-store", "--out", importedStore}); err != nil {
		t.Fatalf("text-import store: %v", err)
	}
	if err := runVerify([]string{"--pack", signedPack, "--trust-store", importedStore}); err != nil {
		t.Fatalf("verify imported store: %v", err)
	}
	trustStoreBody, err := os.ReadFile(trustStore)
	if err != nil {
		t.Fatalf("read trust store: %v", err)
	}
	parsedTrustStore, err := accesspack.ParseTrustStore(trustStoreBody)
	if err != nil {
		t.Fatalf("parse trust store: %v", err)
	}
	if len(parsedTrustStore.TrustedKeys) != 1 {
		t.Fatalf("expected one trusted key, got %d", len(parsedTrustStore.TrustedKeys))
	}
	exportedKeyFile := filepath.Join(dir, "trusted-key.exported.json")
	exportedKeyText := filepath.Join(dir, "trusted-key.exported.txt")
	if err := runTrustExportKey([]string{
		"--trust-store", trustStore,
		"--org-id", "cli-org",
		"--key-id", parsedTrustStore.TrustedKeys[0].KeyID,
		"--out", exportedKeyFile,
		"--text-out", exportedKeyText,
	}); err != nil {
		t.Fatalf("trust-export-key: %v", err)
	}
	if err := runTextImport([]string{"--text-file", exportedKeyText, "--expect-kind", accesspack.EnvelopeKindKey, "--out", filepath.Join(dir, "trusted-key.exported.imported.json")}); err != nil {
		t.Fatalf("text-import exported trusted key: %v", err)
	}
	trustedKeyFile := filepath.Join(dir, "trusted-key.json")
	trustedKeyBody, err := json.MarshalIndent(parsedTrustStore.TrustedKeys[0], "", "  ")
	if err != nil {
		t.Fatalf("marshal trusted key: %v", err)
	}
	if err := os.WriteFile(trustedKeyFile, trustedKeyBody, 0o644); err != nil {
		t.Fatalf("write trusted key: %v", err)
	}
	trustedKeyEnvelope := filepath.Join(dir, "trusted-key.txt")
	importedTrustedKey := filepath.Join(dir, "trusted-key.imported.json")
	if err := runTextExport([]string{"--kind", accesspack.EnvelopeKindKey, "--in", trustedKeyFile, "--out", trustedKeyEnvelope}); err != nil {
		t.Fatalf("text-export trusted key: %v", err)
	}
	if err := runTextImport([]string{"--text-file", trustedKeyEnvelope, "--expect-kind", accesspack.EnvelopeKindKey, "--out", importedTrustedKey}); err != nil {
		t.Fatalf("text-import trusted key: %v", err)
	}
	disabledKey := parsedTrustStore.TrustedKeys[0]
	disabledKey.Disabled = true
	disabledKeyBody, err := json.MarshalIndent(disabledKey, "", "  ")
	if err != nil {
		t.Fatalf("marshal disabled trusted key: %v", err)
	}
	disabledKeyFile := filepath.Join(dir, "trusted-key.disabled.json")
	if err := os.WriteFile(disabledKeyFile, disabledKeyBody, 0o644); err != nil {
		t.Fatalf("write disabled trusted key: %v", err)
	}
	if err := runTextExport([]string{"--kind", accesspack.EnvelopeKindKey, "--in", disabledKeyFile, "--out", filepath.Join(dir, "trusted-key.disabled.txt")}); err == nil {
		t.Fatal("expected text-export to reject disabled trusted-key handoff")
	}
	disabledKeyEnvelope, err := accesspack.EncodeTextEnvelope(accesspack.EnvelopeKindKey, disabledKeyBody)
	if err != nil {
		t.Fatalf("encode disabled trusted-key envelope: %v", err)
	}
	disabledKeyEnvelopeFile := filepath.Join(dir, "trusted-key.disabled.envelope.txt")
	if err := os.WriteFile(disabledKeyEnvelopeFile, []byte(disabledKeyEnvelope+"\n"), 0o644); err != nil {
		t.Fatalf("write disabled trusted-key envelope: %v", err)
	}
	if err := runTextImport([]string{"--text-file", disabledKeyEnvelopeFile, "--expect-kind", accesspack.EnvelopeKindKey, "--out", filepath.Join(dir, "trusted-key.disabled.imported.json")}); err == nil {
		t.Fatal("expected text-import to reject disabled trusted-key handoff")
	}
	if err := runTextExport([]string{"--kind", "bridge-helper-registry", "--in", helperRegistry, "--out", registryEnvelope}); err != nil {
		t.Fatalf("text-export helper registry: %v", err)
	}
	if err := runTextExport([]string{"--kind", accesspack.EnvelopeKindBridgeHelperRegistrySigned, "--in", helperRegistry, "--out", filepath.Join(dir, "registry.bad-signed.txt")}); err == nil {
		t.Fatal("expected text-export to reject raw helper registry mislabeled as signed")
	}
	signedRegistryBody, err := os.ReadFile(signedRegistry)
	if err != nil {
		t.Fatalf("read signed registry: %v", err)
	}
	var badSignedRegistry accesspack.BridgeHelperRegistryArtifact
	if err := json.Unmarshal(signedRegistryBody, &badSignedRegistry); err != nil {
		t.Fatalf("unmarshal signed registry: %v", err)
	}
	badSignedRegistry.Signature.Sig = "bad"
	badSignedRegistryFile := filepath.Join(dir, "registry.bad-signature.json")
	badSignedRegistryBody, err := json.MarshalIndent(badSignedRegistry, "", "  ")
	if err != nil {
		t.Fatalf("marshal bad signed registry: %v", err)
	}
	if err := os.WriteFile(badSignedRegistryFile, badSignedRegistryBody, 0o644); err != nil {
		t.Fatalf("write bad signed registry: %v", err)
	}
	if err := runTextExport([]string{"--kind", accesspack.EnvelopeKindBridgeHelperRegistrySigned, "--in", badSignedRegistryFile, "--out", filepath.Join(dir, "registry.bad-signature.txt")}); err == nil {
		t.Fatal("expected text-export to reject malformed signed helper registry signature")
	}
	rawRegistryBody, err := os.ReadFile(helperRegistry)
	if err != nil {
		t.Fatalf("read helper registry: %v", err)
	}
	badRegistryEnvelope, err := accesspack.EncodeTextEnvelope(accesspack.EnvelopeKindBridgeHelperRegistrySigned, rawRegistryBody)
	if err != nil {
		t.Fatalf("encode bad signed registry envelope: %v", err)
	}
	badRegistryEnvelopeFile := filepath.Join(dir, "registry.bad-signed.txt")
	if err := os.WriteFile(badRegistryEnvelopeFile, []byte(badRegistryEnvelope+"\n"), 0o644); err != nil {
		t.Fatalf("write bad signed registry envelope: %v", err)
	}
	if err := runQRPNG([]string{"--text-file", badRegistryEnvelopeFile, "--out", filepath.Join(dir, "registry.bad-signed.png")}); err == nil {
		t.Fatal("expected qr-png to reject raw helper registry mislabeled as signed")
	}
	if err := runTextImport([]string{"--text-file", registryEnvelope, "--expect-kind", "bridge-helper-registry", "--out", importedRegistry}); err != nil {
		t.Fatalf("text-import helper registry: %v", err)
	}
	if err := runBridgeRegistryCheck([]string{"--helper-registry", importedRegistry, "--helper-id", "helper-cli", "--require-active"}); err != nil {
		t.Fatalf("bridge-registry-check imported registry: %v", err)
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
	if err := runBridgePolicy([]string{"--invite", importedBridge, "--trust-store", importedStore, "--helper-registry", importedRegistry}); err != nil {
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
	if err := runDemoBundle([]string{
		"--out-dir", dir,
		"--base-url", server.URL,
		"--helper-url", server.URL + "/bridge",
		"--helper-id", "helper-pilot",
		"--helper-name", "Pilot Helper",
		"--pack-audience", "Pilot pack users",
		"--invite-audience", "Pilot invite users",
	}); err != nil {
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
		"bridge_helper_registry_signed",
		"access_pack_text",
		"bridge_invite_text",
		"bridge_helper_registry_text",
		"bridge_helper_registry_signed_text",
		"trust_store_text",
		"trusted_key",
		"trusted_key_text",
		"publish_access_pack",
		"publish_bridge_invite",
		"publish_bridge_helper_registry_signed",
		"publish_trusted_key",
		"publish_index",
		"access_pack_qr",
		"bridge_invite_qr",
		"bridge_helper_registry_qr",
		"bridge_helper_registry_signed_qr",
		"trusted_key_qr",
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
	if err := runBridgeRegistryVerify([]string{"--signed-registry", manifest.Files["bridge_helper_registry_signed"], "--trust-store", manifest.Files["trust_store"], "--out-registry", filepath.Join(dir, "bridge-helper-registry.verified.json")}); err != nil {
		t.Fatalf("verify generated bridge helper registry: %v", err)
	}
	importedSignedRegistry := filepath.Join(dir, "bridge-helper-registry.signed.imported.json")
	if err := runTextImport([]string{"--text-file", manifest.Files["bridge_helper_registry_signed_text"], "--expect-kind", accesspack.EnvelopeKindBridgeHelperRegistrySigned, "--out", importedSignedRegistry}); err != nil {
		t.Fatalf("import generated signed bridge helper registry text: %v", err)
	}
	importedTrustedKey := filepath.Join(dir, "recovery-trusted-key.imported.json")
	if err := runTextImport([]string{"--text-file", manifest.Files["trusted_key_text"], "--expect-kind", accesspack.EnvelopeKindKey, "--out", importedTrustedKey}); err != nil {
		t.Fatalf("import generated trusted key text: %v", err)
	}
	if err := runBridgeRegistryVerify([]string{"--signed-registry", importedSignedRegistry, "--trust-store", manifest.Files["trust_store"], "--out-registry", filepath.Join(dir, "bridge-helper-registry.imported.verified.json")}); err != nil {
		t.Fatalf("verify imported bridge helper registry: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", manifest.Files["bridge_invite_signed"], "--trust-store", manifest.Files["trust_store"], "--helper-registry", manifest.Files["bridge_helper_registry"]}); err != nil {
		t.Fatalf("policy generated bridge invite: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", manifest.Files["bridge_invite_signed"], "--trust-store", manifest.Files["trust_store"], "--signed-helper-registry", manifest.Files["bridge_helper_registry_signed"]}); err != nil {
		t.Fatalf("policy generated bridge invite with signed registry: %v", err)
	}
	if err := runBridgeRegistryCheck([]string{"--helper-registry", manifest.Files["bridge_helper_registry"], "--helper-id", "helper-pilot", "--org-id", manifest.OrgID, "--require-active"}); err != nil {
		t.Fatalf("check generated helper registry: %v", err)
	}
	for _, key := range []string{"access_pack_qr", "bridge_invite_qr", "bridge_helper_registry_qr", "bridge_helper_registry_signed_qr", "trusted_key_qr"} {
		qrBody, err := os.ReadFile(manifest.Files[key])
		if err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if !bytes.HasPrefix(qrBody, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
			t.Fatalf("%s is not a png", key)
		}
	}
}

func TestGPMRecoverFetchPublication(t *testing.T) {
	files := map[string]string{
		"/.well-known/gpm/access-pack.json":                   `{"kind":"pack"}`,
		"/.well-known/gpm/bridge-invite.json":                 `{"kind":"bridge"}`,
		"/.well-known/gpm/bridge-helper-registry.signed.json": `{"kind":"registry"}`,
		"/.well-known/gpm/recovery-trusted-key.json":          `{"kind":"key"}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/gpm/recovery-index.json" {
			_ = json.NewEncoder(w).Encode(recoveryPublicationIndex{
				Version: 1,
				Files: map[string]string{
					"access_pack":                   "access-pack.json",
					"bridge_invite":                 "bridge-invite.json",
					"bridge_helper_registry_signed": "bridge-helper-registry.signed.json",
					"trusted_key":                   "recovery-trusted-key.json",
				},
			})
			return
		}
		if body, ok := files[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	outDir := filepath.Join(t.TempDir(), "fetched")
	if err := runFetchPublication([]string{
		"--index-url", server.URL + "/.well-known/gpm/recovery-index.json",
		"--out-dir", outDir,
	}); err != nil {
		t.Fatalf("fetch-publication: %v", err)
	}
	for _, name := range []string{
		"access-pack.json",
		"bridge-invite.json",
		"bridge-helper-registry.signed.json",
		"recovery-trusted-key.json",
	} {
		assertFileExists(t, filepath.Join(outDir, name))
	}
}

func TestGPMRecoverFetchPublicationRejectsCrossOriginFiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(recoveryPublicationIndex{
			Version: 1,
			Files: map[string]string{
				"access_pack":                   "https://evil.example/access-pack.json",
				"bridge_invite":                 "bridge-invite.json",
				"bridge_helper_registry_signed": "bridge-helper-registry.signed.json",
				"trusted_key":                   "recovery-trusted-key.json",
			},
		})
	}))
	t.Cleanup(server.Close)

	err := runFetchPublication([]string{
		"--index-url", server.URL + "/.well-known/gpm/recovery-index.json",
		"--out-dir", filepath.Join(t.TempDir(), "fetched"),
	})
	if err == nil {
		t.Fatal("expected cross-origin publication file to be rejected")
	}
}

func TestTextEnvelopePayloadRejectsExpiredSignedArtifacts(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	pack := testRecoveryPack("https://example.com")
	pack.IssuedAtUTC = now.Add(-48 * time.Hour).Format(time.RFC3339)
	pack.ExpiresAtUTC = now.Add(-24 * time.Hour).Format(time.RFC3339)
	signedPack, err := accesspack.Sign(pack, priv, "")
	if err != nil {
		t.Fatalf("sign expired pack: %v", err)
	}
	packBody, err := json.Marshal(signedPack)
	if err != nil {
		t.Fatalf("marshal expired pack: %v", err)
	}
	if err := validateTextEnvelopePayload(accesspack.EnvelopeKindPack, packBody); err == nil {
		t.Fatal("expected expired access-pack handoff payload to fail")
	}

	invite := testBridgeInvite("https://example.com")
	invite.IssuedAtUTC = now.Add(-48 * time.Hour).Format(time.RFC3339)
	invite.ExpiresAtUTC = now.Add(-24 * time.Hour).Format(time.RFC3339)
	signedInvite, err := accesspack.SignBridgeInvite(invite, priv, "")
	if err != nil {
		t.Fatalf("sign expired bridge invite: %v", err)
	}
	inviteBody, err := json.Marshal(signedInvite)
	if err != nil {
		t.Fatalf("marshal expired bridge invite: %v", err)
	}
	if err := validateTextEnvelopePayload(accesspack.EnvelopeKindBridge, inviteBody); err == nil {
		t.Fatal("expected expired bridge-invite handoff payload to fail")
	}

	artifact := accesspack.BridgeHelperRegistryArtifact{
		SchemaVersion: accesspack.BridgeHelperRegistryArtifactSchemaVersion,
		RegistryID:    "expired-registry",
		Organization: accesspack.Organization{
			OrgID: "cli-org",
			Name:  "CLI Org",
		},
		IssuedAtUTC:  now.Add(-48 * time.Hour).Format(time.RFC3339),
		ExpiresAtUTC: now.Add(-24 * time.Hour).Format(time.RFC3339),
		Registry:     testCLIBridgeHelperRegistry("https://example.com"),
	}
	signedArtifact, err := accesspack.SignBridgeHelperRegistryArtifact(artifact, priv, "")
	if err != nil {
		t.Fatalf("sign expired helper registry artifact: %v", err)
	}
	artifactBody, err := json.Marshal(signedArtifact)
	if err != nil {
		t.Fatalf("marshal expired helper registry artifact: %v", err)
	}
	if err := validateTextEnvelopePayload(accesspack.EnvelopeKindBridgeHelperRegistrySigned, artifactBody); err == nil {
		t.Fatal("expected expired signed helper registry handoff payload to fail")
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
				HelperID:        "helper-cli",
				DisplayName:     "CLI Helper",
				Status:          accesspack.BridgeHelperStatusActive,
				OrgIDs:          []string{"cli-org"},
				ContactURL:      serverURL + "/contact",
				AbuseReportURL:  serverURL + "/abuse",
				RateLimitPolicy: "beta cap: per-user and per-source limits enforced",
				ActiveFromUTC:   now.Add(-2 * time.Hour).Format(time.RFC3339),
				ActiveUntilUTC:  now.Add(8 * 24 * time.Hour).Format(time.RFC3339),
				UpdatedAtUTC:    now.Format(time.RFC3339),
			},
		},
	}
}
