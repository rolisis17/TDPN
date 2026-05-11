package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--helper-registry", helperRegistry, "--require-helper-registry"}); err == nil {
		t.Fatal("expected bridge-policy to reject unsigned helper registry without diagnostic opt-in")
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--helper-registry", helperRegistry, "--allow-unsigned-helper-registry", "--allow-local-access-paths", "--require-helper-registry"}); err != nil {
		t.Fatalf("bridge-policy unsigned diagnostic: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--signed-helper-registry", signedRegistry, "--allow-local-access-paths", "--require-helper-registry"}); err != nil {
		t.Fatalf("bridge-policy signed helper registry: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey}); err == nil {
		t.Fatal("expected bridge-policy to require helper registry by default")
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--public-key-file", publicKey, "--allow-missing-helper-registry", "--allow-local-access-paths"}); err != nil {
		t.Fatalf("bridge-policy diagnostic missing helper registry opt-out: %v", err)
	}
	serviceConfig := filepath.Join(dir, "bridge-service-config.json")
	if err := runBridgeServiceConfig([]string{
		"--invite", signedBridge,
		"--public-key-file", publicKey,
		"--signed-helper-registry", signedRegistry,
		"--allow-local-access-paths",
		"--out", serviceConfig,
	}); err != nil {
		t.Fatalf("bridge-service-config: %v", err)
	}
	serviceConfigBody, err := os.ReadFile(serviceConfig)
	if err != nil {
		t.Fatalf("read bridge service config: %v", err)
	}
	var serviceConfigOut accesspack.BridgeServiceConfig
	if err := json.Unmarshal(serviceConfigBody, &serviceConfigOut); err != nil {
		t.Fatalf("unmarshal bridge service config: %v", err)
	}
	if serviceConfigOut.Status != "pass" || !serviceConfigOut.SignedRegistry || serviceConfigOut.HelperAbuseReportURL == "" || serviceConfigOut.HelperRateLimitPolicy == "" {
		t.Fatalf("unexpected bridge service config: %+v", serviceConfigOut)
	}
	serviceDecision := filepath.Join(dir, "bridge-service-decision.json")
	if err := runBridgeServiceCheck([]string{
		"--config", serviceConfig,
		"--path-id", "bridge-main",
		"--out", serviceDecision,
	}); err != nil {
		t.Fatalf("bridge-service-check: %v", err)
	}
	serviceDecisionBody, err := os.ReadFile(serviceDecision)
	if err != nil {
		t.Fatalf("read bridge service decision: %v", err)
	}
	var serviceDecisionOut accesspack.BridgeServiceDecision
	if err := json.Unmarshal(serviceDecisionBody, &serviceDecisionOut); err != nil {
		t.Fatalf("unmarshal bridge service decision: %v", err)
	}
	if !serviceDecisionOut.Allowed || serviceDecisionOut.MatchedAccessPath == nil || serviceDecisionOut.MatchedAccessPath.PathID != "bridge-main" {
		t.Fatalf("unexpected bridge service decision: %+v", serviceDecisionOut)
	}
	if err := runBridgeServiceCheck([]string{
		"--config", serviceConfig,
		"--path-id", "bridge-contact",
	}); err == nil {
		t.Fatal("expected bridge-service-check to fail closed for manual external-app path")
	}
	codeFile := filepath.Join(dir, "bridge-code.txt")
	codeHashFile := filepath.Join(dir, "bridge-code-hash.json")
	if err := runBridgeServiceCodeGenerate([]string{"--code-out", codeFile, "--hash-out", codeHashFile}); err != nil {
		t.Fatalf("bridge-service-code-generate: %v", err)
	}
	codeHashBody, err := os.ReadFile(codeHashFile)
	if err != nil {
		t.Fatalf("read bridge code hash: %v", err)
	}
	var codeHashOut struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(codeHashBody, &codeHashOut); err != nil {
		t.Fatalf("unmarshal bridge code hash: %v", err)
	}
	if codeHashOut.SHA256 == "" || len(codeHashOut.SHA256) != 64 {
		t.Fatalf("unexpected bridge code hash: %+v", codeHashOut)
	}
	codeHashVerifyFile := filepath.Join(dir, "bridge-code-hash.verify.json")
	if err := runBridgeServiceCodeHash([]string{"--code-file", codeFile, "--out", codeHashVerifyFile}); err != nil {
		t.Fatalf("bridge-service-code-hash generated code: %v", err)
	}
	codeHashVerifyBody, err := os.ReadFile(codeHashVerifyFile)
	if err != nil {
		t.Fatalf("read bridge code hash verify: %v", err)
	}
	var codeHashVerifyOut struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(codeHashVerifyBody, &codeHashVerifyOut); err != nil {
		t.Fatalf("unmarshal bridge code hash verify: %v", err)
	}
	if codeHashVerifyOut.SHA256 != codeHashOut.SHA256 {
		t.Fatalf("generated code hash mismatch: generate=%s hash=%s", codeHashOut.SHA256, codeHashVerifyOut.SHA256)
	}
	serviceConfigSum := sha256.Sum256(serviceConfigBody)
	serviceConfigHash := hex.EncodeToString(serviceConfigSum[:])
	deployDir := filepath.Join(dir, "bridge-deploy")
	if err := runBridgeServiceDeployPack([]string{
		"--out-dir", deployDir,
		"--service-name", "gpm-access-bridge-test",
		"--install-dir", "/etc/gpm/access-bridge-test",
		"--config", "/etc/gpm/access-bridge-test/bridge-service-config.json",
		"--config-sha256", serviceConfigHash,
		"--access-code-sha256", codeHashOut.SHA256,
	}); err != nil {
		t.Fatalf("bridge-service-deploy-pack: %v", err)
	}
	unitBody, err := os.ReadFile(filepath.Join(deployDir, "gpm-access-bridge-test.service"))
	if err != nil {
		t.Fatalf("read bridge deploy unit: %v", err)
	}
	if !bytes.Contains(unitBody, []byte("NoNewPrivileges=true")) ||
		!bytes.Contains(unitBody, []byte("LogsDirectory=gpm")) ||
		!bytes.Contains(unitBody, []byte("run-gpm-access-bridge-test.sh")) {
		t.Fatalf("unexpected bridge deploy unit:\n%s", string(unitBody))
	}
	envBody, err := os.ReadFile(filepath.Join(deployDir, "gpm-access-bridge-test.env"))
	if err != nil {
		t.Fatalf("read bridge deploy env: %v", err)
	}
	if !bytes.Contains(envBody, []byte("GPM_BRIDGE_ACCESS_CODE_SHA256=")) ||
		!bytes.Contains(envBody, []byte("GPM_BRIDGE_ALLOW_UNAUTH_LOCAL=\"false\"")) ||
		!bytes.Contains(envBody, []byte("GPM_BRIDGE_CONFIG_SHA256=\""+serviceConfigHash+"\"")) ||
		!bytes.Contains(envBody, []byte("GPM_BRIDGE_ALLOW_QUERY_CODE=\"false\"")) ||
		!bytes.Contains(envBody, []byte("GPM_BRIDGE_TRUST_PROXY_HEADERS=\"true\"")) {
		t.Fatalf("unexpected bridge deploy env:\n%s", string(envBody))
	}
	wrapperBody, err := os.ReadFile(filepath.Join(deployDir, "run-gpm-access-bridge-test.sh"))
	if err != nil {
		t.Fatalf("read bridge deploy wrapper: %v", err)
	}
	if !bytes.Contains(wrapperBody, []byte("--allow-query-access-code=\"${GPM_BRIDGE_ALLOW_QUERY_CODE}\"")) ||
		!bytes.Contains(wrapperBody, []byte("--allow-unauthenticated-local=\"${GPM_BRIDGE_ALLOW_UNAUTH_LOCAL}\"")) ||
		!bytes.Contains(wrapperBody, []byte("--trust-proxy-headers=\"${GPM_BRIDGE_TRUST_PROXY_HEADERS}\"")) ||
		!bytes.Contains(wrapperBody, []byte("--redirect=\"${GPM_BRIDGE_REDIRECT}\"")) ||
		!bytes.Contains(wrapperBody, []byte("--config-sha256")) {
		t.Fatalf("unexpected bridge deploy wrapper:\n%s", string(wrapperBody))
	}
	caddyBody, err := os.ReadFile(filepath.Join(deployDir, "gpm-access-bridge-test.Caddyfile.example"))
	if err != nil {
		t.Fatalf("read bridge deploy caddy example: %v", err)
	}
	if !bytes.Contains(caddyBody, []byte("Referrer-Policy")) ||
		!bytes.Contains(caddyBody, []byte("reverse_proxy")) ||
		!bytes.Contains(caddyBody, []byte("header_up X-Forwarded-For {remote_host}")) {
		t.Fatalf("unexpected bridge deploy caddy example:\n%s", string(caddyBody))
	}
	nginxBody, err := os.ReadFile(filepath.Join(deployDir, "gpm-access-bridge-test.nginx.example.conf"))
	if err != nil {
		t.Fatalf("read bridge deploy nginx example: %v", err)
	}
	if !bytes.Contains(nginxBody, []byte("proxy_pass")) ||
		!bytes.Contains(nginxBody, []byte("Strict-Transport-Security")) ||
		!bytes.Contains(nginxBody, []byte("proxy_set_header X-Forwarded-For $remote_addr;")) ||
		bytes.Contains(nginxBody, []byte("$proxy_add_x_forwarded_for")) {
		t.Fatalf("unexpected bridge deploy nginx example:\n%s", string(nginxBody))
	}
	if err := runBridgeServiceDeployPack([]string{
		"--out-dir", filepath.Join(dir, "bridge-deploy-redirect"),
		"--config-sha256", serviceConfigHash,
		"--access-code-sha256", codeHashOut.SHA256,
		"--redirect",
	}); err == nil || !strings.Contains(err.Error(), "redirect mode") {
		t.Fatalf("expected redirect deploy pack to fail closed, got %v", err)
	}
	if err := runBridgeServiceDeployPack([]string{
		"--out-dir", filepath.Join(dir, "bridge-deploy-unpinned"),
		"--access-code-sha256", codeHashOut.SHA256,
		"--allow-unpinned-config",
	}); err == nil || !strings.Contains(err.Error(), "allow-unpinned-config") {
		t.Fatalf("expected unpinned deploy pack to fail closed, got %v", err)
	}
	if err := runBridgeServiceDeployPack([]string{
		"--out-dir", filepath.Join(dir, "bridge-deploy-unsafe-unauth"),
		"--config-sha256", serviceConfigHash,
		"--allow-unauthenticated-local",
		"--addr", "0.0.0.0:18980",
	}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected unsafe unauthenticated deploy pack to fail closed, got %v", err)
	}
	if err := runBridgeServiceDeployPack([]string{
		"--out-dir", filepath.Join(dir, "bridge-deploy-query-code-non-loopback"),
		"--config-sha256", serviceConfigHash,
		"--access-code-sha256", codeHashOut.SHA256,
		"--allow-query-access-code",
		"--addr", "0.0.0.0:18980",
	}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected query-code deploy pack on non-loopback to fail closed, got %v", err)
	}
	for _, tc := range []struct {
		name       string
		publicHost string
		want       string
	}{
		{name: "url", publicHost: "https://bridge.example", want: "bare DNS name"},
		{name: "semicolon", publicHost: "bridge.example; root *", want: "unsafe"},
		{name: "newline", publicHost: "bridge.example\nserver_name evil.example", want: "unsafe"},
		{name: "port", publicHost: "bridge.example:443", want: "port"},
		{name: "localhost", publicHost: "localhost", want: "public DNS"},
		{name: "dot-local", publicHost: "bridge.local", want: "public DNS"},
		{name: "dot-internal", publicHost: "bridge.internal", want: "public DNS"},
		{name: "dot-test", publicHost: "bridge.test", want: "public DNS"},
		{name: "dot-example", publicHost: "bridge.example", want: "public DNS"},
		{name: "example-com", publicHost: "example.com", want: "public DNS"},
		{name: "single-label", publicHost: "helper", want: "fully qualified public DNS"},
		{name: "loopback-ip", publicHost: "127.0.0.1", want: "public-routable"},
		{name: "private-ip", publicHost: "10.1.2.3", want: "public-routable"},
		{name: "cgnat-ip", publicHost: "100.64.0.10", want: "public-routable"},
		{name: "link-local-ip", publicHost: "169.254.1.1", want: "public-routable"},
		{name: "ietf-protocol-ip", publicHost: "192.0.0.10", want: "public-routable"},
		{name: "documentation-192-ip", publicHost: "192.0.2.10", want: "public-routable"},
		{name: "documentation-203-ip", publicHost: "203.0.113.10", want: "public-routable"},
		{name: "benchmark-ip", publicHost: "198.19.0.10", want: "public-routable"},
		{name: "multicast-ip", publicHost: "224.0.0.1", want: "public-routable"},
	} {
		err := runBridgeServiceDeployPack([]string{
			"--out-dir", filepath.Join(dir, "bridge-deploy-bad-public-host-"+tc.name),
			"--config-sha256", serviceConfigHash,
			"--access-code-sha256", codeHashOut.SHA256,
			"--public-host", tc.publicHost,
		})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected invalid public-host %q to fail with %q, got %v", tc.publicHost, tc.want, err)
		}
	}
	if err := runBridgeServiceDeployPack([]string{
		"--out-dir", filepath.Join(dir, "bridge-deploy-public-192-0-3"),
		"--config-sha256", serviceConfigHash,
		"--access-code-sha256", codeHashOut.SHA256,
		"--public-host", "192.0.3.10",
	}); err != nil {
		t.Fatalf("expected non-reserved 192.0.3.10 public-host to pass, got %v", err)
	}
	for _, tc := range []struct {
		name string
		addr string
		want string
	}{
		{name: "missing-port", addr: "127.0.0.1", want: "host:port"},
		{name: "bad-port", addr: "127.0.0.1:99999", want: "port"},
		{name: "non-loopback", addr: "0.0.0.0:18980", want: "loopback"},
		{name: "semicolon", addr: "127.0.0.1:18980; root *", want: "unsafe"},
		{name: "newline", addr: "127.0.0.1:18980\nproxy_pass evil", want: "unsafe"},
	} {
		err := runBridgeServiceDeployPack([]string{
			"--out-dir", filepath.Join(dir, "bridge-deploy-bad-addr-"+tc.name),
			"--config-sha256", serviceConfigHash,
			"--access-code-sha256", codeHashOut.SHA256,
			"--addr", tc.addr,
		})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected invalid addr %q to fail with %q, got %v", tc.addr, tc.want, err)
		}
	}
	if err := runBridgeServiceServe([]string{
		"--config", filepath.Join(dir, "missing-bridge-service-config.json"),
		"--config-sha256", strings.Repeat("a", 64),
		"--access-code-sha256", codeHashOut.SHA256,
		"--allow-query-access-code",
		"--addr", "0.0.0.0:18980",
	}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected query-code bridge service on non-loopback to fail closed, got %v", err)
	}
	if err := runBridgeServiceDeployPack([]string{
		"--out-dir", filepath.Join(dir, "bridge-deploy-bad-config-hash"),
		"--config-sha256", "short",
		"--access-code-sha256", codeHashOut.SHA256,
	}); err == nil || !strings.Contains(err.Error(), "bridge service config sha256") {
		t.Fatalf("expected invalid config hash to fail closed, got %v", err)
	}
	if err := runBridgeServiceDeployPack([]string{
		"--out-dir", filepath.Join(dir, "bridge-deploy-bad-code-hash"),
		"--config-sha256", serviceConfigHash,
		"--access-code-sha256", strings.Repeat("z", 64),
	}); err == nil || !strings.Contains(err.Error(), "bridge service access code sha256") {
		t.Fatalf("expected invalid access-code hash to fail closed, got %v", err)
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
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--trust-store", trustStore, "--helper-registry", helperRegistry, "--allow-unsigned-helper-registry", "--allow-local-access-paths", "--require-helper-registry"}); err != nil {
		t.Fatalf("bridge-policy unsigned diagnostic with trust store: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", signedBridge, "--trust-store", trustStore, "--signed-helper-registry", signedRegistry, "--allow-local-access-paths", "--require-helper-registry"}); err != nil {
		t.Fatalf("bridge-policy signed helper registry with trust store: %v", err)
	}
	if err := runCheck([]string{"--pack", signedPack, "--trust-store", trustStore, "--timeout-sec", "2"}); err != nil {
		t.Fatalf("check with trust store: %v", err)
	}
	for name, err := range map[string]error{
		"verify":        runVerify([]string{"--pack", signedPack, "--trust-store", trustStore, "--public-key-file", publicKey}),
		"check":         runCheck([]string{"--pack", signedPack, "--trust-store", trustStore, "--public-key-file", publicKey, "--timeout-sec", "2"}),
		"bridge-verify": runBridgeVerify([]string{"--invite", signedBridge, "--trust-store", trustStore, "--public-key-file", publicKey}),
		"bridge-policy": runBridgePolicy([]string{"--invite", signedBridge, "--trust-store", trustStore, "--public-key-file", publicKey, "--signed-helper-registry", signedRegistry}),
		"bridge-service-config": runBridgeServiceConfig([]string{
			"--invite", signedBridge,
			"--trust-store", trustStore,
			"--public-key-file", publicKey,
			"--signed-helper-registry", signedRegistry,
			"--out", filepath.Join(dir, "bridge-service-config-dual-key.json"),
		}),
		"bridge-registry-verify": runBridgeRegistryVerify([]string{"--signed-registry", signedRegistry, "--trust-store", trustStore, "--public-key-file", publicKey}),
	} {
		if err == nil || !strings.Contains(err.Error(), "accepts only one of --trust-store or --public-key-file") {
			t.Fatalf("%s should reject dual key sources, got %v", name, err)
		}
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
	if err := runBridgePolicy([]string{"--invite", importedBridge, "--trust-store", importedStore, "--helper-registry", importedRegistry, "--allow-unsigned-helper-registry", "--allow-local-access-paths"}); err != nil {
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

func TestVerifyOptionalSHA256(t *testing.T) {
	body := []byte(`{"status":"pass"}`)
	sum := sha256.Sum256(body)
	if err := verifyOptionalSHA256("test body", body, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("expected matching sha256: %v", err)
	}
	if err := verifyOptionalSHA256("test body", body, ""); err != nil {
		t.Fatalf("expected empty sha256 to skip: %v", err)
	}
	if err := verifyOptionalSHA256("test body", body, strings.Repeat("0", 64)); err == nil {
		t.Fatal("expected sha256 mismatch")
	}
	if err := verifyOptionalSHA256("test body", body, "not-hex"); err == nil {
		t.Fatal("expected invalid sha256 error")
	}
}

func TestBridgeServiceCommandsRequireAccessCodeByDefault(t *testing.T) {
	if err := runBridgeServiceDeployPack([]string{"--out-dir", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "--access-code-sha256") {
		t.Fatalf("expected deploy pack access-code requirement, got %v", err)
	}
	if err := runBridgeServiceDeployPack([]string{"--out-dir", t.TempDir(), "--access-code-sha256", strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "--config-sha256") {
		t.Fatalf("expected deploy pack config hash requirement, got %v", err)
	}
	if err := runBridgeServiceServe([]string{"--config", "missing.json"}); err == nil || !strings.Contains(err.Error(), "--access-code-sha256") {
		t.Fatalf("expected serve access-code requirement, got %v", err)
	}
	if err := runBridgeServiceServe([]string{"--config", "missing.json", "--access-code-sha256", strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "--config-sha256") {
		t.Fatalf("expected serve config hash requirement, got %v", err)
	}
	if err := runBridgeServiceServe([]string{"--config", "missing.json", "--allow-unauthenticated-local", "--addr", "0.0.0.0:18980"}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected unauthenticated serve to require loopback, got %v", err)
	}
	if err := runBridgeServiceServe([]string{"--config", "missing.json", "--access-code-sha256", strings.Repeat("0", 64), "--allow-unpinned-local", "--addr", "0.0.0.0:18980"}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected unpinned serve to require loopback, got %v", err)
	}
	if err := runBridgeServiceServe([]string{"--config", "missing.json", "--config-sha256", strings.Repeat("0", 64), "--access-code-sha256", strings.Repeat("0", 64), "--addr", "0.0.0.0:18980", "--rps", "0"}); err == nil || !strings.Contains(err.Error(), "--rps") {
		t.Fatalf("expected public serve with disabled rps to fail closed, got %v", err)
	}
	if err := runBridgeServiceServe([]string{"--config", "missing.json", "--config-sha256", strings.Repeat("0", 64), "--access-code-sha256", strings.Repeat("0", 64), "--addr", "0.0.0.0:18980", "--max-sources", "0"}); err == nil || !strings.Contains(err.Error(), "--max-sources") {
		t.Fatalf("expected public serve with disabled source cap to fail closed, got %v", err)
	}
}

func TestBridgeServiceCodeGenerationAndWeakCodePolicy(t *testing.T) {
	dir := t.TempDir()
	codeFile := filepath.Join(dir, "bridge-code.txt")
	hashFile := filepath.Join(dir, "bridge-code-hash.json")
	if err := runBridgeServiceCodeGenerate([]string{"--code-out", codeFile, "--hash-out", hashFile}); err != nil {
		t.Fatalf("bridge-service-code-generate: %v", err)
	}
	codeBody, err := os.ReadFile(codeFile)
	if err != nil {
		t.Fatalf("read generated bridge code: %v", err)
	}
	code := strings.TrimSpace(string(codeBody))
	if len(code) < minBridgeAccessCodeLength || strings.ContainsAny(code, " \t\r\n") {
		t.Fatalf("generated weak bridge code %q", code)
	}
	hashBody, err := os.ReadFile(hashFile)
	if err != nil {
		t.Fatalf("read generated bridge hash: %v", err)
	}
	var out struct {
		Status string `json:"status"`
		SHA256 string `json:"sha256"`
		Length int    `json:"length"`
		Code   string `json:"code,omitempty"`
	}
	if err := json.Unmarshal(hashBody, &out); err != nil {
		t.Fatalf("unmarshal generated bridge hash: %v", err)
	}
	if out.Status != "ok" || out.SHA256 == "" || out.Length != len(code) || out.Code != "" {
		t.Fatalf("unexpected generated hash output: %+v", out)
	}
	if err := runBridgeServiceCodeHash([]string{"--code", "ticket-123"}); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("expected weak bridge code rejection, got %v", err)
	}
	if err := runBridgeServiceCodeHash([]string{"--code", "ticket-123", "--allow-weak-code"}); err != nil {
		t.Fatalf("expected weak diagnostic code override: %v", err)
	}
	if err := runBridgeServiceCodeHash([]string{"--code", strings.Repeat("a", minBridgeAccessCodeLength) + " " + strings.Repeat("b", minBridgeAccessCodeLength)}); err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("expected whitespace bridge code rejection, got %v", err)
	}
	samePath := filepath.Join(dir, "same-output.json")
	if err := runBridgeServiceCodeGenerate([]string{"--code-out", samePath, "--hash-out", samePath}); err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("expected bridge code generator to reject colliding output paths, got %v", err)
	}
}

func TestGPMRecoverProvenanceSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "recovery.key")
	publicKey := filepath.Join(dir, "recovery.pub")
	trustStore := filepath.Join(dir, "recovery-trust.json")
	summaryJSON := filepath.Join(dir, "access_bridge_pilot_evidence_bundle_summary.json")
	bundleTar := filepath.Join(dir, "access_bridge_pilot_evidence_bundle.tar.gz")
	sidecar := bundleTar + ".sha256"
	provenanceJSON := filepath.Join(dir, "access_bridge_pilot_evidence_bundle.tar.gz.provenance.json")

	if err := runGen([]string{"--private-key-out", privateKey, "--public-key-out", publicKey}); err != nil {
		t.Fatalf("gen: %v", err)
	}
	if err := runTrustAdd([]string{"--trust-store", trustStore, "--org-id", "pilot-org", "--org-name", "Pilot Org", "--public-key-file", publicKey}); err != nil {
		t.Fatalf("trust-add: %v", err)
	}
	if err := os.WriteFile(summaryJSON, []byte(`{"schema":{"id":"access_bridge_pilot_evidence_bundle_summary"},"status":"pass","evidence_scope":"real_helper_https"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	tarBody := []byte("fake tar bytes for provenance cli test")
	if err := os.WriteFile(bundleTar, tarBody, 0o644); err != nil {
		t.Fatalf("write tar: %v", err)
	}
	tarSum := sha256.Sum256(tarBody)
	if err := os.WriteFile(sidecar, []byte(hex.EncodeToString(tarSum[:])+"  "+filepath.Base(bundleTar)+"\n"), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	if err := runProvenanceSign([]string{
		"--summary-json", summaryJSON,
		"--bundle-tar", bundleTar,
		"--bundle-tar-sha256-file", sidecar,
		"--private-key-file", privateKey,
		"--org-id", "pilot-org",
		"--org-name", "Pilot Org",
		"--out", provenanceJSON,
		"--lifetime-hours", "24",
	}); err != nil {
		t.Fatalf("provenance-sign: %v", err)
	}
	if err := runProvenanceVerify([]string{
		"--provenance", provenanceJSON,
		"--summary-json", summaryJSON,
		"--bundle-tar", bundleTar,
		"--bundle-tar-sha256-file", sidecar,
		"--trust-store", trustStore,
	}); err != nil {
		t.Fatalf("provenance-verify trust store: %v", err)
	}
	if err := runProvenanceVerify([]string{
		"--provenance", provenanceJSON,
		"--summary-json", summaryJSON,
		"--bundle-tar", bundleTar,
		"--bundle-tar-sha256-file", sidecar,
		"--public-key-file", publicKey,
	}); err != nil {
		t.Fatalf("provenance-verify public key: %v", err)
	}
	if err := runProvenanceVerify([]string{
		"--provenance", provenanceJSON,
		"--summary-json", summaryJSON,
		"--bundle-tar", bundleTar,
		"--bundle-tar-sha256-file", sidecar,
		"--trust-store", trustStore,
		"--public-key-file", publicKey,
	}); err == nil || !strings.Contains(err.Error(), "accepts only one of --trust-store or --public-key-file") {
		t.Fatalf("provenance-verify should reject dual key sources, got %v", err)
	}

	tamperedSummary := filepath.Join(dir, "tampered-summary.json")
	if err := os.WriteFile(tamperedSummary, []byte(`{"status":"pass","evidence_scope":"diagnostic"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write tampered summary: %v", err)
	}
	if err := runProvenanceVerify([]string{
		"--provenance", provenanceJSON,
		"--summary-json", tamperedSummary,
		"--bundle-tar", bundleTar,
		"--bundle-tar-sha256-file", sidecar,
		"--trust-store", trustStore,
	}); err == nil {
		t.Fatal("expected provenance verify to reject tampered summary")
	}

	wrongTrustStore := filepath.Join(dir, "wrong-trust.json")
	if err := runTrustAdd([]string{"--trust-store", wrongTrustStore, "--org-id", "other-org", "--org-name", "Other Org", "--public-key-file", publicKey}); err != nil {
		t.Fatalf("wrong trust-add: %v", err)
	}
	if err := runProvenanceVerify([]string{
		"--provenance", provenanceJSON,
		"--summary-json", summaryJSON,
		"--bundle-tar", bundleTar,
		"--bundle-tar-sha256-file", sidecar,
		"--trust-store", wrongTrustStore,
	}); err == nil {
		t.Fatal("expected provenance verify to reject wrong trust-store org pin")
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
	if err := runBridgePolicy([]string{"--invite", manifest.Files["bridge_invite_signed"], "--trust-store", manifest.Files["trust_store"], "--helper-registry", manifest.Files["bridge_helper_registry"], "--allow-unsigned-helper-registry", "--allow-local-access-paths"}); err != nil {
		t.Fatalf("policy generated bridge invite with unsigned diagnostic registry: %v", err)
	}
	if err := runBridgePolicy([]string{"--invite", manifest.Files["bridge_invite_signed"], "--trust-store", manifest.Files["trust_store"], "--signed-helper-registry", manifest.Files["bridge_helper_registry_signed"], "--allow-local-access-paths"}); err != nil {
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
		"/.well-known/gpm/access-pack.json":                     `{"kind":"pack"}`,
		"/.well-known/gpm/bridge-invite.json":                   `{"kind":"bridge"}`,
		"/.well-known/gpm/bridge-helper-registry.signed.json":   `{"kind":"registry"}`,
		"/.well-known/gpm/redirected/recovery-trusted-key.json": `{"kind":"key"}`,
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
		if r.URL.Path == "/.well-known/gpm/recovery-trusted-key.json" {
			http.Redirect(w, r, "/.well-known/gpm/redirected/recovery-trusted-key.json", http.StatusFound)
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

func TestGPMRecoverFetchPublicationRejectsRemoteHTTPIndex(t *testing.T) {
	if _, err := parsePublicationIndexURL("http://example.com/.well-known/gpm/recovery-index.json"); err == nil {
		t.Fatal("expected remote http publication index to be rejected")
	}
	if _, err := parsePublicationIndexURL("http://127.0.0.1:18980/.well-known/gpm/recovery-index.json"); err != nil {
		t.Fatalf("expected loopback http publication index to remain available: %v", err)
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

func TestGPMRecoverFetchPublicationRejectsCrossOriginRedirect(t *testing.T) {
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"kind":"key"}`))
	}))
	t.Cleanup(attacker.Close)

	files := map[string]string{
		"/.well-known/gpm/access-pack.json":                   `{"kind":"pack"}`,
		"/.well-known/gpm/bridge-invite.json":                 `{"kind":"bridge"}`,
		"/.well-known/gpm/bridge-helper-registry.signed.json": `{"kind":"registry"}`,
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
		if r.URL.Path == "/.well-known/gpm/recovery-trusted-key.json" {
			http.Redirect(w, r, attacker.URL+"/recovery-trusted-key.json", http.StatusFound)
			return
		}
		if body, ok := files[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	err := runFetchPublication([]string{
		"--index-url", server.URL + "/.well-known/gpm/recovery-index.json",
		"--out-dir", filepath.Join(t.TempDir(), "fetched"),
	})
	if err == nil {
		t.Fatal("expected cross-origin redirect to be rejected")
	}
	if !strings.Contains(err.Error(), "redirects must stay") {
		t.Fatalf("expected redirect policy error, got %v", err)
	}
}

func TestGPMRecoverFetchPublicationRejectsSchemeDowngradeRedirect(t *testing.T) {
	indexURL, err := url.Parse("https://example.com/.well-known/gpm/recovery-index.json")
	if err != nil {
		t.Fatalf("parse index URL: %v", err)
	}
	downgradedURL, err := url.Parse("http://example.com/.well-known/gpm/recovery-trusted-key.json")
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}

	client := newPublicationHTTPClient(indexURL, time.Second)
	err = client.CheckRedirect(&http.Request{URL: downgradedURL}, []*http.Request{{URL: indexURL}})
	if err == nil {
		t.Fatal("expected scheme downgrade redirect to be rejected")
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
