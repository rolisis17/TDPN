package accesspack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/adminauth"
)

func TestSignVerifyBridgeInvite(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed, err := SignBridgeInvite(testBridgeInvite(), priv, "")
	if err != nil {
		t.Fatalf("sign bridge invite: %v", err)
	}
	verified, err := VerifyBridgeInvite(signed, pub, time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("verify bridge invite: %v", err)
	}
	if verified.Invite.Signature == nil {
		t.Fatalf("signature missing after verify")
	}
	if verified.Invite.AccessPaths[0].PathID != "helper-site" {
		t.Fatalf("access paths not normalized by priority: %+v", verified.Invite.AccessPaths)
	}
}

func TestVerifyBridgeInviteRejectsTampering(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed, err := SignBridgeInvite(testBridgeInvite(), priv, "")
	if err != nil {
		t.Fatalf("sign bridge invite: %v", err)
	}
	signed.Helper.DisplayName = "Mallory"
	_, err = VerifyBridgeInvite(signed, pub, time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatalf("expected tampered bridge invite to fail verification")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected signature verification error, got %v", err)
	}
}

func TestBridgeInviteTrustStoreResolution(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed, err := SignBridgeInvite(testBridgeInvite(), priv, "")
	if err != nil {
		t.Fatalf("sign bridge invite: %v", err)
	}
	store, _, err := AddTrustedKey(EmptyTrustStore(), TrustedKey{
		OrgID:     "demo-org",
		OrgName:   "Demo Org",
		PublicKey: adminauth.EncodePublicKey(pub),
	}, time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("add trusted key: %v", err)
	}
	resolved, _, err := ResolveTrustedBridgeInvitePublicKey(store, signed, time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("resolve bridge invite key: %v", err)
	}
	if !bytes.Equal(resolved, pub) {
		t.Fatalf("resolved wrong public key")
	}
}

func TestSignVerifyBridgeHelperRegistryArtifact(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	artifact := testBridgeHelperRegistryArtifact(now)
	signed, err := SignBridgeHelperRegistryArtifact(artifact, priv, "")
	if err != nil {
		t.Fatalf("sign helper registry: %v", err)
	}
	verified, err := VerifyBridgeHelperRegistryArtifact(signed, pub, now)
	if err != nil {
		t.Fatalf("verify helper registry: %v", err)
	}
	if verified.Artifact.Signature == nil {
		t.Fatalf("signature missing after verify")
	}
	if verified.Artifact.Registry.Helpers[0].HelperID != "helper-1" {
		t.Fatalf("registry not normalized: %+v", verified.Artifact.Registry.Helpers)
	}
}

func TestBridgeArtifactsRejectUnsupportedURLSchemes(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	for name, run := range map[string]func() error{
		"bridge invite access path ftp": func() error {
			invite := testBridgeInvite()
			invite.AccessPaths[0].URL = "ftp://helper.gpm-pilot.net/connect"
			_, err := SignBridgeInvite(invite, priv, "")
			return err
		},
		"bridge invite contact ssh": func() error {
			invite := testBridgeInvite()
			invite.Helper.ContactURL = "ssh://helper.gpm-pilot.net/contact"
			_, err := SignBridgeInvite(invite, priv, "")
			return err
		},
		"helper registry abuse javascript": func() error {
			artifact := testBridgeHelperRegistryArtifact(now)
			artifact.Registry.Helpers[0].AbuseReportURL = "javascript://helper.gpm-pilot.net/report"
			_, err := SignBridgeHelperRegistryArtifact(artifact, priv, "")
			return err
		},
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "scheme must be http, https, or mailto") {
			t.Fatalf("%s should reject unsupported URL scheme, got %v", name, err)
		}
	}
}

func TestBridgeHelperRegistryArtifactRejectsTampering(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	signed, err := SignBridgeHelperRegistryArtifact(testBridgeHelperRegistryArtifact(now), priv, "")
	if err != nil {
		t.Fatalf("sign helper registry: %v", err)
	}
	signed.Registry.Helpers[0].ContactURL = "https://evil.example/contact"
	_, err = VerifyBridgeHelperRegistryArtifact(signed, pub, now)
	if err == nil {
		t.Fatalf("expected tampered helper registry to fail verification")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected signature verification error, got %v", err)
	}
}

func TestBridgeHelperRegistryArtifactTrustStoreResolution(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	signed, err := SignBridgeHelperRegistryArtifact(testBridgeHelperRegistryArtifact(now), priv, "")
	if err != nil {
		t.Fatalf("sign helper registry: %v", err)
	}
	store, _, err := AddTrustedKey(EmptyTrustStore(), TrustedKey{
		OrgID:     "demo-org",
		OrgName:   "Demo Org",
		PublicKey: adminauth.EncodePublicKey(pub),
	}, now)
	if err != nil {
		t.Fatalf("add trusted key: %v", err)
	}
	resolved, _, err := ResolveTrustedBridgeHelperRegistryPublicKey(store, signed, now)
	if err != nil {
		t.Fatalf("resolve helper registry key: %v", err)
	}
	if !bytes.Equal(resolved, pub) {
		t.Fatalf("resolved wrong public key")
	}
}

func TestBridgeInvitePolicyPassesDefault(t *testing.T) {
	report := CheckBridgeInvitePolicy(testBridgeInvite(), DefaultBridgeInvitePolicyOptions(), time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC))
	if report.Status != "pass" {
		t.Fatalf("expected policy pass, got %+v", report)
	}
	if report.DistinctHostsCount != 3 {
		t.Fatalf("expected 3 distinct hosts, got %+v", report.DistinctHosts)
	}
}

func TestBridgeInvitePolicyRejectsWeakDiversity(t *testing.T) {
	invite := testBridgeInvite()
	invite.Helper.ContactURL = ""
	invite.AccessPaths = invite.AccessPaths[:1]
	report := CheckBridgeInvitePolicy(invite, DefaultBridgeInvitePolicyOptions(), time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC))
	if report.Status != "fail" {
		t.Fatalf("expected policy fail, got %+v", report)
	}
	var sawPaths bool
	var sawContact bool
	for _, finding := range report.Findings {
		if finding.Code == "bridge_invite_too_few_paths" {
			sawPaths = true
		}
		if finding.Code == "bridge_invite_missing_helper_contact" {
			sawContact = true
		}
	}
	if !sawPaths || !sawContact {
		t.Fatalf("expected path/contact findings, got %+v", report.Findings)
	}
}

func TestBridgeInvitePolicyUsesHelperRegistry(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	registry := testBridgeHelperRegistry()
	options := DefaultBridgeInvitePolicyOptions()
	options.HelperRegistry = &registry
	report := CheckBridgeInvitePolicy(testBridgeInvite(), options, now)
	if report.Status != "pass" {
		t.Fatalf("expected policy pass, got %+v", report)
	}
	if !report.HelperRegistryChecked || !report.HelperRegistered || !report.HelperAllowedOrg || !report.HelperRegistryContactOK {
		t.Fatalf("expected helper registry pass fields, got %+v", report)
	}
	if !report.HelperAbuseReportOK || !report.HelperRateLimitPolicyOK {
		t.Fatalf("expected helper abuse/rate fields, got %+v", report)
	}
	if report.Policy.RequireRegisteredHelper != true {
		t.Fatalf("expected registered-helper policy to be visible, got %+v", report.Policy)
	}
}

func TestBuildBridgeServiceConfigIncludesSignedHelperControls(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	registry := testBridgeHelperRegistry()
	config := BuildBridgeServiceConfig(testBridgeInvite(), registry, BridgeServiceConfigOptions{
		RegistryID:           "registry-demo",
		RegistryExpiresAtUTC: "2026-05-17T01:00:00Z",
		InviteKeyID:          "invite-key",
		RegistryKeyID:        "registry-key",
		SignedRegistry:       true,
	}, now)
	if config.Status != "pass" {
		t.Fatalf("expected service config pass, got %+v", config.Policy.Findings)
	}
	if !config.SignedRegistry || config.RegistryID != "registry-demo" || config.RegistryKeyID != "registry-key" {
		t.Fatalf("expected signed registry metadata, got %+v", config)
	}
	if config.HelperAbuseReportURL != "https://helper.gpm-pilot.net/abuse" {
		t.Fatalf("unexpected abuse report url: %+v", config)
	}
	if config.HelperRateLimitPolicy == "" {
		t.Fatalf("expected rate limit policy: %+v", config)
	}
	if config.InviteIssuedAtUTC == "" || config.InviteExpiresAtUTC == "" {
		t.Fatalf("expected invite validity window: %+v", config)
	}
	if config.InviteSHA256 == "" || config.RegistrySHA256 == "" || config.AccessPathsSHA256 == "" {
		t.Fatalf("expected source/config hashes: %+v", config)
	}
	if len(config.AccessPaths) != 3 {
		t.Fatalf("expected access paths, got %+v", config.AccessPaths)
	}
}

func TestEvaluateBridgeServiceRequestAllowsSignedBridgePath(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := BuildBridgeServiceConfig(testBridgeInvite(), testBridgeHelperRegistry(), BridgeServiceConfigOptions{
		RegistryID:           "registry-demo",
		RegistryExpiresAtUTC: now.Add(24 * time.Hour).Format(time.RFC3339),
		SignedRegistry:       true,
	}, now)
	decision := EvaluateBridgeServiceRequest(config, BridgeServiceRequest{PathID: "helper-site"}, now)
	if !decision.Allowed || decision.Status != "pass" {
		t.Fatalf("expected bridge service request to pass: %+v", decision)
	}
	if decision.MatchedAccessPath == nil || decision.MatchedAccessPath.PathID != "helper-site" {
		t.Fatalf("expected matched helper-site path: %+v", decision.MatchedAccessPath)
	}
	if decision.HelperAbuseReportURL == "" || decision.HelperRateLimitPolicy == "" {
		t.Fatalf("expected enforcement metadata: %+v", decision)
	}
}

func TestEvaluateBridgeServiceRequestRejectsManualPath(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := BuildBridgeServiceConfig(testBridgeInvite(), testBridgeHelperRegistry(), BridgeServiceConfigOptions{
		RegistryID:           "registry-demo",
		RegistryExpiresAtUTC: now.Add(24 * time.Hour).Format(time.RFC3339),
		SignedRegistry:       true,
	}, now)
	decision := EvaluateBridgeServiceRequest(config, BridgeServiceRequest{PathID: "manual-helper"}, now)
	if decision.Allowed || decision.Status != "fail" {
		t.Fatalf("expected manual path to fail closed: %+v", decision)
	}
	if len(decision.Findings) == 0 || decision.Findings[0].Code != "bridge_service_access_path_external_app" {
		t.Fatalf("expected external-app finding: %+v", decision.Findings)
	}
}

func TestEvaluateBridgeServiceRequestRejectsExpiredRegistry(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := BuildBridgeServiceConfig(testBridgeInvite(), testBridgeHelperRegistry(), BridgeServiceConfigOptions{
		RegistryID:           "registry-demo",
		RegistryExpiresAtUTC: now.Add(-1 * time.Minute).Format(time.RFC3339),
		SignedRegistry:       true,
	}, now)
	decision := EvaluateBridgeServiceRequest(config, BridgeServiceRequest{PathID: "helper-site"}, now)
	if decision.Allowed || decision.Status != "fail" {
		t.Fatalf("expected expired registry to fail closed: %+v", decision)
	}
	if len(decision.Findings) == 0 || decision.Findings[0].Code != "bridge_service_registry_expired" {
		t.Fatalf("expected registry expiry finding: %+v", decision.Findings)
	}
}

func TestEvaluateBridgeServiceRequestRejectsExpiredInviteWindow(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := BuildBridgeServiceConfig(testBridgeInvite(), testBridgeHelperRegistry(), BridgeServiceConfigOptions{
		RegistryID:           "registry-demo",
		RegistryExpiresAtUTC: now.Add(24 * time.Hour).Format(time.RFC3339),
		SignedRegistry:       true,
	}, now)
	decision := EvaluateBridgeServiceRequest(config, BridgeServiceRequest{PathID: "helper-site"}, now.Add(15*24*time.Hour))
	if decision.Allowed || decision.Status != "fail" {
		t.Fatalf("expected expired invite window to fail closed: %+v", decision)
	}
	if !sawBridgeServiceFinding(decision, "bridge_service_invite_expired") {
		t.Fatalf("expected invite expiry finding, got %+v", decision.Findings)
	}
}

func TestEvaluateBridgeServiceRequestRejectsAccessPathTamper(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := BuildBridgeServiceConfig(testBridgeInvite(), testBridgeHelperRegistry(), BridgeServiceConfigOptions{
		RegistryID:           "registry-demo",
		RegistryExpiresAtUTC: now.Add(24 * time.Hour).Format(time.RFC3339),
		SignedRegistry:       true,
	}, now)
	config.AccessPaths[0].URL = "https://evil.example/bridge"
	decision := EvaluateBridgeServiceRequest(config, BridgeServiceRequest{PathID: config.AccessPaths[0].PathID}, now)
	if decision.Allowed || decision.Status != "fail" {
		t.Fatalf("expected tampered access path to fail closed: %+v", decision)
	}
	if !sawBridgeServiceFinding(decision, "bridge_service_access_paths_hash_mismatch") {
		t.Fatalf("expected access path hash mismatch, got %+v", decision.Findings)
	}
}

func TestEvaluateBridgeServiceRequestRejectsUnsafeHelperURLs(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		url  string
		code string
	}{
		{name: "plain-http", url: "http://helper.gpm-pilot.net/connect", code: "bridge_service_access_path_plain_http"},
		{name: "private-ip", url: "https://10.0.0.5/connect", code: "bridge_service_access_path_private_host"},
		{name: "reserved-domain", url: "https://reserved-helper.example/connect", code: "bridge_service_access_path_private_host"},
		{name: "single-label", url: "https://helper/connect", code: "bridge_service_access_path_private_host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := BuildBridgeServiceConfig(testBridgeInvite(), testBridgeHelperRegistry(), BridgeServiceConfigOptions{
				RegistryID:           "registry-demo",
				RegistryExpiresAtUTC: now.Add(24 * time.Hour).Format(time.RFC3339),
				SignedRegistry:       true,
			}, now)
			for i := range config.AccessPaths {
				if config.AccessPaths[i].PathID == "helper-site" {
					config.AccessPaths[i].URL = tc.url
				}
			}
			config.AccessPathsSHA256 = bridgeServiceAccessPathsSHA256(config.AccessPaths)
			decision := EvaluateBridgeServiceRequest(config, BridgeServiceRequest{PathID: "helper-site"}, now)
			if decision.Allowed || decision.Status != "fail" {
				t.Fatalf("expected unsafe helper URL to fail closed: %+v", decision)
			}
			if !sawBridgeServiceFinding(decision, tc.code) {
				t.Fatalf("expected %s finding, got %+v", tc.code, decision.Findings)
			}
		})
	}
}

func TestEvaluateBridgeServiceRequestAllowLocalAccessPathsOnlyForLoopback(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	config := BuildBridgeServiceConfig(testBridgeInvite(), testBridgeHelperRegistry(), BridgeServiceConfigOptions{
		RegistryID:            "registry-demo",
		RegistryExpiresAtUTC:  now.Add(24 * time.Hour).Format(time.RFC3339),
		SignedRegistry:        true,
		AllowLocalAccessPaths: true,
	}, now)
	for i := range config.AccessPaths {
		if config.AccessPaths[i].PathID == "helper-site" {
			config.AccessPaths[i].URL = "http://127.0.0.1:18980/connect"
		}
	}
	config.AccessPathsSHA256 = bridgeServiceAccessPathsSHA256(config.AccessPaths)
	decision := EvaluateBridgeServiceRequest(config, BridgeServiceRequest{PathID: "helper-site"}, now)
	if !decision.Allowed || decision.Status != "pass" {
		t.Fatalf("expected loopback diagnostic path to pass, got %+v", decision)
	}

	for i := range config.AccessPaths {
		if config.AccessPaths[i].PathID == "helper-site" {
			config.AccessPaths[i].URL = "http://10.0.0.5/connect"
		}
	}
	config.AccessPathsSHA256 = bridgeServiceAccessPathsSHA256(config.AccessPaths)
	decision = EvaluateBridgeServiceRequest(config, BridgeServiceRequest{PathID: "helper-site"}, now)
	if decision.Allowed || decision.Status != "fail" {
		t.Fatalf("expected private diagnostic path to fail, got %+v", decision)
	}
	if !sawBridgeServiceFinding(decision, "bridge_service_access_path_plain_http") {
		t.Fatalf("expected plain-http finding, got %+v", decision.Findings)
	}
}

func TestBridgeInvitePolicyRejectsUnsafeServiceableHelperURLs(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		url  string
		code string
	}{
		{name: "plain-http", url: "http://helper.gpm-pilot.net/connect", code: "bridge_invite_access_path_plain_http"},
		{name: "private-ip", url: "https://10.0.0.5/connect", code: "bridge_invite_access_path_private_host"},
		{name: "reserved-domain", url: "https://reserved-helper.example/connect", code: "bridge_invite_access_path_private_host"},
		{name: "single-label", url: "https://helper/connect", code: "bridge_invite_access_path_private_host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invite := testBridgeInvite()
			for i := range invite.AccessPaths {
				if invite.AccessPaths[i].PathID == "helper-site" {
					invite.AccessPaths[i].URL = tc.url
				}
			}
			registry := testBridgeHelperRegistry()
			options := DefaultBridgeInvitePolicyOptions()
			options.HelperRegistry = &registry
			report := CheckBridgeInvitePolicy(invite, options, now)
			if report.Status != "fail" {
				t.Fatalf("expected policy fail, got %+v", report)
			}
			if !sawBridgePolicyFinding(report, tc.code) {
				t.Fatalf("expected %s finding, got %+v", tc.code, report.Findings)
			}
		})
	}
}

func TestBridgeInvitePolicyAllowLocalAccessPathsOnlyForLoopback(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	invite := testBridgeInvite()
	for i := range invite.AccessPaths {
		if invite.AccessPaths[i].PathID == "helper-site" {
			invite.AccessPaths[i].URL = "http://localhost:18980/connect"
		}
	}
	options := DefaultBridgeInvitePolicyOptions()
	options.AllowLocalAccessPaths = true
	report := CheckBridgeInvitePolicy(invite, options, now)
	if report.Status != "pass" {
		t.Fatalf("expected loopback diagnostic policy pass, got %+v", report)
	}

	for i := range invite.AccessPaths {
		if invite.AccessPaths[i].PathID == "helper-site" {
			invite.AccessPaths[i].URL = "https://helper.internal/connect"
		}
	}
	report = CheckBridgeInvitePolicy(invite, options, now)
	if report.Status != "fail" {
		t.Fatalf("expected private diagnostic policy fail, got %+v", report)
	}
	if !sawBridgePolicyFinding(report, "bridge_invite_access_path_private_host") {
		t.Fatalf("expected private-host finding, got %+v", report.Findings)
	}
}

func TestBridgeInvitePolicyRequiresServiceableHTTPSPath(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	invite := testBridgeInvite()
	invite.AccessPaths = []AccessPath{
		{PathID: "manual-a", Kind: "instructions", URL: "mailto:a@helpermail.example", Priority: 10, RequiresExternalApp: true},
		{PathID: "manual-b", Kind: "instructions", URL: "mailto:b@helpermail2.example", Priority: 20, RequiresExternalApp: true},
	}
	registry := testBridgeHelperRegistry()
	options := DefaultBridgeInvitePolicyOptions()
	options.HelperRegistry = &registry
	report := CheckBridgeInvitePolicy(invite, options, now)
	if report.Status != "fail" {
		t.Fatalf("expected policy fail, got %+v", report)
	}
	if !sawBridgePolicyFinding(report, "bridge_invite_no_serviceable_https_path") {
		t.Fatalf("expected no serviceable path finding, got %+v", report.Findings)
	}
}

func TestBridgeAccessPathPublicIPv4ReservedRanges(t *testing.T) {
	for _, host := range []string{"192.0.0.10", "192.0.2.10"} {
		if bridgeAccessPathHostLooksPublic(host) {
			t.Fatalf("expected reserved IPv4 host %s to be rejected", host)
		}
	}
	if !bridgeAccessPathHostLooksPublic("192.0.3.10") {
		t.Fatalf("expected non-reserved 192.0.3.10 to remain public-looking")
	}
}

func TestBridgeAccessPathRejectsSingleLabelDNSHost(t *testing.T) {
	for _, host := range []string{"helper", "com"} {
		if bridgeAccessPathHostLooksPublic(host) {
			t.Fatalf("expected single-label DNS host %s to be rejected", host)
		}
	}
	if !bridgeAccessPathHostLooksPublic("helper.gpm-pilot.net") {
		t.Fatalf("expected multi-label public-looking DNS host to pass")
	}
}

func TestBridgeInvitePolicyRejectsHelperMissingAbuseAndRateLimitMetadata(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	registry := testBridgeHelperRegistry()
	registry.Helpers[0].AbuseReportURL = ""
	registry.Helpers[0].RateLimitPolicy = ""
	options := DefaultBridgeInvitePolicyOptions()
	options.HelperRegistry = &registry
	report := CheckBridgeInvitePolicy(testBridgeInvite(), options, now)
	if report.Status != "fail" {
		t.Fatalf("expected policy fail, got %+v", report)
	}
	if !sawBridgePolicyFinding(report, "invalid_bridge_helper_registry") {
		t.Fatalf("expected invalid helper registry finding, got %+v", report.Findings)
	}
}

func sawBridgeServiceFinding(decision BridgeServiceDecision, code string) bool {
	for _, finding := range decision.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func TestBridgeInvitePolicyRejectsQuarantinedHelper(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	registry := testBridgeHelperRegistry()
	registry.Helpers[0].Status = BridgeHelperStatusQuarantined
	registry.Helpers[0].QuarantineReason = "abuse report pending review"
	options := DefaultBridgeInvitePolicyOptions()
	options.HelperRegistry = &registry
	report := CheckBridgeInvitePolicy(testBridgeInvite(), options, now)
	if report.Status != "fail" {
		t.Fatalf("expected policy fail, got %+v", report)
	}
	if !sawBridgePolicyFinding(report, "bridge_helper_not_active") {
		t.Fatalf("expected quarantined helper finding, got %+v", report.Findings)
	}
}

func TestBridgeInvitePolicyRejectsUnregisteredHelper(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	registry := testBridgeHelperRegistry()
	registry.Helpers = nil
	options := DefaultBridgeInvitePolicyOptions()
	options.HelperRegistry = &registry
	report := CheckBridgeInvitePolicy(testBridgeInvite(), options, now)
	if report.Status != "fail" {
		t.Fatalf("expected policy fail, got %+v", report)
	}
	if !sawBridgePolicyFinding(report, "bridge_helper_not_registered") {
		t.Fatalf("expected unregistered helper finding, got %+v", report.Findings)
	}
}

func TestBridgeInvitePolicyRequiresHelperRegistryWhenConfigured(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	options := DefaultBridgeInvitePolicyOptions()
	options.RequireHelperRegistry = true
	report := CheckBridgeInvitePolicy(testBridgeInvite(), options, now)
	if report.Status != "fail" {
		t.Fatalf("expected policy fail, got %+v", report)
	}
	if !report.Policy.RequireRegisteredHelper {
		t.Fatalf("expected registered-helper policy to be required, got %+v", report.Policy)
	}
	if !sawBridgePolicyFinding(report, "bridge_helper_registry_required") {
		t.Fatalf("expected helper registry required finding, got %+v", report.Findings)
	}
}

func TestBridgeHelperRegistryCheckSummarizesAndFilters(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	registry := testBridgeHelperRegistry()
	registry.Helpers = append(registry.Helpers, BridgeHelperRegistration{
		HelperID:         "helper-quarantined",
		DisplayName:      "Quarantined Helper",
		Status:           BridgeHelperStatusQuarantined,
		OrgIDs:           []string{"demo-org"},
		ContactURL:       "https://blocked-helper.gpm-pilot.net/contact",
		QuarantineReason: "operator disabled during review",
		UpdatedAtUTC:     "2026-05-10T00:00:00Z",
	})
	report := CheckBridgeHelperRegistry(registry, BridgeHelperRegistryCheckOptions{
		HelperID:      "helper-1",
		OrgID:         "demo-org",
		RequireActive: true,
	}, now)
	if report.Status != "pass" {
		t.Fatalf("expected registry check pass, got %+v", report)
	}
	if report.HelpersTotal != 2 || report.ActiveCount != 1 || report.QuarantinedCount != 1 || report.MatchedCount != 1 {
		t.Fatalf("unexpected registry counts: %+v", report)
	}
	if report.MatchingHelpers[0].HelperID != "helper-1" {
		t.Fatalf("unexpected helper match: %+v", report.MatchingHelpers)
	}
}

func TestBridgeHelperRegistryCheckRejectsInactiveRequiredHelper(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	registry := testBridgeHelperRegistry()
	registry.Helpers[0].Status = BridgeHelperStatusDisabled
	registry.Helpers[0].QuarantineReason = "operator disabled during review"
	report := CheckBridgeHelperRegistry(registry, BridgeHelperRegistryCheckOptions{
		HelperID:      "helper-1",
		RequireActive: true,
	}, now)
	if report.Status != "fail" {
		t.Fatalf("expected registry check fail, got %+v", report)
	}
	if !sawBridgeRegistryFinding(report, "bridge_helper_not_active") {
		t.Fatalf("expected inactive helper finding, got %+v", report.Findings)
	}
}

func TestBridgeHelperRegistryValidationRequiresInactiveReason(t *testing.T) {
	registry := testBridgeHelperRegistry()
	registry.Helpers[0].Status = BridgeHelperStatusQuarantined
	registry.Helpers[0].QuarantineReason = ""
	if err := ValidateBridgeHelperRegistry(registry, time.Time{}); err == nil {
		t.Fatal("expected missing quarantine reason to fail validation")
	}
	registry = testBridgeHelperRegistry()
	registry.Helpers[0].QuarantineReason = "old incident"
	if err := ValidateBridgeHelperRegistry(registry, time.Time{}); err == nil {
		t.Fatal("expected active helper quarantine reason to fail validation")
	}
}

func TestBridgeHelperRegistryValidationRequiresActiveAbuseAndRateLimitMetadata(t *testing.T) {
	registry := testBridgeHelperRegistry()
	registry.Helpers[0].AbuseReportURL = ""
	if err := ValidateBridgeHelperRegistry(registry, time.Time{}); err == nil {
		t.Fatal("expected active helper missing abuse report url to fail validation")
	}
	registry = testBridgeHelperRegistry()
	registry.Helpers[0].RateLimitPolicy = ""
	if err := ValidateBridgeHelperRegistry(registry, time.Time{}); err == nil {
		t.Fatal("expected active helper missing rate limit policy to fail validation")
	}
}

func TestBridgeHelperRegistryUpsertCreatesHelper(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	updated, report := UpsertBridgeHelperRegistryHelper(EmptyBridgeHelperRegistry(), BridgeHelperRegistryUpsertOptions{
		HelperID:        "helper-new",
		DisplayName:     "New Helper",
		Status:          BridgeHelperStatusActive,
		OrgIDs:          []string{"demo-org"},
		ContactURL:      "https://new-helper.gpm-pilot.net/contact",
		AbuseReportURL:  "https://new-helper.gpm-pilot.net/abuse",
		RateLimitPolicy: "beta cap: per-user and per-source limits enforced",
		ActiveUntilUTC:  "2026-05-20T01:00:00Z",
	}, now)
	if report.Status != "pass" || !report.Created {
		t.Fatalf("expected create pass, got %+v", report)
	}
	if len(updated.Helpers) != 1 {
		t.Fatalf("expected one helper, got %+v", updated.Helpers)
	}
	helper := updated.Helpers[0]
	if helper.HelperID != "helper-new" || helper.Status != BridgeHelperStatusActive || helper.UpdatedAtUTC != now.Format(time.RFC3339) {
		t.Fatalf("unexpected helper: %+v", helper)
	}
}

func TestBridgeHelperRegistryUpsertUpdatesExistingHelper(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	updated, report := UpsertBridgeHelperRegistryHelper(testBridgeHelperRegistry(), BridgeHelperRegistryUpsertOptions{
		HelperID:    "helper-1",
		DisplayName: "Renamed Helper",
		OrgIDs:      []string{"demo-org", "alt-org"},
		ContactURL:  "https://helper.gpm-pilot.net/new-contact",
	}, now)
	if report.Status != "pass" || !report.Updated || report.Created {
		t.Fatalf("expected update pass, got %+v", report)
	}
	helper := updated.Helpers[0]
	if helper.DisplayName != "Renamed Helper" || helper.ContactURL != "https://helper.gpm-pilot.net/new-contact" {
		t.Fatalf("unexpected helper update: %+v", helper)
	}
	if len(helper.OrgIDs) != 2 || helper.OrgIDs[0] != "alt-org" || helper.OrgIDs[1] != "demo-org" {
		t.Fatalf("unexpected org ids: %+v", helper.OrgIDs)
	}
}

func TestBridgeHelperRegistryUpsertRequiresOrgForNewHelper(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	_, report := UpsertBridgeHelperRegistryHelper(EmptyBridgeHelperRegistry(), BridgeHelperRegistryUpsertOptions{
		HelperID: "helper-new",
		Status:   BridgeHelperStatusActive,
	}, now)
	if report.Status != "fail" {
		t.Fatalf("expected upsert fail, got %+v", report)
	}
	if !sawBridgeRegistryUpsertFinding(report, "bridge_helper_org_ids_required") {
		t.Fatalf("expected org ids finding, got %+v", report.Findings)
	}
}

func TestBridgeHelperRegistryStatusUpdateQuarantinesHelper(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	registry := testBridgeHelperRegistry()
	updated, report := SetBridgeHelperRegistryStatus(registry, BridgeHelperRegistryStatusUpdateOptions{
		HelperID: "helper-1",
		Status:   BridgeHelperStatusQuarantined,
		Reason:   "abuse report under review",
	}, now)
	if report.Status != "pass" || !report.Updated {
		t.Fatalf("expected update pass, got %+v", report)
	}
	if report.PreviousStatus != BridgeHelperStatusActive || report.NewStatus != BridgeHelperStatusQuarantined {
		t.Fatalf("unexpected status report: %+v", report)
	}
	helper := updated.Helpers[0]
	if helper.Status != BridgeHelperStatusQuarantined {
		t.Fatalf("expected helper quarantined, got %+v", helper)
	}
	if helper.QuarantineReason != "abuse report under review" {
		t.Fatalf("expected quarantine reason, got %+v", helper)
	}
	if helper.UpdatedAtUTC != now.Format(time.RFC3339) {
		t.Fatalf("expected updated timestamp, got %+v", helper)
	}
}

func TestBridgeHelperRegistryStatusUpdateRequiresReason(t *testing.T) {
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	_, report := SetBridgeHelperRegistryStatus(testBridgeHelperRegistry(), BridgeHelperRegistryStatusUpdateOptions{
		HelperID: "helper-1",
		Status:   BridgeHelperStatusDisabled,
	}, now)
	if report.Status != "fail" {
		t.Fatalf("expected update fail, got %+v", report)
	}
	if !sawBridgeRegistryUpdateFinding(report, "bridge_helper_status_reason_required") {
		t.Fatalf("expected reason-required finding, got %+v", report.Findings)
	}
}

func sawBridgeRegistryFinding(report BridgeHelperRegistryCheckReport, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func sawBridgeRegistryUpdateFinding(report BridgeHelperRegistryStatusUpdateReport, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func sawBridgeRegistryUpsertFinding(report BridgeHelperRegistryUpsertReport, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func sawBridgePolicyFinding(report BridgeInvitePolicyReport, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func testBridgeHelperRegistry() BridgeHelperRegistry {
	return BridgeHelperRegistry{
		Version: BridgeHelperRegistryVersion,
		Helpers: []BridgeHelperRegistration{
			{
				HelperID:        "helper-1",
				DisplayName:     "Demo Helper",
				Status:          BridgeHelperStatusActive,
				OrgIDs:          []string{"demo-org"},
				ContactURL:      "https://helper.gpm-pilot.net/contact",
				AbuseReportURL:  "https://helper.gpm-pilot.net/abuse",
				RateLimitPolicy: "beta cap: per-user and per-source limits enforced",
				ActiveFromUTC:   "2026-05-09T00:00:00Z",
				ActiveUntilUTC:  "2026-05-18T00:00:00Z",
				UpdatedAtUTC:    "2026-05-10T00:00:00Z",
			},
		},
	}
}

func testBridgeHelperRegistryArtifact(now time.Time) BridgeHelperRegistryArtifact {
	return BridgeHelperRegistryArtifact{
		SchemaVersion: BridgeHelperRegistryArtifactSchemaVersion,
		RegistryID:    "registry-demo",
		Organization: Organization{
			OrgID:   "demo-org",
			Name:    "Demo Org",
			HomeURL: "https://demo.example",
		},
		IssuedAtUTC:  now.Format(time.RFC3339),
		ExpiresAtUTC: now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Registry:     testBridgeHelperRegistry(),
	}
}

func testBridgeInvite() BridgeInvite {
	return BridgeInvite{
		SchemaVersion: SchemaVersion,
		InviteID:      "bri-test-demo",
		Organization: Organization{
			OrgID:   "demo-org",
			Name:    "Demo Org",
			HomeURL: "https://demo.example",
		},
		IssuedAtUTC:      "2026-05-10T00:00:00Z",
		ExpiresAtUTC:     "2026-05-17T00:00:00Z",
		IntendedAudience: "Test users blocked from the main site",
		Helper: BridgeHelper{
			HelperID:    "helper-1",
			DisplayName: "Demo Helper",
			ContactURL:  "https://helper.gpm-pilot.net/contact",
			Description: "Temporary assisted bootstrap helper",
		},
		AccessPaths: []AccessPath{
			{PathID: "backup-helper", Kind: "bridge", URL: "https://backup-helper.gpm-pilot.net/connect", Priority: 20},
			{PathID: "helper-site", Kind: "bridge", URL: "https://helper.gpm-pilot.net/connect", Priority: 10},
			{PathID: "manual-helper", Kind: "instructions", URL: "mailto:bridge@helpermail.example", Priority: 30, RequiresExternalApp: true},
		},
		SafetyNotes: []string{"Use only while this invite is unexpired."},
	}
}
