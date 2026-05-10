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
			ContactURL:  "https://helper.example/contact",
			Description: "Temporary assisted bootstrap helper",
		},
		AccessPaths: []AccessPath{
			{PathID: "backup-helper", Kind: "bridge", URL: "https://backup-helper.example/connect", Priority: 20},
			{PathID: "helper-site", Kind: "bridge", URL: "https://helper.example/connect", Priority: 10},
			{PathID: "manual-helper", Kind: "instructions", URL: "mailto:bridge@helpermail.example", Priority: 30, RequiresExternalApp: true},
		},
		SafetyNotes: []string{"Use only while this invite is unexpired."},
	}
}
