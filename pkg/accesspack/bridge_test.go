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
		ExpiresAtUTC:     "2099-01-01T00:00:00Z",
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
		},
		SafetyNotes: []string{"Use only while this invite is unexpired."},
	}
}
