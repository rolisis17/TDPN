package accesspack

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/adminauth"
)

func TestTrustStoreResolveTrustedPublicKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pack := testPack()
	signed, err := Sign(pack, priv, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	store, entry, err := AddTrustedKey(EmptyTrustStore(), TrustedKey{
		OrgID:     signed.Organization.OrgID,
		OrgName:   signed.Organization.Name,
		PublicKey: adminauth.EncodePublicKey(pub),
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("add trusted key: %v", err)
	}
	if entry.KeyID == "" {
		t.Fatal("expected derived key id")
	}
	resolvedPub, resolvedEntry, err := ResolveTrustedPublicKey(store, signed, time.Now().UTC())
	if err != nil {
		t.Fatalf("resolve trusted key: %v", err)
	}
	if string(resolvedPub) != string(pub) {
		t.Fatal("resolved public key mismatch")
	}
	if resolvedEntry.OrgID != signed.Organization.OrgID {
		t.Fatalf("resolved org mismatch: %q", resolvedEntry.OrgID)
	}
}

func TestTrustStoreRejectsWrongOrganizationForTrustedKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pack := testPack()
	signed, err := Sign(pack, priv, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	store, _, err := AddTrustedKey(EmptyTrustStore(), TrustedKey{
		OrgID:     "different-org",
		OrgName:   "Different Org",
		PublicKey: adminauth.EncodePublicKey(pub),
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("add trusted key: %v", err)
	}
	_, _, err = ResolveTrustedPublicKey(store, signed, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "different organization") {
		t.Fatalf("expected organization mismatch, got %v", err)
	}
}

func TestTrustStoreRemoveTrustedKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	store, entry, err := AddTrustedKey(EmptyTrustStore(), TrustedKey{
		OrgID:     "remove-org",
		OrgName:   "Remove Org",
		PublicKey: adminauth.EncodePublicKey(pub),
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("add trusted key: %v", err)
	}
	store, removed := RemoveTrustedKey(store, "remove-org", entry.KeyID)
	if !removed {
		t.Fatal("expected trusted key removal")
	}
	if len(store.TrustedKeys) != 0 {
		t.Fatalf("expected empty trust store, got %d keys", len(store.TrustedKeys))
	}
}

func TestTrustStoreExpiredUnrelatedKeyDoesNotBlockResolution(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	pack := testPack()
	signed, err := Sign(pack, priv, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	store := TrustStore{
		Version: TrustStoreVersion,
		TrustedKeys: []TrustedKey{
			{
				OrgID:        "old-org",
				OrgName:      "Old Org",
				KeyID:        adminauth.KeyIDFromPublicKey(otherPub),
				PublicKey:    adminauth.EncodePublicKey(otherPub),
				AddedAtUTC:   "2026-01-01T00:00:00Z",
				ExpiresAtUTC: "2026-01-02T00:00:00Z",
			},
			{
				OrgID:      signed.Organization.OrgID,
				OrgName:    signed.Organization.Name,
				KeyID:      adminauth.KeyIDFromPublicKey(pub),
				PublicKey:  adminauth.EncodePublicKey(pub),
				AddedAtUTC: "2026-01-01T00:00:00Z",
			},
		},
	}
	if _, _, err := ResolveTrustedPublicKey(store, signed, now); err != nil {
		t.Fatalf("resolve should ignore unrelated expired key: %v", err)
	}
}
