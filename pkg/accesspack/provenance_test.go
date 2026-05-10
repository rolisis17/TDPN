package accesspack

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/adminauth"
)

func TestEvidenceBundleProvenanceRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	prov, err := SignEvidenceBundleProvenance(input, priv)
	if err != nil {
		t.Fatalf("sign provenance: %v", err)
	}
	verified, err := VerifyEvidenceBundleProvenance(prov, input.SummaryBytes, input.BundleTarBytes, input.SidecarBytes, pub, now)
	if err != nil {
		t.Fatalf("verify provenance: %v", err)
	}
	if verified.KeyID != adminauth.KeyIDFromPublicKey(pub) {
		t.Fatalf("verified key id mismatch: %q", verified.KeyID)
	}
	if verified.CanonicalBodySize == 0 {
		t.Fatal("expected canonical body size")
	}
	if verified.Provenance.Signature == nil {
		t.Fatal("expected signature to be preserved")
	}

	store, _, err := AddTrustedKey(EmptyTrustStore(), TrustedKey{
		OrgID:     input.Organization.OrgID,
		OrgName:   input.Organization.Name,
		PublicKey: adminauth.EncodePublicKey(pub),
	}, now)
	if err != nil {
		t.Fatalf("add trusted key: %v", err)
	}
	trusted, entry, err := VerifyEvidenceBundleProvenanceWithTrustStore(store, prov, input.SummaryBytes, input.BundleTarBytes, input.SidecarBytes, now)
	if err != nil {
		t.Fatalf("verify provenance with trust store: %v", err)
	}
	if trusted.KeyID != entry.KeyID {
		t.Fatalf("trusted key id mismatch: verified=%q entry=%q", trusted.KeyID, entry.KeyID)
	}
}

func TestEvidenceBundleProvenanceRejectsSummaryTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	prov, err := SignEvidenceBundleProvenance(input, priv)
	if err != nil {
		t.Fatalf("sign provenance: %v", err)
	}
	_, err = VerifyEvidenceBundleProvenance(prov, append([]byte(nil), []byte(`{"status":"tampered"}`)...), input.BundleTarBytes, input.SidecarBytes, pub, now)
	if err == nil || !strings.Contains(err.Error(), "summary json sha256 mismatch") {
		t.Fatalf("expected summary tamper error, got %v", err)
	}
}

func TestEvidenceBundleProvenanceRejectsTarTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	prov, err := SignEvidenceBundleProvenance(input, priv)
	if err != nil {
		t.Fatalf("sign provenance: %v", err)
	}
	_, err = VerifyEvidenceBundleProvenance(prov, input.SummaryBytes, append([]byte(nil), []byte("tampered tar")...), input.SidecarBytes, pub, now)
	if err == nil || !strings.Contains(err.Error(), "bundle tar sha256 mismatch") {
		t.Fatalf("expected tar tamper error, got %v", err)
	}
}

func TestEvidenceBundleProvenanceRejectsSidecarTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	prov, err := SignEvidenceBundleProvenance(input, priv)
	if err != nil {
		t.Fatalf("sign provenance: %v", err)
	}
	_, err = VerifyEvidenceBundleProvenance(prov, input.SummaryBytes, input.BundleTarBytes, append([]byte(nil), []byte("tampered sidecar")...), pub, now)
	if err == nil || !strings.Contains(err.Error(), "sidecar sha256 mismatch") {
		t.Fatalf("expected sidecar tamper error, got %v", err)
	}
}

func TestEvidenceBundleProvenanceRejectsSidecarDigestMismatch(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	input.SidecarBytes = []byte(strings.Repeat("0", 64) + "  " + input.BundleTarName + "\n")
	_, err = SignEvidenceBundleProvenance(input, priv)
	if err == nil || !strings.Contains(err.Error(), "sidecar digest mismatch") {
		t.Fatalf("expected sidecar digest mismatch, got %v", err)
	}
}

func TestEvidenceBundleProvenanceRejectsSidecarFilenameMismatch(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	input.SidecarBytes = []byte(sha256Hex(input.BundleTarBytes) + "  other.tar.gz\n")
	_, err = SignEvidenceBundleProvenance(input, priv)
	if err == nil || !strings.Contains(err.Error(), "sidecar filename mismatch") {
		t.Fatalf("expected sidecar filename mismatch, got %v", err)
	}
}

func TestEvidenceBundleProvenanceRejectsExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	prov, err := SignEvidenceBundleProvenance(input, priv)
	if err != nil {
		t.Fatalf("sign provenance: %v", err)
	}
	_, err = VerifyEvidenceBundleProvenance(prov, input.SummaryBytes, input.BundleTarBytes, input.SidecarBytes, pub, now.Add(2*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}
}

func TestEvidenceBundleProvenanceRejectsKeyIDMismatch(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	prov, err := SignEvidenceBundleProvenance(input, priv)
	if err != nil {
		t.Fatalf("sign provenance: %v", err)
	}
	_, err = VerifyEvidenceBundleProvenance(prov, input.SummaryBytes, input.BundleTarBytes, input.SidecarBytes, otherPub, now)
	if err == nil || !strings.Contains(err.Error(), "signature key id mismatch") {
		t.Fatalf("expected key id mismatch, got %v", err)
	}
}

func TestEvidenceBundleProvenanceTrustStoreOrgPin(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC)
	input := testEvidenceBundleProvenanceInput(now)
	prov, err := SignEvidenceBundleProvenance(input, priv)
	if err != nil {
		t.Fatalf("sign provenance: %v", err)
	}
	store, _, err := AddTrustedKey(EmptyTrustStore(), TrustedKey{
		OrgID:     "different-org",
		OrgName:   "Different Org",
		PublicKey: adminauth.EncodePublicKey(pub),
	}, now)
	if err != nil {
		t.Fatalf("add trusted key: %v", err)
	}
	_, _, err = VerifyEvidenceBundleProvenanceWithTrustStore(store, prov, input.SummaryBytes, input.BundleTarBytes, input.SidecarBytes, now)
	if err == nil || !strings.Contains(err.Error(), "different organization") {
		t.Fatalf("expected trust store org pin error, got %v", err)
	}
}

func testEvidenceBundleProvenanceInput(now time.Time) EvidenceBundleProvenanceInput {
	bundleTarBytes := []byte("tar-bytes-for-access-bridge-pilot-evidence-bundle")
	bundleTarName := "access_bridge_pilot_evidence_bundle.tar.gz"
	return EvidenceBundleProvenanceInput{
		Organization: Organization{
			OrgID:   "org-access-recovery",
			Name:    "Access Recovery Org",
			HomeURL: "https://example.com",
		},
		IssuedAtUTC:    now.Format(time.RFC3339),
		ExpiresAtUTC:   now.Add(time.Hour).Format(time.RFC3339),
		EvidenceScope:  "real_helper_https",
		BundleTarName:  bundleTarName,
		SummaryBytes:   []byte(`{"bundle":"access_bridge_pilot_evidence_bundle","status":"ok"}`),
		BundleTarBytes: bundleTarBytes,
		SidecarBytes:   []byte(sha256Hex(bundleTarBytes) + "  " + bundleTarName + "\n"),
	}
}
