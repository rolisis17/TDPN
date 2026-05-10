package accesspack

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"privacynode/pkg/adminauth"
)

const (
	EvidenceBundleProvenanceSchemaVersion = 1
	EvidenceBundleSubjectKind             = "access_bridge_pilot_evidence_bundle"
)

type EvidenceBundleProvenance struct {
	SchemaVersion int                                `json:"schema_version"`
	Organization  Organization                       `json:"organization"`
	IssuedAtUTC   string                             `json:"issued_at_utc"`
	ExpiresAtUTC  string                             `json:"expires_at_utc"`
	Subject       EvidenceBundleProvenanceSubject    `json:"subject"`
	Signature     *EvidenceBundleProvenanceSignature `json:"signature,omitempty"`
}

type EvidenceBundleProvenanceSubject struct {
	Kind                         string `json:"kind"`
	EvidenceScope                string `json:"evidence_scope"`
	SummaryJSONSHA256            string `json:"summary_json_sha256"`
	BundleTarSHA256              string `json:"bundle_tar_sha256"`
	BundleTarSHA256SidecarSHA256 string `json:"bundle_tar_sha256_sidecar_sha256"`
	BundleTarName                string `json:"bundle_tar_name"`
}

type EvidenceBundleProvenanceSignature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"`
}

type EvidenceBundleProvenanceInput struct {
	Organization   Organization
	IssuedAtUTC    string
	ExpiresAtUTC   string
	EvidenceScope  string
	BundleTarName  string
	SummaryBytes   []byte
	BundleTarBytes []byte
	SidecarBytes   []byte
}

type VerifiedEvidenceBundleProvenance struct {
	Provenance        EvidenceBundleProvenance `json:"provenance"`
	KeyID             string                   `json:"key_id"`
	CanonicalBodySize int                      `json:"canonical_body_size"`
	ExpiresAt         time.Time                `json:"expires_at"`
}

func SignEvidenceBundleProvenance(input EvidenceBundleProvenanceInput, privateKey ed25519.PrivateKey) (EvidenceBundleProvenance, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return EvidenceBundleProvenance{}, errors.New("invalid private key size")
	}
	if err := validateEvidenceBundleBytes(input.SummaryBytes, input.BundleTarBytes, input.SidecarBytes); err != nil {
		return EvidenceBundleProvenance{}, err
	}
	bundleTarName := strings.TrimSpace(input.BundleTarName)
	bundleTarSHA256 := sha256Hex(input.BundleTarBytes)
	if err := validateEvidenceBundleSidecar(input.SidecarBytes, bundleTarSHA256, bundleTarName); err != nil {
		return EvidenceBundleProvenance{}, err
	}
	prov := EvidenceBundleProvenance{
		SchemaVersion: EvidenceBundleProvenanceSchemaVersion,
		Organization:  input.Organization,
		IssuedAtUTC:   input.IssuedAtUTC,
		ExpiresAtUTC:  input.ExpiresAtUTC,
		Subject: EvidenceBundleProvenanceSubject{
			Kind:                         EvidenceBundleSubjectKind,
			EvidenceScope:                input.EvidenceScope,
			SummaryJSONSHA256:            sha256Hex(input.SummaryBytes),
			BundleTarSHA256:              bundleTarSHA256,
			BundleTarSHA256SidecarSHA256: sha256Hex(input.SidecarBytes),
			BundleTarName:                bundleTarName,
		},
	}
	if err := ValidateEvidenceBundleProvenance(prov, time.Time{}); err != nil {
		return EvidenceBundleProvenance{}, err
	}
	body, err := CanonicalEvidenceBundleProvenancePayload(prov)
	if err != nil {
		return EvidenceBundleProvenance{}, err
	}
	keyID := adminauth.KeyIDFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	prov.Signature = &EvidenceBundleProvenanceSignature{
		Alg:   "ed25519",
		KeyID: keyID,
		Sig:   base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body)),
	}
	return prov, nil
}

func VerifyEvidenceBundleProvenance(prov EvidenceBundleProvenance, summaryBytes []byte, bundleTarBytes []byte, sidecarBytes []byte, publicKey ed25519.PublicKey, now time.Time) (VerifiedEvidenceBundleProvenance, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return VerifiedEvidenceBundleProvenance{}, errors.New("invalid public key size")
	}
	if err := validateEvidenceBundleBytes(summaryBytes, bundleTarBytes, sidecarBytes); err != nil {
		return VerifiedEvidenceBundleProvenance{}, err
	}
	if prov.Signature == nil {
		return VerifiedEvidenceBundleProvenance{}, errors.New("evidence bundle provenance signature is required")
	}
	signature := *prov.Signature
	prov.Signature = nil
	if err := ValidateEvidenceBundleProvenance(prov, now); err != nil {
		return VerifiedEvidenceBundleProvenance{}, err
	}
	if strings.TrimSpace(signature.Alg) != "ed25519" {
		return VerifiedEvidenceBundleProvenance{}, fmt.Errorf("unsupported signature alg %q", signature.Alg)
	}
	actualKeyID := adminauth.KeyIDFromPublicKey(publicKey)
	if strings.TrimSpace(signature.KeyID) != actualKeyID {
		return VerifiedEvidenceBundleProvenance{}, fmt.Errorf("signature key id mismatch: got %q, expected %q", signature.KeyID, actualKeyID)
	}
	if err := verifyEvidenceBundleSubjectHashes(prov.Subject, summaryBytes, bundleTarBytes, sidecarBytes); err != nil {
		return VerifiedEvidenceBundleProvenance{}, err
	}
	if err := validateEvidenceBundleSidecar(sidecarBytes, prov.Subject.BundleTarSHA256, prov.Subject.BundleTarName); err != nil {
		return VerifiedEvidenceBundleProvenance{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signature.Sig))
	if err != nil {
		return VerifiedEvidenceBundleProvenance{}, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return VerifiedEvidenceBundleProvenance{}, fmt.Errorf("invalid signature size %d", len(sig))
	}
	body, err := CanonicalEvidenceBundleProvenancePayload(prov)
	if err != nil {
		return VerifiedEvidenceBundleProvenance{}, err
	}
	if !ed25519.Verify(publicKey, body, sig) {
		return VerifiedEvidenceBundleProvenance{}, errors.New("evidence bundle provenance signature verification failed")
	}
	prov.Signature = &signature
	expiresAt, _ := time.Parse(time.RFC3339, strings.TrimSpace(prov.ExpiresAtUTC))
	return VerifiedEvidenceBundleProvenance{
		Provenance:        NormalizeEvidenceBundleProvenance(prov),
		KeyID:             actualKeyID,
		CanonicalBodySize: len(body),
		ExpiresAt:         expiresAt,
	}, nil
}

func VerifyEvidenceBundleProvenanceWithTrustStore(store TrustStore, prov EvidenceBundleProvenance, summaryBytes []byte, bundleTarBytes []byte, sidecarBytes []byte, now time.Time) (VerifiedEvidenceBundleProvenance, TrustedKey, error) {
	prov = NormalizeEvidenceBundleProvenance(prov)
	if prov.Signature == nil {
		return VerifiedEvidenceBundleProvenance{}, TrustedKey{}, errors.New("evidence bundle provenance signature is required")
	}
	publicKey, entry, err := ResolveTrustedPublicKeyForSignature(store, prov.Organization.OrgID, prov.Signature.KeyID, "evidence bundle provenance", now)
	if err != nil {
		return VerifiedEvidenceBundleProvenance{}, TrustedKey{}, err
	}
	verified, err := VerifyEvidenceBundleProvenance(prov, summaryBytes, bundleTarBytes, sidecarBytes, publicKey, now)
	if err != nil {
		return VerifiedEvidenceBundleProvenance{}, TrustedKey{}, err
	}
	return verified, entry, nil
}

func CanonicalEvidenceBundleProvenancePayload(prov EvidenceBundleProvenance) ([]byte, error) {
	normalized := NormalizeEvidenceBundleProvenance(prov)
	normalized.Signature = nil
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("canonicalize evidence bundle provenance: %w", err)
	}
	return body, nil
}

func ValidateEvidenceBundleProvenance(prov EvidenceBundleProvenance, now time.Time) error {
	prov = NormalizeEvidenceBundleProvenance(prov)
	if prov.SchemaVersion != EvidenceBundleProvenanceSchemaVersion {
		return fmt.Errorf("unsupported evidence bundle provenance schema_version %d", prov.SchemaVersion)
	}
	if err := validateText("organization.org_id", prov.Organization.OrgID, 128, true); err != nil {
		return err
	}
	if err := validateText("organization.name", prov.Organization.Name, 120, true); err != nil {
		return err
	}
	if err := validateOptionalURL("organization.home_url", prov.Organization.HomeURL); err != nil {
		return err
	}
	issuedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(prov.IssuedAtUTC))
	if err != nil {
		return fmt.Errorf("issued_at_utc invalid: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(prov.ExpiresAtUTC))
	if err != nil {
		return fmt.Errorf("expires_at_utc invalid: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return errors.New("expires_at_utc must be after issued_at_utc")
	}
	if !now.IsZero() && !expiresAt.After(now.UTC()) {
		return errors.New("evidence bundle provenance is expired")
	}
	if err := validateText("subject.kind", prov.Subject.Kind, 128, true); err != nil {
		return err
	}
	if prov.Subject.Kind != EvidenceBundleSubjectKind {
		return fmt.Errorf("unsupported evidence bundle subject kind %q", prov.Subject.Kind)
	}
	if err := validateText("subject.evidence_scope", prov.Subject.EvidenceScope, 64, true); err != nil {
		return err
	}
	switch prov.Subject.EvidenceScope {
	case "real_helper_https", "local_rehearsal", "diagnostic", "incomplete":
	default:
		return fmt.Errorf("unsupported evidence bundle evidence_scope %q", prov.Subject.EvidenceScope)
	}
	if err := validateText("subject.bundle_tar_name", prov.Subject.BundleTarName, 255, true); err != nil {
		return err
	}
	if strings.Contains(prov.Subject.BundleTarName, "/") || strings.Contains(prov.Subject.BundleTarName, "\\") {
		return errors.New("subject.bundle_tar_name must be a base filename")
	}
	if err := validateSHA256Hex("subject.summary_json_sha256", prov.Subject.SummaryJSONSHA256); err != nil {
		return err
	}
	if err := validateSHA256Hex("subject.bundle_tar_sha256", prov.Subject.BundleTarSHA256); err != nil {
		return err
	}
	if err := validateSHA256Hex("subject.bundle_tar_sha256_sidecar_sha256", prov.Subject.BundleTarSHA256SidecarSHA256); err != nil {
		return err
	}
	return nil
}

func NormalizeEvidenceBundleProvenance(prov EvidenceBundleProvenance) EvidenceBundleProvenance {
	if prov.SchemaVersion == 0 {
		prov.SchemaVersion = EvidenceBundleProvenanceSchemaVersion
	}
	prov.Organization.OrgID = strings.TrimSpace(prov.Organization.OrgID)
	prov.Organization.Name = strings.TrimSpace(prov.Organization.Name)
	prov.Organization.HomeURL = strings.TrimSpace(prov.Organization.HomeURL)
	prov.IssuedAtUTC = strings.TrimSpace(prov.IssuedAtUTC)
	prov.ExpiresAtUTC = strings.TrimSpace(prov.ExpiresAtUTC)
	prov.Subject.Kind = strings.TrimSpace(prov.Subject.Kind)
	if prov.Subject.Kind == "" {
		prov.Subject.Kind = EvidenceBundleSubjectKind
	}
	prov.Subject.EvidenceScope = strings.TrimSpace(prov.Subject.EvidenceScope)
	prov.Subject.SummaryJSONSHA256 = strings.ToLower(strings.TrimSpace(prov.Subject.SummaryJSONSHA256))
	prov.Subject.BundleTarSHA256 = strings.ToLower(strings.TrimSpace(prov.Subject.BundleTarSHA256))
	prov.Subject.BundleTarSHA256SidecarSHA256 = strings.ToLower(strings.TrimSpace(prov.Subject.BundleTarSHA256SidecarSHA256))
	prov.Subject.BundleTarName = strings.TrimSpace(prov.Subject.BundleTarName)
	if prov.Signature != nil {
		prov.Signature.Alg = strings.TrimSpace(prov.Signature.Alg)
		prov.Signature.KeyID = strings.TrimSpace(prov.Signature.KeyID)
		prov.Signature.Sig = strings.TrimSpace(prov.Signature.Sig)
	}
	return prov
}

func validateEvidenceBundleBytes(summaryBytes []byte, bundleTarBytes []byte, sidecarBytes []byte) error {
	if len(summaryBytes) == 0 {
		return errors.New("summary json bytes are required")
	}
	if len(bundleTarBytes) == 0 {
		return errors.New("bundle tar bytes are required")
	}
	if len(sidecarBytes) == 0 {
		return errors.New("bundle tar sha256 sidecar bytes are required")
	}
	return nil
}

func validateEvidenceBundleSidecar(sidecarBytes []byte, expectedTarSHA256 string, expectedTarName string) error {
	line := ""
	for _, rawLine := range strings.Split(string(sidecarBytes), "\n") {
		if strings.TrimSpace(rawLine) != "" {
			line = strings.TrimSpace(rawLine)
			break
		}
	}
	if line == "" {
		return errors.New("bundle tar sha256 sidecar is empty")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return errors.New("bundle tar sha256 sidecar must contain digest and filename")
	}
	gotSHA256 := strings.ToLower(strings.TrimSpace(fields[0]))
	if err := validateSHA256Hex("bundle tar sha256 sidecar digest", gotSHA256); err != nil {
		return err
	}
	expectedTarSHA256 = strings.ToLower(strings.TrimSpace(expectedTarSHA256))
	if expectedTarSHA256 == "" {
		return errors.New("expected bundle tar sha256 is required")
	}
	if gotSHA256 != expectedTarSHA256 {
		return fmt.Errorf("bundle tar sha256 sidecar digest mismatch: got %s expected %s", gotSHA256, expectedTarSHA256)
	}
	gotName := strings.TrimSpace(fields[1])
	expectedTarName = strings.TrimSpace(expectedTarName)
	if expectedTarName == "" {
		return errors.New("expected bundle tar name is required")
	}
	if gotName != expectedTarName {
		return fmt.Errorf("bundle tar sha256 sidecar filename mismatch: got %q expected %q", gotName, expectedTarName)
	}
	return nil
}

func verifyEvidenceBundleSubjectHashes(subject EvidenceBundleProvenanceSubject, summaryBytes []byte, bundleTarBytes []byte, sidecarBytes []byte) error {
	subject = NormalizeEvidenceBundleProvenance(EvidenceBundleProvenance{Subject: subject}).Subject
	if subject.SummaryJSONSHA256 != sha256Hex(summaryBytes) {
		return errors.New("summary json sha256 mismatch")
	}
	if subject.BundleTarSHA256 != sha256Hex(bundleTarBytes) {
		return errors.New("bundle tar sha256 mismatch")
	}
	if subject.BundleTarSHA256SidecarSHA256 != sha256Hex(sidecarBytes) {
		return errors.New("bundle tar sha256 sidecar sha256 mismatch")
	}
	return nil
}

func validateSHA256Hex(field string, value string) error {
	value = strings.TrimSpace(value)
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("%s must be a sha256 hex digest", field)
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s must be a sha256 hex digest", field)
	}
	if len(raw) != sha256.Size {
		return fmt.Errorf("%s must be a sha256 hex digest", field)
	}
	return nil
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
