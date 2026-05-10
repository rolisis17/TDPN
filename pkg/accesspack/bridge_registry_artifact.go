package accesspack

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"privacynode/pkg/adminauth"
)

const (
	BridgeHelperRegistryArtifactSchemaVersion = 1
	MaxBridgeHelperRegistryArtifactLifetime   = 30 * 24 * time.Hour
)

type BridgeHelperRegistryArtifact struct {
	SchemaVersion int                  `json:"schema_version"`
	RegistryID    string               `json:"registry_id"`
	Organization  Organization         `json:"organization"`
	IssuedAtUTC   string               `json:"issued_at_utc"`
	ExpiresAtUTC  string               `json:"expires_at_utc"`
	Registry      BridgeHelperRegistry `json:"registry"`
	Signature     *Signature           `json:"signature,omitempty"`
}

type VerifiedBridgeHelperRegistryArtifact struct {
	Artifact          BridgeHelperRegistryArtifact `json:"artifact"`
	KeyID             string                       `json:"key_id"`
	CanonicalBodySize int                          `json:"canonical_body_size"`
	ExpiresAt         time.Time                    `json:"expires_at"`
}

func ParseBridgeHelperRegistryArtifact(body []byte) (BridgeHelperRegistryArtifact, error) {
	var artifact BridgeHelperRegistryArtifact
	if err := json.Unmarshal(body, &artifact); err != nil {
		return BridgeHelperRegistryArtifact{}, fmt.Errorf("invalid bridge helper registry artifact json: %w", err)
	}
	return artifact, nil
}

func SignBridgeHelperRegistryArtifact(artifact BridgeHelperRegistryArtifact, privateKey ed25519.PrivateKey, keyID string) (BridgeHelperRegistryArtifact, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return BridgeHelperRegistryArtifact{}, errors.New("invalid private key size")
	}
	artifact.Signature = nil
	if err := ValidateBridgeHelperRegistryArtifact(artifact, time.Time{}); err != nil {
		return BridgeHelperRegistryArtifact{}, err
	}
	body, err := CanonicalBridgeHelperRegistryArtifactPayload(artifact)
	if err != nil {
		return BridgeHelperRegistryArtifact{}, err
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		keyID = adminauth.KeyIDFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	}
	artifact.Signature = &Signature{
		Alg:   "ed25519",
		KeyID: keyID,
		Sig:   base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body)),
	}
	return artifact, nil
}

func VerifyBridgeHelperRegistryArtifact(artifact BridgeHelperRegistryArtifact, publicKey ed25519.PublicKey, now time.Time) (VerifiedBridgeHelperRegistryArtifact, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return VerifiedBridgeHelperRegistryArtifact{}, errors.New("invalid public key size")
	}
	if artifact.Signature == nil {
		return VerifiedBridgeHelperRegistryArtifact{}, errors.New("bridge helper registry signature is required")
	}
	signature := *artifact.Signature
	artifact.Signature = nil
	if err := ValidateBridgeHelperRegistryArtifact(artifact, now); err != nil {
		return VerifiedBridgeHelperRegistryArtifact{}, err
	}
	if strings.TrimSpace(signature.Alg) != "ed25519" {
		return VerifiedBridgeHelperRegistryArtifact{}, fmt.Errorf("unsupported signature alg %q", signature.Alg)
	}
	actualKeyID := adminauth.KeyIDFromPublicKey(publicKey)
	if strings.TrimSpace(signature.KeyID) != actualKeyID {
		return VerifiedBridgeHelperRegistryArtifact{}, fmt.Errorf("signature key id mismatch: got %q, expected %q", signature.KeyID, actualKeyID)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signature.Sig))
	if err != nil {
		return VerifiedBridgeHelperRegistryArtifact{}, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return VerifiedBridgeHelperRegistryArtifact{}, fmt.Errorf("invalid signature size %d", len(sig))
	}
	body, err := CanonicalBridgeHelperRegistryArtifactPayload(artifact)
	if err != nil {
		return VerifiedBridgeHelperRegistryArtifact{}, err
	}
	if !ed25519.Verify(publicKey, body, sig) {
		return VerifiedBridgeHelperRegistryArtifact{}, errors.New("bridge helper registry signature verification failed")
	}
	artifact.Signature = &signature
	expiresAt, _ := time.Parse(time.RFC3339, strings.TrimSpace(artifact.ExpiresAtUTC))
	return VerifiedBridgeHelperRegistryArtifact{
		Artifact:          NormalizeBridgeHelperRegistryArtifact(artifact),
		KeyID:             actualKeyID,
		CanonicalBodySize: len(body),
		ExpiresAt:         expiresAt,
	}, nil
}

func CanonicalBridgeHelperRegistryArtifactPayload(artifact BridgeHelperRegistryArtifact) ([]byte, error) {
	normalized := NormalizeBridgeHelperRegistryArtifact(artifact)
	normalized.Signature = nil
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("canonicalize bridge helper registry artifact: %w", err)
	}
	return body, nil
}

func ValidateBridgeHelperRegistryArtifact(artifact BridgeHelperRegistryArtifact, now time.Time) error {
	artifact = NormalizeBridgeHelperRegistryArtifact(artifact)
	if artifact.SchemaVersion != BridgeHelperRegistryArtifactSchemaVersion {
		return fmt.Errorf("unsupported bridge helper registry artifact schema_version %d", artifact.SchemaVersion)
	}
	if err := validateText("registry_id", artifact.RegistryID, 128, true); err != nil {
		return err
	}
	if err := validateText("organization.org_id", artifact.Organization.OrgID, 128, true); err != nil {
		return err
	}
	if err := validateText("organization.name", artifact.Organization.Name, 120, true); err != nil {
		return err
	}
	if err := validateOptionalURL("organization.home_url", artifact.Organization.HomeURL); err != nil {
		return err
	}
	issuedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(artifact.IssuedAtUTC))
	if err != nil {
		return fmt.Errorf("issued_at_utc invalid: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(artifact.ExpiresAtUTC))
	if err != nil {
		return fmt.Errorf("expires_at_utc invalid: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return errors.New("expires_at_utc must be after issued_at_utc")
	}
	if expiresAt.Sub(issuedAt) > MaxBridgeHelperRegistryArtifactLifetime {
		return fmt.Errorf("bridge helper registry artifact lifetime must be %s or less", MaxBridgeHelperRegistryArtifactLifetime)
	}
	if !now.IsZero() && !expiresAt.After(now.UTC()) {
		return errors.New("bridge helper registry artifact is expired")
	}
	if err := ValidateBridgeHelperRegistry(artifact.Registry, time.Time{}); err != nil {
		return fmt.Errorf("registry invalid: %w", err)
	}
	return nil
}

func NormalizeBridgeHelperRegistryArtifact(artifact BridgeHelperRegistryArtifact) BridgeHelperRegistryArtifact {
	if artifact.SchemaVersion == 0 {
		artifact.SchemaVersion = BridgeHelperRegistryArtifactSchemaVersion
	}
	artifact.RegistryID = strings.TrimSpace(artifact.RegistryID)
	artifact.Organization.OrgID = strings.TrimSpace(artifact.Organization.OrgID)
	artifact.Organization.Name = strings.TrimSpace(artifact.Organization.Name)
	artifact.Organization.HomeURL = strings.TrimSpace(artifact.Organization.HomeURL)
	artifact.IssuedAtUTC = strings.TrimSpace(artifact.IssuedAtUTC)
	artifact.ExpiresAtUTC = strings.TrimSpace(artifact.ExpiresAtUTC)
	artifact.Registry = NormalizeBridgeHelperRegistry(artifact.Registry)
	if artifact.Signature != nil {
		artifact.Signature.Alg = strings.TrimSpace(artifact.Signature.Alg)
		artifact.Signature.KeyID = strings.TrimSpace(artifact.Signature.KeyID)
		artifact.Signature.Sig = strings.TrimSpace(artifact.Signature.Sig)
	}
	return artifact
}
