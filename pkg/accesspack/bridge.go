package accesspack

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"privacynode/pkg/adminauth"
)

type BridgeInvite struct {
	SchemaVersion    int          `json:"schema_version"`
	InviteID         string       `json:"invite_id"`
	Organization     Organization `json:"organization"`
	IssuedAtUTC      string       `json:"issued_at_utc"`
	ExpiresAtUTC     string       `json:"expires_at_utc"`
	IntendedAudience string       `json:"intended_audience"`
	Helper           BridgeHelper `json:"helper"`
	AccessPaths      []AccessPath `json:"access_paths"`
	SafetyNotes      []string     `json:"safety_notes,omitempty"`
	Signature        *Signature   `json:"signature,omitempty"`
}

type BridgeHelper struct {
	HelperID    string `json:"helper_id"`
	DisplayName string `json:"display_name"`
	ContactURL  string `json:"contact_url,omitempty"`
	Description string `json:"description,omitempty"`
}

type VerifiedBridgeInvite struct {
	Invite            BridgeInvite `json:"invite"`
	KeyID             string       `json:"key_id"`
	CanonicalBodySize int          `json:"canonical_body_size"`
	ExpiresAt         time.Time    `json:"expires_at"`
}

func ParseBridgeInvite(body []byte) (BridgeInvite, error) {
	var invite BridgeInvite
	if err := json.Unmarshal(body, &invite); err != nil {
		return BridgeInvite{}, fmt.Errorf("invalid bridge invite json: %w", err)
	}
	return invite, nil
}

func SignBridgeInvite(invite BridgeInvite, privateKey ed25519.PrivateKey, keyID string) (BridgeInvite, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return BridgeInvite{}, errors.New("invalid private key size")
	}
	invite.Signature = nil
	if err := ValidateBridgeInvite(invite, time.Time{}); err != nil {
		return BridgeInvite{}, err
	}
	body, err := CanonicalBridgeInvitePayload(invite)
	if err != nil {
		return BridgeInvite{}, err
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		keyID = adminauth.KeyIDFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	}
	invite.Signature = &Signature{
		Alg:   "ed25519",
		KeyID: keyID,
		Sig:   base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body)),
	}
	return invite, nil
}

func VerifyBridgeInvite(invite BridgeInvite, publicKey ed25519.PublicKey, now time.Time) (VerifiedBridgeInvite, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return VerifiedBridgeInvite{}, errors.New("invalid public key size")
	}
	if invite.Signature == nil {
		return VerifiedBridgeInvite{}, errors.New("bridge invite signature is required")
	}
	signature := *invite.Signature
	invite.Signature = nil
	if err := ValidateBridgeInvite(invite, now); err != nil {
		return VerifiedBridgeInvite{}, err
	}
	if strings.TrimSpace(signature.Alg) != "ed25519" {
		return VerifiedBridgeInvite{}, fmt.Errorf("unsupported signature alg %q", signature.Alg)
	}
	actualKeyID := adminauth.KeyIDFromPublicKey(publicKey)
	if strings.TrimSpace(signature.KeyID) != actualKeyID {
		return VerifiedBridgeInvite{}, fmt.Errorf("signature key id mismatch: got %q, expected %q", signature.KeyID, actualKeyID)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signature.Sig))
	if err != nil {
		return VerifiedBridgeInvite{}, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return VerifiedBridgeInvite{}, fmt.Errorf("invalid signature size %d", len(sig))
	}
	body, err := CanonicalBridgeInvitePayload(invite)
	if err != nil {
		return VerifiedBridgeInvite{}, err
	}
	if !ed25519.Verify(publicKey, body, sig) {
		return VerifiedBridgeInvite{}, errors.New("bridge invite signature verification failed")
	}
	invite.Signature = &signature
	expiresAt, _ := time.Parse(time.RFC3339, strings.TrimSpace(invite.ExpiresAtUTC))
	return VerifiedBridgeInvite{
		Invite:            NormalizeBridgeInvite(invite),
		KeyID:             actualKeyID,
		CanonicalBodySize: len(body),
		ExpiresAt:         expiresAt,
	}, nil
}

func CanonicalBridgeInvitePayload(invite BridgeInvite) ([]byte, error) {
	normalized := NormalizeBridgeInvite(invite)
	normalized.Signature = nil
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("canonicalize bridge invite: %w", err)
	}
	return body, nil
}

func ValidateBridgeInvite(invite BridgeInvite, now time.Time) error {
	if invite.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported bridge invite schema_version %d", invite.SchemaVersion)
	}
	if err := validateText("invite_id", invite.InviteID, 128, true); err != nil {
		return err
	}
	if err := validateText("organization.org_id", invite.Organization.OrgID, 128, true); err != nil {
		return err
	}
	if err := validateText("organization.name", invite.Organization.Name, 120, true); err != nil {
		return err
	}
	if err := validateOptionalURL("organization.home_url", invite.Organization.HomeURL); err != nil {
		return err
	}
	issuedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(invite.IssuedAtUTC))
	if err != nil {
		return fmt.Errorf("issued_at_utc invalid: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(invite.ExpiresAtUTC))
	if err != nil {
		return fmt.Errorf("expires_at_utc invalid: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return errors.New("expires_at_utc must be after issued_at_utc")
	}
	if !now.IsZero() && !expiresAt.After(now.UTC()) {
		return errors.New("bridge invite is expired")
	}
	if err := validateText("intended_audience", invite.IntendedAudience, 240, true); err != nil {
		return err
	}
	if err := validateText("helper.helper_id", invite.Helper.HelperID, 128, true); err != nil {
		return err
	}
	if err := validateText("helper.display_name", invite.Helper.DisplayName, 120, true); err != nil {
		return err
	}
	if err := validateOptionalURL("helper.contact_url", invite.Helper.ContactURL); err != nil {
		return err
	}
	if err := validateText("helper.description", invite.Helper.Description, 180, false); err != nil {
		return err
	}
	if len(invite.AccessPaths) == 0 {
		return errors.New("access_paths is empty")
	}
	if len(invite.AccessPaths) > 16 {
		return fmt.Errorf("access_paths has %d items, max 16", len(invite.AccessPaths))
	}
	for i, path := range invite.AccessPaths {
		prefix := fmt.Sprintf("access_paths[%d]", i)
		if err := validateText(prefix+".path_id", path.PathID, 128, true); err != nil {
			return err
		}
		if err := validateText(prefix+".kind", path.Kind, 32, true); err != nil {
			return err
		}
		if err := validateURL(prefix+".url", path.URL); err != nil {
			return err
		}
		if path.Priority < 0 || path.Priority > 1000 {
			return fmt.Errorf("%s.priority must be between 0 and 1000", prefix)
		}
		if err := validateText(prefix+".launch_hint", path.LaunchHint, 120, false); err != nil {
			return err
		}
		if err := validateText(prefix+".description", path.Description, 180, false); err != nil {
			return err
		}
		if len(path.SafetyNotes) > 8 {
			return fmt.Errorf("%s.safety_notes has %d items, max 8", prefix, len(path.SafetyNotes))
		}
		for j, note := range path.SafetyNotes {
			if err := validateText(fmt.Sprintf("%s.safety_notes[%d]", prefix, j), note, 180, true); err != nil {
				return err
			}
		}
	}
	if len(invite.SafetyNotes) > 8 {
		return fmt.Errorf("safety_notes has %d items, max 8", len(invite.SafetyNotes))
	}
	for i, note := range invite.SafetyNotes {
		if err := validateText(fmt.Sprintf("safety_notes[%d]", i), note, 240, true); err != nil {
			return err
		}
	}
	return nil
}

func NormalizeBridgeInvite(invite BridgeInvite) BridgeInvite {
	invite.InviteID = strings.TrimSpace(invite.InviteID)
	invite.Organization.OrgID = strings.TrimSpace(invite.Organization.OrgID)
	invite.Organization.Name = strings.TrimSpace(invite.Organization.Name)
	invite.Organization.HomeURL = strings.TrimSpace(invite.Organization.HomeURL)
	invite.IssuedAtUTC = strings.TrimSpace(invite.IssuedAtUTC)
	invite.ExpiresAtUTC = strings.TrimSpace(invite.ExpiresAtUTC)
	invite.IntendedAudience = strings.TrimSpace(invite.IntendedAudience)
	invite.Helper.HelperID = strings.TrimSpace(invite.Helper.HelperID)
	invite.Helper.DisplayName = strings.TrimSpace(invite.Helper.DisplayName)
	invite.Helper.ContactURL = strings.TrimSpace(invite.Helper.ContactURL)
	invite.Helper.Description = strings.TrimSpace(invite.Helper.Description)
	for i := range invite.AccessPaths {
		invite.AccessPaths[i].PathID = strings.TrimSpace(invite.AccessPaths[i].PathID)
		invite.AccessPaths[i].Kind = strings.TrimSpace(invite.AccessPaths[i].Kind)
		invite.AccessPaths[i].URL = strings.TrimSpace(invite.AccessPaths[i].URL)
		invite.AccessPaths[i].LaunchHint = strings.TrimSpace(invite.AccessPaths[i].LaunchHint)
		invite.AccessPaths[i].Description = strings.TrimSpace(invite.AccessPaths[i].Description)
		for j := range invite.AccessPaths[i].SafetyNotes {
			invite.AccessPaths[i].SafetyNotes[j] = strings.TrimSpace(invite.AccessPaths[i].SafetyNotes[j])
		}
	}
	for i := range invite.SafetyNotes {
		invite.SafetyNotes[i] = strings.TrimSpace(invite.SafetyNotes[i])
	}
	if invite.Signature != nil {
		invite.Signature.Alg = strings.TrimSpace(invite.Signature.Alg)
		invite.Signature.KeyID = strings.TrimSpace(invite.Signature.KeyID)
		invite.Signature.Sig = strings.TrimSpace(invite.Signature.Sig)
	}
	sort.SliceStable(invite.AccessPaths, func(i, j int) bool {
		if invite.AccessPaths[i].Priority == invite.AccessPaths[j].Priority {
			return invite.AccessPaths[i].PathID < invite.AccessPaths[j].PathID
		}
		return invite.AccessPaths[i].Priority < invite.AccessPaths[j].Priority
	})
	return invite
}
