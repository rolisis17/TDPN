package accesspack

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"privacynode/pkg/adminauth"
)

const SchemaVersion = 0

type Pack struct {
	SchemaVersion    int          `json:"schema_version"`
	PackID           string       `json:"pack_id"`
	Organization     Organization `json:"organization"`
	IssuedAtUTC      string       `json:"issued_at_utc"`
	ExpiresAtUTC     string       `json:"expires_at_utc"`
	IntendedAudience string       `json:"intended_audience"`
	Sources          []Source     `json:"sources"`
	AccessPaths      []AccessPath `json:"access_paths"`
	SafetyNotes      []string     `json:"safety_notes,omitempty"`
	Signature        *Signature   `json:"signature,omitempty"`
}

type Organization struct {
	OrgID   string `json:"org_id"`
	Name    string `json:"name"`
	HomeURL string `json:"home_url,omitempty"`
}

type Source struct {
	SourceID    string `json:"source_id"`
	Kind        string `json:"kind"`
	URL         string `json:"url"`
	Priority    int    `json:"priority,omitempty"`
	Description string `json:"description,omitempty"`
}

type AccessPath struct {
	PathID              string   `json:"path_id"`
	Kind                string   `json:"kind"`
	URL                 string   `json:"url"`
	Priority            int      `json:"priority,omitempty"`
	RequiresExternalApp bool     `json:"requires_external_app,omitempty"`
	LaunchHint          string   `json:"launch_hint,omitempty"`
	Description         string   `json:"description,omitempty"`
	SafetyNotes         []string `json:"safety_notes,omitempty"`
}

type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"`
}

type VerifiedPack struct {
	Pack              Pack      `json:"pack"`
	KeyID             string    `json:"key_id"`
	CanonicalBodySize int       `json:"canonical_body_size"`
	ExpiresAt         time.Time `json:"expires_at"`
}

func Parse(body []byte) (Pack, error) {
	var pack Pack
	if err := json.Unmarshal(body, &pack); err != nil {
		return Pack{}, fmt.Errorf("invalid access pack json: %w", err)
	}
	return pack, nil
}

func Sign(pack Pack, privateKey ed25519.PrivateKey, keyID string) (Pack, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Pack{}, errors.New("invalid private key size")
	}
	pack.Signature = nil
	if err := Validate(pack, time.Time{}); err != nil {
		return Pack{}, err
	}
	body, err := CanonicalPayload(pack)
	if err != nil {
		return Pack{}, err
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		keyID = adminauth.KeyIDFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	}
	pack.Signature = &Signature{
		Alg:   "ed25519",
		KeyID: keyID,
		Sig:   base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body)),
	}
	return pack, nil
}

func Verify(pack Pack, publicKey ed25519.PublicKey, now time.Time) (VerifiedPack, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return VerifiedPack{}, errors.New("invalid public key size")
	}
	if pack.Signature == nil {
		return VerifiedPack{}, errors.New("access pack signature is required")
	}
	signature := *pack.Signature
	pack.Signature = nil
	if err := Validate(pack, now); err != nil {
		return VerifiedPack{}, err
	}
	if strings.TrimSpace(signature.Alg) != "ed25519" {
		return VerifiedPack{}, fmt.Errorf("unsupported signature alg %q", signature.Alg)
	}
	actualKeyID := adminauth.KeyIDFromPublicKey(publicKey)
	if strings.TrimSpace(signature.KeyID) != actualKeyID {
		return VerifiedPack{}, fmt.Errorf("signature key id mismatch: got %q, expected %q", signature.KeyID, actualKeyID)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signature.Sig))
	if err != nil {
		return VerifiedPack{}, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return VerifiedPack{}, fmt.Errorf("invalid signature size %d", len(sig))
	}
	body, err := CanonicalPayload(pack)
	if err != nil {
		return VerifiedPack{}, err
	}
	if !ed25519.Verify(publicKey, body, sig) {
		return VerifiedPack{}, errors.New("access pack signature verification failed")
	}
	pack.Signature = &signature
	expiresAt, _ := time.Parse(time.RFC3339, strings.TrimSpace(pack.ExpiresAtUTC))
	return VerifiedPack{
		Pack:              Normalize(pack),
		KeyID:             actualKeyID,
		CanonicalBodySize: len(body),
		ExpiresAt:         expiresAt,
	}, nil
}

func CanonicalPayload(pack Pack) ([]byte, error) {
	normalized := Normalize(pack)
	normalized.Signature = nil
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("canonicalize access pack: %w", err)
	}
	return body, nil
}

func Validate(pack Pack, now time.Time) error {
	if pack.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported access pack schema_version %d", pack.SchemaVersion)
	}
	if err := validateText("pack_id", pack.PackID, 128, true); err != nil {
		return err
	}
	if err := validateText("organization.org_id", pack.Organization.OrgID, 128, true); err != nil {
		return err
	}
	if err := validateText("organization.name", pack.Organization.Name, 120, true); err != nil {
		return err
	}
	if err := validateOptionalURL("organization.home_url", pack.Organization.HomeURL); err != nil {
		return err
	}
	issuedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(pack.IssuedAtUTC))
	if err != nil {
		return fmt.Errorf("issued_at_utc invalid: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(pack.ExpiresAtUTC))
	if err != nil {
		return fmt.Errorf("expires_at_utc invalid: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return errors.New("expires_at_utc must be after issued_at_utc")
	}
	if !now.IsZero() && !expiresAt.After(now.UTC()) {
		return errors.New("access pack is expired")
	}
	if err := validateText("intended_audience", pack.IntendedAudience, 240, true); err != nil {
		return err
	}
	if len(pack.Sources) > 32 {
		return fmt.Errorf("sources has %d items, max 32", len(pack.Sources))
	}
	if len(pack.AccessPaths) == 0 {
		return errors.New("access_paths is empty")
	}
	if len(pack.AccessPaths) > 64 {
		return fmt.Errorf("access_paths has %d items, max 64", len(pack.AccessPaths))
	}
	for i, source := range pack.Sources {
		prefix := fmt.Sprintf("sources[%d]", i)
		if err := validateText(prefix+".source_id", source.SourceID, 128, true); err != nil {
			return err
		}
		if err := validateText(prefix+".kind", source.Kind, 32, true); err != nil {
			return err
		}
		if err := validateURL(prefix+".url", source.URL); err != nil {
			return err
		}
		if source.Priority < 0 || source.Priority > 1000 {
			return fmt.Errorf("%s.priority must be between 0 and 1000", prefix)
		}
		if err := validateText(prefix+".description", source.Description, 160, false); err != nil {
			return err
		}
	}
	for i, path := range pack.AccessPaths {
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
	if len(pack.SafetyNotes) > 12 {
		return fmt.Errorf("safety_notes has %d items, max 12", len(pack.SafetyNotes))
	}
	for i, note := range pack.SafetyNotes {
		if err := validateText(fmt.Sprintf("safety_notes[%d]", i), note, 240, true); err != nil {
			return err
		}
	}
	return nil
}

func Normalize(pack Pack) Pack {
	pack.PackID = strings.TrimSpace(pack.PackID)
	pack.Organization.OrgID = strings.TrimSpace(pack.Organization.OrgID)
	pack.Organization.Name = strings.TrimSpace(pack.Organization.Name)
	pack.Organization.HomeURL = strings.TrimSpace(pack.Organization.HomeURL)
	pack.IssuedAtUTC = strings.TrimSpace(pack.IssuedAtUTC)
	pack.ExpiresAtUTC = strings.TrimSpace(pack.ExpiresAtUTC)
	pack.IntendedAudience = strings.TrimSpace(pack.IntendedAudience)
	for i := range pack.Sources {
		pack.Sources[i].SourceID = strings.TrimSpace(pack.Sources[i].SourceID)
		pack.Sources[i].Kind = strings.TrimSpace(pack.Sources[i].Kind)
		pack.Sources[i].URL = strings.TrimSpace(pack.Sources[i].URL)
		pack.Sources[i].Description = strings.TrimSpace(pack.Sources[i].Description)
	}
	for i := range pack.AccessPaths {
		pack.AccessPaths[i].PathID = strings.TrimSpace(pack.AccessPaths[i].PathID)
		pack.AccessPaths[i].Kind = strings.TrimSpace(pack.AccessPaths[i].Kind)
		pack.AccessPaths[i].URL = strings.TrimSpace(pack.AccessPaths[i].URL)
		pack.AccessPaths[i].LaunchHint = strings.TrimSpace(pack.AccessPaths[i].LaunchHint)
		pack.AccessPaths[i].Description = strings.TrimSpace(pack.AccessPaths[i].Description)
		for j := range pack.AccessPaths[i].SafetyNotes {
			pack.AccessPaths[i].SafetyNotes[j] = strings.TrimSpace(pack.AccessPaths[i].SafetyNotes[j])
		}
	}
	for i := range pack.SafetyNotes {
		pack.SafetyNotes[i] = strings.TrimSpace(pack.SafetyNotes[i])
	}
	if pack.Signature != nil {
		pack.Signature.Alg = strings.TrimSpace(pack.Signature.Alg)
		pack.Signature.KeyID = strings.TrimSpace(pack.Signature.KeyID)
		pack.Signature.Sig = strings.TrimSpace(pack.Signature.Sig)
	}
	sort.SliceStable(pack.Sources, func(i, j int) bool {
		if pack.Sources[i].Priority == pack.Sources[j].Priority {
			return pack.Sources[i].SourceID < pack.Sources[j].SourceID
		}
		return pack.Sources[i].Priority < pack.Sources[j].Priority
	})
	sort.SliceStable(pack.AccessPaths, func(i, j int) bool {
		if pack.AccessPaths[i].Priority == pack.AccessPaths[j].Priority {
			return pack.AccessPaths[i].PathID < pack.AccessPaths[j].PathID
		}
		return pack.AccessPaths[i].Priority < pack.AccessPaths[j].Priority
	})
	return pack
}

func validateText(field string, value string, maxLen int, required bool) error {
	trimmed := strings.TrimSpace(value)
	if required && trimmed == "" {
		return fmt.Errorf("%s is required", field)
	}
	if maxLen > 0 && len(trimmed) > maxLen {
		return fmt.Errorf("%s exceeds max length %d", field, maxLen)
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", field)
		}
	}
	return nil
}

func validateOptionalURL(field string, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return validateURL(field, value)
}

func validateURL(field string, value string) error {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return fmt.Errorf("%s is required", field)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s invalid: %w", field, err)
	}
	if parsed.Scheme == "" {
		return fmt.Errorf("%s must be absolute", field)
	}
	if strings.TrimSpace(parsed.Host) == "" && parsed.Scheme != "mailto" {
		return fmt.Errorf("%s host is required", field)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s userinfo is not allowed", field)
	}
	return nil
}
