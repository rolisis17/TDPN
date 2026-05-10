package accesspack

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"privacynode/pkg/adminauth"
)

const TrustStoreVersion = 1

type TrustStore struct {
	Version     int          `json:"version"`
	TrustedKeys []TrustedKey `json:"trusted_keys"`
}

type TrustedKey struct {
	OrgID        string   `json:"org_id"`
	OrgName      string   `json:"org_name"`
	KeyID        string   `json:"key_id"`
	PublicKey    string   `json:"public_key"`
	AddedAtUTC   string   `json:"added_at_utc"`
	ExpiresAtUTC string   `json:"expires_at_utc,omitempty"`
	Source       string   `json:"source,omitempty"`
	Notes        []string `json:"notes,omitempty"`
	Disabled     bool     `json:"disabled,omitempty"`
}

func EmptyTrustStore() TrustStore {
	return TrustStore{Version: TrustStoreVersion}
}

func ParseTrustStore(body []byte) (TrustStore, error) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return EmptyTrustStore(), nil
	}
	var store TrustStore
	if err := json.Unmarshal(body, &store); err != nil {
		return TrustStore{}, fmt.Errorf("invalid trust store json: %w", err)
	}
	if store.Version == 0 && len(store.TrustedKeys) == 0 {
		store.Version = TrustStoreVersion
	}
	if err := ValidateTrustStore(store, time.Time{}); err != nil {
		return TrustStore{}, err
	}
	return NormalizeTrustStore(store), nil
}

func MarshalTrustStore(store TrustStore) ([]byte, error) {
	if err := ValidateTrustStore(store, time.Time{}); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(NormalizeTrustStore(store), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal trust store: %w", err)
	}
	return append(body, '\n'), nil
}

func AddTrustedKey(store TrustStore, entry TrustedKey, now time.Time) (TrustStore, TrustedKey, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if store.Version == 0 {
		store.Version = TrustStoreVersion
	}
	entry = normalizeTrustedKey(entry)
	if entry.AddedAtUTC == "" {
		entry.AddedAtUTC = now.UTC().Format(time.RFC3339)
	}
	if err := validateTrustedKey(entry, now); err != nil {
		return TrustStore{}, TrustedKey{}, err
	}
	pub, _ := adminauth.ParsePublicKey(entry.PublicKey)
	derivedKeyID := adminauth.KeyIDFromPublicKey(pub)
	if entry.KeyID == "" {
		entry.KeyID = derivedKeyID
	} else if entry.KeyID != derivedKeyID {
		return TrustStore{}, TrustedKey{}, fmt.Errorf("key_id mismatch: got %q, derived %q from public_key", entry.KeyID, derivedKeyID)
	}
	replaced := false
	for i, existing := range store.TrustedKeys {
		existing = normalizeTrustedKey(existing)
		if existing.OrgID == entry.OrgID && existing.KeyID == entry.KeyID {
			if entry.AddedAtUTC == "" {
				entry.AddedAtUTC = existing.AddedAtUTC
			}
			store.TrustedKeys[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		store.TrustedKeys = append(store.TrustedKeys, entry)
	}
	if err := ValidateTrustStore(store, now); err != nil {
		return TrustStore{}, TrustedKey{}, err
	}
	return NormalizeTrustStore(store), entry, nil
}

func RemoveTrustedKey(store TrustStore, orgID string, keyID string) (TrustStore, bool) {
	orgID = strings.TrimSpace(orgID)
	keyID = strings.TrimSpace(keyID)
	next := EmptyTrustStore()
	if store.Version != 0 {
		next.Version = store.Version
	}
	removed := false
	for _, entry := range store.TrustedKeys {
		entry = normalizeTrustedKey(entry)
		if entry.OrgID == orgID && entry.KeyID == keyID {
			removed = true
			continue
		}
		next.TrustedKeys = append(next.TrustedKeys, entry)
	}
	return NormalizeTrustStore(next), removed
}

func ResolveTrustedPublicKey(store TrustStore, pack Pack, now time.Time) (ed25519.PublicKey, TrustedKey, error) {
	pack = Normalize(pack)
	if pack.Signature == nil {
		return nil, TrustedKey{}, errors.New("access pack signature is required")
	}
	return resolveTrustedPublicKeyFor(store, pack.Organization.OrgID, pack.Signature.KeyID, "access pack", now)
}

func ResolveTrustedBridgeInvitePublicKey(store TrustStore, invite BridgeInvite, now time.Time) (ed25519.PublicKey, TrustedKey, error) {
	invite = NormalizeBridgeInvite(invite)
	if invite.Signature == nil {
		return nil, TrustedKey{}, errors.New("bridge invite signature is required")
	}
	return resolveTrustedPublicKeyFor(store, invite.Organization.OrgID, invite.Signature.KeyID, "bridge invite", now)
}

func ResolveTrustedBridgeHelperRegistryPublicKey(store TrustStore, artifact BridgeHelperRegistryArtifact, now time.Time) (ed25519.PublicKey, TrustedKey, error) {
	artifact = NormalizeBridgeHelperRegistryArtifact(artifact)
	if artifact.Signature == nil {
		return nil, TrustedKey{}, errors.New("bridge helper registry signature is required")
	}
	return resolveTrustedPublicKeyFor(store, artifact.Organization.OrgID, artifact.Signature.KeyID, "bridge helper registry", now)
}

func resolveTrustedPublicKeyFor(store TrustStore, orgID string, keyID string, label string, now time.Time) (ed25519.PublicKey, TrustedKey, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	store = NormalizeTrustStore(store)
	if err := ValidateTrustStore(store, time.Time{}); err != nil {
		return nil, TrustedKey{}, err
	}
	orgID = strings.TrimSpace(orgID)
	keyID = strings.TrimSpace(keyID)
	label = strings.TrimSpace(label)
	if label == "" {
		label = "artifact"
	}
	if keyID == "" {
		return nil, TrustedKey{}, fmt.Errorf("%s signature key id is required", label)
	}
	var sawKeyID bool
	var sawDisabled bool
	var sawOrgMismatch bool
	var sawExpired bool
	for _, entry := range store.TrustedKeys {
		entry = normalizeTrustedKey(entry)
		if entry.KeyID != keyID {
			continue
		}
		sawKeyID = true
		if entry.Disabled {
			sawDisabled = true
			continue
		}
		if entry.OrgID != orgID {
			sawOrgMismatch = true
			continue
		}
		if trustKeyExpired(entry, now) {
			sawExpired = true
			continue
		}
		pub, err := adminauth.ParsePublicKey(entry.PublicKey)
		if err != nil {
			return nil, TrustedKey{}, fmt.Errorf("trusted key %q invalid: %w", entry.KeyID, err)
		}
		if adminauth.KeyIDFromPublicKey(pub) != entry.KeyID {
			return nil, TrustedKey{}, fmt.Errorf("trusted key %q public_key does not match key_id", entry.KeyID)
		}
		return pub, entry, nil
	}
	switch {
	case sawDisabled:
		return nil, TrustedKey{}, fmt.Errorf("trusted key %q is disabled", keyID)
	case sawOrgMismatch:
		return nil, TrustedKey{}, fmt.Errorf("trusted key %q is pinned to a different organization", keyID)
	case sawExpired:
		return nil, TrustedKey{}, fmt.Errorf("trusted key %q is expired", keyID)
	case sawKeyID:
		return nil, TrustedKey{}, fmt.Errorf("trusted key %q is not usable", keyID)
	default:
		return nil, TrustedKey{}, fmt.Errorf("%s key %q is not trusted", label, keyID)
	}
}

func ValidateTrustStore(store TrustStore, now time.Time) error {
	if store.Version != TrustStoreVersion {
		return fmt.Errorf("unsupported trust store version %d", store.Version)
	}
	if len(store.TrustedKeys) > 256 {
		return fmt.Errorf("trusted_keys has %d items, max 256", len(store.TrustedKeys))
	}
	seen := map[string]bool{}
	for i, entry := range store.TrustedKeys {
		prefix := fmt.Sprintf("trusted_keys[%d]", i)
		entry = normalizeTrustedKey(entry)
		if err := validateTrustedKey(entry, now); err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		key := entry.OrgID + "\x00" + entry.KeyID
		if seen[key] {
			return fmt.Errorf("%s duplicates org_id/key_id", prefix)
		}
		seen[key] = true
	}
	return nil
}

func NormalizeTrustStore(store TrustStore) TrustStore {
	if store.Version == 0 {
		store.Version = TrustStoreVersion
	}
	for i := range store.TrustedKeys {
		store.TrustedKeys[i] = normalizeTrustedKey(store.TrustedKeys[i])
	}
	sort.SliceStable(store.TrustedKeys, func(i, j int) bool {
		if store.TrustedKeys[i].OrgID == store.TrustedKeys[j].OrgID {
			return store.TrustedKeys[i].KeyID < store.TrustedKeys[j].KeyID
		}
		return store.TrustedKeys[i].OrgID < store.TrustedKeys[j].OrgID
	})
	return store
}

func normalizeTrustedKey(entry TrustedKey) TrustedKey {
	entry.OrgID = strings.TrimSpace(entry.OrgID)
	entry.OrgName = strings.TrimSpace(entry.OrgName)
	entry.KeyID = strings.TrimSpace(entry.KeyID)
	entry.PublicKey = strings.TrimSpace(entry.PublicKey)
	entry.AddedAtUTC = strings.TrimSpace(entry.AddedAtUTC)
	entry.ExpiresAtUTC = strings.TrimSpace(entry.ExpiresAtUTC)
	entry.Source = strings.TrimSpace(entry.Source)
	for i := range entry.Notes {
		entry.Notes[i] = strings.TrimSpace(entry.Notes[i])
	}
	return entry
}

func validateTrustedKey(entry TrustedKey, now time.Time) error {
	if err := validateText("org_id", entry.OrgID, 128, true); err != nil {
		return err
	}
	if err := validateText("org_name", entry.OrgName, 120, true); err != nil {
		return err
	}
	pub, err := adminauth.ParsePublicKey(entry.PublicKey)
	if err != nil {
		return fmt.Errorf("public_key invalid: %w", err)
	}
	derivedKeyID := adminauth.KeyIDFromPublicKey(pub)
	if entry.KeyID != "" && entry.KeyID != derivedKeyID {
		return fmt.Errorf("key_id mismatch: got %q, derived %q from public_key", entry.KeyID, derivedKeyID)
	}
	if err := validateText("key_id", derivedKeyID, 160, true); err != nil {
		return err
	}
	if entry.AddedAtUTC != "" {
		if _, err := time.Parse(time.RFC3339, entry.AddedAtUTC); err != nil {
			return fmt.Errorf("added_at_utc invalid: %w", err)
		}
	}
	if entry.ExpiresAtUTC != "" {
		expiresAt, err := time.Parse(time.RFC3339, entry.ExpiresAtUTC)
		if err != nil {
			return fmt.Errorf("expires_at_utc invalid: %w", err)
		}
		if !now.IsZero() && !expiresAt.After(now.UTC()) {
			return errors.New("trusted key is expired")
		}
	}
	if err := validateText("source", entry.Source, 180, false); err != nil {
		return err
	}
	if len(entry.Notes) > 8 {
		return fmt.Errorf("notes has %d items, max 8", len(entry.Notes))
	}
	for i, note := range entry.Notes {
		if err := validateText(fmt.Sprintf("notes[%d]", i), note, 180, false); err != nil {
			return err
		}
	}
	return nil
}

func trustKeyExpired(entry TrustedKey, now time.Time) bool {
	entry = normalizeTrustedKey(entry)
	if entry.ExpiresAtUTC == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, entry.ExpiresAtUTC)
	if err != nil {
		return true
	}
	return !expiresAt.After(now.UTC())
}
