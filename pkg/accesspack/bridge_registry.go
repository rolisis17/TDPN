package accesspack

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	BridgeHelperRegistryVersion = 1

	BridgeHelperStatusActive      = "active"
	BridgeHelperStatusQuarantined = "quarantined"
	BridgeHelperStatusDisabled    = "disabled"
)

type BridgeHelperRegistry struct {
	Version int                        `json:"version"`
	Helpers []BridgeHelperRegistration `json:"helpers"`
}

type BridgeHelperRegistration struct {
	HelperID         string   `json:"helper_id"`
	DisplayName      string   `json:"display_name,omitempty"`
	Status           string   `json:"status"`
	OrgIDs           []string `json:"org_ids"`
	ContactURL       string   `json:"contact_url,omitempty"`
	ActiveFromUTC    string   `json:"active_from_utc,omitempty"`
	ActiveUntilUTC   string   `json:"active_until_utc,omitempty"`
	QuarantineReason string   `json:"quarantine_reason,omitempty"`
	UpdatedAtUTC     string   `json:"updated_at_utc,omitempty"`
}

func EmptyBridgeHelperRegistry() BridgeHelperRegistry {
	return BridgeHelperRegistry{Version: BridgeHelperRegistryVersion, Helpers: []BridgeHelperRegistration{}}
}

func ParseBridgeHelperRegistry(body []byte) (BridgeHelperRegistry, error) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return EmptyBridgeHelperRegistry(), nil
	}
	var registry BridgeHelperRegistry
	if err := json.Unmarshal(body, &registry); err != nil {
		return BridgeHelperRegistry{}, fmt.Errorf("invalid bridge helper registry json: %w", err)
	}
	if registry.Version == 0 && len(registry.Helpers) == 0 {
		registry.Version = BridgeHelperRegistryVersion
	}
	if err := ValidateBridgeHelperRegistry(registry, time.Time{}); err != nil {
		return BridgeHelperRegistry{}, err
	}
	return NormalizeBridgeHelperRegistry(registry), nil
}

func MarshalBridgeHelperRegistry(registry BridgeHelperRegistry) ([]byte, error) {
	if err := ValidateBridgeHelperRegistry(registry, time.Time{}); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(NormalizeBridgeHelperRegistry(registry), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal bridge helper registry: %w", err)
	}
	return append(body, '\n'), nil
}

func ValidateBridgeHelperRegistry(registry BridgeHelperRegistry, now time.Time) error {
	registry = NormalizeBridgeHelperRegistry(registry)
	if registry.Version != BridgeHelperRegistryVersion {
		return fmt.Errorf("unsupported bridge helper registry version %d", registry.Version)
	}
	if len(registry.Helpers) > 512 {
		return fmt.Errorf("helpers has %d items, max 512", len(registry.Helpers))
	}
	seen := map[string]bool{}
	for i, helper := range registry.Helpers {
		prefix := fmt.Sprintf("helpers[%d]", i)
		if err := validateBridgeHelperRegistration(prefix, helper, now); err != nil {
			return err
		}
		if seen[helper.HelperID] {
			return fmt.Errorf("%s duplicates helper_id", prefix)
		}
		seen[helper.HelperID] = true
	}
	return nil
}

func NormalizeBridgeHelperRegistry(registry BridgeHelperRegistry) BridgeHelperRegistry {
	if registry.Version == 0 {
		registry.Version = BridgeHelperRegistryVersion
	}
	if registry.Helpers == nil {
		registry.Helpers = []BridgeHelperRegistration{}
	}
	for i := range registry.Helpers {
		registry.Helpers[i] = normalizeBridgeHelperRegistration(registry.Helpers[i])
	}
	sort.SliceStable(registry.Helpers, func(i, j int) bool {
		return registry.Helpers[i].HelperID < registry.Helpers[j].HelperID
	})
	return registry
}

func normalizeBridgeHelperRegistration(helper BridgeHelperRegistration) BridgeHelperRegistration {
	helper.HelperID = strings.TrimSpace(helper.HelperID)
	helper.DisplayName = strings.TrimSpace(helper.DisplayName)
	helper.Status = strings.ToLower(strings.TrimSpace(helper.Status))
	if helper.Status == "" {
		helper.Status = BridgeHelperStatusActive
	}
	helper.ContactURL = strings.TrimSpace(helper.ContactURL)
	helper.ActiveFromUTC = strings.TrimSpace(helper.ActiveFromUTC)
	helper.ActiveUntilUTC = strings.TrimSpace(helper.ActiveUntilUTC)
	helper.QuarantineReason = strings.TrimSpace(helper.QuarantineReason)
	helper.UpdatedAtUTC = strings.TrimSpace(helper.UpdatedAtUTC)
	for i := range helper.OrgIDs {
		helper.OrgIDs[i] = strings.TrimSpace(helper.OrgIDs[i])
	}
	sort.Strings(helper.OrgIDs)
	return helper
}

func validateBridgeHelperRegistration(prefix string, helper BridgeHelperRegistration, now time.Time) error {
	helper = normalizeBridgeHelperRegistration(helper)
	if err := validateText(prefix+".helper_id", helper.HelperID, 128, true); err != nil {
		return err
	}
	if err := validateText(prefix+".display_name", helper.DisplayName, 120, false); err != nil {
		return err
	}
	switch helper.Status {
	case BridgeHelperStatusActive, BridgeHelperStatusQuarantined, BridgeHelperStatusDisabled:
	default:
		return fmt.Errorf("%s.status must be active, quarantined, or disabled", prefix)
	}
	if len(helper.OrgIDs) == 0 {
		return fmt.Errorf("%s.org_ids must name at least one organization", prefix)
	}
	if len(helper.OrgIDs) > 32 {
		return fmt.Errorf("%s.org_ids has %d items, max 32", prefix, len(helper.OrgIDs))
	}
	seenOrg := map[string]bool{}
	for i, orgID := range helper.OrgIDs {
		if err := validateText(fmt.Sprintf("%s.org_ids[%d]", prefix, i), orgID, 128, true); err != nil {
			return err
		}
		if seenOrg[orgID] {
			return fmt.Errorf("%s.org_ids[%d] duplicates organization id %q", prefix, i, orgID)
		}
		seenOrg[orgID] = true
	}
	if err := validateOptionalURL(prefix+".contact_url", helper.ContactURL); err != nil {
		return err
	}
	activeFrom, err := parseOptionalBridgeRegistryTime(prefix+".active_from_utc", helper.ActiveFromUTC)
	if err != nil {
		return err
	}
	activeUntil, err := parseOptionalBridgeRegistryTime(prefix+".active_until_utc", helper.ActiveUntilUTC)
	if err != nil {
		return err
	}
	if !activeFrom.IsZero() && !activeUntil.IsZero() && !activeUntil.After(activeFrom) {
		return fmt.Errorf("%s.active_until_utc must be after active_from_utc", prefix)
	}
	if err := validateText(prefix+".quarantine_reason", helper.QuarantineReason, 180, false); err != nil {
		return err
	}
	if helper.Status == BridgeHelperStatusActive && helper.QuarantineReason != "" {
		return fmt.Errorf("%s.quarantine_reason must be empty when status is active", prefix)
	}
	if helper.Status != BridgeHelperStatusActive && helper.QuarantineReason == "" {
		return fmt.Errorf("%s.quarantine_reason is required when status is quarantined or disabled", prefix)
	}
	if _, err := parseOptionalBridgeRegistryTime(prefix+".updated_at_utc", helper.UpdatedAtUTC); err != nil {
		return err
	}
	if !now.IsZero() && !activeUntil.IsZero() && !activeUntil.After(now.UTC()) {
		return fmt.Errorf("%s.active_until_utc is expired", prefix)
	}
	return nil
}

func parseOptionalBridgeRegistryTime(field string, raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s invalid: %w", field, err)
	}
	return value, nil
}
