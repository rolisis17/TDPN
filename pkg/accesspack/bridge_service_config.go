package accesspack

import (
	"strings"
	"time"
)

type BridgeServiceConfigOptions struct {
	RegistryID           string `json:"registry_id,omitempty"`
	RegistryExpiresAtUTC string `json:"registry_expires_at_utc,omitempty"`
	InviteKeyID          string `json:"invite_key_id,omitempty"`
	RegistryKeyID        string `json:"registry_key_id,omitempty"`
	SignedRegistry       bool   `json:"signed_registry"`
}

type BridgeServiceConfig struct {
	Status                string                   `json:"status"`
	GeneratedAtUTC        string                   `json:"generated_at_utc"`
	InviteID              string                   `json:"invite_id"`
	OrganizationID        string                   `json:"organization_id"`
	OrganizationName      string                   `json:"organization_name"`
	HelperID              string                   `json:"helper_id"`
	HelperName            string                   `json:"helper_name,omitempty"`
	HelperContactURL      string                   `json:"helper_contact_url,omitempty"`
	HelperAbuseReportURL  string                   `json:"helper_abuse_report_url,omitempty"`
	HelperRateLimitPolicy string                   `json:"helper_rate_limit_policy,omitempty"`
	HelperActiveFromUTC   string                   `json:"helper_active_from_utc,omitempty"`
	HelperActiveUntilUTC  string                   `json:"helper_active_until_utc,omitempty"`
	RegistryID            string                   `json:"registry_id,omitempty"`
	RegistryExpiresAtUTC  string                   `json:"registry_expires_at_utc,omitempty"`
	InviteKeyID           string                   `json:"invite_key_id,omitempty"`
	RegistryKeyID         string                   `json:"registry_key_id,omitempty"`
	SignedRegistry        bool                     `json:"signed_registry"`
	AccessPaths           []AccessPath             `json:"access_paths,omitempty"`
	Policy                BridgeInvitePolicyReport `json:"policy"`
}

func BuildBridgeServiceConfig(invite BridgeInvite, registry BridgeHelperRegistry, options BridgeServiceConfigOptions, now time.Time) BridgeServiceConfig {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	invite = NormalizeBridgeInvite(invite)
	registry = NormalizeBridgeHelperRegistry(registry)
	policyOptions := DefaultBridgeInvitePolicyOptions()
	policyOptions.RequireHelperRegistry = true
	policyOptions.HelperRegistry = &registry
	policy := CheckBridgeInvitePolicy(invite, policyOptions, now)
	config := BridgeServiceConfig{
		Status:               policy.Status,
		GeneratedAtUTC:       now.Format(time.RFC3339),
		InviteID:             invite.InviteID,
		OrganizationID:       invite.Organization.OrgID,
		OrganizationName:     invite.Organization.Name,
		HelperID:             invite.Helper.HelperID,
		HelperName:           invite.Helper.DisplayName,
		HelperContactURL:     invite.Helper.ContactURL,
		RegistryID:           strings.TrimSpace(options.RegistryID),
		RegistryExpiresAtUTC: strings.TrimSpace(options.RegistryExpiresAtUTC),
		InviteKeyID:          strings.TrimSpace(options.InviteKeyID),
		RegistryKeyID:        strings.TrimSpace(options.RegistryKeyID),
		SignedRegistry:       options.SignedRegistry,
		AccessPaths:          invite.AccessPaths,
		Policy:               policy,
	}
	if helper, ok := findBridgeHelperRegistration(registry, invite.Helper.HelperID); ok {
		config.HelperAbuseReportURL = helper.AbuseReportURL
		config.HelperRateLimitPolicy = helper.RateLimitPolicy
		config.HelperActiveFromUTC = helper.ActiveFromUTC
		config.HelperActiveUntilUTC = helper.ActiveUntilUTC
	}
	return config
}
