package accesspack

import (
	"net/url"
	"strings"
	"time"
)

type BridgeInvitePolicyOptions struct {
	MinAccessPaths               int                   `json:"min_access_paths"`
	MinDistinctHosts             int                   `json:"min_distinct_hosts"`
	MaxLifetime                  time.Duration         `json:"max_lifetime"`
	RequireHelperContact         bool                  `json:"require_helper_contact"`
	RequireManualFallback        bool                  `json:"require_manual_fallback"`
	RequireHelperRegistry        bool                  `json:"require_helper_registry"`
	RequireHelperAbuseReport     bool                  `json:"require_helper_abuse_report"`
	RequireHelperRateLimitPolicy bool                  `json:"require_helper_rate_limit_policy"`
	HelperRegistry               *BridgeHelperRegistry `json:"-"`
}

type BridgeInvitePolicyReport struct {
	Status                  string                `json:"status"`
	InviteID                string                `json:"invite_id"`
	OrganizationID          string                `json:"organization_id"`
	HelperID                string                `json:"helper_id"`
	AccessPathsCount        int                   `json:"access_paths_count"`
	DistinctHostsCount      int                   `json:"distinct_hosts_count"`
	DistinctHosts           []string              `json:"distinct_hosts"`
	LifetimeSeconds         int64                 `json:"lifetime_seconds"`
	MaxLifetimeSeconds      int64                 `json:"max_lifetime_seconds"`
	HasHelperContact        bool                  `json:"has_helper_contact"`
	HasManualFallback       bool                  `json:"has_manual_fallback"`
	HelperRegistryChecked   bool                  `json:"helper_registry_checked"`
	HelperRegistered        bool                  `json:"helper_registered"`
	HelperStatus            string                `json:"helper_status,omitempty"`
	HelperAllowedOrg        bool                  `json:"helper_allowed_org"`
	HelperRegistryContactOK bool                  `json:"helper_registry_contact_ok"`
	HelperAbuseReportOK     bool                  `json:"helper_abuse_report_ok"`
	HelperRateLimitPolicyOK bool                  `json:"helper_rate_limit_policy_ok"`
	Policy                  BridgeInvitePolicy    `json:"policy"`
	Findings                []BridgePolicyFinding `json:"findings"`
}

type BridgeInvitePolicy struct {
	MinAccessPaths               int   `json:"min_access_paths"`
	MinDistinctHosts             int   `json:"min_distinct_hosts"`
	MaxLifetimeSeconds           int64 `json:"max_lifetime_seconds"`
	RequireHelperContact         bool  `json:"require_helper_contact"`
	RequireManualFallback        bool  `json:"require_manual_fallback"`
	RequireHelperRegistry        bool  `json:"require_helper_registry"`
	RequireRegisteredHelper      bool  `json:"require_registered_helper"`
	RequireHelperAbuseReport     bool  `json:"require_helper_abuse_report"`
	RequireHelperRateLimitPolicy bool  `json:"require_helper_rate_limit_policy"`
}

type BridgePolicyFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func DefaultBridgeInvitePolicyOptions() BridgeInvitePolicyOptions {
	return BridgeInvitePolicyOptions{
		MinAccessPaths:               2,
		MinDistinctHosts:             2,
		MaxLifetime:                  MaxBridgeInviteLifetime,
		RequireHelperContact:         true,
		RequireManualFallback:        true,
		RequireHelperAbuseReport:     true,
		RequireHelperRateLimitPolicy: true,
	}
}

func CheckBridgeInvitePolicy(invite BridgeInvite, options BridgeInvitePolicyOptions, now time.Time) BridgeInvitePolicyReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	options = normalizeBridgePolicyOptions(options)
	invite = NormalizeBridgeInvite(invite)
	report := BridgeInvitePolicyReport{
		Status:             "pass",
		InviteID:           invite.InviteID,
		OrganizationID:     invite.Organization.OrgID,
		HelperID:           invite.Helper.HelperID,
		AccessPathsCount:   len(invite.AccessPaths),
		HasHelperContact:   strings.TrimSpace(invite.Helper.ContactURL) != "",
		MaxLifetimeSeconds: int64(options.MaxLifetime.Seconds()),
		Policy: BridgeInvitePolicy{
			MinAccessPaths:               options.MinAccessPaths,
			MinDistinctHosts:             options.MinDistinctHosts,
			MaxLifetimeSeconds:           int64(options.MaxLifetime.Seconds()),
			RequireHelperContact:         options.RequireHelperContact,
			RequireManualFallback:        options.RequireManualFallback,
			RequireHelperRegistry:        options.RequireHelperRegistry,
			RequireRegisteredHelper:      options.RequireHelperRegistry || options.HelperRegistry != nil,
			RequireHelperAbuseReport:     options.RequireHelperAbuseReport,
			RequireHelperRateLimitPolicy: options.RequireHelperRateLimitPolicy,
		},
	}
	if err := ValidateBridgeInvite(invite, now); err != nil {
		report.addFinding("invalid_bridge_invite", "error", err.Error())
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339, strings.TrimSpace(invite.IssuedAtUTC))
	expiresAt, expiresErr := time.Parse(time.RFC3339, strings.TrimSpace(invite.ExpiresAtUTC))
	if issuedErr == nil && expiresErr == nil {
		report.LifetimeSeconds = int64(expiresAt.Sub(issuedAt).Seconds())
		if options.MaxLifetime > 0 && expiresAt.Sub(issuedAt) > options.MaxLifetime {
			report.addFinding("bridge_invite_lifetime_too_long", "error", "bridge invite lifetime exceeds policy")
		}
	}
	if len(invite.AccessPaths) < options.MinAccessPaths {
		report.addFinding("bridge_invite_too_few_paths", "error", "bridge invite has fewer access paths than policy requires")
	}
	hosts := bridgeInviteHosts(invite)
	report.DistinctHosts = hosts
	report.DistinctHostsCount = len(hosts)
	if len(hosts) < options.MinDistinctHosts {
		report.addFinding("bridge_invite_insufficient_host_diversity", "error", "bridge invite has fewer distinct helper/contact hosts than policy requires")
	}
	report.HasManualFallback = bridgeInviteHasManualFallback(invite)
	if options.RequireHelperContact && !report.HasHelperContact {
		report.addFinding("bridge_invite_missing_helper_contact", "error", "bridge invite helper contact is required by policy")
	}
	if options.RequireManualFallback && !report.HasManualFallback {
		report.addFinding("bridge_invite_missing_manual_fallback", "error", "bridge invite needs a manual or external-app fallback path")
	}
	if options.HelperRegistry != nil {
		checkBridgeHelperRegistryPolicy(invite, options.HelperRegistry, now, issuedAt, expiresAt, &report)
	} else if options.RequireHelperRegistry {
		report.addFinding("bridge_helper_registry_required", "error", "bridge helper registry is required by policy")
	}
	if len(report.Findings) > 0 {
		report.Status = "fail"
	}
	return report
}

func normalizeBridgePolicyOptions(options BridgeInvitePolicyOptions) BridgeInvitePolicyOptions {
	defaults := DefaultBridgeInvitePolicyOptions()
	if options.MinAccessPaths <= 0 {
		options.MinAccessPaths = defaults.MinAccessPaths
	}
	if options.MinDistinctHosts <= 0 {
		options.MinDistinctHosts = defaults.MinDistinctHosts
	}
	if options.MaxLifetime <= 0 {
		options.MaxLifetime = defaults.MaxLifetime
	}
	return options
}

func bridgeInviteHosts(invite BridgeInvite) []string {
	seen := map[string]bool{}
	var hosts []string
	add := func(raw string) {
		host := bridgeInviteHost(raw)
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	add(invite.Helper.ContactURL)
	for _, path := range invite.AccessPaths {
		add(path.URL)
	}
	return hosts
}

func bridgeInviteHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if parsed.Scheme == "mailto" {
		address := parsed.Opaque
		if address == "" {
			address = parsed.Path
		}
		if at := strings.LastIndex(address, "@"); at >= 0 && at+1 < len(address) {
			return strings.ToLower(strings.TrimSpace(address[at+1:]))
		}
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
}

func bridgeInviteHasManualFallback(invite BridgeInvite) bool {
	for _, path := range invite.AccessPaths {
		kind := strings.ToLower(strings.TrimSpace(path.Kind))
		scheme := ""
		if parsed, err := url.Parse(strings.TrimSpace(path.URL)); err == nil {
			scheme = strings.ToLower(parsed.Scheme)
		}
		if path.RequiresExternalApp || kind == "instructions" || scheme == "mailto" {
			return true
		}
	}
	return false
}

func checkBridgeHelperRegistryPolicy(invite BridgeInvite, registry *BridgeHelperRegistry, now time.Time, issuedAt time.Time, expiresAt time.Time, report *BridgeInvitePolicyReport) {
	report.HelperRegistryChecked = true
	if registry == nil {
		return
	}
	normalized := NormalizeBridgeHelperRegistry(*registry)
	if err := ValidateBridgeHelperRegistry(normalized, time.Time{}); err != nil {
		report.addFinding("invalid_bridge_helper_registry", "error", err.Error())
		return
	}
	helper, ok := findBridgeHelperRegistration(normalized, invite.Helper.HelperID)
	if !ok {
		report.addFinding("bridge_helper_not_registered", "error", "bridge invite helper is not present in the helper registry")
		return
	}
	report.HelperRegistered = true
	report.HelperStatus = helper.Status
	report.HelperAllowedOrg = bridgeHelperAllowsOrg(helper, invite.Organization.OrgID)
	report.HelperRegistryContactOK = bridgeHelperContactMatches(helper, invite.Helper.ContactURL)
	report.HelperAbuseReportOK = strings.TrimSpace(helper.AbuseReportURL) != ""
	report.HelperRateLimitPolicyOK = strings.TrimSpace(helper.RateLimitPolicy) != ""
	if helper.Status != BridgeHelperStatusActive {
		message := "bridge helper is not active in the helper registry"
		if helper.QuarantineReason != "" {
			message += ": " + helper.QuarantineReason
		}
		report.addFinding("bridge_helper_not_active", "error", message)
	}
	if !report.HelperAllowedOrg {
		report.addFinding("bridge_helper_org_not_allowed", "error", "bridge helper is not registered for this organization")
	}
	if !report.HelperRegistryContactOK {
		report.addFinding("bridge_helper_contact_mismatch", "error", "bridge invite helper contact does not match the helper registry")
	}
	if report.Policy.RequireHelperAbuseReport && !report.HelperAbuseReportOK {
		report.addFinding("bridge_helper_missing_abuse_report", "error", "bridge helper registry must include an abuse report URL")
	}
	if report.Policy.RequireHelperRateLimitPolicy && !report.HelperRateLimitPolicyOK {
		report.addFinding("bridge_helper_missing_rate_limit_policy", "error", "bridge helper registry must include a rate-limit policy")
	}
	activeFrom, activeFromErr := parseOptionalBridgeRegistryTime("helper.active_from_utc", helper.ActiveFromUTC)
	activeUntil, activeUntilErr := parseOptionalBridgeRegistryTime("helper.active_until_utc", helper.ActiveUntilUTC)
	if activeFromErr != nil {
		report.addFinding("bridge_helper_active_from_invalid", "error", activeFromErr.Error())
	}
	if activeUntilErr != nil {
		report.addFinding("bridge_helper_active_until_invalid", "error", activeUntilErr.Error())
	}
	if !activeFrom.IsZero() {
		if now.Before(activeFrom) {
			report.addFinding("bridge_helper_not_active_yet", "error", "bridge helper active window has not started")
		}
		if !issuedAt.IsZero() && issuedAt.Before(activeFrom) {
			report.addFinding("bridge_invite_before_helper_active", "error", "bridge invite was issued before the helper active window")
		}
	}
	if !activeUntil.IsZero() {
		if !activeUntil.After(now) {
			report.addFinding("bridge_helper_expired", "error", "bridge helper active window has ended")
		}
		if !expiresAt.IsZero() && expiresAt.After(activeUntil) {
			report.addFinding("bridge_invite_exceeds_helper_window", "error", "bridge invite expires after the helper active window")
		}
	}
}

func findBridgeHelperRegistration(registry BridgeHelperRegistry, helperID string) (BridgeHelperRegistration, bool) {
	helperID = strings.TrimSpace(helperID)
	for _, helper := range registry.Helpers {
		if helper.HelperID == helperID {
			return helper, true
		}
	}
	return BridgeHelperRegistration{}, false
}

func bridgeHelperAllowsOrg(helper BridgeHelperRegistration, orgID string) bool {
	orgID = strings.TrimSpace(orgID)
	for _, allowedOrgID := range helper.OrgIDs {
		if strings.TrimSpace(allowedOrgID) == orgID {
			return true
		}
	}
	return false
}

func bridgeHelperContactMatches(helper BridgeHelperRegistration, inviteContactURL string) bool {
	registryContact := strings.TrimSpace(helper.ContactURL)
	if registryContact == "" {
		return true
	}
	return registryContact == strings.TrimSpace(inviteContactURL)
}

func (report *BridgeInvitePolicyReport) addFinding(code string, severity string, message string) {
	report.Findings = append(report.Findings, BridgePolicyFinding{
		Code:     code,
		Severity: severity,
		Message:  message,
	})
}
