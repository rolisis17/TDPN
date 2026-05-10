package accesspack

import (
	"net/url"
	"strings"
	"time"
)

type BridgeInvitePolicyOptions struct {
	MinAccessPaths        int           `json:"min_access_paths"`
	MinDistinctHosts      int           `json:"min_distinct_hosts"`
	MaxLifetime           time.Duration `json:"max_lifetime"`
	RequireHelperContact  bool          `json:"require_helper_contact"`
	RequireManualFallback bool          `json:"require_manual_fallback"`
}

type BridgeInvitePolicyReport struct {
	Status             string                `json:"status"`
	InviteID           string                `json:"invite_id"`
	OrganizationID     string                `json:"organization_id"`
	HelperID           string                `json:"helper_id"`
	AccessPathsCount   int                   `json:"access_paths_count"`
	DistinctHostsCount int                   `json:"distinct_hosts_count"`
	DistinctHosts      []string              `json:"distinct_hosts"`
	LifetimeSeconds    int64                 `json:"lifetime_seconds"`
	MaxLifetimeSeconds int64                 `json:"max_lifetime_seconds"`
	HasHelperContact   bool                  `json:"has_helper_contact"`
	HasManualFallback  bool                  `json:"has_manual_fallback"`
	Policy             BridgeInvitePolicy    `json:"policy"`
	Findings           []BridgePolicyFinding `json:"findings"`
}

type BridgeInvitePolicy struct {
	MinAccessPaths        int   `json:"min_access_paths"`
	MinDistinctHosts      int   `json:"min_distinct_hosts"`
	MaxLifetimeSeconds    int64 `json:"max_lifetime_seconds"`
	RequireHelperContact  bool  `json:"require_helper_contact"`
	RequireManualFallback bool  `json:"require_manual_fallback"`
}

type BridgePolicyFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func DefaultBridgeInvitePolicyOptions() BridgeInvitePolicyOptions {
	return BridgeInvitePolicyOptions{
		MinAccessPaths:        2,
		MinDistinctHosts:      2,
		MaxLifetime:           MaxBridgeInviteLifetime,
		RequireHelperContact:  true,
		RequireManualFallback: true,
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
			MinAccessPaths:        options.MinAccessPaths,
			MinDistinctHosts:      options.MinDistinctHosts,
			MaxLifetimeSeconds:    int64(options.MaxLifetime.Seconds()),
			RequireHelperContact:  options.RequireHelperContact,
			RequireManualFallback: options.RequireManualFallback,
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

func (report *BridgeInvitePolicyReport) addFinding(code string, severity string, message string) {
	report.Findings = append(report.Findings, BridgePolicyFinding{
		Code:     code,
		Severity: severity,
		Message:  message,
	})
}
