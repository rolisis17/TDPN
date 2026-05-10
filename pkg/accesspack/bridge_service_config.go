package accesspack

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
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
	InviteSHA256          string                   `json:"invite_sha256,omitempty"`
	RegistrySHA256        string                   `json:"registry_sha256,omitempty"`
	AccessPathsSHA256     string                   `json:"access_paths_sha256,omitempty"`
	AccessPaths           []AccessPath             `json:"access_paths,omitempty"`
	Policy                BridgeInvitePolicyReport `json:"policy"`
}

type BridgeServiceRequest struct {
	PathID string `json:"path_id,omitempty"`
	URL    string `json:"url,omitempty"`
	Source string `json:"source,omitempty"`
}

type BridgeServiceDecision struct {
	Status                string                      `json:"status"`
	Allowed               bool                        `json:"allowed"`
	Reason                string                      `json:"reason"`
	GeneratedAtUTC        string                      `json:"generated_at_utc"`
	InviteID              string                      `json:"invite_id,omitempty"`
	OrganizationID        string                      `json:"organization_id,omitempty"`
	HelperID              string                      `json:"helper_id,omitempty"`
	RegistryID            string                      `json:"registry_id,omitempty"`
	SignedRegistry        bool                        `json:"signed_registry"`
	HelperAbuseReportURL  string                      `json:"helper_abuse_report_url,omitempty"`
	HelperRateLimitPolicy string                      `json:"helper_rate_limit_policy,omitempty"`
	MatchedAccessPath     *AccessPath                 `json:"matched_access_path,omitempty"`
	Findings              []BridgeServiceCheckFinding `json:"findings,omitempty"`
}

type BridgeServiceCheckFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
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
		InviteSHA256:         bridgeServiceInviteSHA256(invite),
		RegistrySHA256:       bridgeServiceRegistrySHA256(registry),
		AccessPathsSHA256:    bridgeServiceAccessPathsSHA256(invite.AccessPaths),
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

func ParseBridgeServiceConfig(body []byte) (BridgeServiceConfig, error) {
	var config BridgeServiceConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return BridgeServiceConfig{}, fmt.Errorf("invalid bridge service config json: %w", err)
	}
	return NormalizeBridgeServiceConfig(config), nil
}

func NormalizeBridgeServiceConfig(config BridgeServiceConfig) BridgeServiceConfig {
	config.Status = strings.TrimSpace(config.Status)
	config.GeneratedAtUTC = strings.TrimSpace(config.GeneratedAtUTC)
	config.InviteID = strings.TrimSpace(config.InviteID)
	config.OrganizationID = strings.TrimSpace(config.OrganizationID)
	config.OrganizationName = strings.TrimSpace(config.OrganizationName)
	config.HelperID = strings.TrimSpace(config.HelperID)
	config.HelperName = strings.TrimSpace(config.HelperName)
	config.HelperContactURL = strings.TrimSpace(config.HelperContactURL)
	config.HelperAbuseReportURL = strings.TrimSpace(config.HelperAbuseReportURL)
	config.HelperRateLimitPolicy = strings.TrimSpace(config.HelperRateLimitPolicy)
	config.HelperActiveFromUTC = strings.TrimSpace(config.HelperActiveFromUTC)
	config.HelperActiveUntilUTC = strings.TrimSpace(config.HelperActiveUntilUTC)
	config.RegistryID = strings.TrimSpace(config.RegistryID)
	config.RegistryExpiresAtUTC = strings.TrimSpace(config.RegistryExpiresAtUTC)
	config.InviteKeyID = strings.TrimSpace(config.InviteKeyID)
	config.RegistryKeyID = strings.TrimSpace(config.RegistryKeyID)
	config.InviteSHA256 = strings.TrimSpace(config.InviteSHA256)
	config.RegistrySHA256 = strings.TrimSpace(config.RegistrySHA256)
	config.AccessPathsSHA256 = strings.TrimSpace(config.AccessPathsSHA256)
	for i := range config.AccessPaths {
		config.AccessPaths[i].PathID = strings.TrimSpace(config.AccessPaths[i].PathID)
		config.AccessPaths[i].Kind = strings.TrimSpace(config.AccessPaths[i].Kind)
		config.AccessPaths[i].URL = strings.TrimSpace(config.AccessPaths[i].URL)
		config.AccessPaths[i].LaunchHint = strings.TrimSpace(config.AccessPaths[i].LaunchHint)
		config.AccessPaths[i].Description = strings.TrimSpace(config.AccessPaths[i].Description)
		for j := range config.AccessPaths[i].SafetyNotes {
			config.AccessPaths[i].SafetyNotes[j] = strings.TrimSpace(config.AccessPaths[i].SafetyNotes[j])
		}
	}
	return config
}

func EvaluateBridgeServiceRequest(config BridgeServiceConfig, request BridgeServiceRequest, now time.Time) BridgeServiceDecision {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	config = NormalizeBridgeServiceConfig(config)
	request.PathID = strings.TrimSpace(request.PathID)
	request.URL = strings.TrimSpace(request.URL)
	request.Source = strings.TrimSpace(request.Source)
	decision := BridgeServiceDecision{
		Status:                "pass",
		Allowed:               true,
		Reason:                "bridge service config is valid",
		GeneratedAtUTC:        now.Format(time.RFC3339),
		InviteID:              config.InviteID,
		OrganizationID:        config.OrganizationID,
		HelperID:              config.HelperID,
		RegistryID:            config.RegistryID,
		SignedRegistry:        config.SignedRegistry,
		HelperAbuseReportURL:  config.HelperAbuseReportURL,
		HelperRateLimitPolicy: config.HelperRateLimitPolicy,
	}
	if config.Status != "pass" {
		decision.addFinding("bridge_service_config_not_pass", "error", "bridge service config policy status is not pass")
	}
	if config.Policy.Status != "" && config.Policy.Status != "pass" {
		decision.addFinding("bridge_service_policy_not_pass", "error", "embedded bridge policy status is not pass")
	}
	if !config.SignedRegistry {
		decision.addFinding("bridge_service_unsigned_registry", "error", "bridge service config must come from a signed helper registry")
	}
	if config.InviteID == "" || config.OrganizationID == "" || config.HelperID == "" {
		decision.addFinding("bridge_service_missing_identity", "error", "bridge service config is missing invite, organization, or helper identity")
	}
	if config.HelperAbuseReportURL == "" {
		decision.addFinding("bridge_service_missing_abuse_report", "error", "bridge service config is missing helper abuse-report URL")
	}
	if config.HelperRateLimitPolicy == "" {
		decision.addFinding("bridge_service_missing_rate_limit_policy", "error", "bridge service config is missing helper rate-limit policy")
	}
	if len(config.AccessPaths) == 0 {
		decision.addFinding("bridge_service_no_access_paths", "error", "bridge service config has no access paths")
	}
	if config.AccessPathsSHA256 == "" {
		decision.addFinding("bridge_service_missing_access_paths_hash", "error", "bridge service config is missing access paths hash")
	} else if actual := bridgeServiceAccessPathsSHA256(config.AccessPaths); actual != config.AccessPathsSHA256 {
		decision.addFinding("bridge_service_access_paths_hash_mismatch", "error", "bridge service access paths do not match the generated hash")
	}
	if config.RegistryExpiresAtUTC != "" {
		expiresAt, err := time.Parse(time.RFC3339, config.RegistryExpiresAtUTC)
		if err != nil {
			decision.addFinding("bridge_service_registry_expiry_invalid", "error", "bridge service registry expiry is invalid")
		} else if !expiresAt.After(now) {
			decision.addFinding("bridge_service_registry_expired", "error", "bridge service registry has expired")
		}
	}
	activeFrom, activeFromErr := parseOptionalBridgeRegistryTime("helper_active_from_utc", config.HelperActiveFromUTC)
	if activeFromErr != nil {
		decision.addFinding("bridge_service_helper_active_from_invalid", "error", activeFromErr.Error())
	} else if !activeFrom.IsZero() && now.Before(activeFrom) {
		decision.addFinding("bridge_service_helper_not_active_yet", "error", "bridge helper active window has not started")
	}
	activeUntil, activeUntilErr := parseOptionalBridgeRegistryTime("helper_active_until_utc", config.HelperActiveUntilUTC)
	if activeUntilErr != nil {
		decision.addFinding("bridge_service_helper_active_until_invalid", "error", activeUntilErr.Error())
	} else if !activeUntil.IsZero() && !activeUntil.After(now) {
		decision.addFinding("bridge_service_helper_expired", "error", "bridge helper active window has ended")
	}
	if request.PathID != "" || request.URL != "" {
		path, ok := findBridgeServiceAccessPath(config, request)
		if !ok {
			decision.addFinding("bridge_service_access_path_not_found", "error", "requested bridge access path is not present in the signed service config")
		} else {
			decision.MatchedAccessPath = &path
			if path.RequiresExternalApp {
				decision.addFinding("bridge_service_access_path_external_app", "error", "requested access path requires an external app and cannot be served by the bridge service")
			}
			if !bridgeServicePathIsHTTP(path) {
				decision.addFinding("bridge_service_access_path_unserviceable_scheme", "error", "requested access path is not an HTTP(S) bridge service URL")
			}
			if request.URL != "" && !bridgeServiceSameURL(path.URL, request.URL) {
				decision.addFinding("bridge_service_access_path_url_mismatch", "error", "requested URL does not match the signed access path URL")
			}
		}
	}
	if len(decision.Findings) > 0 {
		decision.Status = "fail"
		decision.Allowed = false
		decision.Reason = decision.Findings[0].Message
	}
	return decision
}

func findBridgeServiceAccessPath(config BridgeServiceConfig, request BridgeServiceRequest) (AccessPath, bool) {
	if request.PathID != "" {
		for _, path := range config.AccessPaths {
			if strings.TrimSpace(path.PathID) == request.PathID {
				return path, true
			}
		}
		return AccessPath{}, false
	}
	if request.URL != "" {
		for _, path := range config.AccessPaths {
			if bridgeServiceSameURL(path.URL, request.URL) {
				return path, true
			}
		}
	}
	return AccessPath{}, false
}

func bridgeServicePathIsHTTP(path AccessPath) bool {
	parsed, err := url.Parse(strings.TrimSpace(path.URL))
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}

func bridgeServiceSameURL(left string, right string) bool {
	l, err := url.Parse(strings.TrimSpace(left))
	if err != nil {
		return false
	}
	r, err := url.Parse(strings.TrimSpace(right))
	if err != nil {
		return false
	}
	if !strings.EqualFold(l.Scheme, r.Scheme) || !strings.EqualFold(l.Host, r.Host) {
		return false
	}
	leftPath := l.EscapedPath()
	rightPath := r.EscapedPath()
	if leftPath == "" {
		leftPath = "/"
	}
	if rightPath == "" {
		rightPath = "/"
	}
	return leftPath == rightPath && l.RawQuery == r.RawQuery
}

func (decision *BridgeServiceDecision) addFinding(code string, severity string, message string) {
	decision.Findings = append(decision.Findings, BridgeServiceCheckFinding{
		Code:     code,
		Severity: severity,
		Message:  message,
	})
}

func bridgeServiceInviteSHA256(invite BridgeInvite) string {
	body, err := CanonicalBridgeInvitePayload(invite)
	if err != nil {
		body, _ = json.Marshal(NormalizeBridgeInvite(invite))
	}
	return bridgeServiceSHA256(body)
}

func bridgeServiceRegistrySHA256(registry BridgeHelperRegistry) string {
	body, _ := json.Marshal(NormalizeBridgeHelperRegistry(registry))
	return bridgeServiceSHA256(body)
}

func bridgeServiceAccessPathsSHA256(paths []AccessPath) string {
	normalized := NormalizeBridgeInvite(BridgeInvite{AccessPaths: append([]AccessPath(nil), paths...)})
	body, _ := json.Marshal(normalized.AccessPaths)
	return bridgeServiceSHA256(body)
}

func bridgeServiceSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}
