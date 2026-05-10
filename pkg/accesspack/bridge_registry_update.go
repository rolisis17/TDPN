package accesspack

import (
	"strings"
	"time"
)

type BridgeHelperRegistryStatusUpdateOptions struct {
	HelperID string `json:"helper_id,omitempty"`
	Status   string `json:"status,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type BridgeHelperRegistryStatusUpdateReport struct {
	Status         string                `json:"status"`
	GeneratedAtUTC string                `json:"generated_at_utc"`
	HelperID       string                `json:"helper_id,omitempty"`
	PreviousStatus string                `json:"previous_status,omitempty"`
	NewStatus      string                `json:"new_status,omitempty"`
	UpdatedAtUTC   string                `json:"updated_at_utc,omitempty"`
	Updated        bool                  `json:"updated"`
	Findings       []BridgePolicyFinding `json:"findings"`
}

type BridgeHelperRegistryUpsertOptions struct {
	HelperID        string   `json:"helper_id,omitempty"`
	DisplayName     string   `json:"display_name,omitempty"`
	Status          string   `json:"status,omitempty"`
	OrgIDs          []string `json:"org_ids,omitempty"`
	ContactURL      string   `json:"contact_url,omitempty"`
	AbuseReportURL  string   `json:"abuse_report_url,omitempty"`
	RateLimitPolicy string   `json:"rate_limit_policy,omitempty"`
	ActiveFromUTC   string   `json:"active_from_utc,omitempty"`
	ActiveUntilUTC  string   `json:"active_until_utc,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

type BridgeHelperRegistryUpsertReport struct {
	Status         string                `json:"status"`
	GeneratedAtUTC string                `json:"generated_at_utc"`
	HelperID       string                `json:"helper_id,omitempty"`
	PreviousStatus string                `json:"previous_status,omitempty"`
	NewStatus      string                `json:"new_status,omitempty"`
	Created        bool                  `json:"created"`
	Updated        bool                  `json:"updated"`
	UpdatedAtUTC   string                `json:"updated_at_utc,omitempty"`
	Findings       []BridgePolicyFinding `json:"findings"`
}

func UpsertBridgeHelperRegistryHelper(registry BridgeHelperRegistry, options BridgeHelperRegistryUpsertOptions, now time.Time) (BridgeHelperRegistry, BridgeHelperRegistryUpsertReport) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	normalized := NormalizeBridgeHelperRegistry(registry)
	options = normalizeBridgeHelperRegistryUpsertOptions(options)
	report := BridgeHelperRegistryUpsertReport{
		Status:         "pass",
		GeneratedAtUTC: now.Format(time.RFC3339),
		HelperID:       options.HelperID,
		NewStatus:      options.Status,
		UpdatedAtUTC:   now.Format(time.RFC3339),
	}
	if err := ValidateBridgeHelperRegistry(normalized, time.Time{}); err != nil {
		report.addFinding("invalid_bridge_helper_registry", "error", err.Error())
		report.Status = "fail"
		return normalized, report
	}
	if options.HelperID == "" {
		report.addFinding("bridge_helper_id_required", "error", "helper id is required")
	}
	if options.Status != "" && !isBridgeHelperStatus(options.Status) {
		report.addFinding("bridge_helper_status_invalid", "error", "status must be active, quarantined, or disabled")
	}
	if len(report.Findings) > 0 {
		report.Status = "fail"
		return normalized, report
	}
	for i, helper := range normalized.Helpers {
		if helper.HelperID != options.HelperID {
			continue
		}
		report.PreviousStatus = helper.Status
		updated := applyBridgeHelperRegistryUpsert(helper, options, now)
		normalized.Helpers[i] = updated
		if err := ValidateBridgeHelperRegistry(normalized, time.Time{}); err != nil {
			report.addFinding("bridge_helper_registry_upsert_invalid", "error", err.Error())
			report.Status = "fail"
			return NormalizeBridgeHelperRegistry(registry), report
		}
		report.NewStatus = updated.Status
		report.Updated = true
		return NormalizeBridgeHelperRegistry(normalized), report
	}
	if len(options.OrgIDs) == 0 {
		report.addFinding("bridge_helper_org_ids_required", "error", "org ids are required when adding a new helper")
		report.Status = "fail"
		return normalized, report
	}
	helper := BridgeHelperRegistration{
		HelperID:         options.HelperID,
		DisplayName:      options.DisplayName,
		Status:           options.Status,
		OrgIDs:           options.OrgIDs,
		ContactURL:       options.ContactURL,
		AbuseReportURL:   options.AbuseReportURL,
		RateLimitPolicy:  options.RateLimitPolicy,
		ActiveFromUTC:    options.ActiveFromUTC,
		ActiveUntilUTC:   options.ActiveUntilUTC,
		QuarantineReason: options.Reason,
		UpdatedAtUTC:     now.Format(time.RFC3339),
	}
	if helper.Status == "" {
		helper.Status = BridgeHelperStatusActive
	}
	normalized.Helpers = append(normalized.Helpers, helper)
	normalized = NormalizeBridgeHelperRegistry(normalized)
	if err := ValidateBridgeHelperRegistry(normalized, time.Time{}); err != nil {
		report.addFinding("bridge_helper_registry_upsert_invalid", "error", err.Error())
		report.Status = "fail"
		return NormalizeBridgeHelperRegistry(registry), report
	}
	report.NewStatus = normalizeBridgeHelperRegistration(helper).Status
	report.Created = true
	return normalized, report
}

func SetBridgeHelperRegistryStatus(registry BridgeHelperRegistry, options BridgeHelperRegistryStatusUpdateOptions, now time.Time) (BridgeHelperRegistry, BridgeHelperRegistryStatusUpdateReport) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	normalized := NormalizeBridgeHelperRegistry(registry)
	options.HelperID = strings.TrimSpace(options.HelperID)
	options.Status = strings.ToLower(strings.TrimSpace(options.Status))
	options.Reason = strings.TrimSpace(options.Reason)
	report := BridgeHelperRegistryStatusUpdateReport{
		Status:         "pass",
		GeneratedAtUTC: now.Format(time.RFC3339),
		HelperID:       options.HelperID,
		NewStatus:      options.Status,
		UpdatedAtUTC:   now.Format(time.RFC3339),
	}
	if err := ValidateBridgeHelperRegistry(normalized, time.Time{}); err != nil {
		report.addFinding("invalid_bridge_helper_registry", "error", err.Error())
		report.Status = "fail"
		return normalized, report
	}
	if options.HelperID == "" {
		report.addFinding("bridge_helper_id_required", "error", "helper id is required")
	}
	if !isBridgeHelperStatus(options.Status) {
		report.addFinding("bridge_helper_status_invalid", "error", "status must be active, quarantined, or disabled")
	}
	if options.Status != "" && options.Status != BridgeHelperStatusActive && options.Reason == "" {
		report.addFinding("bridge_helper_status_reason_required", "error", "reason is required when quarantining or disabling a helper")
	}
	if len(report.Findings) > 0 {
		report.Status = "fail"
		return normalized, report
	}
	for i, helper := range normalized.Helpers {
		if helper.HelperID != options.HelperID {
			continue
		}
		report.PreviousStatus = helper.Status
		normalized.Helpers[i].Status = options.Status
		normalized.Helpers[i].UpdatedAtUTC = now.Format(time.RFC3339)
		if options.Status == BridgeHelperStatusActive {
			normalized.Helpers[i].QuarantineReason = ""
		} else {
			normalized.Helpers[i].QuarantineReason = options.Reason
		}
		if err := ValidateBridgeHelperRegistry(normalized, time.Time{}); err != nil {
			report.addFinding("bridge_helper_registry_update_invalid", "error", err.Error())
			report.Status = "fail"
			return NormalizeBridgeHelperRegistry(registry), report
		}
		report.Updated = true
		return NormalizeBridgeHelperRegistry(normalized), report
	}
	report.addFinding("bridge_helper_not_registered", "error", "helper id was not found in the helper registry")
	report.Status = "fail"
	return normalized, report
}

func normalizeBridgeHelperRegistryUpsertOptions(options BridgeHelperRegistryUpsertOptions) BridgeHelperRegistryUpsertOptions {
	options.HelperID = strings.TrimSpace(options.HelperID)
	options.DisplayName = strings.TrimSpace(options.DisplayName)
	options.Status = strings.ToLower(strings.TrimSpace(options.Status))
	options.ContactURL = strings.TrimSpace(options.ContactURL)
	options.AbuseReportURL = strings.TrimSpace(options.AbuseReportURL)
	options.RateLimitPolicy = strings.TrimSpace(options.RateLimitPolicy)
	options.ActiveFromUTC = strings.TrimSpace(options.ActiveFromUTC)
	options.ActiveUntilUTC = strings.TrimSpace(options.ActiveUntilUTC)
	options.Reason = strings.TrimSpace(options.Reason)
	normalizedOrgIDs := make([]string, 0, len(options.OrgIDs))
	seen := map[string]bool{}
	for _, orgID := range options.OrgIDs {
		orgID = strings.TrimSpace(orgID)
		if orgID == "" || seen[orgID] {
			continue
		}
		seen[orgID] = true
		normalizedOrgIDs = append(normalizedOrgIDs, orgID)
	}
	options.OrgIDs = normalizedOrgIDs
	return options
}

func applyBridgeHelperRegistryUpsert(helper BridgeHelperRegistration, options BridgeHelperRegistryUpsertOptions, now time.Time) BridgeHelperRegistration {
	if options.DisplayName != "" {
		helper.DisplayName = options.DisplayName
	}
	if options.Status != "" {
		helper.Status = options.Status
	}
	if len(options.OrgIDs) > 0 {
		helper.OrgIDs = options.OrgIDs
	}
	if options.ContactURL != "" {
		helper.ContactURL = options.ContactURL
	}
	if options.AbuseReportURL != "" {
		helper.AbuseReportURL = options.AbuseReportURL
	}
	if options.RateLimitPolicy != "" {
		helper.RateLimitPolicy = options.RateLimitPolicy
	}
	if options.ActiveFromUTC != "" {
		helper.ActiveFromUTC = options.ActiveFromUTC
	}
	if options.ActiveUntilUTC != "" {
		helper.ActiveUntilUTC = options.ActiveUntilUTC
	}
	if helper.Status == BridgeHelperStatusActive {
		helper.QuarantineReason = ""
	} else if options.Reason != "" {
		helper.QuarantineReason = options.Reason
	}
	helper.UpdatedAtUTC = now.Format(time.RFC3339)
	return helper
}

func isBridgeHelperStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case BridgeHelperStatusActive, BridgeHelperStatusQuarantined, BridgeHelperStatusDisabled:
		return true
	default:
		return false
	}
}

func (report *BridgeHelperRegistryUpsertReport) addFinding(code string, severity string, message string) {
	report.Findings = append(report.Findings, BridgePolicyFinding{
		Code:     code,
		Severity: severity,
		Message:  message,
	})
}

func (report *BridgeHelperRegistryStatusUpdateReport) addFinding(code string, severity string, message string) {
	report.Findings = append(report.Findings, BridgePolicyFinding{
		Code:     code,
		Severity: severity,
		Message:  message,
	})
}
