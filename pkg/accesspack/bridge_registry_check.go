package accesspack

import (
	"strings"
	"time"
)

type BridgeHelperRegistryCheckOptions struct {
	HelperID      string `json:"helper_id,omitempty"`
	OrgID         string `json:"org_id,omitempty"`
	RequireActive bool   `json:"require_active"`
}

type BridgeHelperRegistryCheckReport struct {
	Status           string                     `json:"status"`
	GeneratedAtUTC   string                     `json:"generated_at_utc"`
	HelpersTotal     int                        `json:"helpers_total"`
	ActiveCount      int                        `json:"active_count"`
	QuarantinedCount int                        `json:"quarantined_count"`
	DisabledCount    int                        `json:"disabled_count"`
	MatchedCount     int                        `json:"matched_count"`
	RequireActive    bool                       `json:"require_active"`
	FilterHelperID   string                     `json:"filter_helper_id,omitempty"`
	FilterOrgID      string                     `json:"filter_org_id,omitempty"`
	MatchingHelpers  []BridgeHelperRegistration `json:"matching_helpers"`
	Findings         []BridgePolicyFinding      `json:"findings"`
}

func CheckBridgeHelperRegistry(registry BridgeHelperRegistry, options BridgeHelperRegistryCheckOptions, now time.Time) BridgeHelperRegistryCheckReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	options.HelperID = strings.TrimSpace(options.HelperID)
	options.OrgID = strings.TrimSpace(options.OrgID)
	report := BridgeHelperRegistryCheckReport{
		Status:         "pass",
		GeneratedAtUTC: now.UTC().Format(time.RFC3339),
		RequireActive:  options.RequireActive,
		FilterHelperID: options.HelperID,
		FilterOrgID:    options.OrgID,
	}
	normalized := NormalizeBridgeHelperRegistry(registry)
	report.HelpersTotal = len(normalized.Helpers)
	if err := ValidateBridgeHelperRegistry(normalized, time.Time{}); err != nil {
		report.addFinding("invalid_bridge_helper_registry", "error", err.Error())
		report.Status = "fail"
		return report
	}
	for _, helper := range normalized.Helpers {
		switch helper.Status {
		case BridgeHelperStatusActive:
			report.ActiveCount++
		case BridgeHelperStatusQuarantined:
			report.QuarantinedCount++
		case BridgeHelperStatusDisabled:
			report.DisabledCount++
		}
		if options.HelperID != "" && helper.HelperID != options.HelperID {
			continue
		}
		if options.OrgID != "" && !bridgeHelperAllowsOrg(helper, options.OrgID) {
			continue
		}
		report.MatchingHelpers = append(report.MatchingHelpers, helper)
		if options.RequireActive {
			checkBridgeRegistryHelperActive(helper, now, &report)
		}
	}
	report.MatchedCount = len(report.MatchingHelpers)
	if options.HelperID != "" && report.MatchedCount == 0 {
		report.addFinding("bridge_helper_not_registered", "error", "helper id was not found in the helper registry")
	}
	if options.OrgID != "" && report.MatchedCount == 0 {
		report.addFinding("bridge_helper_org_not_allowed", "error", "no matching helper is registered for this organization")
	}
	if len(report.Findings) > 0 {
		report.Status = "fail"
	}
	return report
}

func checkBridgeRegistryHelperActive(helper BridgeHelperRegistration, now time.Time, report *BridgeHelperRegistryCheckReport) {
	if helper.Status != BridgeHelperStatusActive {
		message := "bridge helper is not active"
		if helper.QuarantineReason != "" {
			message += ": " + helper.QuarantineReason
		}
		report.addFinding("bridge_helper_not_active", "error", message)
		return
	}
	activeFrom, activeFromErr := parseOptionalBridgeRegistryTime("helper.active_from_utc", helper.ActiveFromUTC)
	activeUntil, activeUntilErr := parseOptionalBridgeRegistryTime("helper.active_until_utc", helper.ActiveUntilUTC)
	if activeFromErr != nil {
		report.addFinding("bridge_helper_active_from_invalid", "error", activeFromErr.Error())
	}
	if activeUntilErr != nil {
		report.addFinding("bridge_helper_active_until_invalid", "error", activeUntilErr.Error())
	}
	if !activeFrom.IsZero() && now.Before(activeFrom) {
		report.addFinding("bridge_helper_not_active_yet", "error", "bridge helper active window has not started")
	}
	if !activeUntil.IsZero() && !activeUntil.After(now) {
		report.addFinding("bridge_helper_expired", "error", "bridge helper active window has ended")
	}
}

func (report *BridgeHelperRegistryCheckReport) addFinding(code string, severity string, message string) {
	report.Findings = append(report.Findings, BridgePolicyFinding{
		Code:     code,
		Severity: severity,
		Message:  message,
	})
}
