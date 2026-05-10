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

func isBridgeHelperStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case BridgeHelperStatusActive, BridgeHelperStatusQuarantined, BridgeHelperStatusDisabled:
		return true
	default:
		return false
	}
}

func (report *BridgeHelperRegistryStatusUpdateReport) addFinding(code string, severity string, message string) {
	report.Findings = append(report.Findings, BridgePolicyFinding{
		Code:     code,
		Severity: severity,
		Message:  message,
	})
}
