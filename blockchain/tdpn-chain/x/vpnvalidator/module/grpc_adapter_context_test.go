package module

import (
	"errors"
	"strings"
	"testing"

	validatorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnvalidator/v1"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
)

func TestGRPCAdaptersNilContextDoesNotPanic(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgServerAdapter(&k)
	queryAdapter := NewGRPCQueryServerAdapter(&k)

	_, eligibilityErr := msgAdapter.SetValidatorEligibility(nil, nil)
	if !errors.Is(eligibilityErr, ErrInvalidEligibility) {
		t.Fatalf("expected ErrInvalidEligibility for nil context/request, got %v", eligibilityErr)
	}

	_, statusErr := msgAdapter.RecordValidatorStatus(nil, nil)
	if !errors.Is(statusErr, ErrInvalidStatusRecord) {
		t.Fatalf("expected ErrInvalidStatusRecord for nil context/request, got %v", statusErr)
	}

	eligibilityResp, err := queryAdapter.ValidatorEligibility(nil, nil)
	if err != nil {
		t.Fatalf("expected nil error for nil-context missing eligibility query, got %v", err)
	}
	if eligibilityResp.GetFound() {
		t.Fatal("expected found=false for nil-context missing eligibility query")
	}

	statusResp, err := queryAdapter.ValidatorStatusRecord(nil, nil)
	if err != nil {
		t.Fatalf("expected nil error for nil-context missing status query, got %v", err)
	}
	if statusResp.GetFound() {
		t.Fatal("expected found=false for nil-context missing status query")
	}

	listEligibilitiesResp, err := queryAdapter.ListValidatorEligibilities(nil, &validatorpb.QueryListValidatorEligibilitiesRequest{})
	if err != nil {
		t.Fatalf("expected nil error for nil-context eligibility list, got %v", err)
	}
	if len(listEligibilitiesResp.GetEligibilities()) != 0 {
		t.Fatalf("expected empty eligibility list, got %d", len(listEligibilitiesResp.GetEligibilities()))
	}

	listStatusResp, err := queryAdapter.ListValidatorStatusRecords(nil, &validatorpb.QueryListValidatorStatusRecordsRequest{})
	if err != nil {
		t.Fatalf("expected nil error for nil-context status list, got %v", err)
	}
	if len(listStatusResp.GetRecords()) != 0 {
		t.Fatalf("expected empty status list, got %d", len(listStatusResp.GetRecords()))
	}

	_, previewErr := queryAdapter.PreviewEpochSelection(nil, nil)
	if previewErr == nil {
		t.Fatal("expected deterministic validation error for nil-context preview request")
	}
	if !strings.Contains(previewErr.Error(), "at least one stable or rotating seat is required") {
		t.Fatalf("expected seat validation error, got %v", previewErr)
	}
}
