package module

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	validatorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnvalidator/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	validatortypes "github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestGRPCMsgServerAdapterSetValidatorEligibility(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgServerAdapter(&k)

	resp, err := adapter.SetValidatorEligibility(context.Background(), &validatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &validatorpb.ValidatorEligibility{
			ValidatorId:     "val-1",
			OperatorAddress: "tdpnvaloper1abc",
			Eligible:        true,
			PolicyReason:    "bootstrap allowlist",
			UpdatedAtUnix:   4102444800,
		},
	})
	if err != nil {
		t.Fatalf("expected set validator eligibility success, got %v", err)
	}
	if resp.GetEligibility() == nil {
		t.Fatal("expected eligibility in response")
	}
	if resp.GetEligibility().GetValidatorId() != "val-1" {
		t.Fatalf("expected validator_id val-1, got %q", resp.GetEligibility().GetValidatorId())
	}
}

func TestGRPCMsgServerAdapterSetValidatorEligibilityConflictClassification(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgServerAdapter(&k)

	_, err := adapter.SetValidatorEligibility(context.Background(), &validatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &validatorpb.ValidatorEligibility{
			ValidatorId:     "val-conflict-1",
			OperatorAddress: "tdpnvaloper1conflict",
			Eligible:        true,
		},
	})
	if err != nil {
		t.Fatalf("seed set eligibility failed: %v", err)
	}

	_, err = adapter.SetValidatorEligibility(context.Background(), &validatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &validatorpb.ValidatorEligibility{
			ValidatorId:     "val-conflict-1",
			OperatorAddress: "tdpnvaloper1conflict",
			Eligible:        false,
		},
	})
	if err == nil {
		t.Fatal("expected eligibility conflict error")
	}
	if !errors.Is(err, ErrEligibilityConflict) {
		t.Fatalf("expected ErrEligibilityConflict, got %v", err)
	}

	stored, ok := k.GetEligibility("val-conflict-1")
	if !ok {
		t.Fatal("expected seeded eligibility to remain stored")
	}
	if !stored.Eligible {
		t.Fatal("expected stored eligibility to remain true after conflict")
	}
}

func TestGRPCMsgServerAdapterRecordValidatorStatus(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgServerAdapter(&k)

	_, err := adapter.SetValidatorEligibility(context.Background(), &validatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &validatorpb.ValidatorEligibility{
			ValidatorId:     "val-1",
			OperatorAddress: "tdpnvaloper1abc",
			Eligible:        true,
		},
	})
	if err != nil {
		t.Fatalf("expected set eligibility success, got %v", err)
	}

	resp, err := adapter.RecordValidatorStatus(context.Background(), &validatorpb.MsgRecordValidatorStatusRequest{
		Record: &validatorpb.ValidatorStatusRecord{
			StatusId:        "status-1",
			ValidatorId:     "val-1",
			LifecycleStatus: validatortypes.ValidatorLifecycleActive,
			EvidenceHeight:  10,
		},
	})
	if err != nil {
		t.Fatalf("expected record status success, got %v", err)
	}
	if resp.GetRecord() == nil {
		t.Fatal("expected record in response")
	}
	if resp.GetRecord().GetStatusId() != "status-1" {
		t.Fatalf("expected status_id status-1, got %q", resp.GetRecord().GetStatusId())
	}

	stored, ok := k.GetStatusRecord("status-1")
	if !ok {
		t.Fatal("expected status to be persisted")
	}
	if stored.ValidatorID != "val-1" {
		t.Fatalf("expected persisted validator id val-1, got %q", stored.ValidatorID)
	}
}

func TestGRPCQueryServerAdapterNotFoundReturnsFoundFalse(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCQueryServerAdapter(&k)

	eligibilityResp, err := adapter.ValidatorEligibility(context.Background(), &validatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: "missing-validator",
	})
	if err != nil {
		t.Fatalf("expected nil error for missing eligibility lookup, got %v", err)
	}
	if eligibilityResp.GetFound() {
		t.Fatal("expected found=false for missing eligibility")
	}

	statusResp, err := adapter.ValidatorStatusRecord(context.Background(), &validatorpb.QueryValidatorStatusRecordRequest{
		StatusId: "missing-status",
	})
	if err != nil {
		t.Fatalf("expected nil error for missing status lookup, got %v", err)
	}
	if statusResp.GetFound() {
		t.Fatal("expected found=false for missing status")
	}
}

func TestGRPCQueryServerAdapterFoundAndList(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEligibility(validatortypes.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
		Status:          chaintypes.ReconciliationPending,
	})
	k.UpsertStatusRecord(validatortypes.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: validatortypes.ValidatorLifecycleJailed,
		EvidenceHeight:  22,
		Status:          chaintypes.ReconciliationSubmitted,
	})
	adapter := NewGRPCQueryServerAdapter(&k)

	eligibilityResp, err := adapter.ValidatorEligibility(context.Background(), &validatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: "val-1",
	})
	if err != nil {
		t.Fatalf("expected eligibility lookup success, got %v", err)
	}
	if !eligibilityResp.GetFound() {
		t.Fatal("expected found=true for eligibility lookup")
	}
	if eligibilityResp.GetEligibility().GetValidatorId() != "val-1" {
		t.Fatalf("expected validator_id val-1, got %q", eligibilityResp.GetEligibility().GetValidatorId())
	}

	statusResp, err := adapter.ValidatorStatusRecord(context.Background(), &validatorpb.QueryValidatorStatusRecordRequest{
		StatusId: "status-1",
	})
	if err != nil {
		t.Fatalf("expected status lookup success, got %v", err)
	}
	if !statusResp.GetFound() {
		t.Fatal("expected found=true for status lookup")
	}
	if statusResp.GetRecord().GetStatusId() != "status-1" {
		t.Fatalf("expected status_id status-1, got %q", statusResp.GetRecord().GetStatusId())
	}
	if statusResp.GetRecord().GetStatus() != validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected submitted status, got %v", statusResp.GetRecord().GetStatus())
	}

	listEligibilityResp, err := adapter.ListValidatorEligibilities(context.Background(), &validatorpb.QueryListValidatorEligibilitiesRequest{})
	if err != nil {
		t.Fatalf("expected list eligibilities success, got %v", err)
	}
	if len(listEligibilityResp.GetEligibilities()) != 1 {
		t.Fatalf("expected 1 eligibility, got %d", len(listEligibilityResp.GetEligibilities()))
	}
	if listEligibilityResp.GetEligibilities()[0].GetValidatorId() != "val-1" {
		t.Fatalf("expected listed validator_id val-1, got %q", listEligibilityResp.GetEligibilities()[0].GetValidatorId())
	}

	listStatusResp, err := adapter.ListValidatorStatusRecords(context.Background(), &validatorpb.QueryListValidatorStatusRecordsRequest{})
	if err != nil {
		t.Fatalf("expected list statuses success, got %v", err)
	}
	if len(listStatusResp.GetRecords()) != 1 {
		t.Fatalf("expected 1 status, got %d", len(listStatusResp.GetRecords()))
	}
	if listStatusResp.GetRecords()[0].GetStatusId() != "status-1" {
		t.Fatalf("expected listed status_id status-1, got %q", listStatusResp.GetRecords()[0].GetStatusId())
	}
}

func TestGRPCAdaptersEligibilityCanonicalWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgServerAdapter(&k)
	queryAdapter := NewGRPCQueryServerAdapter(&k)

	setResp, err := msgAdapter.SetValidatorEligibility(context.Background(), &validatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &validatorpb.ValidatorEligibility{
			ValidatorId:     "  VAL-GRPC-ELIG-1  ",
			OperatorAddress: "  TDPNVALOPER1GRPCELIG  ",
			Eligible:        true,
		},
	})
	if err != nil {
		t.Fatalf("expected set validator eligibility success, got %v", err)
	}
	if setResp.GetEligibility() == nil {
		t.Fatal("expected eligibility in set response")
	}
	if setResp.GetEligibility().GetValidatorId() != "val-grpc-elig-1" {
		t.Fatalf("expected canonical validator_id val-grpc-elig-1, got %q", setResp.GetEligibility().GetValidatorId())
	}

	queryResp, err := queryAdapter.ValidatorEligibility(context.Background(), &validatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: "  VAL-GRPC-ELIG-1  ",
	})
	if err != nil {
		t.Fatalf("expected mixed-case eligibility query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case eligibility query")
	}
	if queryResp.GetEligibility() == nil {
		t.Fatal("expected eligibility in query response")
	}
	if queryResp.GetEligibility().GetValidatorId() != "val-grpc-elig-1" {
		t.Fatalf("expected canonical queried validator_id val-grpc-elig-1, got %q", queryResp.GetEligibility().GetValidatorId())
	}
	if queryResp.GetEligibility().GetOperatorAddress() != "tdpnvaloper1grpcelig" {
		t.Fatalf("expected canonical operator_address tdpnvaloper1grpcelig, got %q", queryResp.GetEligibility().GetOperatorAddress())
	}
}

func TestGRPCAdaptersStatusCanonicalWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgServerAdapter(&k)
	queryAdapter := NewGRPCQueryServerAdapter(&k)

	_, err := msgAdapter.SetValidatorEligibility(context.Background(), &validatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &validatorpb.ValidatorEligibility{
			ValidatorId:     "  VAL-GRPC-STATUS-1 ",
			OperatorAddress: " tdpnvaloper1grpcstatus ",
			Eligible:        true,
		},
	})
	if err != nil {
		t.Fatalf("expected set eligibility success before recording status, got %v", err)
	}

	recordResp, err := msgAdapter.RecordValidatorStatus(context.Background(), &validatorpb.MsgRecordValidatorStatusRequest{
		Record: &validatorpb.ValidatorStatusRecord{
			StatusId:         "  STATUS-GRPC-1  ",
			ValidatorId:      "  VAL-GRPC-STATUS-1  ",
			ConsensusAddress: "  TDPNVALCONS1GRPCSTATUS  ",
			LifecycleStatus:  "  ACTIVE ",
			EvidenceHeight:   33,
		},
	})
	if err != nil {
		t.Fatalf("expected record validator status success, got %v", err)
	}
	if recordResp.GetRecord() == nil {
		t.Fatal("expected status record in create response")
	}
	if recordResp.GetRecord().GetStatusId() != "status-grpc-1" {
		t.Fatalf("expected canonical status_id status-grpc-1, got %q", recordResp.GetRecord().GetStatusId())
	}
	if recordResp.GetRecord().GetValidatorId() != "val-grpc-status-1" {
		t.Fatalf("expected canonical validator_id val-grpc-status-1, got %q", recordResp.GetRecord().GetValidatorId())
	}

	queryResp, err := queryAdapter.ValidatorStatusRecord(context.Background(), &validatorpb.QueryValidatorStatusRecordRequest{
		StatusId: "  STATUS-GRPC-1  ",
	})
	if err != nil {
		t.Fatalf("expected mixed-case status query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case status query")
	}
	if queryResp.GetRecord() == nil {
		t.Fatal("expected status record in query response")
	}
	if queryResp.GetRecord().GetStatusId() != "status-grpc-1" {
		t.Fatalf("expected canonical queried status_id status-grpc-1, got %q", queryResp.GetRecord().GetStatusId())
	}
	if queryResp.GetRecord().GetValidatorId() != "val-grpc-status-1" {
		t.Fatalf("expected canonical queried validator_id val-grpc-status-1, got %q", queryResp.GetRecord().GetValidatorId())
	}
}

func TestGRPCQueryServerAdapterPreviewEpochSelectionDeterministic(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCQueryServerAdapter(&k)

	requestA := &validatorpb.QueryPreviewEpochSelectionRequest{
		Policy: baselinePreviewPolicyProto(),
		Candidates: []*validatorpb.EpochValidatorCandidate{
			previewCandidateProto("rotate-top", "op-rotate-top", "asn-rotate-top", "apac", 99, false),
			previewCandidateProto("stable-low", "op-stable-low", "asn-stable-low", "eu", 80, true),
			previewCandidateProto("rotate-next", "op-rotate-next", "asn-rotate-next", "latam", 70, false),
			previewCandidateProto("stable-high", "op-stable-high", "asn-stable-high", "us", 90, true),
		},
	}
	requestB := &validatorpb.QueryPreviewEpochSelectionRequest{
		Policy: baselinePreviewPolicyProto(),
		Candidates: []*validatorpb.EpochValidatorCandidate{
			requestA.Candidates[3],
			requestA.Candidates[2],
			requestA.Candidates[0],
			requestA.Candidates[1],
		},
	}

	respA, err := adapter.PreviewEpochSelection(context.Background(), requestA)
	if err != nil {
		t.Fatalf("expected preview selection success, got %v", err)
	}
	respB, err := adapter.PreviewEpochSelection(context.Background(), requestB)
	if err != nil {
		t.Fatalf("expected preview selection success for shuffled input, got %v", err)
	}

	idsA := previewResultValidatorIDs(respA.GetResult())
	idsB := previewResultValidatorIDs(respB.GetResult())
	if !reflect.DeepEqual(idsA, idsB) {
		t.Fatalf("expected deterministic selected ids, got %v and %v", idsA, idsB)
	}

	if len(respA.GetResult().GetStableSeats()) != 1 || respA.GetResult().GetStableSeats()[0].GetValidatorId() != "stable-high" {
		t.Fatalf("expected stable seat [stable-high], got %+v", respA.GetResult().GetStableSeats())
	}
	if len(respA.GetResult().GetRotatingSeats()) != 2 {
		t.Fatalf("expected 2 rotating seats, got %d", len(respA.GetResult().GetRotatingSeats()))
	}
	if respA.GetResult().GetRotatingSeats()[0].GetValidatorId() != "rotate-top" ||
		respA.GetResult().GetRotatingSeats()[1].GetValidatorId() != "stable-low" {
		t.Fatalf("expected rotating seats [rotate-top stable-low], got %+v", respA.GetResult().GetRotatingSeats())
	}
}

func TestGRPCQueryServerAdapterPreviewEpochSelectionValidationErrorPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCQueryServerAdapter(&k)

	_, err := adapter.PreviewEpochSelection(context.Background(), &validatorpb.QueryPreviewEpochSelectionRequest{
		Policy: &validatorpb.EpochSelectionPolicy{
			Epoch:             10,
			StableSeatCount:   0,
			RotatingSeatCount: 0,
		},
	})
	if err == nil {
		t.Fatal("expected preview validation error")
	}
	if !strings.Contains(err.Error(), "at least one stable or rotating seat is required") {
		t.Fatalf("expected seat validation error, got %v", err)
	}
}

func TestGRPCAdaptersNilKeeperPropagatesErrNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	msgAdapter := NewGRPCMsgServerAdapter(k)
	queryAdapter := NewGRPCQueryServerAdapter(k)

	_, msgErr := msgAdapter.SetValidatorEligibility(context.Background(), &validatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &validatorpb.ValidatorEligibility{
			ValidatorId:     "val-nil",
			OperatorAddress: "tdpnvaloper1nil",
			Eligible:        true,
		},
	})
	if !errors.Is(msgErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from msg adapter, got %v", msgErr)
	}

	_, queryErr := queryAdapter.ListValidatorEligibilities(context.Background(), &validatorpb.QueryListValidatorEligibilitiesRequest{})
	if !errors.Is(queryErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from query adapter, got %v", queryErr)
	}
}

func TestGRPCAdaptersNilRequestsAreFailSafe(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgServerAdapter(&k)
	queryAdapter := NewGRPCQueryServerAdapter(&k)

	_, setErr := msgAdapter.SetValidatorEligibility(context.Background(), nil)
	if !errors.Is(setErr, ErrInvalidEligibility) {
		t.Fatalf("expected ErrInvalidEligibility for nil set request, got %v", setErr)
	}

	_, statusErr := msgAdapter.RecordValidatorStatus(context.Background(), nil)
	if !errors.Is(statusErr, ErrInvalidStatusRecord) {
		t.Fatalf("expected ErrInvalidStatusRecord for nil status request, got %v", statusErr)
	}

	eligibilityResp, eligibilityErr := queryAdapter.ValidatorEligibility(context.Background(), nil)
	if eligibilityErr != nil {
		t.Fatalf("expected nil error for nil eligibility query request, got %v", eligibilityErr)
	}
	if eligibilityResp.GetFound() {
		t.Fatal("expected found=false for nil eligibility query request")
	}
	if eligibilityResp.GetEligibility() != nil {
		t.Fatal("expected nil eligibility when found=false")
	}

	statusResp, statusErr2 := queryAdapter.ValidatorStatusRecord(context.Background(), nil)
	if statusErr2 != nil {
		t.Fatalf("expected nil error for nil status query request, got %v", statusErr2)
	}
	if statusResp.GetFound() {
		t.Fatal("expected found=false for nil status query request")
	}
	if statusResp.GetRecord() != nil {
		t.Fatal("expected nil status record when found=false")
	}

	_, previewErr := queryAdapter.PreviewEpochSelection(context.Background(), nil)
	if previewErr == nil {
		t.Fatal("expected deterministic validation error for nil preview request")
	}
	if !strings.Contains(previewErr.Error(), "at least one stable or rotating seat is required") {
		t.Fatalf("expected seat validation error for nil preview request, got %v", previewErr)
	}
}

func TestStatusMappingFromAndToProtoCoversExplicitAndDefaultBranches(t *testing.T) {
	t.Parallel()

	fromProtoCases := []struct {
		name string
		in   validatorpb.ReconciliationStatus
		want chaintypes.ReconciliationStatus
	}{
		{
			name: "pending",
			in:   validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
			want: chaintypes.ReconciliationPending,
		},
		{
			name: "submitted",
			in:   validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
			want: chaintypes.ReconciliationSubmitted,
		},
		{
			name: "confirmed",
			in:   validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
			want: chaintypes.ReconciliationConfirmed,
		},
		{
			name: "failed",
			in:   validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
			want: chaintypes.ReconciliationFailed,
		},
		{
			name: "default-unspecified",
			in:   validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
			want: "",
		},
	}
	for _, tc := range fromProtoCases {
		tc := tc
		t.Run("fromProto/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := statusFromProto(tc.in)
			if got != tc.want {
				t.Fatalf("statusFromProto(%v): expected %q, got %q", tc.in, tc.want, got)
			}
		})
	}

	toProtoCases := []struct {
		name string
		in   chaintypes.ReconciliationStatus
		want validatorpb.ReconciliationStatus
	}{
		{
			name: "pending",
			in:   chaintypes.ReconciliationPending,
			want: validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
		},
		{
			name: "submitted",
			in:   chaintypes.ReconciliationSubmitted,
			want: validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
		{
			name: "confirmed",
			in:   chaintypes.ReconciliationConfirmed,
			want: validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
		},
		{
			name: "failed",
			in:   chaintypes.ReconciliationFailed,
			want: validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
		},
		{
			name: "default-empty",
			in:   "",
			want: validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
		},
	}
	for _, tc := range toProtoCases {
		tc := tc
		t.Run("toProto/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := statusToProto(tc.in)
			if got != tc.want {
				t.Fatalf("statusToProto(%q): expected %v, got %v", tc.in, tc.want, got)
			}
		})
	}
}

func baselinePreviewPolicyProto() *validatorpb.EpochSelectionPolicy {
	return &validatorpb.EpochSelectionPolicy{
		Epoch:               10,
		StableSeatCount:     1,
		RotatingSeatCount:   2,
		MinStake:            100,
		MinStakeAgeEpochs:   3,
		MinHealthScore:      70,
		MinResourceHeadroom: 20,
		WarmupEpochs:        2,
		CooldownEpochs:      3,
		MaxSeatsPerOperator: 10,
		MaxSeatsPerAsn:      10,
		MaxSeatsPerRegion:   10,
	}
}

func previewCandidateProto(validatorID string, operatorID string, asn string, region string, score int64, stablePreferred bool) *validatorpb.EpochValidatorCandidate {
	return &validatorpb.EpochValidatorCandidate{
		ValidatorId:               validatorID,
		OperatorId:                operatorID,
		Asn:                       asn,
		Region:                    region,
		Stake:                     1_000,
		StakeAgeEpochs:            6,
		HealthScore:               95,
		ResourceHeadroom:          60,
		ConsecutiveEligibleEpochs: 4,
		LastRemovedEpoch:          -1,
		Score:                     score,
		StableSeatPreferred:       stablePreferred,
	}
}

func previewResultValidatorIDs(result *validatorpb.EpochSelectionResult) []string {
	if result == nil {
		return nil
	}

	ids := make([]string, 0, len(result.GetStableSeats())+len(result.GetRotatingSeats()))
	for _, candidate := range result.GetStableSeats() {
		ids = append(ids, candidate.GetValidatorId())
	}
	for _, candidate := range result.GetRotatingSeats() {
		ids = append(ids, candidate.GetValidatorId())
	}
	return ids
}
