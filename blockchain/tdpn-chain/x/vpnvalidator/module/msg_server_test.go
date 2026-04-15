package module

import (
	"errors"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestMsgServerSetValidatorEligibilityHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	resp, err := server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-1",
			OperatorAddress: "tdpnvaloper1abc",
			Eligible:        true,
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first eligibility")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first eligibility")
	}
	if resp.Eligibility.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, resp.Eligibility.Status)
	}
}

func TestMsgServerSetValidatorEligibilityIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-2",
			OperatorAddress: "tdpnvaloper1def",
			Eligible:        true,
		},
	}
	if _, err := server.SetValidatorEligibility(req); err != nil {
		t.Fatalf("first set eligibility failed: %v", err)
	}

	resp, err := server.SetValidatorEligibility(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replay")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replay")
	}
}

func TestMsgServerSetValidatorEligibilityConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	base := SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-3",
			OperatorAddress: "tdpnvaloper1ghi",
			Eligible:        true,
		},
	}
	if _, err := server.SetValidatorEligibility(base); err != nil {
		t.Fatalf("seed eligibility failed: %v", err)
	}

	conflict := base
	conflict.Eligibility.Eligible = false
	resp, err := server.SetValidatorEligibility(conflict)
	if err == nil {
		t.Fatal("expected eligibility conflict error")
	}
	if !errors.Is(err, ErrEligibilityConflict) {
		t.Fatalf("expected ErrEligibilityConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerSetValidatorEligibilityInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID: "val-invalid",
			Eligible:    true,
		},
	})
	if err == nil {
		t.Fatal("expected invalid eligibility error")
	}
	if !errors.Is(err, ErrInvalidEligibility) {
		t.Fatalf("expected ErrInvalidEligibility, got %v", err)
	}
}

func TestMsgServerRecordValidatorStatusHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-4",
			OperatorAddress: "tdpnvaloper1jkl",
			Eligible:        true,
		},
	}); err != nil {
		t.Fatalf("set eligibility failed: %v", err)
	}

	resp, err := server.RecordValidatorStatus(RecordValidatorStatusRequest{
		Record: types.ValidatorStatusRecord{
			StatusID:        "status-4",
			ValidatorID:     "val-4",
			LifecycleStatus: types.ValidatorLifecycleActive,
			EvidenceHeight:  100,
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first status")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first status")
	}
	if resp.Record.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationSubmitted, resp.Record.Status)
	}
}

func TestMsgServerRecordValidatorStatusIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-5",
			OperatorAddress: "tdpnvaloper1mno",
			Eligible:        true,
		},
	}); err != nil {
		t.Fatalf("set eligibility failed: %v", err)
	}

	req := RecordValidatorStatusRequest{
		Record: types.ValidatorStatusRecord{
			StatusID:        "status-5",
			ValidatorID:     "val-5",
			LifecycleStatus: types.ValidatorLifecycleJailed,
			EvidenceHeight:  200,
		},
	}
	if _, err := server.RecordValidatorStatus(req); err != nil {
		t.Fatalf("first status record failed: %v", err)
	}

	resp, err := server.RecordValidatorStatus(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replay")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replay")
	}
}

func TestMsgServerRecordValidatorStatusConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-6",
			OperatorAddress: "tdpnvaloper1pqr",
			Eligible:        true,
		},
	}); err != nil {
		t.Fatalf("set eligibility failed: %v", err)
	}

	base := RecordValidatorStatusRequest{
		Record: types.ValidatorStatusRecord{
			StatusID:        "status-6",
			ValidatorID:     "val-6",
			LifecycleStatus: types.ValidatorLifecycleActive,
			EvidenceHeight:  300,
		},
	}
	if _, err := server.RecordValidatorStatus(base); err != nil {
		t.Fatalf("first status record failed: %v", err)
	}

	conflict := base
	conflict.Record.LifecycleStatus = types.ValidatorLifecycleSuspended
	resp, err := server.RecordValidatorStatus(conflict)
	if err == nil {
		t.Fatal("expected status conflict error")
	}
	if !errors.Is(err, ErrStatusConflict) {
		t.Fatalf("expected ErrStatusConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerRecordValidatorStatusInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-7",
			OperatorAddress: "tdpnvaloper1stu",
			Eligible:        true,
		},
	}); err != nil {
		t.Fatalf("set eligibility failed: %v", err)
	}

	_, err := server.RecordValidatorStatus(RecordValidatorStatusRequest{
		Record: types.ValidatorStatusRecord{
			StatusID:    "status-invalid",
			ValidatorID: "val-7",
		},
	})
	if err == nil {
		t.Fatal("expected invalid status error")
	}
	if !errors.Is(err, ErrInvalidStatusRecord) {
		t.Fatalf("expected ErrInvalidStatusRecord, got %v", err)
	}
}

func TestMsgServerRecordValidatorStatusEligibilityNotFoundPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.RecordValidatorStatus(RecordValidatorStatusRequest{
		Record: types.ValidatorStatusRecord{
			StatusID:        "status-missing",
			ValidatorID:     "val-missing",
			LifecycleStatus: types.ValidatorLifecycleActive,
		},
	})
	if err == nil {
		t.Fatal("expected eligibility not found error")
	}
	if !errors.Is(err, ErrEligibilityNotFound) {
		t.Fatalf("expected ErrEligibilityNotFound, got %v", err)
	}
}

func TestMsgServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewMsgServer(k)

	_, setErr := server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-nil",
			OperatorAddress: "tdpnvaloper1nil",
			Eligible:        true,
		},
	})
	if !errors.Is(setErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on set eligibility, got %v", setErr)
	}

	_, statusErr := server.RecordValidatorStatus(RecordValidatorStatusRequest{
		Record: types.ValidatorStatusRecord{
			StatusID:        "status-nil",
			ValidatorID:     "val-nil",
			LifecycleStatus: types.ValidatorLifecycleActive,
		},
	})
	if !errors.Is(statusErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on record status, got %v", statusErr)
	}
}

func TestMsgServerRecordValidatorStatusErrorIncludesConflictDetails(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: types.ValidatorEligibility{
			ValidatorID:     "val-err-details",
			OperatorAddress: "tdpnvaloper1err",
			Eligible:        true,
		},
	}); err != nil {
		t.Fatalf("set eligibility failed: %v", err)
	}

	base := RecordValidatorStatusRequest{
		Record: types.ValidatorStatusRecord{
			StatusID:        "status-err-details",
			ValidatorID:     "val-err-details",
			LifecycleStatus: types.ValidatorLifecycleActive,
			EvidenceHeight:  1,
		},
	}
	if _, err := server.RecordValidatorStatus(base); err != nil {
		t.Fatalf("seed status failed: %v", err)
	}

	conflict := base
	conflict.Record.EvidenceHeight = 2
	_, err := server.RecordValidatorStatus(conflict)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflicting fields detail, got: %v", err)
	}
}
