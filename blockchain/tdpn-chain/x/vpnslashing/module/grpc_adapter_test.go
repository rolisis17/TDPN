package module

import (
	"context"
	"errors"
	"testing"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	modtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

func TestGRPCMsgAdapterSubmitEvidenceAndRecordPenalty(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgAdapter(NewMsgServer(&k))

	evidenceResp, err := adapter.SubmitEvidence(context.Background(), &pb.MsgSubmitEvidenceRequest{
		Evidence: &pb.SlashEvidence{
			EvidenceId:    "evidence-grpc-1",
			ProviderId:    "provider-grpc-1",
			SessionId:     "session-grpc-1",
			ViolationType: "double-sign",
			Kind:          modtypes.EvidenceKindObjective,
			ProofHash:     testSHAProof("proof-grpc-1"),
			SlashAmount:   1500,
			SlashDenom:    "UTDPN",
			Status:        pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
		},
	})
	if err != nil {
		t.Fatalf("SubmitEvidence returned unexpected error: %v", err)
	}
	if evidenceResp.GetEvidence().GetEvidenceId() != "evidence-grpc-1" {
		t.Fatalf("expected evidence id %q, got %q", "evidence-grpc-1", evidenceResp.GetEvidence().GetEvidenceId())
	}
	if evidenceResp.GetEvidence().GetViolationType() != "double-sign" {
		t.Fatalf("expected violation_type %q, got %q", "double-sign", evidenceResp.GetEvidence().GetViolationType())
	}
	if evidenceResp.GetEvidence().GetSlashAmount() != 1500 {
		t.Fatalf("expected evidence slash amount 1500, got %d", evidenceResp.GetEvidence().GetSlashAmount())
	}
	if evidenceResp.GetEvidence().GetSlashDenom() != "utdpn" {
		t.Fatalf("expected evidence slash denom %q, got %q", "utdpn", evidenceResp.GetEvidence().GetSlashDenom())
	}
	if evidenceResp.GetEvidence().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected server-owned submitted evidence status, got %v", evidenceResp.GetEvidence().GetStatus())
	}
	confirmResp, err := adapter.ConfirmEvidence(context.Background(), &pb.MsgConfirmEvidenceRequest{
		EvidenceId: " EVIDENCE-GRPC-1 ",
	})
	if err != nil {
		t.Fatalf("ConfirmEvidence returned unexpected error: %v", err)
	}
	if confirmResp.GetEvidence().GetEvidenceId() != "evidence-grpc-1" {
		t.Fatalf("expected confirmed evidence id %q, got %q", "evidence-grpc-1", confirmResp.GetEvidence().GetEvidenceId())
	}
	if confirmResp.GetEvidence().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED {
		t.Fatalf("expected confirmed evidence status, got %v", confirmResp.GetEvidence().GetStatus())
	}

	penaltyResp, err := adapter.RecordPenalty(context.Background(), &pb.MsgRecordPenaltyRequest{
		Penalty: &pb.PenaltyDecision{
			PenaltyId:       "penalty-grpc-1",
			EvidenceId:      "evidence-grpc-1",
			SlashBasisPoint: 42,
			SlashAmount:     1500,
			SlashDenom:      "UTDPN",
		},
	})
	if err != nil {
		t.Fatalf("RecordPenalty returned unexpected error: %v", err)
	}
	if penaltyResp.GetPenalty().GetPenaltyId() != "penalty-grpc-1" {
		t.Fatalf("expected penalty id %q, got %q", "penalty-grpc-1", penaltyResp.GetPenalty().GetPenaltyId())
	}
	if penaltyResp.GetPenalty().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected submitted status, got %v", penaltyResp.GetPenalty().GetStatus())
	}
	if penaltyResp.GetPenalty().GetSlashAmount() != 1500 {
		t.Fatalf("expected penalty slash amount 1500, got %d", penaltyResp.GetPenalty().GetSlashAmount())
	}
	if penaltyResp.GetPenalty().GetSlashDenom() != "utdpn" {
		t.Fatalf("expected penalty slash denom %q, got %q", "utdpn", penaltyResp.GetPenalty().GetSlashDenom())
	}
}

func TestGRPCMsgAdapterCanonicalizesViolationTypeAcrossSubmitQueryAndList(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgAdapter(NewMsgServer(&k))
	queryAdapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	const evidenceID = "evidence-grpc-canonical-1"
	const inputViolationType = "  Session-Replay-Proof  "
	const expectedViolationType = "session-replay-proof"

	evidenceResp, err := msgAdapter.SubmitEvidence(context.Background(), &pb.MsgSubmitEvidenceRequest{
		Evidence: &pb.SlashEvidence{
			EvidenceId:    evidenceID,
			ProviderId:    "provider-grpc-canonical-1",
			SessionId:     "session-grpc-canonical-1",
			ViolationType: inputViolationType,
			Kind:          modtypes.EvidenceKindObjective,
			ProofHash:     testSHAProof("proof-grpc-canonical-1"),
		},
	})
	if err != nil {
		t.Fatalf("SubmitEvidence returned unexpected error: %v", err)
	}
	if got := evidenceResp.GetEvidence().GetViolationType(); got != expectedViolationType {
		t.Fatalf("expected canonical submit violation_type %q, got %q", expectedViolationType, got)
	}

	stored, found := k.GetEvidence(evidenceID)
	if !found {
		t.Fatalf("expected persisted evidence %q", evidenceID)
	}
	if stored.ViolationType != expectedViolationType {
		t.Fatalf("expected persisted canonical violation_type %q, got %q", expectedViolationType, stored.ViolationType)
	}

	evidenceByID, err := queryAdapter.SlashEvidence(context.Background(), &pb.QuerySlashEvidenceRequest{EvidenceId: evidenceID})
	if err != nil {
		t.Fatalf("SlashEvidence returned unexpected error: %v", err)
	}
	if !evidenceByID.GetFound() {
		t.Fatalf("expected evidence %q to be found", evidenceID)
	}
	if got := evidenceByID.GetEvidence().GetViolationType(); got != expectedViolationType {
		t.Fatalf("expected canonical query violation_type %q, got %q", expectedViolationType, got)
	}

	evidenceList, err := queryAdapter.ListSlashEvidence(context.Background(), &pb.QueryListSlashEvidenceRequest{})
	if err != nil {
		t.Fatalf("ListSlashEvidence returned unexpected error: %v", err)
	}
	if len(evidenceList.GetEvidence()) != 1 {
		t.Fatalf("expected 1 evidence record in list, got %d", len(evidenceList.GetEvidence()))
	}
	if got := evidenceList.GetEvidence()[0].GetViolationType(); got != expectedViolationType {
		t.Fatalf("expected canonical list violation_type %q, got %q", expectedViolationType, got)
	}
}

func TestGRPCMsgAdapterNilRequestsMapToValidationClassification(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgAdapter(NewMsgServer(&k))

	_, evidenceErr := adapter.SubmitEvidence(context.Background(), nil)
	if !errors.Is(evidenceErr, ErrInvalidEvidence) {
		t.Fatalf("expected ErrInvalidEvidence for nil evidence request, got %v", evidenceErr)
	}

	_, confirmErr := adapter.ConfirmEvidence(context.Background(), nil)
	if !errors.Is(confirmErr, ErrInvalidEvidence) {
		t.Fatalf("expected ErrInvalidEvidence for nil confirm request, got %v", confirmErr)
	}

	_, penaltyErr := adapter.RecordPenalty(context.Background(), nil)
	if !errors.Is(penaltyErr, ErrInvalidPenalty) {
		t.Fatalf("expected ErrInvalidPenalty for nil penalty request, got %v", penaltyErr)
	}
}

func TestGRPCMsgAdapterSubmitEvidenceHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgAdapter(NewMsgServer(&k))

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	const evidenceID = "evidence-grpc-canceled-submit"
	_, err := adapter.SubmitEvidence(canceledCtx, &pb.MsgSubmitEvidenceRequest{
		Evidence: &pb.SlashEvidence{
			EvidenceId:    evidenceID,
			ProviderId:    "provider-grpc-canceled-submit",
			SessionId:     "session-grpc-canceled-submit",
			ViolationType: "double-sign",
			Kind:          modtypes.EvidenceKindObjective,
			ProofHash:     testSHAProof("proof-grpc-canceled-submit"),
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, ok := k.GetEvidence(evidenceID); ok {
		t.Fatal("did not expect evidence persistence on canceled context")
	}
}

func TestGRPCMsgAdapterConfirmEvidenceHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgAdapter(NewMsgServer(&k))

	const evidenceID = "evidence-grpc-canceled-confirm"
	if _, err := adapter.SubmitEvidence(context.Background(), &pb.MsgSubmitEvidenceRequest{
		Evidence: &pb.SlashEvidence{
			EvidenceId:    evidenceID,
			ProviderId:    "provider-grpc-canceled-confirm",
			SessionId:     "session-grpc-canceled-confirm",
			ViolationType: "double-sign",
			Kind:          modtypes.EvidenceKindObjective,
			ProofHash:     testSHAProof("proof-grpc-canceled-confirm"),
		},
	}); err != nil {
		t.Fatalf("SubmitEvidence returned unexpected error: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := adapter.ConfirmEvidence(canceledCtx, &pb.MsgConfirmEvidenceRequest{EvidenceId: evidenceID})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	stored, ok := k.GetEvidence(evidenceID)
	if !ok {
		t.Fatalf("expected persisted evidence %q", evidenceID)
	}
	if stored.Status == chaintypes.ReconciliationConfirmed {
		t.Fatal("did not expect evidence confirmation on canceled context")
	}
}

func TestGRPCMsgAdapterRecordPenaltyHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgAdapter(NewMsgServer(&k))

	const evidenceID = "evidence-grpc-canceled-penalty"
	const penaltyID = "penalty-grpc-canceled-penalty"
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:    evidenceID,
		ViolationType: "double-sign",
		Kind:          modtypes.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-grpc-canceled-penalty"),
	})

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := adapter.RecordPenalty(canceledCtx, &pb.MsgRecordPenaltyRequest{
		Penalty: &pb.PenaltyDecision{
			PenaltyId:       penaltyID,
			EvidenceId:      evidenceID,
			SlashBasisPoint: 10,
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, ok := k.GetPenalty(penaltyID); ok {
		t.Fatal("did not expect penalty persistence on canceled context")
	}
}

func TestGRPCQueryAdapterListMethodsHonorCanceledContext(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, evidenceErr := adapter.ListSlashEvidence(canceledCtx, &pb.QueryListSlashEvidenceRequest{})
	if !errors.Is(evidenceErr, context.Canceled) {
		t.Fatalf("expected context.Canceled from ListSlashEvidence, got %v", evidenceErr)
	}

	_, penaltyErr := adapter.ListPenaltyDecisions(canceledCtx, &pb.QueryListPenaltyDecisionsRequest{})
	if !errors.Is(penaltyErr, context.Canceled) {
		t.Fatalf("expected context.Canceled from ListPenaltyDecisions, got %v", penaltyErr)
	}
}

func TestGRPCQueryAdapterNotFoundMapsToFoundFalse(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	evidenceResp, err := adapter.SlashEvidence(context.Background(), &pb.QuerySlashEvidenceRequest{EvidenceId: "missing-evidence"})
	if err != nil {
		t.Fatalf("SlashEvidence returned unexpected error: %v", err)
	}
	if evidenceResp.GetFound() {
		t.Fatal("expected found=false for missing evidence")
	}
	if evidenceResp.GetEvidence() != nil {
		t.Fatal("expected nil evidence when found=false")
	}

	penaltyResp, err := adapter.PenaltyDecision(context.Background(), &pb.QueryPenaltyDecisionRequest{PenaltyId: "missing-penalty"})
	if err != nil {
		t.Fatalf("PenaltyDecision returned unexpected error: %v", err)
	}
	if penaltyResp.GetFound() {
		t.Fatal("expected found=false for missing penalty")
	}
	if penaltyResp.GetPenalty() != nil {
		t.Fatal("expected nil penalty when found=false")
	}
}

func TestGRPCQueryAdapterSlashEvidenceRoundtripIncludesViolationType(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:    "evidence-query-1",
		ViolationType: "invalid-settlement-proof",
		Kind:          modtypes.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-query-1"),
	})

	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))
	resp, err := adapter.SlashEvidence(context.Background(), &pb.QuerySlashEvidenceRequest{EvidenceId: "evidence-query-1"})
	if err != nil {
		t.Fatalf("SlashEvidence returned unexpected error: %v", err)
	}
	if !resp.GetFound() {
		t.Fatal("expected found=true for existing evidence")
	}
	if resp.GetEvidence().GetViolationType() != "invalid-settlement-proof" {
		t.Fatalf("expected violation_type %q, got %q", "invalid-settlement-proof", resp.GetEvidence().GetViolationType())
	}
}

func TestGRPCQueryAdapterListMethods(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:    "evidence-b",
		ViolationType: "session-replay-proof",
		Kind:          modtypes.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-b"),
	})
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:    "evidence-a",
		ViolationType: "downtime-proof",
		Kind:          modtypes.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-a"),
	})
	k.UpsertPenalty(modtypes.PenaltyDecision{
		PenaltyID:       "penalty-b",
		EvidenceID:      "evidence-b",
		SlashBasisPoint: 20,
	})
	k.UpsertPenalty(modtypes.PenaltyDecision{
		PenaltyID:       "penalty-a",
		EvidenceID:      "evidence-a",
		SlashBasisPoint: 10,
	})

	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	evidenceResp, err := adapter.ListSlashEvidence(context.Background(), &pb.QueryListSlashEvidenceRequest{})
	if err != nil {
		t.Fatalf("ListSlashEvidence returned unexpected error: %v", err)
	}
	if len(evidenceResp.GetEvidence()) != 2 {
		t.Fatalf("expected 2 evidence records, got %d", len(evidenceResp.GetEvidence()))
	}
	if evidenceResp.GetEvidence()[0].GetEvidenceId() != "evidence-a" || evidenceResp.GetEvidence()[1].GetEvidenceId() != "evidence-b" {
		t.Fatalf("expected sorted evidence IDs [evidence-a evidence-b], got [%s %s]", evidenceResp.GetEvidence()[0].GetEvidenceId(), evidenceResp.GetEvidence()[1].GetEvidenceId())
	}
	if evidenceResp.GetEvidence()[0].GetViolationType() != "downtime-proof" || evidenceResp.GetEvidence()[1].GetViolationType() != "session-replay-proof" {
		t.Fatalf("expected sorted violation types [downtime-proof session-replay-proof], got [%s %s]", evidenceResp.GetEvidence()[0].GetViolationType(), evidenceResp.GetEvidence()[1].GetViolationType())
	}

	penaltiesResp, err := adapter.ListPenaltyDecisions(context.Background(), &pb.QueryListPenaltyDecisionsRequest{})
	if err != nil {
		t.Fatalf("ListPenaltyDecisions returned unexpected error: %v", err)
	}
	if len(penaltiesResp.GetPenalties()) != 2 {
		t.Fatalf("expected 2 penalties, got %d", len(penaltiesResp.GetPenalties()))
	}
	if penaltiesResp.GetPenalties()[0].GetPenaltyId() != "penalty-a" || penaltiesResp.GetPenalties()[1].GetPenaltyId() != "penalty-b" {
		t.Fatalf("expected sorted penalty IDs [penalty-a penalty-b], got [%s %s]", penaltiesResp.GetPenalties()[0].GetPenaltyId(), penaltiesResp.GetPenalties()[1].GetPenaltyId())
	}
}

func TestGRPCQueryAdapterListSlashEvidenceForwardsFilters(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:      "evidence-filter-target",
		ProviderID:      "provider-filter-1",
		SessionID:       "session-filter-1",
		ViolationType:   "double-sign",
		Kind:            modtypes.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-filter-target"),
		SubmittedAtUnix: 200,
		Status:          chaintypes.ReconciliationConfirmed,
	})
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:      "evidence-filter-too-old",
		ProviderID:      "provider-filter-1",
		SessionID:       "session-filter-1",
		ViolationType:   "double-sign",
		Kind:            modtypes.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-filter-too-old"),
		SubmittedAtUnix: 50,
		Status:          chaintypes.ReconciliationConfirmed,
	})
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:      "evidence-filter-failed",
		ProviderID:      "provider-filter-1",
		SessionID:       "session-filter-1",
		ViolationType:   "double-sign",
		Kind:            modtypes.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-filter-failed"),
		SubmittedAtUnix: 210,
		Status:          chaintypes.ReconciliationFailed,
	})
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:      "evidence-filter-provider-mismatch",
		ProviderID:      "provider-filter-2",
		SessionID:       "session-filter-1",
		ViolationType:   "double-sign",
		Kind:            modtypes.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-filter-provider-mismatch"),
		SubmittedAtUnix: 220,
		Status:          chaintypes.ReconciliationConfirmed,
	})
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:    "evidence-filter-zero",
		ProviderID:    "provider-filter-1",
		SessionID:     "session-filter-1",
		ViolationType: "double-sign",
		Kind:          modtypes.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-filter-zero"),
		Status:        chaintypes.ReconciliationConfirmed,
	})

	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))
	resp, err := adapter.ListSlashEvidence(context.Background(), &pb.QueryListSlashEvidenceRequest{
		ProviderId:             "provider-filter-1",
		SessionId:              "session-filter-1",
		ViolationType:          "double-sign",
		SubmittedAtOrAfterUnix: 100,
		SubmittedBeforeUnix:    300,
		IncludeFailed:          boolPtr(false),
	})
	if err != nil {
		t.Fatalf("ListSlashEvidence returned unexpected error: %v", err)
	}
	if len(resp.GetEvidence()) != 1 {
		t.Fatalf("expected 1 filtered evidence record, got %d: %+v", len(resp.GetEvidence()), resp.GetEvidence())
	}
	if got := resp.GetEvidence()[0].GetEvidenceId(); got != "evidence-filter-target" {
		t.Fatalf("expected filtered evidence id %q, got %q", "evidence-filter-target", got)
	}
}

func TestGRPCQueryAdapterListSlashEvidenceReturnsFailedStatusWhenIncluded(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:      "evidence-status-submitted",
		ProviderID:      "provider-status-1",
		SessionID:       "session-status-1",
		ViolationType:   "double-sign",
		Kind:            modtypes.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-status-submitted"),
		SubmittedAtUnix: 200,
		Status:          chaintypes.ReconciliationSubmitted,
	})
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:      "evidence-status-failed",
		ProviderID:      "provider-status-1",
		SessionID:       "session-status-1",
		ViolationType:   "double-sign",
		Kind:            modtypes.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-status-failed"),
		SubmittedAtUnix: 210,
		Status:          chaintypes.ReconciliationFailed,
	})

	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))
	resp, err := adapter.ListSlashEvidence(context.Background(), &pb.QueryListSlashEvidenceRequest{
		ProviderId:    "provider-status-1",
		SessionId:     "session-status-1",
		IncludeFailed: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("ListSlashEvidence returned unexpected error: %v", err)
	}
	if len(resp.GetEvidence()) != 2 {
		t.Fatalf("expected submitted and failed evidence records, got %d", len(resp.GetEvidence()))
	}
	seenFailed := false
	for _, evidence := range resp.GetEvidence() {
		if evidence.GetEvidenceId() == "evidence-status-failed" {
			seenFailed = true
			if evidence.GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED {
				t.Fatalf("expected failed status in query response, got %v", evidence.GetStatus())
			}
		}
	}
	if !seenFailed {
		t.Fatal("expected failed evidence record to be returned when include_failed=true")
	}
}

func TestGRPCQueryAdapterListSlashEvidenceIncludeFailedPresence(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:    "evidence-grpc-presence-submitted",
		ViolationType: "double-sign",
		Kind:          modtypes.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-grpc-presence-submitted"),
		Status:        chaintypes.ReconciliationSubmitted,
	})
	k.UpsertEvidence(modtypes.SlashEvidence{
		EvidenceID:    "evidence-grpc-presence-failed",
		ViolationType: "double-sign",
		Kind:          modtypes.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-grpc-presence-failed"),
		Status:        chaintypes.ReconciliationFailed,
	})

	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))
	defaultResp, err := adapter.ListSlashEvidence(context.Background(), &pb.QueryListSlashEvidenceRequest{})
	if err != nil {
		t.Fatalf("ListSlashEvidence returned unexpected error: %v", err)
	}
	if len(defaultResp.GetEvidence()) != 2 {
		t.Fatalf("expected unset include_failed to preserve failed records, got %d", len(defaultResp.GetEvidence()))
	}

	explicitFalseResp, err := adapter.ListSlashEvidence(context.Background(), &pb.QueryListSlashEvidenceRequest{
		IncludeFailed: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("ListSlashEvidence returned unexpected error: %v", err)
	}
	if len(explicitFalseResp.GetEvidence()) != 1 {
		t.Fatalf("expected explicit false include_failed to drop failed records, got %d", len(explicitFalseResp.GetEvidence()))
	}
	if got := explicitFalseResp.GetEvidence()[0].GetEvidenceId(); got != "evidence-grpc-presence-submitted" {
		t.Fatalf("expected submitted evidence after explicit false include_failed, got %q", got)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func TestGRPCAdaptersNilKeeperPropagatesErrNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	msgAdapter := NewGRPCMsgAdapter(NewMsgServer(k))
	queryAdapter := NewGRPCQueryAdapter(NewQueryServer(k))

	_, msgErr := msgAdapter.SubmitEvidence(context.Background(), &pb.MsgSubmitEvidenceRequest{
		Evidence: &pb.SlashEvidence{EvidenceId: "evidence-nil"},
	})
	if !errors.Is(msgErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from msg adapter, got %v", msgErr)
	}

	_, queryErr := queryAdapter.ListSlashEvidence(context.Background(), &pb.QueryListSlashEvidenceRequest{})
	if !errors.Is(queryErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from query adapter, got %v", queryErr)
	}
}

func TestModuleStatusToProtoMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  chaintypes.ReconciliationStatus
		expect pb.ReconciliationStatus
	}{
		{
			name:   "pending",
			input:  chaintypes.ReconciliationPending,
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
		},
		{
			name:   "submitted",
			input:  chaintypes.ReconciliationSubmitted,
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
		{
			name:   "confirmed",
			input:  chaintypes.ReconciliationConfirmed,
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
		},
		{
			name:   "failed",
			input:  chaintypes.ReconciliationFailed,
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
		},
		{
			name:   "default unknown",
			input:  chaintypes.ReconciliationStatus("unexpected-status"),
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := moduleStatusToProto(tc.input)
			if got != tc.expect {
				t.Fatalf("expected proto status %v, got %v", tc.expect, got)
			}
		})
	}
}

func TestProtoStatusToModuleMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  pb.ReconciliationStatus
		expect chaintypes.ReconciliationStatus
	}{
		{
			name:   "pending",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
			expect: chaintypes.ReconciliationPending,
		},
		{
			name:   "submitted",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
			expect: chaintypes.ReconciliationSubmitted,
		},
		{
			name:   "confirmed",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
			expect: chaintypes.ReconciliationConfirmed,
		},
		{
			name:   "failed",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
			expect: chaintypes.ReconciliationFailed,
		},
		{
			name:   "default unspecified",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
			expect: "",
		},
		{
			name:   "default unknown enum",
			input:  pb.ReconciliationStatus(999),
			expect: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := protoStatusToModule(tc.input)
			if got != tc.expect {
				t.Fatalf("expected module status %q, got %q", tc.expect, got)
			}
		})
	}
}
