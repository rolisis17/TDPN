package keeper

import (
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestKeeperEligibilityUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetEligibility("missing"); ok {
		t.Fatal("expected missing eligibility lookup to return ok=false")
	}

	initial := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}
	k.UpsertEligibility(initial)

	got, ok := k.GetEligibility(initial.ValidatorID)
	if !ok {
		t.Fatal("expected inserted eligibility to be found")
	}
	if got.Eligible != initial.Eligible {
		t.Fatalf("expected eligible=%v, got %v", initial.Eligible, got.Eligible)
	}

	updated := initial
	updated.Eligible = false
	k.UpsertEligibility(updated)

	got, ok = k.GetEligibility(initial.ValidatorID)
	if !ok {
		t.Fatal("expected updated eligibility to be found")
	}
	if got.Eligible != updated.Eligible {
		t.Fatalf("expected updated eligible=%v, got %v", updated.Eligible, got.Eligible)
	}
}

func TestKeeperStatusUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetStatusRecord("missing"); ok {
		t.Fatal("expected missing status lookup to return ok=false")
	}

	initial := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  10,
	}
	k.UpsertStatusRecord(initial)

	got, ok := k.GetStatusRecord(initial.StatusID)
	if !ok {
		t.Fatal("expected inserted status to be found")
	}
	if got.LifecycleStatus != initial.LifecycleStatus {
		t.Fatalf("expected lifecycle %q, got %q", initial.LifecycleStatus, got.LifecycleStatus)
	}

	updated := initial
	updated.LifecycleStatus = types.ValidatorLifecycleJailed
	k.UpsertStatusRecord(updated)

	got, ok = k.GetStatusRecord(initial.StatusID)
	if !ok {
		t.Fatal("expected updated status to be found")
	}
	if got.LifecycleStatus != updated.LifecycleStatus {
		t.Fatalf("expected updated lifecycle %q, got %q", updated.LifecycleStatus, got.LifecycleStatus)
	}
}

func TestKeeperCreateEligibilityDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	input := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}

	created, err := k.CreateEligibility(input)
	if err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}

	idempotent, err := k.CreateEligibility(input)
	if err != nil {
		t.Fatalf("CreateEligibility idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent result to match created record, got %+v vs %+v", idempotent, created)
	}

	explicitPending := input
	explicitPending.Status = chaintypes.ReconciliationPending
	idempotent, err = k.CreateEligibility(explicitPending)
	if err != nil {
		t.Fatalf("CreateEligibility explicit pending call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected explicit pending result to match created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperCreateEligibilityConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	initial := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}
	if _, err := k.CreateEligibility(initial); err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.Eligible = false
	_, err := k.CreateEligibility(conflict)
	if err == nil {
		t.Fatal("expected conflict error for eligibility with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperCreateEligibilityValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID: "val-1",
	})
	if err == nil {
		t.Fatal("expected validation error for missing operator address")
	}
}

func TestKeeperCreateStatusDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}); err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	input := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  100,
	}

	created, err := k.CreateStatusRecord(input)
	if err != nil {
		t.Fatalf("CreateStatusRecord returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationSubmitted, created.Status)
	}

	idempotent, err := k.CreateStatusRecord(input)
	if err != nil {
		t.Fatalf("CreateStatusRecord idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent result to match created record, got %+v vs %+v", idempotent, created)
	}

	explicitSubmitted := input
	explicitSubmitted.Status = chaintypes.ReconciliationSubmitted
	idempotent, err = k.CreateStatusRecord(explicitSubmitted)
	if err != nil {
		t.Fatalf("CreateStatusRecord explicit submitted call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected explicit submitted result to match created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperCreateStatusConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}); err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	initial := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  100,
	}
	if _, err := k.CreateStatusRecord(initial); err != nil {
		t.Fatalf("CreateStatusRecord returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.EvidenceHeight = 101
	_, err := k.CreateStatusRecord(conflict)
	if err == nil {
		t.Fatal("expected conflict error for status with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperCreateStatusValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:    "status-1",
		ValidatorID: "val-1",
	})
	if err == nil {
		t.Fatal("expected validation error for missing lifecycle status")
	}
}

func TestKeeperCreateStatusEligibilityNotFound(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "missing",
		LifecycleStatus: types.ValidatorLifecycleActive,
	})
	if err == nil {
		t.Fatal("expected eligibility not found error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found message, got: %v", err)
	}
}

func TestKeeperListEligibilitiesDeterministicByValidatorID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "val-3", OperatorAddress: "op-3", Eligible: true})
	k.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "val-1", OperatorAddress: "op-1", Eligible: true})
	k.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "val-2", OperatorAddress: "op-2", Eligible: true})

	list := k.ListEligibilities()
	if len(list) != 3 {
		t.Fatalf("expected 3 eligibilities, got %d", len(list))
	}
	if list[0].ValidatorID != "val-1" || list[1].ValidatorID != "val-2" || list[2].ValidatorID != "val-3" {
		t.Fatalf("expected sorted validator ids [val-1 val-2 val-3], got [%s %s %s]",
			list[0].ValidatorID, list[1].ValidatorID, list[2].ValidatorID)
	}
}

func TestKeeperListStatusRecordsDeterministicByStatusID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertStatusRecord(types.ValidatorStatusRecord{StatusID: "status-3", ValidatorID: "val-1", LifecycleStatus: types.ValidatorLifecycleActive})
	k.UpsertStatusRecord(types.ValidatorStatusRecord{StatusID: "status-1", ValidatorID: "val-1", LifecycleStatus: types.ValidatorLifecycleActive})
	k.UpsertStatusRecord(types.ValidatorStatusRecord{StatusID: "status-2", ValidatorID: "val-1", LifecycleStatus: types.ValidatorLifecycleActive})

	list := k.ListStatusRecords()
	if len(list) != 3 {
		t.Fatalf("expected 3 status records, got %d", len(list))
	}
	if list[0].StatusID != "status-1" || list[1].StatusID != "status-2" || list[2].StatusID != "status-3" {
		t.Fatalf("expected sorted status ids [status-1 status-2 status-3], got [%s %s %s]",
			list[0].StatusID, list[1].StatusID, list[2].StatusID)
	}
}

func TestKeeperCreateEligibilityCanonicalCreateGetList(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	created, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "  VAL-Can-1  ",
		OperatorAddress: "  TDPNVALOPER1ABC  ",
		Eligible:        true,
		PolicyReason:    "  policy override  ",
		Status:          chaintypes.ReconciliationStatus("  PENDING  "),
	})
	if err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}
	if created.ValidatorID != "val-can-1" {
		t.Fatalf("expected canonical validator id val-can-1, got %q", created.ValidatorID)
	}
	if created.OperatorAddress != "tdpnvaloper1abc" {
		t.Fatalf("expected canonical operator address tdpnvaloper1abc, got %q", created.OperatorAddress)
	}
	if created.PolicyReason != "policy override" {
		t.Fatalf("expected trimmed policy reason, got %q", created.PolicyReason)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected canonical status pending, got %q", created.Status)
	}

	got, ok := k.GetEligibility("  VAL-CAN-1  ")
	if !ok {
		t.Fatal("expected canonical get by mixed-case validator id to succeed")
	}
	if got != created {
		t.Fatalf("expected get result %+v, got %+v", created, got)
	}

	list := k.ListEligibilities()
	if len(list) != 1 {
		t.Fatalf("expected 1 eligibility in list, got %d", len(list))
	}
	if list[0] != created {
		t.Fatalf("expected canonical list record %+v, got %+v", created, list[0])
	}
}

func TestKeeperCreateEligibilityCanonicalIdempotentReplayAndConflictBoundary(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	created, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "  VAL-Replay-1  ",
		OperatorAddress: "  TDPNVALOPER1DEF  ",
		Eligible:        true,
		PolicyReason:    " reason ",
	})
	if err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	replay, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-replay-1",
		OperatorAddress: "tdpnvaloper1def",
		Eligible:        true,
		PolicyReason:    "reason",
		Status:          chaintypes.ReconciliationStatus("  PENDING "),
	})
	if err != nil {
		t.Fatalf("expected canonical replay to be idempotent, got error %v", err)
	}
	if replay != created {
		t.Fatalf("expected idempotent replay %+v, got %+v", created, replay)
	}

	_, err = k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     " VAL-REPLAY-1 ",
		OperatorAddress: "tdpnvaloper1def",
		Eligible:        false,
		PolicyReason:    "reason",
	})
	if err == nil {
		t.Fatal("expected conflict for same canonical validator id with changed eligibility")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got %v", err)
	}
}

func TestKeeperCreateStatusCanonicalCreateGetList(t *testing.T) {
	t.Parallel()

	const uppercaseSHA256 = "SHA256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"

	k := NewKeeper()
	if _, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "  VAL-Status-1 ",
		OperatorAddress: " tdpnvaloper1ghi ",
		Eligible:        true,
	}); err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	created, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:         "  STATUS-Can-1 ",
		ValidatorID:      "  VAL-STATUS-1  ",
		ConsensusAddress: "  TDPNVALCONS1ABC  ",
		LifecycleStatus:  "  ACTIVE ",
		EvidenceHeight:   22,
		EvidenceRef:      "  " + uppercaseSHA256 + "  ",
		Status:           chaintypes.ReconciliationStatus("  SUBMITTED "),
	})
	if err != nil {
		t.Fatalf("CreateStatusRecord returned unexpected error: %v", err)
	}
	if created.StatusID != "status-can-1" {
		t.Fatalf("expected canonical status id status-can-1, got %q", created.StatusID)
	}
	if created.ValidatorID != "val-status-1" {
		t.Fatalf("expected canonical validator id val-status-1, got %q", created.ValidatorID)
	}
	if created.ConsensusAddress != "tdpnvalcons1abc" {
		t.Fatalf("expected canonical consensus address tdpnvalcons1abc, got %q", created.ConsensusAddress)
	}
	if created.LifecycleStatus != types.ValidatorLifecycleActive {
		t.Fatalf("expected canonical lifecycle active, got %q", created.LifecycleStatus)
	}
	if created.EvidenceRef != "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Fatalf("expected canonical evidence ref, got %q", created.EvidenceRef)
	}
	if created.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected canonical reconciliation status submitted, got %q", created.Status)
	}

	got, ok := k.GetStatusRecord("  status-CAN-1  ")
	if !ok {
		t.Fatal("expected canonical get by mixed-case status id to succeed")
	}
	if got != created {
		t.Fatalf("expected get result %+v, got %+v", created, got)
	}

	list := k.ListStatusRecords()
	if len(list) != 1 {
		t.Fatalf("expected 1 status record in list, got %d", len(list))
	}
	if list[0] != created {
		t.Fatalf("expected canonical list record %+v, got %+v", created, list[0])
	}
}

func TestKeeperCreateStatusCanonicalIdempotentReplayAndConflictBoundary(t *testing.T) {
	t.Parallel()

	const uppercaseSHA256 = "SHA256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"

	k := NewKeeper()
	if _, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-status-replay-1",
		OperatorAddress: "tdpnvaloper1jkl",
		Eligible:        true,
	}); err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	created, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:        " status-replay-1 ",
		ValidatorID:     " val-status-replay-1 ",
		LifecycleStatus: " JAILED ",
		EvidenceHeight:  50,
		EvidenceRef:     " " + uppercaseSHA256 + " ",
	})
	if err != nil {
		t.Fatalf("CreateStatusRecord returned unexpected error: %v", err)
	}

	replay, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "STATUS-REPLAY-1",
		ValidatorID:     "VAL-STATUS-REPLAY-1",
		LifecycleStatus: "jailed",
		EvidenceHeight:  50,
		EvidenceRef:     "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Status:          chaintypes.ReconciliationStatus(" submitted "),
	})
	if err != nil {
		t.Fatalf("expected canonical replay to be idempotent, got error %v", err)
	}
	if replay != created {
		t.Fatalf("expected idempotent replay %+v, got %+v", created, replay)
	}

	_, err = k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:        " STATUS-REPLAY-1 ",
		ValidatorID:     " val-status-replay-1 ",
		LifecycleStatus: " JAILED ",
		EvidenceHeight:  51,
		EvidenceRef:     "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	})
	if err == nil {
		t.Fatal("expected conflict for same canonical status id with changed evidence height")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got %v", err)
	}
}

func TestKeeperGetEligibilitySupportsLegacyRawAndCanonicalLookup(t *testing.T) {
	t.Parallel()

	store := NewInMemoryStore()
	store.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "VAL-Legacy-Get-1",
		OperatorAddress: "TDPNVALOPER1LegacyGet",
		Eligible:        true,
		PolicyReason:    " legacy ",
		Status:          chaintypes.ReconciliationStatus(" PENDING "),
	})
	k := NewKeeperWithStore(store)

	lookups := []string{
		"VAL-Legacy-Get-1",
		"val-legacy-get-1",
		"  VAL-LEGACY-GET-1  ",
	}
	for _, lookup := range lookups {
		got, ok := k.GetEligibility(lookup)
		if !ok {
			t.Fatalf("expected eligibility lookup %q to succeed", lookup)
		}
		if got.ValidatorID != "val-legacy-get-1" {
			t.Fatalf("expected canonical validator id val-legacy-get-1, got %q", got.ValidatorID)
		}
		if got.OperatorAddress != "tdpnvaloper1legacyget" {
			t.Fatalf("expected canonical operator address tdpnvaloper1legacyget, got %q", got.OperatorAddress)
		}
	}
}

func TestKeeperCreateEligibilityProtectsLegacyCanonicalDuplicates(t *testing.T) {
	t.Parallel()

	store := NewInMemoryStore()
	store.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "VAL-Legacy-Create-1",
		OperatorAddress: " TDPNVALOPER1LEGACYCREATE ",
		Eligible:        true,
		PolicyReason:    " legacy reason ",
		Status:          chaintypes.ReconciliationStatus(" PENDING "),
	})
	k := NewKeeperWithStore(store)

	created, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-legacy-create-1",
		OperatorAddress: "tdpnvaloper1legacycreate",
		Eligible:        true,
		PolicyReason:    "legacy reason",
		Status:          chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("expected legacy canonical replay to be idempotent, got error %v", err)
	}
	if created.ValidatorID != "val-legacy-create-1" {
		t.Fatalf("expected canonical validator id val-legacy-create-1, got %q", created.ValidatorID)
	}

	list := k.ListEligibilities()
	if len(list) != 1 {
		t.Fatalf("expected canonical dedupe to return 1 eligibility, got %d", len(list))
	}
	if list[0].ValidatorID != "val-legacy-create-1" {
		t.Fatalf("expected canonical list validator id val-legacy-create-1, got %q", list[0].ValidatorID)
	}

	_, err = k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     " VAL-LEGACY-CREATE-1 ",
		OperatorAddress: "tdpnvaloper1legacycreate",
		Eligible:        false,
		PolicyReason:    "legacy reason",
		Status:          chaintypes.ReconciliationPending,
	})
	if err == nil {
		t.Fatal("expected conflict when legacy canonical duplicate changes fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got %v", err)
	}
}

func TestKeeperListEligibilitiesDedupesLegacyCaseVariants(t *testing.T) {
	t.Parallel()

	store := NewInMemoryStore()
	store.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "VAL-B-1", OperatorAddress: "op-b", Eligible: true})
	store.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "val-b-1", OperatorAddress: "OP-B", Eligible: true})
	store.UpsertEligibility(types.ValidatorEligibility{ValidatorID: " Val-A-1 ", OperatorAddress: "op-a", Eligible: true})
	k := NewKeeperWithStore(store)

	list := k.ListEligibilities()
	if len(list) != 2 {
		t.Fatalf("expected canonical dedupe to return 2 eligibilities, got %d", len(list))
	}
	if list[0].ValidatorID != "val-a-1" || list[1].ValidatorID != "val-b-1" {
		t.Fatalf("expected sorted canonical validator ids [val-a-1 val-b-1], got [%s %s]",
			list[0].ValidatorID, list[1].ValidatorID)
	}
}

func TestKeeperGetStatusSupportsLegacyRawAndCanonicalLookup(t *testing.T) {
	t.Parallel()

	store := NewInMemoryStore()
	store.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "STATUS-Legacy-Get-1",
		ValidatorID:     "VAL-Legacy-Status-1",
		LifecycleStatus: " ACTIVE ",
		EvidenceHeight:  12,
		Status:          chaintypes.ReconciliationStatus(" SUBMITTED "),
	})
	k := NewKeeperWithStore(store)

	lookups := []string{
		"STATUS-Legacy-Get-1",
		"status-legacy-get-1",
		"  STATUS-LEGACY-GET-1  ",
	}
	for _, lookup := range lookups {
		got, ok := k.GetStatusRecord(lookup)
		if !ok {
			t.Fatalf("expected status lookup %q to succeed", lookup)
		}
		if got.StatusID != "status-legacy-get-1" {
			t.Fatalf("expected canonical status id status-legacy-get-1, got %q", got.StatusID)
		}
		if got.ValidatorID != "val-legacy-status-1" {
			t.Fatalf("expected canonical validator id val-legacy-status-1, got %q", got.ValidatorID)
		}
		if got.LifecycleStatus != types.ValidatorLifecycleActive {
			t.Fatalf("expected canonical lifecycle status active, got %q", got.LifecycleStatus)
		}
	}
}

func TestKeeperCreateStatusProtectsLegacyCanonicalDuplicates(t *testing.T) {
	t.Parallel()

	const uppercaseSHA256 = "SHA256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"

	store := NewInMemoryStore()
	store.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "VAL-Legacy-Status-Create-1",
		OperatorAddress: "tdpnvaloper1legacycreate",
		Eligible:        true,
	})
	store.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "STATUS-Legacy-Create-1",
		ValidatorID:     "VAL-Legacy-Status-Create-1",
		LifecycleStatus: " ACTIVE ",
		EvidenceHeight:  40,
		EvidenceRef:     " " + uppercaseSHA256 + " ",
		Status:          chaintypes.ReconciliationStatus(" SUBMITTED "),
	})
	k := NewKeeperWithStore(store)

	created, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-legacy-create-1",
		ValidatorID:     "val-legacy-status-create-1",
		LifecycleStatus: "active",
		EvidenceHeight:  40,
		EvidenceRef:     "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Status:          chaintypes.ReconciliationSubmitted,
	})
	if err != nil {
		t.Fatalf("expected legacy canonical replay to be idempotent, got error %v", err)
	}
	if created.StatusID != "status-legacy-create-1" {
		t.Fatalf("expected canonical status id status-legacy-create-1, got %q", created.StatusID)
	}

	list := k.ListStatusRecords()
	if len(list) != 1 {
		t.Fatalf("expected canonical dedupe to return 1 status record, got %d", len(list))
	}
	if list[0].StatusID != "status-legacy-create-1" {
		t.Fatalf("expected canonical list status id status-legacy-create-1, got %q", list[0].StatusID)
	}

	_, err = k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:        " STATUS-LEGACY-CREATE-1 ",
		ValidatorID:     " VAL-LEGACY-STATUS-CREATE-1 ",
		LifecycleStatus: " ACTIVE ",
		EvidenceHeight:  41,
		EvidenceRef:     "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	})
	if err == nil {
		t.Fatal("expected conflict when legacy canonical status duplicate changes fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got %v", err)
	}
}

func TestKeeperListStatusRecordsDedupesLegacyCaseVariants(t *testing.T) {
	t.Parallel()

	store := NewInMemoryStore()
	store.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "STATUS-B-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
	})
	store.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-b-1",
		ValidatorID:     "VAL-1",
		LifecycleStatus: " ACTIVE ",
	})
	store.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        " Status-A-1 ",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
	})
	k := NewKeeperWithStore(store)

	list := k.ListStatusRecords()
	if len(list) != 2 {
		t.Fatalf("expected canonical dedupe to return 2 status records, got %d", len(list))
	}
	if list[0].StatusID != "status-a-1" || list[1].StatusID != "status-b-1" {
		t.Fatalf("expected sorted canonical status ids [status-a-1 status-b-1], got [%s %s]",
			list[0].StatusID, list[1].StatusID)
	}
}
