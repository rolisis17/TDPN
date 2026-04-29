package settlement

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeAdapter struct {
	fail bool
}

func (f fakeAdapter) SubmitSessionSettlement(_ context.Context, _ SessionSettlement) (string, error) {
	if f.fail {
		return "", errFakeAdapter
	}
	return "chain-set-1", nil
}

func (f fakeAdapter) SubmitRewardIssue(_ context.Context, _ RewardIssue) (string, error) {
	if f.fail {
		return "", errFakeAdapter
	}
	return "chain-rew-1", nil
}

func (f fakeAdapter) SubmitSponsorReservation(_ context.Context, _ SponsorCreditReservation) (string, error) {
	if f.fail {
		return "", errFakeAdapter
	}
	return "chain-sponsor-res-1", nil
}

func (f fakeAdapter) SubmitSlashEvidence(_ context.Context, _ SlashEvidence) (string, error) {
	if f.fail {
		return "", errFakeAdapter
	}
	return "chain-slash-1", nil
}

func (f fakeAdapter) Health(_ context.Context) error {
	if f.fail {
		return errFakeAdapter
	}
	return nil
}

type fundReservationCapturingAdapter struct {
	fakeAdapter
	mu               sync.Mutex
	failReservation  bool
	submitDelay      time.Duration
	fundReservations []FundReservation
}

func (a *fundReservationCapturingAdapter) SubmitFundReservation(_ context.Context, reservation FundReservation) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failReservation {
		return "", errFakeAdapter
	}
	if a.submitDelay > 0 {
		time.Sleep(a.submitDelay)
	}
	a.fundReservations = append(a.fundReservations, reservation)
	return "chain-res-" + reservation.ReservationID, nil
}

func (a *fundReservationCapturingAdapter) capturedFundReservations() []FundReservation {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]FundReservation(nil), a.fundReservations...)
}

type fundReservationStatusAdapter struct {
	fundReservationCapturingAdapter
	status  OperationStatus
	found   bool
	err     error
	queries []string
}

func (a *fundReservationStatusAdapter) FundReservationStatus(_ context.Context, reservationID string) (OperationStatus, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.queries = append(a.queries, reservationID)
	return a.status, a.found, a.err
}

func (a *fundReservationStatusAdapter) statusQueries() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.queries...)
}

type fundReservationMaterialAdapter struct {
	fakeAdapter
	mu               sync.Mutex
	status           OperationStatus
	settlementStatus OperationStatus
	reservations     map[string]FundReservation
	settlements      map[string]SessionSettlement
}

func (a *fundReservationMaterialAdapter) SubmitFundReservation(_ context.Context, reservation FundReservation) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reservations == nil {
		a.reservations = map[string]FundReservation{}
	}
	chainReservation := reservation
	if a.status != "" {
		chainReservation.Status = a.status
	} else {
		chainReservation.Status = OperationStatusConfirmed
	}
	a.reservations[reservation.ReservationID] = chainReservation
	return "chain-res-" + reservation.ReservationID, nil
}

func (a *fundReservationMaterialAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.settlements == nil {
		a.settlements = map[string]SessionSettlement{}
	}
	chainSettlement := settlement
	if a.settlementStatus != "" {
		chainSettlement.Status = a.settlementStatus
	} else {
		chainSettlement.Status = OperationStatusConfirmed
	}
	a.settlements[settlement.SettlementID] = chainSettlement
	return "chain-set-" + settlement.SessionID, nil
}

func (a *fundReservationMaterialAdapter) FundReservation(_ context.Context, reservationID string) (FundReservation, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reservation, ok := a.reservations[reservationID]
	return reservation, ok, nil
}

func (a *fundReservationMaterialAdapter) SessionSettlement(_ context.Context, settlementID string) (SessionSettlement, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	settlement, ok := a.settlements[settlementID]
	return settlement, ok, nil
}

func (a *fundReservationMaterialAdapter) SessionSettlementStatus(ctx context.Context, settlementID string) (OperationStatus, bool, error) {
	settlement, found, err := a.SessionSettlement(ctx, settlementID)
	if err != nil || !found {
		return "", found, err
	}
	return settlement.Status, true, nil
}

func (a *fundReservationMaterialAdapter) RewardIssueStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a *fundReservationMaterialAdapter) SponsorReservationStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a *fundReservationMaterialAdapter) SlashEvidenceStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a *fundReservationMaterialAdapter) ListSlashEvidence(context.Context, SlashEvidenceFilter) ([]SlashEvidence, error) {
	return nil, nil
}

func (a *fundReservationMaterialAdapter) setReservationStatus(reservationID string, status OperationStatus) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if reservation, ok := a.reservations[reservationID]; ok {
		reservation.Status = status
		a.reservations[reservationID] = reservation
	}
}

func (a *fundReservationMaterialAdapter) mutateReservation(reservationID string, mutate func(FundReservation) FundReservation) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if reservation, ok := a.reservations[reservationID]; ok {
		a.reservations[reservationID] = mutate(reservation)
	}
}

func (a *fundReservationMaterialAdapter) mutateSettlement(settlementID string, mutate func(SessionSettlement) SessionSettlement) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if settlement, ok := a.settlements[settlementID]; ok {
		a.settlements[settlementID] = mutate(settlement)
	}
}

type blockingFundReservationAdapter struct {
	fakeAdapter
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   int32
}

func newBlockingFundReservationAdapter() *blockingFundReservationAdapter {
	return &blockingFundReservationAdapter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (a *blockingFundReservationAdapter) SubmitFundReservation(ctx context.Context, reservation FundReservation) (string, error) {
	atomic.AddInt32(&a.calls, 1)
	a.once.Do(func() { close(a.started) })
	select {
	case <-a.release:
		return "chain-res-" + reservation.ReservationID, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (a *blockingFundReservationAdapter) fundReservationCalls() int {
	return int(atomic.LoadInt32(&a.calls))
}

type sponsorReservationCapturingAdapter struct {
	fakeAdapter
	mu                  sync.Mutex
	submitDelay         time.Duration
	sponsorReservations []SponsorCreditReservation
}

func (a *sponsorReservationCapturingAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.submitDelay > 0 {
		time.Sleep(a.submitDelay)
	}
	a.sponsorReservations = append(a.sponsorReservations, reservation)
	return "chain-sponsor-res-" + reservation.ReservationID, nil
}

func (a *sponsorReservationCapturingAdapter) capturedSponsorReservations() []SponsorCreditReservation {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]SponsorCreditReservation(nil), a.sponsorReservations...)
}

type blockingSettlementAdapter struct {
	fakeAdapter
	ready            chan struct{}
	release          chan struct{}
	once             sync.Once
	calls            int32
	mu               sync.Mutex
	fundReservations map[string]FundReservation
}

func newBlockingSettlementAdapter() *blockingSettlementAdapter {
	return &blockingSettlementAdapter{
		ready:   make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (a *blockingSettlementAdapter) SubmitSessionSettlement(ctx context.Context, settlement SessionSettlement) (string, error) {
	atomic.AddInt32(&a.calls, 1)
	a.once.Do(func() { close(a.ready) })
	select {
	case <-a.release:
		return "chain-set-" + settlement.SessionID, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (a *blockingSettlementAdapter) SubmitFundReservation(_ context.Context, reservation FundReservation) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fundReservations == nil {
		a.fundReservations = map[string]FundReservation{}
	}
	chainReservation := reservation
	chainReservation.Status = OperationStatusConfirmed
	a.fundReservations[reservation.ReservationID] = chainReservation
	return "chain-res-" + reservation.ReservationID, nil
}

func (a *blockingSettlementAdapter) FundReservation(_ context.Context, reservationID string) (FundReservation, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reservation, ok := a.fundReservations[reservationID]
	return reservation, ok, nil
}

func (a *blockingSettlementAdapter) FundReservationStatus(_ context.Context, reservationID string) (OperationStatus, bool, error) {
	if reservationID == "" {
		return "", false, nil
	}
	return OperationStatusConfirmed, true, nil
}

func (a *blockingSettlementAdapter) settlementCalls() int {
	return int(atomic.LoadInt32(&a.calls))
}

type rewardProofRequiringAdapter struct {
	fakeAdapter
}

func (a rewardProofRequiringAdapter) RequiresRewardProofReference() bool {
	return true
}

type rewardProofCapturingAdapter struct {
	fakeAdapter
	mu     sync.Mutex
	err    error
	proofs []RewardProofRecord
}

func (a *rewardProofCapturingAdapter) SubmitRewardProof(_ context.Context, proof RewardProofRecord) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return "", a.err
	}
	a.proofs = append(a.proofs, proof)
	return "chain-proof-" + proof.ProofPath, nil
}

func (a *rewardProofCapturingAdapter) capturedRewardProofs() []RewardProofRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]RewardProofRecord(nil), a.proofs...)
}

type recordingRewardProofVerifier struct {
	mu         sync.Mutex
	verified   bool
	verifierID string
	verifiedAt time.Time
	err        error
	requests   []RewardProofVerificationRequest
}

func newAcceptingRewardProofVerifier() *recordingRewardProofVerifier {
	return &recordingRewardProofVerifier{
		verified:   true,
		verifierID: "test-reward-proof-verifier",
		verifiedAt: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
	}
}

func (v *recordingRewardProofVerifier) VerifyRewardProof(ctx context.Context, request RewardProofVerificationRequest) (RewardProofVerification, error) {
	select {
	case <-ctx.Done():
		return RewardProofVerification{}, ctx.Err()
	default:
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.requests = append(v.requests, request)
	if v.err != nil {
		return RewardProofVerification{}, v.err
	}
	return RewardProofVerification{
		Verified:   v.verified,
		VerifierID: v.verifierID,
		VerifiedAt: v.verifiedAt,
	}, nil
}

func (v *recordingRewardProofVerifier) setVerified(verified bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.verified = verified
}

func (v *recordingRewardProofVerifier) lastRequest() (RewardProofVerificationRequest, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.requests) == 0 {
		return RewardProofVerificationRequest{}, false
	}
	return v.requests[len(v.requests)-1], true
}

type slashEvidenceListingAdapter struct {
	fakeAdapter
	evidence []SlashEvidence
	err      error
	filter   SlashEvidenceFilter
}

func (a *slashEvidenceListingAdapter) ListSlashEvidence(_ context.Context, filter SlashEvidenceFilter) ([]SlashEvidence, error) {
	a.filter = filter
	if a.err != nil {
		return nil, a.err
	}
	return append([]SlashEvidence(nil), a.evidence...), nil
}

var errFakeAdapter = &fakeErr{"adapter-fail"}

type fakeErr struct {
	msg string
}

func (e *fakeErr) Error() string {
	return e.msg
}

func testSHA256Ref(seed string) string {
	const alphabet = "0123456789abcdef"
	if seed == "" {
		seed = "seed"
	}
	out := make([]byte, 64)
	for i := 0; i < len(out); i++ {
		out[i] = alphabet[int(seed[i%len(seed)])%len(alphabet)]
	}
	return "sha256:" + string(out)
}

type switchableAdapter struct {
	mu                 sync.Mutex
	fail               bool
	sessionSubmitCalls int
}

func (a *switchableAdapter) setFail(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = v
}

func (a *switchableAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	a.sessionSubmitCalls++
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-set-" + settlement.SessionID, nil
}

func (a *switchableAdapter) SubmitRewardIssue(_ context.Context, _ RewardIssue) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-rew-ok", nil
}

func (a *switchableAdapter) SubmitSponsorReservation(_ context.Context, _ SponsorCreditReservation) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-sponsor-res-ok", nil
}

func (a *switchableAdapter) SubmitSlashEvidence(_ context.Context, _ SlashEvidence) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-slash-ok", nil
}

func (a *switchableAdapter) Health(_ context.Context) error {
	return nil
}

func (a *switchableAdapter) settlementCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionSubmitCalls
}

type statusCapturingReplayAdapter struct {
	mu                 sync.Mutex
	failFirst          bool
	settlementStatuses []OperationStatus
}

func (a *statusCapturingReplayAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	a.settlementStatuses = append(a.settlementStatuses, settlement.Status)
	call := len(a.settlementStatuses)
	fail := a.failFirst && call == 1
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-set-" + settlement.SessionID, nil
}

func (a *statusCapturingReplayAdapter) SubmitRewardIssue(_ context.Context, _ RewardIssue) (string, error) {
	return "chain-rew-ok", nil
}

func (a *statusCapturingReplayAdapter) SubmitSponsorReservation(_ context.Context, _ SponsorCreditReservation) (string, error) {
	return "chain-sponsor-res-ok", nil
}

func (a *statusCapturingReplayAdapter) SubmitSlashEvidence(_ context.Context, _ SlashEvidence) (string, error) {
	return "chain-slash-ok", nil
}

func (a *statusCapturingReplayAdapter) Health(_ context.Context) error {
	return nil
}

func (a *statusCapturingReplayAdapter) settlementStatusesSnapshot() []OperationStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]OperationStatus(nil), a.settlementStatuses...)
}

type replayConfirmingAdapter struct {
	mu                 sync.Mutex
	fail               bool
	sessionSubmitCalls int
	settlements        map[string]SessionSettlement
}

func (a *replayConfirmingAdapter) setFail(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = v
}

func (a *replayConfirmingAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	a.sessionSubmitCalls++
	fail := a.fail
	if !fail {
		if a.settlements == nil {
			a.settlements = map[string]SessionSettlement{}
		}
		chainSettlement := settlement
		chainSettlement.Status = OperationStatusConfirmed
		a.settlements[settlement.SettlementID] = chainSettlement
	}
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-set-" + settlement.SessionID, nil
}

func (a *replayConfirmingAdapter) SubmitRewardIssue(_ context.Context, _ RewardIssue) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-rew-ok", nil
}

func (a *replayConfirmingAdapter) SubmitSponsorReservation(_ context.Context, _ SponsorCreditReservation) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-sponsor-res-ok", nil
}

func (a *replayConfirmingAdapter) SubmitSlashEvidence(_ context.Context, _ SlashEvidence) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-slash-ok", nil
}

func (a *replayConfirmingAdapter) Health(_ context.Context) error { return nil }

func (a *replayConfirmingAdapter) HasSessionSettlement(_ context.Context, settlementID string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fail := a.fail
	if fail || settlementID == "" {
		return false, nil
	}
	_, ok := a.settlements[settlementID]
	return ok, nil
}

func (a *replayConfirmingAdapter) SessionSettlementStatus(ctx context.Context, settlementID string) (OperationStatus, bool, error) {
	settlement, found, err := a.SessionSettlement(ctx, settlementID)
	if err != nil || !found {
		return "", found, err
	}
	return settlement.Status, true, nil
}

func (a *replayConfirmingAdapter) SessionSettlement(_ context.Context, settlementID string) (SessionSettlement, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fail := a.fail
	if fail || settlementID == "" {
		return SessionSettlement{}, false, nil
	}
	settlement, ok := a.settlements[settlementID]
	return settlement, ok, nil
}

func (a *replayConfirmingAdapter) HasRewardIssue(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a *replayConfirmingAdapter) RewardIssueStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a *replayConfirmingAdapter) HasSponsorReservation(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a *replayConfirmingAdapter) SponsorReservationStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a *replayConfirmingAdapter) HasSlashEvidence(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a *replayConfirmingAdapter) SlashEvidenceStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a *replayConfirmingAdapter) settlementCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionSubmitCalls
}

type multiOperationReplayAdapter struct {
	mu                 sync.Mutex
	fail               bool
	sessionSubmitCalls int
	rewardSubmitCalls  int
	sponsorSubmitCalls int
	slashEvidenceCalls int
	settlements        map[string]SessionSettlement
	rewards            map[string]RewardIssue
	slashEvidence      map[string]SlashEvidence
}

func (a *multiOperationReplayAdapter) setFail(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = v
}

func (a *multiOperationReplayAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	a.sessionSubmitCalls++
	fail := a.fail
	if !fail {
		if a.settlements == nil {
			a.settlements = map[string]SessionSettlement{}
		}
		chainSettlement := settlement
		chainSettlement.Status = OperationStatusConfirmed
		a.settlements[settlement.SettlementID] = chainSettlement
	}
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-set-" + settlement.SessionID, nil
}

func (a *multiOperationReplayAdapter) SubmitRewardIssue(_ context.Context, reward RewardIssue) (string, error) {
	a.mu.Lock()
	a.rewardSubmitCalls++
	fail := a.fail
	if !fail {
		if a.rewards == nil {
			a.rewards = map[string]RewardIssue{}
		}
		chainReward := reward
		chainReward.Status = OperationStatusConfirmed
		a.rewards[reward.RewardID] = chainReward
	}
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-rew-" + reward.RewardID, nil
}

func (a *multiOperationReplayAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	a.mu.Lock()
	a.sponsorSubmitCalls++
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-sponsor-res-" + reservation.ReservationID, nil
}

func (a *multiOperationReplayAdapter) SubmitSlashEvidence(_ context.Context, evidence SlashEvidence) (string, error) {
	a.mu.Lock()
	a.slashEvidenceCalls++
	fail := a.fail
	if !fail {
		if a.slashEvidence == nil {
			a.slashEvidence = map[string]SlashEvidence{}
		}
		chainEvidence := evidence
		chainEvidence.Status = OperationStatusConfirmed
		a.slashEvidence[evidence.EvidenceID] = chainEvidence
	}
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-slash-" + evidence.EvidenceID, nil
}

func (a *multiOperationReplayAdapter) Health(_ context.Context) error { return nil }

func (a *multiOperationReplayAdapter) HasSessionSettlement(_ context.Context, settlementID string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fail := a.fail
	if fail || settlementID == "" {
		return false, nil
	}
	_, ok := a.settlements[settlementID]
	return ok, nil
}

func (a *multiOperationReplayAdapter) SessionSettlementStatus(ctx context.Context, settlementID string) (OperationStatus, bool, error) {
	settlement, found, err := a.SessionSettlement(ctx, settlementID)
	if err != nil || !found {
		return "", found, err
	}
	return settlement.Status, true, nil
}

func (a *multiOperationReplayAdapter) SessionSettlement(_ context.Context, settlementID string) (SessionSettlement, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fail := a.fail
	if fail || settlementID == "" {
		return SessionSettlement{}, false, nil
	}
	settlement, ok := a.settlements[settlementID]
	return settlement, ok, nil
}

func (a *multiOperationReplayAdapter) HasRewardIssue(_ context.Context, rewardID string) (bool, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	return !fail && strings.TrimSpace(rewardID) != "", nil
}

func (a *multiOperationReplayAdapter) RewardIssueStatus(ctx context.Context, rewardID string) (OperationStatus, bool, error) {
	reward, found, err := a.RewardIssue(ctx, rewardID)
	if err != nil || !found {
		return "", found, err
	}
	return reward.Status, true, nil
}

func (a *multiOperationReplayAdapter) RewardIssue(_ context.Context, rewardID string) (RewardIssue, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fail := a.fail
	if fail || strings.TrimSpace(rewardID) == "" {
		return RewardIssue{}, false, nil
	}
	reward, ok := a.rewards[rewardID]
	return reward, ok, nil
}

func (a *multiOperationReplayAdapter) HasSponsorReservation(_ context.Context, reservationID string) (bool, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	return !fail && strings.TrimSpace(reservationID) != "", nil
}

func (a *multiOperationReplayAdapter) SponsorReservationStatus(ctx context.Context, reservationID string) (OperationStatus, bool, error) {
	found, err := a.HasSponsorReservation(ctx, reservationID)
	if err != nil || !found {
		return "", found, err
	}
	return OperationStatusConfirmed, true, nil
}

func (a *multiOperationReplayAdapter) HasSlashEvidence(_ context.Context, evidenceID string) (bool, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	return !fail && strings.TrimSpace(evidenceID) != "", nil
}

func (a *multiOperationReplayAdapter) SlashEvidenceStatus(ctx context.Context, evidenceID string) (OperationStatus, bool, error) {
	evidence, found, err := a.SlashEvidence(ctx, evidenceID)
	if err != nil || !found {
		return "", found, err
	}
	return evidence.Status, true, nil
}

func (a *multiOperationReplayAdapter) SlashEvidence(_ context.Context, evidenceID string) (SlashEvidence, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fail := a.fail
	if fail || strings.TrimSpace(evidenceID) == "" {
		return SlashEvidence{}, false, nil
	}
	evidence, ok := a.slashEvidence[evidenceID]
	return evidence, ok, nil
}

func (a *multiOperationReplayAdapter) settlementCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionSubmitCalls
}

func (a *multiOperationReplayAdapter) rewardCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rewardSubmitCalls
}

func (a *multiOperationReplayAdapter) sponsorCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sponsorSubmitCalls
}

func (a *multiOperationReplayAdapter) slashCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.slashEvidenceCalls
}

type blockingRewardAdapter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
}

func newBlockingRewardAdapter() *blockingRewardAdapter {
	return &blockingRewardAdapter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (a *blockingRewardAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	return "chain-set-" + settlement.SessionID, nil
}

func (a *blockingRewardAdapter) SubmitRewardIssue(ctx context.Context, reward RewardIssue) (string, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	a.once.Do(func() {
		close(a.started)
	})
	select {
	case <-a.release:
		return "chain-rew-" + reward.RewardID, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (a *blockingRewardAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	return "chain-sponsor-res-" + reservation.ReservationID, nil
}

func (a *blockingRewardAdapter) SubmitSlashEvidence(_ context.Context, evidence SlashEvidence) (string, error) {
	return "chain-slash-" + evidence.EvidenceID, nil
}

func (a *blockingRewardAdapter) Health(_ context.Context) error { return nil }

func (a *blockingRewardAdapter) rewardCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

type blockingSlashAdapter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
}

func newBlockingSlashAdapter() *blockingSlashAdapter {
	return &blockingSlashAdapter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (a *blockingSlashAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	return "chain-set-" + settlement.SessionID, nil
}

func (a *blockingSlashAdapter) SubmitRewardIssue(_ context.Context, reward RewardIssue) (string, error) {
	return "chain-rew-" + reward.RewardID, nil
}

func (a *blockingSlashAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	return "chain-sponsor-res-" + reservation.ReservationID, nil
}

func (a *blockingSlashAdapter) SubmitSlashEvidence(ctx context.Context, evidence SlashEvidence) (string, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	a.once.Do(func() {
		close(a.started)
	})
	select {
	case <-a.release:
		return "chain-slash-" + evidence.EvidenceID, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (a *blockingSlashAdapter) Health(_ context.Context) error { return nil }

func (a *blockingSlashAdapter) slashCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

type confirmingAdapter struct{}

func (a confirmingAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	return "chain-set-" + settlement.SessionID, nil
}

func (a confirmingAdapter) SubmitFundReservation(_ context.Context, reservation FundReservation) (string, error) {
	return "chain-res-" + reservation.ReservationID, nil
}

func (a confirmingAdapter) FundReservationStatus(_ context.Context, reservationID string) (OperationStatus, bool, error) {
	if reservationID == "" {
		return "", false, nil
	}
	return OperationStatusConfirmed, true, nil
}

func (a confirmingAdapter) SubmitRewardIssue(_ context.Context, reward RewardIssue) (string, error) {
	return "chain-rew-" + reward.RewardID, nil
}

func (a confirmingAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	return "chain-sponsor-" + reservation.ReservationID, nil
}

func (a confirmingAdapter) SubmitSlashEvidence(_ context.Context, evidence SlashEvidence) (string, error) {
	return "chain-slash-" + evidence.EvidenceID, nil
}

func (a confirmingAdapter) Health(_ context.Context) error { return nil }

func (a confirmingAdapter) HasSessionSettlement(_ context.Context, settlementID string) (bool, error) {
	return settlementID != "", nil
}

func (a confirmingAdapter) SessionSettlementStatus(_ context.Context, settlementID string) (OperationStatus, bool, error) {
	if settlementID == "" {
		return "", false, nil
	}
	return OperationStatusConfirmed, true, nil
}

func (a confirmingAdapter) HasRewardIssue(_ context.Context, rewardID string) (bool, error) {
	return rewardID != "", nil
}

func (a confirmingAdapter) RewardIssueStatus(_ context.Context, rewardID string) (OperationStatus, bool, error) {
	if rewardID == "" {
		return "", false, nil
	}
	return OperationStatusConfirmed, true, nil
}

func (a confirmingAdapter) HasSponsorReservation(_ context.Context, reservationID string) (bool, error) {
	return reservationID != "", nil
}

func (a confirmingAdapter) SponsorReservationStatus(_ context.Context, reservationID string) (OperationStatus, bool, error) {
	if reservationID == "" {
		return "", false, nil
	}
	return OperationStatusConfirmed, true, nil
}

func (a confirmingAdapter) HasSlashEvidence(_ context.Context, evidenceID string) (bool, error) {
	return evidenceID != "", nil
}

func (a confirmingAdapter) SlashEvidenceStatus(_ context.Context, evidenceID string) (OperationStatus, bool, error) {
	if evidenceID == "" {
		return "", false, nil
	}
	return OperationStatusConfirmed, true, nil
}

type notFoundConfirmingAdapter struct{ confirmingAdapter }

func (a notFoundConfirmingAdapter) HasSessionSettlement(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a notFoundConfirmingAdapter) SessionSettlementStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a notFoundConfirmingAdapter) HasRewardIssue(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a notFoundConfirmingAdapter) RewardIssueStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a notFoundConfirmingAdapter) HasSponsorReservation(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a notFoundConfirmingAdapter) SponsorReservationStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

func (a notFoundConfirmingAdapter) HasSlashEvidence(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a notFoundConfirmingAdapter) SlashEvidenceStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, nil
}

type errorConfirmingAdapter struct{ confirmingAdapter }

func (a errorConfirmingAdapter) HasSessionSettlement(_ context.Context, _ string) (bool, error) {
	return false, errFakeAdapter
}

func (a errorConfirmingAdapter) SessionSettlementStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, errFakeAdapter
}

func (a errorConfirmingAdapter) HasRewardIssue(_ context.Context, _ string) (bool, error) {
	return false, errFakeAdapter
}

func (a errorConfirmingAdapter) RewardIssueStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, errFakeAdapter
}

func (a errorConfirmingAdapter) HasSponsorReservation(_ context.Context, _ string) (bool, error) {
	return false, errFakeAdapter
}

func (a errorConfirmingAdapter) SponsorReservationStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, errFakeAdapter
}

func (a errorConfirmingAdapter) HasSlashEvidence(_ context.Context, _ string) (bool, error) {
	return false, errFakeAdapter
}

func (a errorConfirmingAdapter) SlashEvidenceStatus(context.Context, string) (OperationStatus, bool, error) {
	return "", false, errFakeAdapter
}

type nonFinalStatusAdapter struct {
	confirmingAdapter
	status OperationStatus
}

func (a nonFinalStatusAdapter) SessionSettlementStatus(_ context.Context, settlementID string) (OperationStatus, bool, error) {
	return a.status, settlementID != "", nil
}

func (a nonFinalStatusAdapter) RewardIssueStatus(_ context.Context, rewardID string) (OperationStatus, bool, error) {
	return a.status, rewardID != "", nil
}

func (a nonFinalStatusAdapter) SponsorReservationStatus(_ context.Context, reservationID string) (OperationStatus, bool, error) {
	return a.status, reservationID != "", nil
}

func (a nonFinalStatusAdapter) SlashEvidenceStatus(_ context.Context, evidenceID string) (OperationStatus, bool, error) {
	return a.status, evidenceID != "", nil
}

type materialSettlementConfirmingAdapter struct {
	confirmingAdapter
	settlements   map[string]SessionSettlement
	rewards       map[string]RewardIssue
	slashEvidence map[string]SlashEvidence
}

func (a materialSettlementConfirmingAdapter) SessionSettlement(_ context.Context, settlementID string) (SessionSettlement, bool, error) {
	settlement, ok := a.settlements[settlementID]
	return settlement, ok, nil
}

func (a materialSettlementConfirmingAdapter) RewardIssue(_ context.Context, rewardID string) (RewardIssue, bool, error) {
	reward, ok := a.rewards[rewardID]
	return reward, ok, nil
}

func (a materialSettlementConfirmingAdapter) SlashEvidence(_ context.Context, evidenceID string) (SlashEvidence, bool, error) {
	evidence, ok := a.slashEvidence[evidenceID]
	return evidence, ok, nil
}

func setupDeferredSettlement(t *testing.T, s *MemoryService, sessionID string) {
	t.Helper()
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-" + sessionID,
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	err = s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-" + sessionID,
		BytesIngress: 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if !settlement.AdapterDeferred {
		t.Fatalf("expected deferred settlement for session %s", sessionID)
	}
}

func setupDeferredNonSettlementOperations(t *testing.T, s *MemoryService, suffix string) (string, string, string, string, string) {
	t.Helper()
	ctx := context.Background()

	sessionID := "sess-replay-" + suffix
	rewardID := "rew-replay-" + suffix
	reservationID := "sres-replay-" + suffix
	evidenceID := "ev-replay-" + suffix
	slashSubjectID := "provider-" + suffix

	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          rewardID,
		ProviderSubjectID: "provider-" + suffix,
		SessionID:         sessionID,
		RewardMicros:      33,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if !reward.AdapterDeferred {
		t.Fatalf("expected deferred reward for %s", rewardID)
	}

	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: reservationID,
		SponsorID:     "sponsor-" + suffix,
		SubjectID:     "client-" + suffix,
		SessionID:     sessionID,
		AmountMicros:  150,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if !reservation.AdapterDeferred {
		t.Fatalf("expected deferred sponsor reservation for %s", reservationID)
	}

	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    evidenceID,
		SubjectID:     slashSubjectID,
		SessionID:     sessionID,
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("replay-" + suffix),
		SlashMicros:   9,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if !evidence.AdapterDeferred {
		t.Fatalf("expected deferred slash evidence for %s", evidenceID)
	}

	return sessionID, rewardID, reservationID, evidenceID, slashSubjectID
}

func setupSettledSessionForShadowTests(t *testing.T, s *MemoryService, sessionID string) SessionSettlement {
	t.Helper()
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-" + sessionID,
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	err = s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-" + sessionID,
		BytesIngress: 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	return settlement
}

func TestMemoryServiceSettleIdempotent(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1024 * 1024))
	ctx := context.Background()
	reservation, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-1",
		SubjectID:    "client-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	err = s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-1",
		SubjectID:    "client-1",
		BytesIngress: 1024 * 1024,
		BytesEgress:  0,
		RecordedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlementA, err := s.SettleSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("SettleSession first: %v", err)
	}
	settlementB, err := s.SettleSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("SettleSession second: %v", err)
	}
	if settlementA.SettlementID != settlementB.SettlementID {
		t.Fatalf("expected same settlement id, got %s vs %s", settlementA.SettlementID, settlementB.SettlementID)
	}
	if settlementA.ReservationID != reservation.ReservationID {
		t.Fatalf("expected reservation id %s carried into settlement, got %s", reservation.ReservationID, settlementA.ReservationID)
	}
	if settlementB.ReservationID != reservation.ReservationID {
		t.Fatalf("expected reservation id %s preserved on replay, got %s", reservation.ReservationID, settlementB.ReservationID)
	}
	if !settlementB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on second settle")
	}
}

func TestMemoryServiceSettleSessionConcurrentCallsSubmitOnce(t *testing.T) {
	adapter := newBlockingSettlementAdapter()
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()
	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-concurrent-settle-1",
		SubjectID:    "client-concurrent-settle-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-concurrent-settle-1",
		SubjectID:    "client-concurrent-settle-1",
		BytesIngress: 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	const callers = 12
	var wg sync.WaitGroup
	results := make(chan SessionSettlement, callers)
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			settlement, err := s.SettleSession(ctx, "sess-concurrent-settle-1")
			if err != nil {
				errs <- err
				return
			}
			results <- settlement
		}()
	}
	select {
	case <-adapter.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for settlement adapter call")
	}
	time.Sleep(50 * time.Millisecond)
	if calls := adapter.settlementCalls(); calls != 1 {
		close(adapter.release)
		wg.Wait()
		t.Fatalf("settlement adapter calls while first submit blocked=%d want=1", calls)
	}
	close(adapter.release)
	wg.Wait()
	close(results)
	close(errs)

	if len(errs) > 0 {
		t.Fatalf("unexpected concurrent settle error: %v", <-errs)
	}
	falseReplayCount := 0
	resultCount := 0
	for settlement := range results {
		resultCount++
		if settlement.SettlementID != "set-sess-concurrent-settle-1" {
			t.Fatalf("settlement_id=%q want set-sess-concurrent-settle-1", settlement.SettlementID)
		}
		if !settlement.IdempotentReplay {
			falseReplayCount++
		}
	}
	if resultCount != callers {
		t.Fatalf("result count=%d want=%d", resultCount, callers)
	}
	if falseReplayCount != 1 {
		t.Fatalf("non-replay settlement count=%d want=1", falseReplayCount)
	}
	if calls := adapter.settlementCalls(); calls != 1 {
		t.Fatalf("settlement adapter calls=%d want=1", calls)
	}
}

func TestMemoryServiceRecordUsageRejectsWritesWhileSettlementInFlight(t *testing.T) {
	adapter := newBlockingSettlementAdapter()
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()
	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-in-flight-usage-1",
		SubjectID:    "client-in-flight-usage-1",
		AmountMicros: 4_000_000,
		Currency:     "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-in-flight-usage-1",
		SubjectID:    "client-in-flight-usage-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage initial: %v", err)
	}

	settleDone := make(chan error, 1)
	go func() {
		_, err := s.SettleSession(ctx, "sess-in-flight-usage-1")
		settleDone <- err
	}()
	select {
	case <-adapter.ready:
	case <-time.After(time.Second):
		t.Fatalf("settlement adapter did not start")
	}

	err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-in-flight-usage-1",
		SubjectID:    "client-in-flight-usage-1",
		BytesIngress: 1024 * 1024,
	})
	if err == nil || !strings.Contains(err.Error(), "session settlement in progress") {
		close(adapter.release)
		t.Fatalf("expected in-flight settlement usage write to fail closed, got %v", err)
	}

	close(adapter.release)
	select {
	case err := <-settleDone:
		if err != nil {
			t.Fatalf("SettleSession: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("settlement did not finish after adapter release")
	}
}

func TestMemoryServiceReserveFundsSubmitsBillingReservationInBlockchainMode(t *testing.T) {
	adapter := &fundReservationCapturingAdapter{}
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	reservation, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-chain-reservation-1",
		SubjectID:    "client-chain-reservation-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if reservation.Status != OperationStatusSubmitted {
		t.Fatalf("expected chain reservation status submitted, got %s", reservation.Status)
	}
	captured := adapter.capturedFundReservations()
	if len(captured) != 1 {
		t.Fatalf("expected one chain billing reservation submit, got %d", len(captured))
	}
	if captured[0].ReservationID != reservation.ReservationID {
		t.Fatalf("expected submitted reservation id %s, got %s", reservation.ReservationID, captured[0].ReservationID)
	}
	if captured[0].Status != OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation payload status, got %s", captured[0].Status)
	}
}

func TestMemoryServiceFundReservationStatusForwardsToChainAdapter(t *testing.T) {
	adapter := &fundReservationStatusAdapter{
		status: OperationStatusConfirmed,
		found:  true,
	}
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	reservation, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-chain-reservation-status-1",
		SubjectID:    "client-chain-reservation-status-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if reservation.Status != OperationStatusSubmitted {
		t.Fatalf("reservation status before chain query=%s want submitted", reservation.Status)
	}

	status, found, err := s.FundReservationStatus(ctx, reservation.ReservationID)
	if err != nil {
		t.Fatalf("FundReservationStatus: %v", err)
	}
	if !found || status != OperationStatusConfirmed {
		t.Fatalf("FundReservationStatus got status=%s found=%v want confirmed found", status, found)
	}
	queries := adapter.statusQueries()
	if len(queries) != 1 || queries[0] != reservation.ReservationID {
		t.Fatalf("status queries=%v want one query for %q", queries, reservation.ReservationID)
	}

	replay, err := s.ReserveFunds(ctx, FundReservation{
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		SubjectID:     reservation.SubjectID,
		AmountMicros:  reservation.AmountMicros,
		Currency:      reservation.Currency,
	})
	if err != nil {
		t.Fatalf("ReserveFunds replay: %v", err)
	}
	if replay.Status != OperationStatusConfirmed {
		t.Fatalf("replay status=%s want confirmed after forwarded chain status", replay.Status)
	}
}

func TestMemoryServiceSettleSessionRequiresConfirmedFundReservationInBlockchainMode(t *testing.T) {
	adapter := &fundReservationMaterialAdapter{
		status: OperationStatusSubmitted,
	}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	reservation, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-chain-settle-finality-1",
		SubjectID:    "client-chain-settle-finality-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    reservation.SessionID,
		SubjectID:    reservation.SubjectID,
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	if settlement, err := s.SettleSession(ctx, reservation.SessionID); err == nil {
		t.Fatalf("expected non-final fund reservation to block settlement, got %+v", settlement)
	} else if !strings.Contains(err.Error(), "chain-finalized fund reservation") {
		t.Fatalf("unexpected non-final reservation error: %v", err)
	}
	s.mu.Lock()
	if _, ok := s.settledBySession[reservation.SessionID]; ok {
		t.Fatalf("non-final reservation should not create settlement")
	}
	if _, ok := s.reservationsBySession[reservation.SessionID]; !ok {
		t.Fatalf("non-final reservation should remain available")
	}
	s.mu.Unlock()

	adapter.setReservationStatus(reservation.ReservationID, OperationStatusConfirmed)
	settlement, err := s.SettleSession(ctx, reservation.SessionID)
	if err != nil {
		t.Fatalf("SettleSession after confirmed reservation: %v", err)
	}
	if settlement.Status != OperationStatusSubmitted || !settlement.AdapterSubmitted || settlement.AdapterDeferred {
		t.Fatalf("expected chain settlement submission after confirmed reservation, got %+v", settlement)
	}
	s.mu.Lock()
	if _, ok := s.reservationsBySession[reservation.SessionID]; ok {
		t.Fatalf("confirmed reservation should be consumed after successful settlement submit")
	}
	s.mu.Unlock()
}

func TestMemoryServiceSettleSessionRejectsStatusOnlyConfirmedFundReservationInBlockchainMode(t *testing.T) {
	adapter := &fundReservationStatusAdapter{
		status: OperationStatusConfirmed,
		found:  true,
	}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	reservation, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-chain-settle-status-only-1",
		SubjectID:    "client-chain-settle-status-only-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    reservation.SessionID,
		SubjectID:    reservation.SubjectID,
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	if settlement, err := s.SettleSession(ctx, reservation.SessionID); err == nil {
		t.Fatalf("expected status-only confirmed reservation to block settlement, got %+v", settlement)
	} else if !strings.Contains(err.Error(), "fund reservation material query") {
		t.Fatalf("unexpected status-only reservation error: %v", err)
	}
	s.mu.Lock()
	if _, ok := s.settledBySession[reservation.SessionID]; ok {
		t.Fatalf("status-only confirmed reservation should not create settlement")
	}
	s.mu.Unlock()
}

func TestMemoryServiceSettleSessionRejectsMismatchedFundReservationMaterialInBlockchainMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(FundReservation) FundReservation
	}{
		{name: "session mismatch", mutate: func(v FundReservation) FundReservation { v.SessionID = "sess-forged"; return v }},
		{name: "subject mismatch", mutate: func(v FundReservation) FundReservation { v.SubjectID = "client-forged"; return v }},
		{name: "amount mismatch", mutate: func(v FundReservation) FundReservation { v.AmountMicros++; return v }},
		{name: "currency mismatch", mutate: func(v FundReservation) FundReservation { v.Currency = "uusdc"; return v }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &fundReservationMaterialAdapter{}
			s := NewMemoryService(
				WithPricePerMiBMicros(1024*1024),
				WithBlockchainMode(true),
				WithChainAdapter(adapter),
			)
			ctx := context.Background()

			reservation, err := s.ReserveFunds(ctx, FundReservation{
				SessionID:    "sess-chain-settle-material-1",
				SubjectID:    "client-chain-settle-material-1",
				AmountMicros: 2_000_000,
				Currency:     "TDPNC",
			})
			if err != nil {
				t.Fatalf("ReserveFunds: %v", err)
			}
			adapter.mutateReservation(reservation.ReservationID, tc.mutate)
			if err := s.RecordUsage(ctx, UsageRecord{
				SessionID:    reservation.SessionID,
				SubjectID:    reservation.SubjectID,
				BytesIngress: 1024 * 1024,
			}); err != nil {
				t.Fatalf("RecordUsage: %v", err)
			}

			if settlement, err := s.SettleSession(ctx, reservation.SessionID); err == nil {
				t.Fatalf("expected mismatched reservation material to block settlement, got %+v", settlement)
			} else if !strings.Contains(err.Error(), "fund reservation material mismatch") {
				t.Fatalf("unexpected material mismatch error: %v", err)
			}
		})
	}
}

func TestMemoryServiceReserveFundsConcurrentBlockchainModeSubmitsOnce(t *testing.T) {
	adapter := &fundReservationCapturingAdapter{submitDelay: 20 * time.Millisecond}
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	const callers = 12
	results := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			_, err := s.ReserveFunds(ctx, FundReservation{
				SessionID:    "sess-chain-reservation-concurrent-1",
				SubjectID:    "client-chain-reservation-concurrent-1",
				AmountMicros: 2_000_000,
				Currency:     "TDPNC",
			})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("ReserveFunds concurrent: %v", err)
		}
	}
	captured := adapter.capturedFundReservations()
	if len(captured) != 1 {
		t.Fatalf("expected one chain billing reservation submit under concurrency, got %d", len(captured))
	}
}

func TestMemoryServiceReserveFundsRejectsReservationIDReuseAcrossSessions(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1024 * 1024))
	ctx := context.Background()
	if _, err := s.ReserveFunds(ctx, FundReservation{
		ReservationID: "res-global-id-reuse-1",
		SessionID:     "sess-res-id-owner-1",
		SubjectID:     "client-res-id-owner-1",
		AmountMicros:  2_000_000,
		Currency:      "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveFunds owner: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-res-id-owner-1",
		SubjectID:    "client-res-id-owner-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage owner: %v", err)
	}
	if _, err := s.SettleSession(ctx, "sess-res-id-owner-1"); err != nil {
		t.Fatalf("SettleSession owner: %v", err)
	}
	_, err := s.ReserveFunds(ctx, FundReservation{
		ReservationID: "res-global-id-reuse-1",
		SessionID:     "sess-res-id-collide-1",
		SubjectID:     "client-res-id-collide-1",
		AmountMicros:  2_000_000,
		Currency:      "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "fund reservation idempotency conflict") {
		t.Fatalf("expected reservation id reuse to fail closed, got %v", err)
	}
}

func TestMemoryServiceReserveFundsChainSubmitDoesNotHoldServiceLock(t *testing.T) {
	adapter := newBlockingFundReservationAdapter()
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()
	reserveDone := make(chan error, 1)
	go func() {
		_, err := s.ReserveFunds(ctx, FundReservation{
			SessionID:    "sess-blocking-reserve-1",
			SubjectID:    "client-blocking-reserve-1",
			AmountMicros: 2_000_000,
			Currency:     "TDPNC",
		})
		reserveDone <- err
	}()

	select {
	case <-adapter.started:
	case <-time.After(time.Second):
		t.Fatalf("reservation adapter did not start")
	}

	recordDone := make(chan error, 1)
	go func() {
		recordDone <- s.RecordUsage(ctx, UsageRecord{
			SessionID:    "sess-independent-while-reserve-blocked-1",
			SubjectID:    "client-independent-while-reserve-blocked-1",
			BytesIngress: 1024,
			BytesEgress:  2048,
		})
	}()
	select {
	case err := <-recordDone:
		if err != nil {
			t.Fatalf("RecordUsage while reservation submit blocked: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("RecordUsage blocked behind chain reservation submit")
	}

	err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-blocking-reserve-1",
		SubjectID:    "client-blocking-reserve-mismatch-1",
		BytesIngress: 1024,
	})
	if err == nil || !strings.Contains(err.Error(), "session subject mismatch") {
		t.Fatalf("expected in-flight reservation subject mismatch to fail closed, got %v", err)
	}

	close(adapter.release)
	select {
	case err := <-reserveDone:
		if err != nil {
			t.Fatalf("ReserveFunds: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("reservation did not finish after adapter release")
	}
	if calls := adapter.fundReservationCalls(); calls != 1 {
		t.Fatalf("fund reservation submit calls=%d want=1", calls)
	}
}

func TestMemoryServiceReserveSponsorCreditsConcurrentBlockchainModeSubmitsOnce(t *testing.T) {
	adapter := &sponsorReservationCapturingAdapter{submitDelay: 20 * time.Millisecond}
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	const callers = 12
	results := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
				ReservationID: "sres-chain-reservation-concurrent-1",
				SponsorID:     "sponsor-chain-reservation-concurrent-1",
				SubjectID:     "client-chain-reservation-concurrent-1",
				SessionID:     "sess-chain-reservation-concurrent-1",
				AmountMicros:  2_000_000,
				Currency:      "TDPNC",
			})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("ReserveSponsorCredits concurrent: %v", err)
		}
	}
	captured := adapter.capturedSponsorReservations()
	if len(captured) != 1 {
		t.Fatalf("expected one chain sponsor reservation submit under concurrency, got %d", len(captured))
	}
}

func TestMemoryServiceReserveFundsFailsClosedInBlockchainModeWithoutBillingReservationSubmitter(t *testing.T) {
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(fakeAdapter{}),
	)
	ctx := context.Background()

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-chain-reservation-no-submit-1",
		SubjectID:    "client-chain-reservation-no-submit-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err == nil {
		t.Fatalf("expected missing billing reservation submitter to fail closed")
	}
	if !strings.Contains(err.Error(), "chain billing reservation submitter") {
		t.Fatalf("unexpected missing submitter error: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.reservationsBySession["sess-chain-reservation-no-submit-1"]; ok {
		t.Fatalf("expected failed chain reservation to not be stored locally")
	}
}

func TestMemoryServiceReserveFundsFailsClosedWhenBillingReservationSubmitFails(t *testing.T) {
	adapter := &fundReservationCapturingAdapter{failReservation: true}
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-chain-reservation-submit-fail-1",
		SubjectID:    "client-chain-reservation-submit-fail-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err == nil {
		t.Fatalf("expected failed billing reservation submit to fail closed")
	}
	if !strings.Contains(err.Error(), "chain reservation submit failed") {
		t.Fatalf("unexpected submit failure error: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.reservationsBySession["sess-chain-reservation-submit-fail-1"]; ok {
		t.Fatalf("expected failed chain reservation to not be stored locally")
	}
}

func TestMemoryServiceSessionSubjectConsistencyRejectsMismatches(t *testing.T) {
	ctx := context.Background()

	t.Run("record usage rejects mismatch with existing reservation subject", func(t *testing.T) {
		s := NewMemoryService()
		const (
			sessionID        = "sess-subject-mismatch-record-1"
			reservationSubj  = "client-subject-good-1"
			recordUsageSubj  = "client-subject-bad-1"
			reservationFunds = int64(10_000)
		)

		if _, err := s.ReserveFunds(ctx, FundReservation{
			SessionID:    sessionID,
			SubjectID:    reservationSubj,
			AmountMicros: reservationFunds,
			Currency:     "TDPNC",
		}); err != nil {
			t.Fatalf("ReserveFunds: %v", err)
		}
		err := s.RecordUsage(ctx, UsageRecord{
			SessionID:    sessionID,
			SubjectID:    recordUsageSubj,
			BytesIngress: 1024,
		})
		if err == nil {
			t.Fatalf("expected mismatched usage subject to fail")
		}
		if !strings.Contains(err.Error(), "session subject mismatch for session "+sessionID) {
			t.Fatalf("unexpected mismatch error: %v", err)
		}
	})

	t.Run("reserve funds rejects mismatch with existing usage subject", func(t *testing.T) {
		s := NewMemoryService()
		const (
			sessionID       = "sess-subject-mismatch-reservation-1"
			usageSubject    = "client-subject-good-2"
			reserveSubject  = "client-subject-bad-2"
			reservationFund = int64(20_000)
		)

		if err := s.RecordUsage(ctx, UsageRecord{
			SessionID:    sessionID,
			SubjectID:    usageSubject,
			BytesIngress: 1024,
		}); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}
		_, err := s.ReserveFunds(ctx, FundReservation{
			SessionID:    sessionID,
			SubjectID:    reserveSubject,
			AmountMicros: reservationFund,
			Currency:     "TDPNC",
		})
		if err == nil {
			t.Fatalf("expected mismatched reservation subject to fail")
		}
		if !strings.Contains(err.Error(), "session subject mismatch for session "+sessionID) {
			t.Fatalf("unexpected mismatch error: %v", err)
		}
	})

	t.Run("reserve sponsor credits rejects mismatch with existing usage subject", func(t *testing.T) {
		s := NewMemoryService()
		const (
			sessionID                = "sess-subject-mismatch-sponsor-reservation-1"
			usageSubject             = "client-subject-good-2a"
			sponsorProofSubj         = "client-subject-bad-2a"
			sponsorReserveID         = "sres-subject-mismatch-sponsor-reservation-1"
			sponsorReservationAmount = int64(20_000)
		)

		if err := s.RecordUsage(ctx, UsageRecord{
			SessionID:    sessionID,
			SubjectID:    usageSubject,
			BytesIngress: 1024,
		}); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}
		_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
			ReservationID: sponsorReserveID,
			SponsorID:     "sponsor-subject-mismatch-2a",
			SubjectID:     sponsorProofSubj,
			SessionID:     sessionID,
			AmountMicros:  sponsorReservationAmount,
			Currency:      "TDPNC",
		})
		if err == nil {
			t.Fatalf("expected mismatched sponsor reservation subject to fail")
		}
		if !strings.Contains(err.Error(), "session subject mismatch for session "+sessionID) {
			t.Fatalf("unexpected mismatch error: %v", err)
		}

		s.mu.Lock()
		_, ok := s.sponsorReservationsByID[sponsorReserveID]
		s.mu.Unlock()
		if ok {
			t.Fatalf("expected mismatched sponsor reservation to not be stored")
		}
	})

	t.Run("settle session rejects mixed usage subjects fail closed", func(t *testing.T) {
		s := NewMemoryService(WithPricePerMiBMicros(1024 * 1024))
		const (
			sessionID      = "sess-subject-mismatch-settle-1"
			sessionSubject = "client-subject-good-3"
		)

		if _, err := s.ReserveFunds(ctx, FundReservation{
			SessionID:    sessionID,
			SubjectID:    sessionSubject,
			AmountMicros: 3_000_000,
			Currency:     "TDPNC",
		}); err != nil {
			t.Fatalf("ReserveFunds: %v", err)
		}
		if err := s.RecordUsage(ctx, UsageRecord{
			SessionID:    sessionID,
			SubjectID:    sessionSubject,
			BytesIngress: 1024 * 1024,
		}); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}

		s.mu.Lock()
		s.usageBySession[sessionID] = append(s.usageBySession[sessionID], UsageRecord{
			SessionID:    sessionID,
			SubjectID:    "client-subject-bad-3",
			BytesIngress: 1024,
		})
		s.mu.Unlock()

		_, err := s.SettleSession(ctx, sessionID)
		if err == nil {
			t.Fatalf("expected mixed subject usage to fail settlement")
		}
		if !strings.Contains(err.Error(), "session subject mismatch for session "+sessionID) {
			t.Fatalf("unexpected settle mismatch error: %v", err)
		}
	})
}

func TestMemoryServiceSessionSubjectConsistencyValidLifecycle(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1_000_000))
	ctx := context.Background()
	const (
		sessionID = "sess-subject-consistent-valid-1"
		subjectID = "client-subject-consistent-valid-1"
	)

	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage first: %v", err)
	}

	reservationA, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 3_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds first: %v", err)
	}
	reservationB, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 3_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds second: %v", err)
	}
	if reservationA.ReservationID != reservationB.ReservationID {
		t.Fatalf("expected idempotent reservation replay for consistent subject")
	}
	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 9_999_999,
		Currency:     "TDPNC",
	}); err == nil || !strings.Contains(err.Error(), "fund reservation idempotency conflict") {
		t.Fatalf("expected changed reservation amount to fail idempotency conflict, got %v", err)
	}

	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:   sessionID,
		SubjectID:   subjectID,
		BytesEgress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage second: %v", err)
	}

	settlement, err := s.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.SubjectID != subjectID {
		t.Fatalf("expected settlement subject %s, got %s", subjectID, settlement.SubjectID)
	}
	if settlement.ChargedMicros != 2_000_000 {
		t.Fatalf("expected charged micros 2000000, got %d", settlement.ChargedMicros)
	}
}

func TestMemoryServiceSessionSubjectConsistencyRejectsUsageAndReserveFundsAfterSettlement(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1_000_000))
	ctx := context.Background()
	const (
		sessionID = "sess-settled-write-reject-1"
		subjectID = "client-settled-write-reject-1"
	)

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if _, err := s.SettleSession(ctx, sessionID); err != nil {
		t.Fatalf("SettleSession: %v", err)
	}

	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		BytesIngress: 1024,
	}); err == nil {
		t.Fatalf("expected RecordUsage on settled session to fail closed")
	} else if !strings.Contains(err.Error(), "session already settled for session "+sessionID) {
		t.Fatalf("unexpected RecordUsage error: %v", err)
	}

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 10_000,
		Currency:     "TDPNC",
	}); err == nil {
		t.Fatalf("expected ReserveFunds on settled session to fail closed")
	} else if !strings.Contains(err.Error(), "session already settled for session "+sessionID) {
		t.Fatalf("unexpected ReserveFunds error: %v", err)
	}
}

func TestMemoryServiceAdapterDeferredOnFailure(t *testing.T) {
	s := NewMemoryService(WithChainAdapter(fakeAdapter{fail: true}))
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-2",
		SubjectID:    "client-2",
		AmountMicros: 10_000,
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-2",
		SubjectID:    "client-2",
		BytesIngress: 1024,
		BytesEgress:  1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-2")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if !settlement.AdapterDeferred {
		t.Fatalf("expected adapter deferred settlement on adapter failure")
	}
	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-2",
		RewardMicros:      50,
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if !reward.AdapterDeferred {
		t.Fatalf("expected adapter deferred reward on adapter failure")
	}
	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-1",
		SponsorID:     "sponsor-1",
		SubjectID:     "client-2",
		SessionID:     "sess-2",
		AmountMicros:  100,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if !reservation.AdapterDeferred {
		t.Fatalf("expected adapter deferred sponsor reservation on adapter failure")
	}
	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-1",
		SubjectID:     "provider-1",
		SessionID:     "sess-2",
		ViolationType: "double-sign",
		EvidenceRef:   "obj://validator/double-sign/sess-2",
		SlashMicros:   7,
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if !evidence.AdapterDeferred {
		t.Fatalf("expected adapter deferred slash evidence on adapter failure")
	}
	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 4 {
		t.Fatalf("expected pending adapter operations 4, got %d", report.PendingAdapterOperations)
	}
	if len(s.deferredAdapterOps) != 4 {
		t.Fatalf("expected deferred backlog entries 4, got %d", len(s.deferredAdapterOps))
	}
}

func TestMemoryServiceIssueRewardBackfillsSettlementReference(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1024 * 1024))
	ctx := context.Background()

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-reward-proof-1",
		SubjectID:    "client-reward-proof-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-reward-proof-1",
		SubjectID:    "client-reward-proof-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-reward-proof-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}

	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-reward-proof-1",
		ProviderSubjectID: "provider-reward-proof-1",
		SessionID:         "sess-reward-proof-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if reward.SettlementReferenceID != settlement.SettlementID {
		t.Fatalf("expected reward settlement reference %s, got %s", settlement.SettlementID, reward.SettlementReferenceID)
	}
	if reward.TrafficProofRef != "" {
		t.Fatalf("expected local-mode settlement backfill to leave traffic proof empty, got %s", reward.TrafficProofRef)
	}
}

func TestMemoryServiceIssueRewardRequiresProofReferenceInBlockchainMode(t *testing.T) {
	s := NewMemoryService(WithBlockchainMode(true))
	ctx := context.Background()
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	_, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-blockchain-missing-proof-1",
		ProviderSubjectID: "provider-blockchain-missing-proof-1",
		SessionID:         "sess-blockchain-missing-proof-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil {
		t.Fatalf("expected blockchain-mode reward without proof reference to fail")
	}
	if !strings.Contains(err.Error(), "verified traffic_proof_ref") {
		t.Fatalf("unexpected missing proof error: %v", err)
	}

	formatOnlyProofRef := testSHA256Ref("traffic-proof-reward-1")
	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-blockchain-format-only-proof-1",
		ProviderSubjectID: "provider-blockchain-format-only-proof-1",
		SessionID:         "sess-blockchain-format-only-proof-1",
		TrafficProofRef:   formatOnlyProofRef,
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "verified traffic_proof_ref") {
		t.Fatalf("expected format-only traffic proof to fail closed, got %v", err)
	}

	proofRef := "obj://traffic-proof/reward-1"
	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-blockchain-unverified-traffic-proof-1",
		ProviderSubjectID: "provider-blockchain-traffic-proof-1",
		SessionID:         "sess-blockchain-traffic-proof-1",
		TrafficProofRef:   proofRef,
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "requires reward proof verifier") {
		t.Fatalf("expected unverified obj traffic proof to fail closed, got %v", err)
	}

	verifier := newAcceptingRewardProofVerifier()
	s = NewMemoryService(WithBlockchainMode(true), WithRewardProofVerifier(verifier))
	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-blockchain-missing-period-1",
		ProviderSubjectID: "provider-blockchain-missing-period-1",
		SessionID:         "sess-blockchain-missing-period-1",
		TrafficProofRef:   "obj://traffic-proof/reward-missing-period-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "weekly payout period") {
		t.Fatalf("expected verified chain-backed reward without payout period to fail closed, got %v", err)
	}
	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-blockchain-traffic-proof-1",
		ProviderSubjectID: "provider-blockchain-traffic-proof-1",
		SessionID:         "sess-blockchain-traffic-proof-1",
		TrafficProofRef:   proofRef,
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodStart.Add(weeklyRewardPayoutPeriod),
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward with traffic proof: %v", err)
	}
	if reward.TrafficProofRef != proofRef {
		t.Fatalf("expected traffic proof ref %s, got %s", proofRef, reward.TrafficProofRef)
	}
	if !reward.TrafficProofVerified || reward.TrafficProofVerifierID != verifier.verifierID {
		t.Fatalf("expected verified traffic proof metadata, got %+v", reward)
	}
	if reward.TrafficProofTrustContract != RewardProofTrustContractObjectiveTrafficV1 {
		t.Fatalf("traffic proof trust contract=%q want %q", reward.TrafficProofTrustContract, RewardProofTrustContractObjectiveTrafficV1)
	}
	request, ok := verifier.lastRequest()
	if !ok {
		t.Fatal("expected verifier request")
	}
	if request.TrustContract != RewardProofTrustContractObjectiveTrafficV1 ||
		request.TrafficProofRef != proofRef ||
		request.RewardID != reward.RewardID ||
		request.ProviderSubjectID != reward.ProviderSubjectID ||
		request.SessionID != reward.SessionID ||
		request.RewardMicros != reward.RewardMicros ||
		request.Currency != reward.Currency {
		t.Fatalf("unexpected verifier trust contract request: %+v reward=%+v", request, reward)
	}
	if reward.Status != OperationStatusPending || !reward.AdapterDeferred {
		t.Fatalf("expected blockchain-mode reward with missing adapter to remain pending+deferred")
	}
}

func TestMemoryServiceIssueRewardRequiresProofReferenceWithChainAdapter(t *testing.T) {
	s := NewMemoryService(WithChainAdapter(rewardProofRequiringAdapter{}))
	ctx := context.Background()
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	_, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-adapter-missing-proof-1",
		ProviderSubjectID: "provider-adapter-missing-proof-1",
		SessionID:         "sess-adapter-missing-proof-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "verified traffic_proof_ref") {
		t.Fatalf("expected adapter-backed reward without proof metadata to fail closed, got %v", err)
	}

	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-adapter-format-only-proof-1",
		ProviderSubjectID: "provider-adapter-format-only-proof-1",
		SessionID:         "sess-adapter-format-only-proof-1",
		TrafficProofRef:   testSHA256Ref("adapter-format-only-proof-1"),
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "verified traffic_proof_ref") {
		t.Fatalf("expected adapter-backed format-only proof to fail closed, got %v", err)
	}

	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-adapter-unverified-proof-1",
		ProviderSubjectID: "provider-adapter-unverified-proof-1",
		SessionID:         "sess-adapter-unverified-proof-1",
		TrafficProofRef:   "obj://traffic-proof/adapter-unverified-proof-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "requires reward proof verifier") {
		t.Fatalf("expected adapter-backed unverified obj proof to fail closed, got %v", err)
	}

	verifier := newAcceptingRewardProofVerifier()
	s = NewMemoryService(WithChainAdapter(rewardProofRequiringAdapter{}), WithRewardProofVerifier(verifier))
	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-adapter-verified-proof-1",
		ProviderSubjectID: "provider-adapter-verified-proof-1",
		SessionID:         "sess-adapter-verified-proof-1",
		TrafficProofRef:   "obj://traffic-proof/adapter-verified-proof-1",
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodStart.Add(weeklyRewardPayoutPeriod),
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward with verifier-backed adapter proof: %v", err)
	}
	if !reward.TrafficProofVerified || reward.TrafficProofVerifierID != verifier.verifierID {
		t.Fatalf("expected verified adapter-backed proof, got %+v", reward)
	}
}

func testRewardProofRecord(seed string) RewardProofRecord {
	issuedAt := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	proofPath := "traffic-proof/" + seed
	return RewardProofRecord{
		ProofPath:         proofPath,
		TrafficProofRef:   "obj://" + proofPath,
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "rew-" + seed,
		ProviderSubjectID: "provider-" + seed,
		SessionID:         "sess-" + seed,
		PayoutPeriodStart: issuedAt.Truncate(24 * time.Hour),
		PayoutPeriodEnd:   issuedAt.Truncate(24*time.Hour).AddDate(0, 0, 7),
		RewardMicros:      50,
		Currency:          "TDPNC",
		IssuedAt:          issuedAt,
		Verified:          true,
		VerifierID:        "test-verifier",
		VerifiedAt:        issuedAt,
	}
}

func TestMemoryServiceRegisterRewardProofRequiresVerifiedProof(t *testing.T) {
	adapter := &rewardProofCapturingAdapter{}
	s := NewMemoryService(WithChainAdapter(adapter))

	proof := testRewardProofRecord("unverified-register")
	proof.Verified = false
	proof.VerifierID = ""
	err := s.RegisterRewardProof(context.Background(), proof)
	if err == nil || !strings.Contains(err.Error(), "verified proof") {
		t.Fatalf("expected unverified proof registration to fail closed, got %v", err)
	}
	if got := adapter.capturedRewardProofs(); len(got) != 0 {
		t.Fatalf("unverified proof should not reach chain adapter: %+v", got)
	}
}

func TestMemoryServiceRegisterRewardProofValidatesObjectiveRefBinding(t *testing.T) {
	adapter := &rewardProofCapturingAdapter{}
	s := NewMemoryService(WithChainAdapter(adapter))

	proof := testRewardProofRecord("mismatch-register")
	proof.TrafficProofRef = "obj://traffic-proof/different-proof"
	err := s.RegisterRewardProof(context.Background(), proof)
	if err == nil || !strings.Contains(err.Error(), "matching obj://") {
		t.Fatalf("expected mismatched obj proof ref to fail closed, got %v", err)
	}
	if got := adapter.capturedRewardProofs(); len(got) != 0 {
		t.Fatalf("mismatched proof should not reach chain adapter: %+v", got)
	}
}

func TestMemoryServiceRegisterRewardProofSubmitsPrimaryAndShadowAdapters(t *testing.T) {
	primary := &rewardProofCapturingAdapter{}
	shadow := &rewardProofCapturingAdapter{}
	s := NewMemoryService(WithChainAdapter(primary), WithShadowChainAdapter(shadow))

	proof := testRewardProofRecord("adapter-submit")
	proof.Currency = "tdpnc"
	proof.VerifierID = " verifier-1 "
	if err := s.RegisterRewardProof(context.Background(), proof); err != nil {
		t.Fatalf("RegisterRewardProof: %v", err)
	}

	primaryProofs := primary.capturedRewardProofs()
	shadowProofs := shadow.capturedRewardProofs()
	if len(primaryProofs) != 1 || len(shadowProofs) != 1 {
		t.Fatalf("expected primary and shadow proof submissions, got primary=%+v shadow=%+v", primaryProofs, shadowProofs)
	}
	if primaryProofs[0].Currency != "TDPNC" || primaryProofs[0].VerifierID != "verifier-1" {
		t.Fatalf("expected canonicalized proof metadata before adapter submit, got %+v", primaryProofs[0])
	}
	if shadowProofs[0].ProofPath != primaryProofs[0].ProofPath || shadowProofs[0].RewardID != primaryProofs[0].RewardID {
		t.Fatalf("shadow proof mismatch primary=%+v shadow=%+v", primaryProofs[0], shadowProofs[0])
	}
}

func TestMemoryServiceRegisterRewardProofFailsClosedOnPrimaryAdapterError(t *testing.T) {
	primary := &rewardProofCapturingAdapter{err: errFakeAdapter}
	shadow := &rewardProofCapturingAdapter{}
	s := NewMemoryService(WithChainAdapter(primary), WithShadowChainAdapter(shadow))

	err := s.RegisterRewardProof(context.Background(), testRewardProofRecord("primary-error"))
	if err == nil || !strings.Contains(err.Error(), errFakeAdapter.Error()) {
		t.Fatalf("expected primary adapter failure, got %v", err)
	}
	if got := primary.capturedRewardProofs(); len(got) != 0 {
		t.Fatalf("failed primary should not record proof as submitted: %+v", got)
	}
	if got := shadow.capturedRewardProofs(); len(got) != 0 {
		t.Fatalf("shadow should not run after primary failure: %+v", got)
	}
}

func TestMemoryServiceRegisterRewardProofIgnoresShadowAdapterError(t *testing.T) {
	primary := &rewardProofCapturingAdapter{}
	shadow := &rewardProofCapturingAdapter{err: errFakeAdapter}
	s := NewMemoryService(WithChainAdapter(primary), WithShadowChainAdapter(shadow))

	if err := s.RegisterRewardProof(context.Background(), testRewardProofRecord("shadow-error")); err != nil {
		t.Fatalf("shadow adapter failure should be best-effort, got %v", err)
	}
	if got := primary.capturedRewardProofs(); len(got) != 1 {
		t.Fatalf("expected primary proof submission despite shadow failure, got %+v", got)
	}
}

func TestMemoryServiceIssueRewardRejectsUnverifiedProofBeforeWeeklyPayoutPrepared(t *testing.T) {
	verifier := newAcceptingRewardProofVerifier()
	verifier.setVerified(false)
	s := NewMemoryService(WithBlockchainMode(true), WithRewardProofVerifier(verifier))
	ctx := context.Background()
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	_, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-unverified-weekly-1",
		ProviderSubjectID: "provider-unverified-weekly-1",
		SessionID:         "sess-unverified-weekly-1",
		TrafficProofRef:   "obj://traffic-proof/unverified-weekly-1",
		PayoutPeriodStart: periodStart,
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "traffic proof not verified") {
		t.Fatalf("expected unverified weekly proof to fail closed, got %v", err)
	}

	s.mu.Lock()
	if len(s.rewardsByID) != 0 || len(s.weeklyRewardPayoutByKey) != 0 {
		t.Fatalf("unverified proof should not prepare reward or weekly payout key: rewards=%+v weekly=%+v", s.rewardsByID, s.weeklyRewardPayoutByKey)
	}
	s.mu.Unlock()

	verifier.setVerified(true)
	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-verified-weekly-1",
		ProviderSubjectID: "provider-unverified-weekly-1",
		SessionID:         "sess-verified-weekly-1",
		TrafficProofRef:   "obj://traffic-proof/verified-weekly-1",
		PayoutPeriodStart: periodStart,
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward after proof verifier accepts: %v", err)
	}
	if !reward.TrafficProofVerified {
		t.Fatalf("expected verified weekly proof metadata, got %+v", reward)
	}
}

func TestMemoryServiceReconcileKeepsUnverifiedTrafficProofRewardSubmitted(t *testing.T) {
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(confirmingAdapter{}),
	)
	s.mu.Lock()
	s.rewardsByID["rew-legacy-unverified-proof-1"] = RewardIssue{
		RewardID:          "rew-legacy-unverified-proof-1",
		ProviderSubjectID: "provider-legacy-unverified-proof-1",
		SessionID:         "sess-legacy-unverified-proof-1",
		TrafficProofRef:   "obj://traffic-proof/legacy-unverified-proof-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
		IssuedAt:          time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		AdapterSubmitted:  true,
		Status:            OperationStatusSubmitted,
	}
	s.mu.Unlock()

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 0 || report.SubmittedOperations != 1 {
		t.Fatalf("expected unverified reward to remain submitted, report=%+v", report)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reward := s.rewardsByID["rew-legacy-unverified-proof-1"]
	if reward.Status != OperationStatusSubmitted || reward.TrafficProofVerified {
		t.Fatalf("expected unverified proof reward to remain submitted, got %+v", reward)
	}
}

func TestMemoryServiceReconcileRequiresTrafficProofWithConfirmedSettlementReference(t *testing.T) {
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(confirmingAdapter{}),
	)
	s.mu.Lock()
	s.settledBySession["sess-legacy-settlement-ref-no-proof-1"] = SessionSettlement{
		SettlementID: "set-legacy-settlement-ref-no-proof-1",
		SessionID:    "sess-legacy-settlement-ref-no-proof-1",
		Status:       OperationStatusConfirmed,
	}
	s.rewardsByID["rew-legacy-settlement-ref-no-proof-1"] = RewardIssue{
		RewardID:              "rew-legacy-settlement-ref-no-proof-1",
		ProviderSubjectID:     "provider-legacy-settlement-ref-no-proof-1",
		SessionID:             "sess-legacy-settlement-ref-no-proof-1",
		SettlementReferenceID: "set-legacy-settlement-ref-no-proof-1",
		RewardMicros:          50,
		Currency:              "TDPNC",
		IssuedAt:              time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		AdapterSubmitted:      true,
		Status:                OperationStatusSubmitted,
	}
	s.mu.Unlock()

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.SubmittedOperations != 1 || report.ConfirmedOperations != 1 {
		t.Fatalf("expected reward with confirmed settlement ref and no proof to stay unconfirmed, report=%+v", report)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reward := s.rewardsByID["rew-legacy-settlement-ref-no-proof-1"]
	if reward.Status != OperationStatusSubmitted || reward.TrafficProofVerified {
		t.Fatalf("expected settlement reference without traffic proof to remain submitted, got %+v", reward)
	}
}

func TestMemoryServiceReconcileVerifiesTrafficProofBeforeRewardFinalization(t *testing.T) {
	verifier := newAcceptingRewardProofVerifier()
	reward := RewardIssue{
		RewardID:          "rew-legacy-verified-proof-1",
		ProviderSubjectID: "provider-legacy-verified-proof-1",
		SessionID:         "sess-legacy-verified-proof-1",
		TrafficProofRef:   "obj://traffic-proof/legacy-verified-proof-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
		IssuedAt:          time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		AdapterSubmitted:  true,
		Status:            OperationStatusSubmitted,
	}
	chainReward := reward
	chainReward.Status = OperationStatusConfirmed
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(materialSettlementConfirmingAdapter{
			rewards: map[string]RewardIssue{reward.RewardID: chainReward},
		}),
		WithRewardProofVerifier(verifier),
	)
	s.mu.Lock()
	s.rewardsByID[reward.RewardID] = reward
	s.mu.Unlock()

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 1 {
		t.Fatalf("expected verified proof reward to confirm, report=%+v", report)
	}
	s.mu.Lock()
	reward = s.rewardsByID["rew-legacy-verified-proof-1"]
	s.mu.Unlock()
	if reward.Status != OperationStatusConfirmed || !reward.TrafficProofVerified || reward.TrafficProofVerifierID != verifier.verifierID {
		t.Fatalf("expected verified proof reward to finalize with verifier metadata, got %+v", reward)
	}
	request, ok := verifier.lastRequest()
	if !ok || request.RewardID != reward.RewardID || request.TrafficProofRef != reward.TrafficProofRef {
		t.Fatalf("unexpected reconcile verifier request: ok=%v request=%+v reward=%+v", ok, request, reward)
	}
}

func TestMemoryServiceIssueRewardRequiresFinalSettlementReferenceInBlockchainMode(t *testing.T) {
	verifier := newAcceptingRewardProofVerifier()
	adapter := &fundReservationMaterialAdapter{}
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
		WithPricePerMiBMicros(1024*1024),
		WithRewardProofVerifier(verifier),
	)
	ctx := context.Background()
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-reward-finality-1",
		SubjectID:    "client-reward-finality-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-reward-finality-1",
		SubjectID:    "client-reward-finality-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-reward-finality-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("settlement status=%s want submitted before reconcile", settlement.Status)
	}

	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:              "rew-reward-finality-pending-1",
		ProviderSubjectID:     "provider-reward-finality-1",
		SessionID:             "sess-reward-finality-1",
		SettlementReferenceID: settlement.SettlementID,
		TrafficProofRef:       "obj://traffic-proof/reward-finality-pending-1",
		RewardMicros:          50,
		Currency:              "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "requires chain-finalized settlement reference") {
		t.Fatalf("expected pending settlement reference to be rejected, got %v", err)
	}

	if _, err := s.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:              "rew-reward-finality-confirmed-no-proof-1",
		ProviderSubjectID:     "provider-reward-finality-1",
		SessionID:             "sess-reward-finality-1",
		SettlementReferenceID: settlement.SettlementID,
		RewardMicros:          50,
		Currency:              "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "verified traffic_proof_ref") {
		t.Fatalf("expected confirmed settlement reference without proof to be rejected, got %v", err)
	}

	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:              "rew-reward-finality-confirmed-1",
		ProviderSubjectID:     "provider-reward-finality-1",
		SessionID:             "sess-reward-finality-1",
		SettlementReferenceID: settlement.SettlementID,
		TrafficProofRef:       "obj://traffic-proof/reward-finality-confirmed-1",
		PayoutPeriodStart:     periodStart,
		PayoutPeriodEnd:       periodStart.Add(weeklyRewardPayoutPeriod),
		RewardMicros:          50,
		Currency:              "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward after settlement confirmation: %v", err)
	}
	if reward.SettlementReferenceID != settlement.SettlementID {
		t.Fatalf("reward settlement reference=%q want=%q", reward.SettlementReferenceID, settlement.SettlementID)
	}

	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:              "rew-reward-finality-mismatch-1",
		ProviderSubjectID:     "provider-reward-finality-1",
		SessionID:             "sess-reward-finality-1",
		SettlementReferenceID: "set-forged-finality-1",
		TrafficProofRef:       "obj://traffic-proof/reward-finality-mismatch-1",
		RewardMicros:          50,
		Currency:              "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "settlement reference mismatch") {
		t.Fatalf("expected forged settlement reference to be rejected, got %v", err)
	}
}

func TestMemoryServiceIssueRewardEnforcesWeeklyPayoutUniqueness(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	rewardA, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-weekly-1",
		ProviderSubjectID: "provider-weekly-1",
		SessionID:         "sess-weekly-1",
		TrafficProofRef:   testSHA256Ref("weekly-proof-1"),
		PayoutPeriodStart: periodStart,
		RewardMicros:      75,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward first weekly payout: %v", err)
	}
	if !rewardA.PayoutPeriodStart.Equal(periodStart) {
		t.Fatalf("expected payout period start %s, got %s", periodStart, rewardA.PayoutPeriodStart)
	}
	if !rewardA.PayoutPeriodEnd.Equal(periodStart.Add(weeklyRewardPayoutPeriod)) {
		t.Fatalf("expected payout period end %s, got %s", periodStart.Add(weeklyRewardPayoutPeriod), rewardA.PayoutPeriodEnd)
	}

	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-weekly-duplicate-1",
		ProviderSubjectID: "provider-weekly-1",
		SessionID:         "sess-weekly-duplicate-1",
		TrafficProofRef:   testSHA256Ref("weekly-proof-duplicate-1"),
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodStart.Add(weeklyRewardPayoutPeriod),
		RewardMicros:      80,
		Currency:          "TDPNC",
	})
	if err == nil {
		t.Fatalf("expected duplicate weekly payout period to fail")
	}
	if !strings.Contains(err.Error(), "reward payout already issued for provider provider-weekly-1") {
		t.Fatalf("unexpected duplicate weekly payout error: %v", err)
	}

	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-weekly-1",
		ProviderSubjectID: "provider-weekly-override",
		SessionID:         "sess-weekly-override",
		TrafficProofRef:   testSHA256Ref("weekly-proof-override"),
		PayoutPeriodStart: periodStart.Add(weeklyRewardPayoutPeriod),
		RewardMicros:      90,
		Currency:          "TDPNC",
	})
	if err != nil {
		if !strings.Contains(err.Error(), "conflict") {
			t.Fatalf("expected conflicting reward id replay to fail with conflict, got %v", err)
		}
	} else {
		t.Fatalf("expected conflicting reward id replay to fail")
	}

	if _, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-weekly-next-1",
		ProviderSubjectID: "provider-weekly-1",
		SessionID:         "sess-weekly-next-1",
		TrafficProofRef:   testSHA256Ref("weekly-proof-next-1"),
		PayoutPeriodStart: periodStart.Add(weeklyRewardPayoutPeriod),
		RewardMicros:      85,
		Currency:          "TDPNC",
	}); err != nil {
		t.Fatalf("IssueReward next weekly payout: %v", err)
	}
}

func TestMemoryServiceIssueRewardBlocksWeeklyPayoutWhenSlashEvidenceExists(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-weekly-reward-hold-1",
		SubjectID:     "provider-weekly-held",
		SessionID:     "sess-weekly-held",
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   testSHA256Ref("weekly-reward-hold"),
		SlashMicros:   25,
		Currency:      "TDPNC",
		ObservedAt:    periodStart.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}

	_, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-weekly-held-1",
		ProviderSubjectID: "provider-weekly-held",
		SessionID:         "sess-weekly-held-reward",
		TrafficProofRef:   testSHA256Ref("weekly-held-proof"),
		PayoutPeriodStart: periodStart,
		RewardMicros:      75,
		Currency:          "TDPNC",
	})
	if err == nil {
		t.Fatal("expected slash evidence to block weekly payout")
	}
	if !strings.Contains(err.Error(), "blocked by slash evidence") {
		t.Fatalf("unexpected slash hold error: %v", err)
	}
}

func TestMemoryServiceIssueRewardFailsClosedWhenChainSlashEvidenceCannotBeListed(t *testing.T) {
	s := NewMemoryService(
		WithChainAdapter(fakeAdapter{}),
		WithBlockchainMode(true),
		WithRewardProofVerifier(newAcceptingRewardProofVerifier()),
	)
	ctx := context.Background()
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	_, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-weekly-no-lister-1",
		ProviderSubjectID: "provider-weekly-no-lister",
		SessionID:         "sess-weekly-no-lister",
		TrafficProofRef:   "obj://traffic-proof/weekly-no-lister-proof",
		PayoutPeriodStart: periodStart,
		RewardMicros:      75,
		Currency:          "TDPNC",
	})
	if err == nil {
		t.Fatal("expected chain slash evidence lister failure")
	}
	if !strings.Contains(err.Error(), "slash evidence hold check") || !strings.Contains(err.Error(), "chain slash evidence lister") {
		t.Fatalf("unexpected chain slash hold error: %v", err)
	}
}

func TestMemoryServiceIssueRewardValidatesPayoutAndTrafficProofReferences(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()

	_, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-invalid-proof-ref-1",
		ProviderSubjectID: "provider-invalid-proof-ref-1",
		SessionID:         "sess-invalid-proof-ref-1",
		TrafficProofRef:   "manual-note://not-objective",
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil {
		t.Fatalf("expected invalid traffic proof ref to fail")
	}
	if !strings.Contains(err.Error(), "objective traffic_proof_ref") {
		t.Fatalf("unexpected invalid traffic proof error: %v", err)
	}

	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-invalid-period-1",
		ProviderSubjectID: "provider-invalid-period-1",
		SessionID:         "sess-invalid-period-1",
		TrafficProofRef:   testSHA256Ref("invalid-period-1"),
		PayoutPeriodStart: time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC),
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err == nil {
		t.Fatalf("expected non-weekly payout period to fail")
	}
	if !strings.Contains(err.Error(), "Monday 00:00 UTC") {
		t.Fatalf("unexpected invalid payout period error: %v", err)
	}
}

func TestMemoryServiceBlockchainModeWithoutAdapterFailsClosed(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithBlockchainMode(true),
		WithRewardProofVerifier(newAcceptingRewardProofVerifier()),
	)
	ctx := context.Background()
	periodStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	s.mu.Lock()
	s.reservationsBySession["sess-blockchain-no-adapter-1"] = FundReservation{
		ReservationID: "res-sess-blockchain-no-adapter-1",
		SessionID:     "sess-blockchain-no-adapter-1",
		SubjectID:     "client-blockchain-no-adapter-1",
		AmountMicros:  10_000,
		Currency:      "TDPNC",
		CreatedAt:     time.Now().UTC(),
		Status:        OperationStatusSubmitted,
	}
	s.mu.Unlock()
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-blockchain-no-adapter-1",
		SubjectID:    "client-blockchain-no-adapter-1",
		BytesIngress: 1024,
		BytesEgress:  1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-blockchain-no-adapter-1")
	if err == nil {
		t.Fatalf("expected SettleSession to fail closed before consuming non-final reservation, got settlement=%+v", settlement)
	}
	if !strings.Contains(err.Error(), "fund reservation material query") {
		t.Fatalf("unexpected SettleSession error: %v", err)
	}

	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-blockchain-no-adapter-1",
		ProviderSubjectID: "provider-blockchain-no-adapter-1",
		SessionID:         "sess-blockchain-no-adapter-1",
		TrafficProofRef:   "obj://traffic-proof/blockchain-no-adapter-reward-proof",
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodStart.Add(weeklyRewardPayoutPeriod),
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if reward.Status != OperationStatusPending || !reward.AdapterDeferred || reward.AdapterSubmitted {
		t.Fatalf("expected reward pending+deferred when blockchain mode has no adapter")
	}
	rewardRef := cosmosID("reward", reward.RewardID, reward.SessionID)
	if reward.AdapterReferenceID != rewardRef {
		t.Fatalf("expected reward adapter reference id %s, got %s", rewardRef, reward.AdapterReferenceID)
	}

	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-blockchain-no-adapter-1",
		SponsorID:     "sponsor-blockchain-no-adapter-1",
		SubjectID:     "client-blockchain-no-adapter-1",
		SessionID:     "sess-blockchain-no-adapter-1",
		AmountMicros:  100,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != OperationStatusPending || !reservation.AdapterDeferred || reservation.AdapterSubmitted {
		t.Fatalf("expected sponsor reservation pending+deferred when blockchain mode has no adapter")
	}
	reservationRef := cosmosID("sponsor-reservation", reservation.ReservationID, reservation.SessionID)
	if reservation.AdapterReferenceID != reservationRef {
		t.Fatalf("expected reservation adapter reference id %s, got %s", reservationRef, reservation.AdapterReferenceID)
	}
	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: reservation.ReservationID,
		SponsorID:     reservation.SponsorID,
		SubjectID:     reservation.SubjectID,
		SessionID:     reservation.SessionID,
	})
	if err == nil {
		t.Fatalf("expected authorize payment to fail for pending deferred reservation in blockchain mode")
	}
	if err.Error() != "reservation pending chain submission: sres-blockchain-no-adapter-1" {
		t.Fatalf("unexpected authorize payment error for pending deferred reservation: %v", err)
	}

	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-blockchain-no-adapter-1",
		SubjectID:     "provider-blockchain-no-adapter-1",
		SessionID:     "sess-blockchain-no-adapter-1",
		ViolationType: "double-sign",
		EvidenceRef:   "obj://validator/double-sign/sess-blockchain-no-adapter-1",
		SlashMicros:   7,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if evidence.Status != OperationStatusPending || !evidence.AdapterDeferred || evidence.AdapterSubmitted {
		t.Fatalf("expected slash evidence pending+deferred when blockchain mode has no adapter")
	}
	evidenceRef := cosmosID("slash", evidence.EvidenceID, evidence.SubjectID)
	if evidence.AdapterReferenceID != evidenceRef {
		t.Fatalf("expected slash evidence adapter reference id %s, got %s", evidenceRef, evidence.AdapterReferenceID)
	}

	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 3 {
		t.Fatalf("expected pending adapter operations 3 when adapter is missing in blockchain mode, got %d", report.PendingAdapterOperations)
	}
	if report.PendingOperations != 3 {
		t.Fatalf("expected pending operations 3 when adapter is missing in blockchain mode, got %d", report.PendingOperations)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	storedReservation := s.sponsorReservationsByID["sres-blockchain-no-adapter-1"]
	if storedReservation.Status != OperationStatusPending || !storedReservation.AdapterDeferred || storedReservation.AdapterSubmitted {
		t.Fatalf("expected pending deferred sponsor reservation to remain unchanged after failed authorize")
	}
	if !storedReservation.ConsumedAt.IsZero() {
		t.Fatalf("expected pending deferred sponsor reservation to remain unconsumed after failed authorize")
	}
	if _, ok := s.paymentAuthByReservationID["sres-blockchain-no-adapter-1"]; ok {
		t.Fatalf("expected no payment authorization record for pending deferred sponsor reservation")
	}
	if _, ok := s.settledBySession["sess-blockchain-no-adapter-1"]; ok {
		t.Fatalf("expected failed settlement to not be stored locally")
	}
	if _, ok := s.reservationsBySession["sess-blockchain-no-adapter-1"]; !ok {
		t.Fatalf("expected non-final client reservation to remain available after failed settlement")
	}
	if len(s.deferredAdapterOps) != 3 {
		t.Fatalf("expected deferred backlog entries 3, got %d", len(s.deferredAdapterOps))
	}
	for _, idempotencyKey := range []string{rewardRef, reservationRef, evidenceRef} {
		op, ok := s.deferredAdapterOps[idempotencyKey]
		if !ok {
			t.Fatalf("expected deferred operation for %s", idempotencyKey)
		}
		if op.LastError != errChainAdapterNotConfigured.Error() {
			t.Fatalf("expected deferred operation error %q for %s, got %q", errChainAdapterNotConfigured.Error(), idempotencyKey, op.LastError)
		}
	}
}

func TestMemoryServiceAuthorizePaymentRequiresFinalizedStateInBlockchainMode(t *testing.T) {
	s := NewMemoryService(WithBlockchainMode(true))
	ctx := context.Background()

	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-deferred-states-1",
		SponsorID:     "sponsor-deferred-states-1",
		SubjectID:     "client-deferred-states-1",
		SessionID:     "sess-deferred-states-1",
		AmountMicros:  100,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != OperationStatusPending || !reservation.AdapterDeferred || reservation.AdapterSubmitted {
		t.Fatalf("expected initial blockchain-mode reservation to be pending+deferred")
	}

	proof := PaymentProof{
		ReservationID: reservation.ReservationID,
		SponsorID:     reservation.SponsorID,
		SubjectID:     reservation.SubjectID,
		SessionID:     reservation.SessionID,
	}

	testCases := []struct {
		name             string
		status           OperationStatus
		adapterDeferred  bool
		adapterSubmitted bool
		wantErr          string
	}{
		{
			name:             "pending deferred",
			status:           OperationStatusPending,
			adapterDeferred:  true,
			adapterSubmitted: false,
			wantErr:          "reservation pending chain submission: sres-deferred-states-1",
		},
		{
			name:             "failed deferred",
			status:           OperationStatusFailed,
			adapterDeferred:  true,
			adapterSubmitted: false,
			wantErr:          "reservation not chain-finalized: sres-deferred-states-1",
		},
		{
			name:             "submitted deferred",
			status:           OperationStatusSubmitted,
			adapterDeferred:  true,
			adapterSubmitted: true,
			wantErr:          "reservation not chain-finalized: sres-deferred-states-1",
		},
		{
			name:             "submitted non-deferred",
			status:           OperationStatusSubmitted,
			adapterDeferred:  false,
			adapterSubmitted: true,
			wantErr:          "reservation not chain-finalized: sres-deferred-states-1",
		},
		{
			name:             "confirmed deferred",
			status:           OperationStatusConfirmed,
			adapterDeferred:  true,
			adapterSubmitted: true,
			wantErr:          "",
		},
		{
			name:             "confirmed non-deferred",
			status:           OperationStatusConfirmed,
			adapterDeferred:  false,
			adapterSubmitted: true,
			wantErr:          "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s.mu.Lock()
			stored := s.sponsorReservationsByID[reservation.ReservationID]
			stored.Status = tc.status
			stored.AdapterDeferred = tc.adapterDeferred
			stored.AdapterSubmitted = tc.adapterSubmitted
			stored.ConsumedAt = time.Time{}
			s.sponsorReservationsByID[reservation.ReservationID] = stored
			delete(s.paymentAuthByReservationID, reservation.ReservationID)
			s.mu.Unlock()

			auth, err := s.AuthorizePayment(ctx, proof)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected authorize to fail for status %s", tc.status)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("unexpected authorize error for status %s: got %v want %s", tc.status, err, tc.wantErr)
				}
				s.mu.Lock()
				after := s.sponsorReservationsByID[reservation.ReservationID]
				_, hasAuth := s.paymentAuthByReservationID[reservation.ReservationID]
				s.mu.Unlock()
				if !after.ConsumedAt.IsZero() {
					t.Fatalf("expected reservation to remain unconsumed after failed authorize for status %s", tc.status)
				}
				if hasAuth {
					t.Fatalf("expected no payment authorization record after failed authorize for status %s", tc.status)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected authorize to succeed for status %s, got %v", tc.status, err)
			}
			if auth.Status != OperationStatusConfirmed {
				t.Fatalf("expected confirmed authorization status for status %s, got %s", tc.status, auth.Status)
			}
			s.mu.Lock()
			after := s.sponsorReservationsByID[reservation.ReservationID]
			_, hasAuth := s.paymentAuthByReservationID[reservation.ReservationID]
			s.mu.Unlock()
			if after.ConsumedAt.IsZero() {
				t.Fatalf("expected reservation to be consumed after successful authorize for status %s", tc.status)
			}
			if !hasAuth {
				t.Fatalf("expected payment authorization record after successful authorize for status %s", tc.status)
			}
		})
	}
}

func TestMemoryServiceDefaultMemoryModeWithoutAdapterStaysConfirmed(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1024 * 1024))
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-memory-no-adapter-1",
		SubjectID:    "client-memory-no-adapter-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	err = s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-memory-no-adapter-1",
		SubjectID:    "client-memory-no-adapter-1",
		BytesIngress: 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-memory-no-adapter-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusConfirmed {
		t.Fatalf("expected confirmed settlement status in default memory mode, got %s", settlement.Status)
	}
	if settlement.AdapterDeferred || settlement.AdapterSubmitted {
		t.Fatalf("expected settlement adapter state deferred=false submitted=false in default memory mode")
	}
	if settlement.AdapterReferenceID != "" {
		t.Fatalf("expected empty settlement adapter reference id in default memory mode, got %s", settlement.AdapterReferenceID)
	}
	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-memory-no-adapter-1",
		ProviderSubjectID: "provider-memory-no-adapter-1",
		SessionID:         "sess-memory-no-adapter-1",
		RewardMicros:      55,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if reward.Status != OperationStatusConfirmed || reward.AdapterDeferred || reward.AdapterSubmitted {
		t.Fatalf("expected reward to remain confirmed and non-deferred in default memory mode")
	}
	if reward.AdapterReferenceID != "" {
		t.Fatalf("expected empty reward adapter reference id in default memory mode, got %s", reward.AdapterReferenceID)
	}
	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-memory-no-adapter-1",
		SponsorID:     "sponsor-memory-no-adapter-1",
		SubjectID:     "client-memory-no-adapter-1",
		SessionID:     "sess-memory-no-adapter-1",
		AmountMicros:  300,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != OperationStatusConfirmed || reservation.AdapterDeferred || reservation.AdapterSubmitted {
		t.Fatalf("expected sponsor reservation to remain confirmed and non-deferred in default memory mode")
	}
	if reservation.AdapterReferenceID != "" {
		t.Fatalf("expected empty sponsor reservation adapter reference id in default memory mode, got %s", reservation.AdapterReferenceID)
	}
	auth, err := s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: reservation.ReservationID,
		SponsorID:     reservation.SponsorID,
		SubjectID:     reservation.SubjectID,
		SessionID:     reservation.SessionID,
	})
	if err != nil {
		t.Fatalf("AuthorizePayment: %v", err)
	}
	if auth.Status != OperationStatusConfirmed {
		t.Fatalf("expected payment authorization confirmed in default memory mode, got %s", auth.Status)
	}
	storedReservation, err := s.GetSponsorReservation(ctx, reservation.ReservationID)
	if err != nil {
		t.Fatalf("GetSponsorReservation: %v", err)
	}
	if storedReservation.Status != OperationStatusConfirmed {
		t.Fatalf("expected consumed sponsor reservation to remain confirmed in default memory mode, got %s", storedReservation.Status)
	}
	if storedReservation.ConsumedAt.IsZero() {
		t.Fatalf("expected consumed sponsor reservation timestamp to be set in default memory mode")
	}
	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-memory-no-adapter-1",
		SubjectID:     "provider-memory-no-adapter-1",
		SessionID:     "sess-memory-no-adapter-1",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("ev-memory-no-adapter-1"),
		SlashMicros:   9,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if evidence.Status != OperationStatusConfirmed || evidence.AdapterDeferred || evidence.AdapterSubmitted {
		t.Fatalf("expected slash evidence to remain confirmed and non-deferred in default memory mode")
	}
	if evidence.AdapterReferenceID != "" {
		t.Fatalf("expected empty slash evidence adapter reference id in default memory mode, got %s", evidence.AdapterReferenceID)
	}
	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected no deferred adapter operations in default memory mode, got %d", report.PendingAdapterOperations)
	}
	if report.PendingOperations != 0 {
		t.Fatalf("expected no pending operations in default memory mode, got %d", report.PendingOperations)
	}
}

func TestMemoryServiceShadowAdapterSuccessRecordsOutcome(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(fakeAdapter{}),
		WithShadowChainAdapter(fakeAdapter{}),
	)
	settlement := setupSettledSessionForShadowTests(t, s, "sess-shadow-success-1")
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected primary settlement status submitted, got %s", settlement.Status)
	}
	if !settlement.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submission marker")
	}
	if settlement.ShadowAdapterStatus != OperationStatusSubmitted {
		t.Fatalf("expected shadow adapter status submitted, got %s", settlement.ShadowAdapterStatus)
	}
	if settlement.ShadowAdapterLastAttemptAt.IsZero() {
		t.Fatalf("expected shadow adapter attempt timestamp")
	}
	if settlement.ShadowAdapterReferenceID == "" {
		t.Fatalf("expected shadow adapter reference id")
	}
	if settlement.ShadowAdapterLastError != "" {
		t.Fatalf("expected empty shadow adapter error, got %q", settlement.ShadowAdapterLastError)
	}
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !report.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter configured marker")
	}
	if report.ShadowAttemptedOperations != 1 || report.ShadowSubmittedOperations != 1 || report.ShadowFailedOperations != 0 {
		t.Fatalf("unexpected shadow report counts attempted=%d submitted=%d failed=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations, report.ShadowFailedOperations)
	}
}

func TestMemoryServiceShadowAdapterFailureDoesNotAffectPrimaryPath(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(fakeAdapter{}),
		WithShadowChainAdapter(fakeAdapter{fail: true}),
	)
	settlement := setupSettledSessionForShadowTests(t, s, "sess-shadow-fail-1")
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected primary settlement status submitted, got %s", settlement.Status)
	}
	if settlement.AdapterDeferred {
		t.Fatalf("expected primary adapter not deferred when primary succeeds")
	}
	if settlement.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submission to be marked failed")
	}
	if settlement.ShadowAdapterStatus != OperationStatusFailed {
		t.Fatalf("expected shadow adapter status failed, got %s", settlement.ShadowAdapterStatus)
	}
	if settlement.ShadowAdapterLastAttemptAt.IsZero() {
		t.Fatalf("expected shadow adapter attempt timestamp")
	}
	if settlement.ShadowAdapterLastError == "" {
		t.Fatalf("expected shadow adapter error")
	}
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected no primary deferred backlog, got %d", report.PendingAdapterOperations)
	}
	if report.ShadowAttemptedOperations != 1 || report.ShadowSubmittedOperations != 0 || report.ShadowFailedOperations != 1 {
		t.Fatalf("unexpected shadow report counts attempted=%d submitted=%d failed=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations, report.ShadowFailedOperations)
	}
}

func TestMemoryServiceShadowAdapterNotConfiguredLeavesShadowMetadataEmpty(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(fakeAdapter{}),
	)
	settlement := setupSettledSessionForShadowTests(t, s, "sess-shadow-none-1")
	if settlement.ShadowAdapterSubmitted {
		t.Fatalf("expected no shadow submission marker when shadow adapter is not configured")
	}
	if !settlement.ShadowAdapterLastAttemptAt.IsZero() {
		t.Fatalf("expected zero shadow adapter attempt timestamp")
	}
	if settlement.ShadowAdapterReferenceID != "" {
		t.Fatalf("expected empty shadow adapter reference id when unconfigured")
	}
	if settlement.ShadowAdapterStatus != "" {
		t.Fatalf("expected empty shadow adapter status when unconfigured, got %s", settlement.ShadowAdapterStatus)
	}
	if settlement.ShadowAdapterLastError != "" {
		t.Fatalf("expected empty shadow adapter error when unconfigured")
	}
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter configured marker false")
	}
	if report.ShadowAttemptedOperations != 0 || report.ShadowSubmittedOperations != 0 || report.ShadowFailedOperations != 0 {
		t.Fatalf("expected empty shadow report counts attempted=%d submitted=%d failed=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations, report.ShadowFailedOperations)
	}
}

func TestMemoryServicePrimaryFailureStillDefersWhenShadowSucceeds(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(fakeAdapter{fail: true}),
		WithShadowChainAdapter(fakeAdapter{}),
	)
	settlement := setupSettledSessionForShadowTests(t, s, "sess-shadow-primary-fail-1")
	if settlement.Status != OperationStatusPending {
		t.Fatalf("expected primary settlement pending when primary adapter fails, got %s", settlement.Status)
	}
	if !settlement.AdapterDeferred || settlement.AdapterSubmitted {
		t.Fatalf("expected primary deferred marker when primary adapter fails")
	}
	if !settlement.ShadowAdapterSubmitted || settlement.ShadowAdapterStatus != OperationStatusSubmitted {
		t.Fatalf("expected successful shadow submission despite primary failure")
	}
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 1 {
		t.Fatalf("expected primary deferred backlog to remain 1, got %d", report.PendingAdapterOperations)
	}
}

func TestMemoryServiceReconcileReplaySuccessClearsBacklog(t *testing.T) {
	adapter := &switchableAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-1")
	ctx := context.Background()

	before, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile before recovery: %v", err)
	}
	if before.PendingAdapterOperations != 1 {
		t.Fatalf("expected 1 deferred operation before recovery, got %d", before.PendingAdapterOperations)
	}

	adapter.setFail(false)
	after, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile after recovery: %v", err)
	}
	if after.PendingAdapterOperations != 0 {
		t.Fatalf("expected deferred backlog to clear after replay, got %d pending", after.PendingAdapterOperations)
	}

	s.mu.Lock()
	settlement := s.settledBySession["sess-replay-1"]
	s.mu.Unlock()
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected settlement status submitted after replay, got %s", settlement.Status)
	}
	if !settlement.AdapterSubmitted || settlement.AdapterDeferred {
		t.Fatalf("expected settlement adapter state submitted=true deferred=false after replay")
	}
}

func TestMemoryServiceDeferredReplayUsesNormalizedSubmissionStatus(t *testing.T) {
	adapter := &statusCapturingReplayAdapter{failFirst: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-status-normalization-1")

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected deferred backlog to clear after replay, got %d", report.PendingAdapterOperations)
	}

	statuses := adapter.settlementStatusesSnapshot()
	if len(statuses) != 2 {
		t.Fatalf("expected exactly two settlement submissions (initial fail + replay), got %d", len(statuses))
	}
	for idx, status := range statuses {
		if status != OperationStatusSubmitted {
			t.Fatalf("expected settlement submission call %d to use status %q, got %q", idx+1, OperationStatusSubmitted, status)
		}
	}
}

func TestMemoryServiceReconcileReplayFailureMarksFailedAndRetainsBacklog(t *testing.T) {
	adapter := &switchableAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-fail-1")
	ctx := context.Background()

	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile with persistent adapter failure: %v", err)
	}
	if report.PendingAdapterOperations != 1 {
		t.Fatalf("expected deferred backlog to remain 1 after failed replay, got %d", report.PendingAdapterOperations)
	}
	if report.FailedOperations < 1 {
		t.Fatalf("expected at least one failed operation after failed replay, got %d", report.FailedOperations)
	}

	s.mu.Lock()
	settlement := s.settledBySession["sess-replay-fail-1"]
	deferredOp, hasDeferredOp := s.deferredAdapterOps["settlement:set-sess-replay-fail-1"]
	s.mu.Unlock()

	if settlement.Status != OperationStatusFailed {
		t.Fatalf("expected settlement status failed after failed replay, got %s", settlement.Status)
	}
	if !settlement.AdapterDeferred || settlement.AdapterSubmitted {
		t.Fatalf("expected settlement adapter state deferred=true submitted=false after failed replay")
	}
	if !hasDeferredOp {
		t.Fatalf("expected deferred operation to remain after failed replay")
	}
	if deferredOp.Attempts < 2 {
		t.Fatalf("expected deferred operation attempts >= 2 (initial submit + replay), got %d", deferredOp.Attempts)
	}
	if gotCalls := adapter.settlementCalls(); gotCalls != 2 {
		t.Fatalf("expected exactly two settlement submissions (initial fail + replay fail), got %d", gotCalls)
	}
}

func TestMemoryServiceReconcileReplayIsIdempotentAcrossRepeatedCalls(t *testing.T) {
	adapter := &switchableAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-2")
	ctx := context.Background()

	adapter.setFail(false)
	first, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile first: %v", err)
	}
	second, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile second: %v", err)
	}
	if first.PendingAdapterOperations != 0 || second.PendingAdapterOperations != 0 {
		t.Fatalf("expected no pending operations after successful replay, got first=%d second=%d",
			first.PendingAdapterOperations, second.PendingAdapterOperations)
	}
	if gotCalls := adapter.settlementCalls(); gotCalls != 2 {
		t.Fatalf("expected exactly two settlement submissions (initial fail + single replay), got %d", gotCalls)
	}
}

func TestMemoryServiceReconcileReplayPromotesToConfirmedWhenQuerierAvailable(t *testing.T) {
	adapter := &replayConfirmingAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-confirm-1")
	ctx := context.Background()

	adapter.setFail(false)
	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected deferred backlog cleared after replay, got %d", report.PendingAdapterOperations)
	}
	if report.ConfirmedOperations < 1 {
		t.Fatalf("expected at least one confirmed operation after replay+query, got %d", report.ConfirmedOperations)
	}

	s.mu.Lock()
	settlement := s.settledBySession["sess-replay-confirm-1"]
	s.mu.Unlock()
	if settlement.Status != OperationStatusConfirmed {
		t.Fatalf("expected settlement confirmed after replay+query, got %s", settlement.Status)
	}
	if !settlement.AdapterSubmitted || settlement.AdapterDeferred {
		t.Fatalf("expected adapter state submitted=true deferred=false after replay+query")
	}
	if gotCalls := adapter.settlementCalls(); gotCalls != 2 {
		t.Fatalf("expected exactly two settlement submissions (initial fail + single replay), got %d", gotCalls)
	}
}

func TestMemoryServiceReconcileReplayFailureRetainsBacklogAcrossNonSettlementOperations(t *testing.T) {
	adapter := &multiOperationReplayAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	sessionID, rewardID, reservationID, evidenceID, slashSubjectID := setupDeferredNonSettlementOperations(t, s, "non-set-fail-1")

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile with persistent adapter failure: %v", err)
	}
	if report.PendingAdapterOperations != 3 {
		t.Fatalf("expected deferred backlog 3 after failed replay, got %d", report.PendingAdapterOperations)
	}
	if report.FailedOperations < 3 {
		t.Fatalf("expected at least three failed operations after failed replay, got %d", report.FailedOperations)
	}

	s.mu.Lock()
	reward := s.rewardsByID[rewardID]
	reservation := s.sponsorReservationsByID[reservationID]
	evidence := s.slashEvidenceByID[evidenceID]
	rewardOp, hasRewardOp := s.deferredAdapterOps[cosmosID("reward", rewardID, sessionID)]
	reservationOp, hasReservationOp := s.deferredAdapterOps[cosmosID("sponsor-reservation", reservationID, sessionID)]
	evidenceOp, hasEvidenceOp := s.deferredAdapterOps[cosmosID("slash", evidenceID, slashSubjectID)]
	s.mu.Unlock()

	if reward.Status != OperationStatusFailed || !reward.AdapterDeferred || reward.AdapterSubmitted {
		t.Fatalf("expected reward to retain failed+deferred state after failed replay")
	}
	if reservation.Status != OperationStatusFailed || !reservation.AdapterDeferred || reservation.AdapterSubmitted {
		t.Fatalf("expected sponsor reservation to retain failed+deferred state after failed replay")
	}
	if evidence.Status != OperationStatusFailed || !evidence.AdapterDeferred || evidence.AdapterSubmitted {
		t.Fatalf("expected slash evidence to retain failed+deferred state after failed replay")
	}
	if !hasRewardOp || !hasReservationOp || !hasEvidenceOp {
		t.Fatalf("expected deferred operations to be retained for reward/sponsor/slash after failed replay")
	}
	if rewardOp.Attempts < 2 || reservationOp.Attempts < 2 || evidenceOp.Attempts < 2 {
		t.Fatalf("expected deferred attempts >=2 for reward/sponsor/slash, got reward=%d sponsor=%d slash=%d",
			rewardOp.Attempts, reservationOp.Attempts, evidenceOp.Attempts)
	}
	if adapter.rewardCalls() != 2 || adapter.sponsorCalls() != 2 || adapter.slashCalls() != 2 {
		t.Fatalf("expected exactly two submissions per non-settlement op (initial fail + replay fail), got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
	}
}

func TestMemoryServiceReconcileReplayRejectsUnverifiedRewardProofBeforeAdapterSubmit(t *testing.T) {
	adapter := &multiOperationReplayAdapter{}
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	rewardID := "rew-deferred-unverified-proof-1"
	sessionID := "sess-deferred-unverified-proof-1"
	opKey := cosmosID("reward", rewardID, sessionID)
	s.mu.Lock()
	s.rewardsByID[rewardID] = RewardIssue{
		RewardID:          rewardID,
		ProviderSubjectID: "provider-deferred-unverified-proof-1",
		SessionID:         sessionID,
		TrafficProofRef:   "obj://traffic-proof/deferred-unverified-proof-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
		IssuedAt:          time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		AdapterDeferred:   true,
		Status:            OperationStatusPending,
	}
	s.deferredAdapterOps[opKey] = deferredAdapterOperation{
		Type:           deferredOperationReward,
		RecordKey:      rewardID,
		IdempotencyKey: opKey,
		DeferredAt:     time.Now().UTC(),
	}
	s.pendingAdapterOps = 1
	s.mu.Unlock()

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if adapter.rewardCalls() != 0 {
		t.Fatalf("expected unverified deferred reward proof to block adapter submit, got reward calls=%d", adapter.rewardCalls())
	}
	if report.PendingAdapterOperations != 1 || report.FailedOperations < 1 {
		t.Fatalf("expected deferred unverified reward to remain failed backlog, report=%+v", report)
	}
	s.mu.Lock()
	reward := s.rewardsByID[rewardID]
	deferredOp, hasDeferredOp := s.deferredAdapterOps[opKey]
	s.mu.Unlock()
	if reward.Status != OperationStatusFailed || !reward.AdapterDeferred || reward.AdapterSubmitted || reward.TrafficProofVerified {
		t.Fatalf("expected unverified deferred reward to fail closed without adapter submission, got %+v", reward)
	}
	if !hasDeferredOp || deferredOp.Attempts != 1 {
		t.Fatalf("expected deferred reward op retained with one guarded attempt, has=%v op=%+v", hasDeferredOp, deferredOp)
	}
}

func TestMemoryServiceReconcileReplayRecoveryConfirmsAcrossNonSettlementOperations(t *testing.T) {
	adapter := &multiOperationReplayAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	sessionID, rewardID, reservationID, evidenceID, slashSubjectID := setupDeferredNonSettlementOperations(t, s, "non-set-recover-1")

	adapter.setFail(false)
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile after adapter recovery: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected deferred backlog cleared after replay recovery, got %d", report.PendingAdapterOperations)
	}
	if report.ConfirmedOperations < 3 {
		t.Fatalf("expected at least three confirmed operations after replay recovery, got %d", report.ConfirmedOperations)
	}

	s.mu.Lock()
	reward := s.rewardsByID[rewardID]
	reservation := s.sponsorReservationsByID[reservationID]
	evidence := s.slashEvidenceByID[evidenceID]
	_, hasRewardOp := s.deferredAdapterOps[cosmosID("reward", rewardID, sessionID)]
	_, hasReservationOp := s.deferredAdapterOps[cosmosID("sponsor-reservation", reservationID, sessionID)]
	_, hasEvidenceOp := s.deferredAdapterOps[cosmosID("slash", evidenceID, slashSubjectID)]
	s.mu.Unlock()

	if reward.Status != OperationStatusConfirmed || !reward.AdapterSubmitted || reward.AdapterDeferred {
		t.Fatalf("expected reward to be confirmed with submitted adapter state after replay recovery")
	}
	if reservation.Status != OperationStatusConfirmed || !reservation.AdapterSubmitted || reservation.AdapterDeferred {
		t.Fatalf("expected sponsor reservation to be confirmed with submitted adapter state after replay recovery")
	}
	if evidence.Status != OperationStatusConfirmed || !evidence.AdapterSubmitted || evidence.AdapterDeferred {
		t.Fatalf("expected slash evidence to be confirmed with submitted adapter state after replay recovery")
	}
	if hasRewardOp || hasReservationOp || hasEvidenceOp {
		t.Fatalf("expected replay recovery to clear deferred operations for reward/sponsor/slash")
	}

	if adapter.rewardCalls() != 2 || adapter.sponsorCalls() != 2 || adapter.slashCalls() != 2 {
		t.Fatalf("expected exactly two submissions per non-settlement op (initial fail + single replay), got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
	}

	if _, err := s.Reconcile(context.Background()); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if adapter.rewardCalls() != 2 || adapter.sponsorCalls() != 2 || adapter.slashCalls() != 2 {
		t.Fatalf("expected replay to be idempotent after backlog clears, got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
	}
}

func TestMemoryServiceCosmosAdapterAsyncFailureAfterEnqueueReplaysAndConfirms(t *testing.T) {
	var failWrites atomic.Bool
	failWrites.Store(true)

	var submittedMu sync.Mutex
	submittedSettlementByID := map[string]SessionSettlement{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/x/vpnbilling/settlements":
			var settlement SessionSettlement
			if err := json.NewDecoder(r.Body).Decode(&settlement); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if failWrites.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			submittedMu.Lock()
			submittedSettlementByID[settlement.SettlementID] = settlement
			submittedMu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/x/vpnbilling/settlements/"):
			settlementID := strings.TrimPrefix(r.URL.Path, "/x/vpnbilling/settlements/")
			submittedMu.Lock()
			settlement, ok := submittedSettlementByID[settlementID]
			submittedMu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"settlement": map[string]any{
					"SettlementID":   settlementID,
					"ReservationID":  settlement.ReservationID,
					"SessionID":      settlement.SessionID,
					"SubjectID":      settlement.SubjectID,
					"ChargedMicros":  settlement.ChargedMicros,
					"Currency":       settlement.Currency,
					"SettledAt":      settlement.SettledAt,
					"OperationState": string(OperationStatusConfirmed),
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  0,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-cosmos-adapter-replay-1",
		SubjectID:    "client-cosmos-adapter-replay-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-cosmos-adapter-replay-1",
		SubjectID:    "client-cosmos-adapter-replay-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-cosmos-adapter-replay-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected fail-soft settlement submit status submitted, got %s", settlement.Status)
	}
	if settlement.AdapterDeferred {
		t.Fatalf("expected fail-soft async adapter path to avoid immediate deferred state")
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 1
	}, "adapter deferred backlog after async failure")
	reportWithDeferred, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile with async adapter deferred backlog: %v", err)
	}
	if reportWithDeferred.PendingAdapterOperations < 1 {
		t.Fatalf("expected reconcile report pending adapter operations >= 1 while adapter backlog exists, got %d", reportWithDeferred.PendingAdapterOperations)
	}

	failWrites.Store(false)
	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 0
	}, "adapter deferred backlog replay clear")

	waitForCondition(t, 3*time.Second, func() bool {
		_, err := s.Reconcile(ctx)
		if err != nil {
			return false
		}
		s.mu.Lock()
		current := s.settledBySession["sess-cosmos-adapter-replay-1"]
		s.mu.Unlock()
		return current.Status == OperationStatusConfirmed && current.AdapterSubmitted && !current.AdapterDeferred
	}, "memory reconcile confirmation after async replay")
}

func TestMemoryServiceReconcileMarksSubmittedAsConfirmedWhenQueryable(t *testing.T) {
	adapter := materialSettlementConfirmingAdapter{
		settlements:   map[string]SessionSettlement{},
		rewards:       map[string]RewardIssue{},
		slashEvidence: map[string]SlashEvidence{},
	}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-confirm-1",
		SubjectID:    "client-confirm-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-confirm-1",
		SubjectID:    "client-confirm-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-confirm-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	chainSettlement := settlement
	chainSettlement.Status = OperationStatusConfirmed
	adapter.settlements[settlement.SettlementID] = chainSettlement
	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-confirm-1",
		ProviderSubjectID: "provider-confirm-1",
		SessionID:         "sess-confirm-1",
		RewardMicros:      25,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	chainReward := reward
	chainReward.Status = OperationStatusConfirmed
	adapter.rewards[reward.RewardID] = chainReward
	if _, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-confirm-1",
		SponsorID:     "sponsor-confirm-1",
		SubjectID:     "client-confirm-1",
		SessionID:     "sess-confirm-1",
		AmountMicros:  100,
		Currency:      "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-confirm-1",
		SubjectID:     "provider-confirm-1",
		SessionID:     "sess-confirm-1",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("ev-confirm-1"),
		SlashMicros:   11,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	chainEvidence := evidence
	chainEvidence.Status = OperationStatusConfirmed
	adapter.slashEvidence[evidence.EvidenceID] = chainEvidence

	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations < 4 {
		t.Fatalf("expected at least four confirmed operations, got %d", report.ConfirmedOperations)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if got := s.settledBySession["sess-confirm-1"].Status; got != OperationStatusConfirmed {
		t.Fatalf("expected settlement confirmed, got %s", got)
	}
	if got := s.rewardsByID["rew-confirm-1"].Status; got != OperationStatusConfirmed {
		t.Fatalf("expected reward confirmed, got %s", got)
	}
	if got := s.sponsorReservationsByID["sres-confirm-1"].Status; got != OperationStatusConfirmed {
		t.Fatalf("expected sponsor reservation confirmed, got %s", got)
	}
	if got := s.slashEvidenceByID["ev-confirm-1"].Status; got != OperationStatusConfirmed {
		t.Fatalf("expected slash evidence confirmed, got %s", got)
	}
}

func TestMemoryServiceReconcileConfirmsChainBackedSettlementWithReservationSnapshotAfterConsumption(t *testing.T) {
	adapter := &fundReservationMaterialAdapter{}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithBlockchainMode(true),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	reservation, err := s.ReserveFunds(ctx, FundReservation{
		ReservationID: "res-chain-settlement-snapshot-1",
		SessionID:     "sess-chain-settlement-snapshot-1",
		SubjectID:     "client-chain-settlement-snapshot-1",
		AmountMicros:  2_000_000,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    reservation.SessionID,
		SubjectID:    reservation.SubjectID,
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, reservation.SessionID)
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected submitted settlement before reconcile, got %+v", settlement)
	}
	s.mu.Lock()
	if _, ok := s.reservationsBySession[reservation.SessionID]; ok {
		t.Fatalf("expected settlement to consume open reservation")
	}
	s.mu.Unlock()

	adapter.mutateSettlement(settlement.SettlementID, func(chain SessionSettlement) SessionSettlement {
		chain.SubjectID = ""
		chain.Status = OperationStatusConfirmed
		return chain
	})

	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 1 {
		t.Fatalf("expected reconciled settlement confirmation, report=%+v", report)
	}
	s.mu.Lock()
	reconciled := s.settledBySession[reservation.SessionID]
	s.mu.Unlock()
	if reconciled.Status != OperationStatusConfirmed {
		t.Fatalf("expected settlement confirmed from preserved reservation material, got %+v", reconciled)
	}
}

func TestMemoryServiceReconcileRejectsChainBackedSettlementMaterialMismatchAfterReservationConsumption(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(SessionSettlement) SessionSettlement
	}{
		{
			name: "subject mismatch",
			mutate: func(chain SessionSettlement) SessionSettlement {
				chain.SubjectID = "client-forged"
				return chain
			},
		},
		{
			name: "session mismatch",
			mutate: func(chain SessionSettlement) SessionSettlement {
				chain.SessionID = "sess-forged"
				return chain
			},
		},
		{
			name: "amount mismatch",
			mutate: func(chain SessionSettlement) SessionSettlement {
				chain.ChargedMicros++
				return chain
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &fundReservationMaterialAdapter{}
			s := NewMemoryService(
				WithPricePerMiBMicros(1024*1024),
				WithBlockchainMode(true),
				WithChainAdapter(adapter),
			)
			ctx := context.Background()
			suffix := strings.ReplaceAll(tc.name, " ", "-")
			sessionID := "sess-chain-settlement-mismatch-" + suffix
			subjectID := "client-chain-settlement-mismatch-" + suffix

			reservation, err := s.ReserveFunds(ctx, FundReservation{
				ReservationID: "res-chain-settlement-mismatch-" + suffix,
				SessionID:     sessionID,
				SubjectID:     subjectID,
				AmountMicros:  2_000_000,
				Currency:      "TDPNC",
			})
			if err != nil {
				t.Fatalf("ReserveFunds: %v", err)
			}
			if err := s.RecordUsage(ctx, UsageRecord{
				SessionID:    sessionID,
				SubjectID:    subjectID,
				BytesIngress: 1024 * 1024,
			}); err != nil {
				t.Fatalf("RecordUsage: %v", err)
			}
			settlement, err := s.SettleSession(ctx, sessionID)
			if err != nil {
				t.Fatalf("SettleSession: %v", err)
			}
			s.mu.Lock()
			if _, ok := s.reservationsBySession[reservation.SessionID]; ok {
				t.Fatalf("expected settlement to consume open reservation")
			}
			s.mu.Unlock()

			adapter.mutateSettlement(settlement.SettlementID, func(chain SessionSettlement) SessionSettlement {
				chain = tc.mutate(chain)
				chain.Status = OperationStatusConfirmed
				return chain
			})

			report, err := s.Reconcile(ctx)
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if report.ConfirmedOperations != 0 {
				t.Fatalf("expected material mismatch not to confirm, report=%+v", report)
			}
			s.mu.Lock()
			reconciled := s.settledBySession[sessionID]
			s.mu.Unlock()
			if reconciled.Status != OperationStatusSubmitted {
				t.Fatalf("expected mismatched settlement to remain submitted, got %+v", reconciled)
			}
		})
	}
}

func setupSubmittedConfirmationRecords(t *testing.T, s *MemoryService, suffix string) (string, string, string, string) {
	t.Helper()
	ctx := context.Background()

	sessionID := "sess-confirm-" + suffix
	subjectID := "client-confirm-" + suffix
	rewardID := "rew-confirm-" + suffix
	sponsorReservationID := "sres-confirm-" + suffix
	evidenceID := "ev-confirm-" + suffix

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected settlement submitted before reconcile confirmation checks, got %s", settlement.Status)
	}

	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          rewardID,
		ProviderSubjectID: "provider-" + suffix,
		SessionID:         sessionID,
		RewardMicros:      25,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if reward.Status != OperationStatusSubmitted {
		t.Fatalf("expected reward submitted before reconcile confirmation checks, got %s", reward.Status)
	}

	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: sponsorReservationID,
		SponsorID:     "sponsor-" + suffix,
		SubjectID:     subjectID,
		SessionID:     sessionID,
		AmountMicros:  100,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != OperationStatusSubmitted {
		t.Fatalf("expected sponsor reservation submitted before reconcile confirmation checks, got %s", reservation.Status)
	}

	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    evidenceID,
		SubjectID:     "provider-" + suffix,
		SessionID:     sessionID,
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref(suffix),
		SlashMicros:   11,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if evidence.Status != OperationStatusSubmitted {
		t.Fatalf("expected slash evidence submitted before reconcile confirmation checks, got %s", evidence.Status)
	}

	return sessionID, rewardID, sponsorReservationID, evidenceID
}

func assertSubmittedConfirmationRecords(t *testing.T, s *MemoryService, sessionID string, rewardID string, sponsorReservationID string, evidenceID string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()

	settlement := s.settledBySession[sessionID]
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected settlement to remain submitted, got %s", settlement.Status)
	}
	if !settlement.AdapterSubmitted || settlement.AdapterDeferred {
		t.Fatalf("expected settlement adapter state submitted=true deferred=false")
	}

	reward := s.rewardsByID[rewardID]
	if reward.Status != OperationStatusSubmitted {
		t.Fatalf("expected reward to remain submitted, got %s", reward.Status)
	}
	if !reward.AdapterSubmitted || reward.AdapterDeferred {
		t.Fatalf("expected reward adapter state submitted=true deferred=false")
	}

	reservation := s.sponsorReservationsByID[sponsorReservationID]
	if reservation.Status != OperationStatusSubmitted {
		t.Fatalf("expected sponsor reservation to remain submitted, got %s", reservation.Status)
	}
	if !reservation.AdapterSubmitted || reservation.AdapterDeferred {
		t.Fatalf("expected sponsor reservation adapter state submitted=true deferred=false")
	}

	evidence := s.slashEvidenceByID[evidenceID]
	if evidence.Status != OperationStatusSubmitted {
		t.Fatalf("expected slash evidence to remain submitted, got %s", evidence.Status)
	}
	if !evidence.AdapterSubmitted || evidence.AdapterDeferred {
		t.Fatalf("expected slash evidence adapter state submitted=true deferred=false")
	}
}

func TestMemoryServiceReconcileKeepsSubmittedWhenConfirmationNotFound(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(notFoundConfirmingAdapter{}),
	)
	sessionID, rewardID, sponsorReservationID, evidenceID := setupSubmittedConfirmationRecords(t, s, "not-found-1")

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 0 {
		t.Fatalf("expected no confirmed operations when lookups return not found, got %d", report.ConfirmedOperations)
	}
	if report.SubmittedOperations < 4 {
		t.Fatalf("expected at least four submitted operations, got %d", report.SubmittedOperations)
	}

	assertSubmittedConfirmationRecords(t, s, sessionID, rewardID, sponsorReservationID, evidenceID)
}

func TestMemoryServiceReconcileKeepsSubmittedWhenConfirmationLookupErrors(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(errorConfirmingAdapter{}),
	)
	sessionID, rewardID, sponsorReservationID, evidenceID := setupSubmittedConfirmationRecords(t, s, "lookup-error-1")

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 0 {
		t.Fatalf("expected no confirmed operations when lookups return errors, got %d", report.ConfirmedOperations)
	}
	if report.SubmittedOperations < 4 {
		t.Fatalf("expected at least four submitted operations, got %d", report.SubmittedOperations)
	}

	assertSubmittedConfirmationRecords(t, s, sessionID, rewardID, sponsorReservationID, evidenceID)
}

func TestMemoryServiceReconcileKeepsSubmittedWhenChainStatusIsNotFinal(t *testing.T) {
	testCases := []struct {
		name   string
		status OperationStatus
	}{
		{name: "pending", status: OperationStatusPending},
		{name: "submitted", status: OperationStatusSubmitted},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMemoryService(
				WithPricePerMiBMicros(1024*1024),
				WithChainAdapter(nonFinalStatusAdapter{status: tc.status}),
			)
			sessionID, rewardID, sponsorReservationID, evidenceID := setupSubmittedConfirmationRecords(t, s, tc.name+"-status-1")

			report, err := s.Reconcile(context.Background())
			if err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			if report.ConfirmedOperations != 0 {
				t.Fatalf("expected no confirmed operations for chain status %s, got %d", tc.status, report.ConfirmedOperations)
			}
			if report.SubmittedOperations < 4 {
				t.Fatalf("expected at least four submitted operations for chain status %s, got %d", tc.status, report.SubmittedOperations)
			}

			assertSubmittedConfirmationRecords(t, s, sessionID, rewardID, sponsorReservationID, evidenceID)
		})
	}
}

func TestMemoryServiceReconcileRequiresScopedSettlementMaterial(t *testing.T) {
	local := SessionSettlement{
		SettlementID:  "set-scoped-finality-1",
		ReservationID: "res-scoped-finality-1",
		SessionID:     "sess-scoped-finality-1",
		SubjectID:     "client-scoped-finality-1",
		ChargedMicros: 1234,
		Currency:      "TDPNC",
		SettledAt:     time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		Status:        OperationStatusSubmitted,
	}
	chain := local
	chain.Status = OperationStatusConfirmed

	for _, tc := range []struct {
		name         string
		chain        SessionSettlement
		wantPromoted bool
	}{
		{name: "matching", chain: chain, wantPromoted: true},
		{name: "session mismatch", chain: func() SessionSettlement { v := chain; v.SessionID = "sess-forged"; return v }()},
		{name: "reservation mismatch", chain: func() SessionSettlement { v := chain; v.ReservationID = "res-forged"; return v }()},
		{name: "subject mismatch", chain: func() SessionSettlement { v := chain; v.SubjectID = "client-forged"; return v }()},
		{name: "amount mismatch", chain: func() SessionSettlement { v := chain; v.ChargedMicros++; return v }()},
		{name: "currency mismatch", chain: func() SessionSettlement { v := chain; v.Currency = "uusdc"; return v }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMemoryService(
				WithChainAdapter(materialSettlementConfirmingAdapter{
					settlements: map[string]SessionSettlement{local.SettlementID: tc.chain},
				}),
			)
			s.mu.Lock()
			s.settledBySession[local.SessionID] = local
			s.mu.Unlock()

			if _, err := s.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			s.mu.Lock()
			settlement := s.settledBySession[local.SessionID]
			s.mu.Unlock()
			if tc.wantPromoted {
				if settlement.Status != OperationStatusConfirmed {
					t.Fatalf("expected matching material to promote, got %+v", settlement)
				}
				return
			}
			if settlement.Status != OperationStatusSubmitted {
				t.Fatalf("expected material mismatch to stay submitted, got %+v", settlement)
			}
		})
	}
}

func TestMemoryServiceReconcileDoesNotPromoteSettlementFromStatusOnlyFinality(t *testing.T) {
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(confirmingAdapter{}),
	)
	s.mu.Lock()
	s.settledBySession["sess-status-only-finality-1"] = SessionSettlement{
		SettlementID:     "set-status-only-finality-1",
		ReservationID:    "res-status-only-finality-1",
		SessionID:        "sess-status-only-finality-1",
		SubjectID:        "client-status-only-finality-1",
		ChargedMicros:    1234,
		Currency:         "TDPNC",
		SettledAt:        time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		AdapterSubmitted: true,
		Status:           OperationStatusSubmitted,
	}
	s.mu.Unlock()

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 0 {
		t.Fatalf("status-only settlement finality must not confirm operations, report=%+v", report)
	}
	s.mu.Lock()
	settlement := s.settledBySession["sess-status-only-finality-1"]
	s.mu.Unlock()
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("status-only settlement finality promoted submitted settlement: %+v", settlement)
	}
}

func TestMemoryServiceReconcileDoesNotPromoteRewardFromStatusOnlyFinality(t *testing.T) {
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(confirmingAdapter{}),
	)
	s.mu.Lock()
	s.rewardsByID["rew-status-only-finality-1"] = RewardIssue{
		RewardID:          "rew-status-only-finality-1",
		ProviderSubjectID: "provider-status-only-finality-1",
		SessionID:         "sess-status-only-finality-1",
		TrafficProofRef:   "obj://traffic-proof/status-only-finality-1",
		RewardMicros:      1234,
		Currency:          "TDPNC",
		IssuedAt:          time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		AdapterSubmitted:  true,
		Status:            OperationStatusSubmitted,
	}
	s.mu.Unlock()

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 0 {
		t.Fatalf("status-only reward finality must not confirm operations, report=%+v", report)
	}
	s.mu.Lock()
	reward := s.rewardsByID["rew-status-only-finality-1"]
	s.mu.Unlock()
	if reward.Status != OperationStatusSubmitted {
		t.Fatalf("status-only reward finality promoted submitted reward: %+v", reward)
	}
}

func TestMemoryServiceReconcileDoesNotPromoteSlashEvidenceFromStatusOnlyFinality(t *testing.T) {
	s := NewMemoryService(
		WithBlockchainMode(true),
		WithChainAdapter(confirmingAdapter{}),
	)
	s.mu.Lock()
	s.slashEvidenceByID["ev-status-only-finality-1"] = SlashEvidence{
		EvidenceID:       "ev-status-only-finality-1",
		SubjectID:        "provider-status-only-finality-1",
		SessionID:        "sess-status-only-finality-1",
		ViolationType:    "double-sign",
		EvidenceRef:      testSHA256Ref("status-only-finality-1"),
		SlashMicros:      1234,
		Currency:         "TDPNC",
		ObservedAt:       time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		AdapterSubmitted: true,
		Status:           OperationStatusSubmitted,
	}
	s.mu.Unlock()

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 0 {
		t.Fatalf("status-only slash finality must not confirm operations, report=%+v", report)
	}
	s.mu.Lock()
	evidence := s.slashEvidenceByID["ev-status-only-finality-1"]
	s.mu.Unlock()
	if evidence.Status != OperationStatusSubmitted {
		t.Fatalf("status-only slash finality promoted submitted evidence: %+v", evidence)
	}
}

func TestMemoryServiceGetSponsorReservationReturnsStoredReservationByID(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()

	stored, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-get-1",
		SponsorID:     "sponsor-get-1",
		SubjectID:     "client-get-1",
		SessionID:     "sess-get-1",
		AmountMicros:  777,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	got, err := s.GetSponsorReservation(ctx, "sres-get-1")
	if err != nil {
		t.Fatalf("GetSponsorReservation: %v", err)
	}
	if got.ReservationID != stored.ReservationID {
		t.Fatalf("expected reservation id %s, got %s", stored.ReservationID, got.ReservationID)
	}
	if got.SponsorID != stored.SponsorID {
		t.Fatalf("expected sponsor id %s, got %s", stored.SponsorID, got.SponsorID)
	}
	if got.SubjectID != stored.SubjectID {
		t.Fatalf("expected subject id %s, got %s", stored.SubjectID, got.SubjectID)
	}
	if got.SessionID != stored.SessionID {
		t.Fatalf("expected session id %s, got %s", stored.SessionID, got.SessionID)
	}
	if got.AmountMicros != stored.AmountMicros {
		t.Fatalf("expected amount_micros %d, got %d", stored.AmountMicros, got.AmountMicros)
	}
	if got.Currency != stored.Currency {
		t.Fatalf("expected currency %s, got %s", stored.Currency, got.Currency)
	}
	if got.Status != stored.Status {
		t.Fatalf("expected status %s, got %s", stored.Status, got.Status)
	}
	if got.CreatedAt.IsZero() {
		t.Fatalf("expected created_at to be set")
	}
	if got.ExpiresAt.IsZero() {
		t.Fatalf("expected expires_at to be set")
	}
}

func TestMemoryServiceGetSponsorReservationNotFoundReturnsErrorContract(t *testing.T) {
	s := NewMemoryService()

	_, err := s.GetSponsorReservation(context.Background(), "sres-missing-1")
	if err == nil {
		t.Fatalf("expected unknown reservation lookup to fail")
	}
	if err.Error() != "reservation not found: sres-missing-1" {
		t.Fatalf("unexpected error for unknown reservation lookup: %v", err)
	}
}

func TestMemoryServiceGetSponsorReservationStatusPersistsAfterConsumeAndSessionSettle(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	sessionID := "sess-sponsor-status-1"

	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-status-1",
		SponsorID:     "sponsor-status-1",
		SubjectID:     "client-status-1",
		SessionID:     sessionID,
		AmountMicros:  1500,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	beforeConsume, err := s.GetSponsorReservation(ctx, "sres-status-1")
	if err != nil {
		t.Fatalf("GetSponsorReservation before consume: %v", err)
	}
	if beforeConsume.Status != OperationStatusConfirmed {
		t.Fatalf("expected pre-consume status confirmed, got %s", beforeConsume.Status)
	}
	if !beforeConsume.ConsumedAt.IsZero() {
		t.Fatalf("expected pre-consume consumed_at to be zero")
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-status-1",
		SponsorID:     "sponsor-status-1",
		SubjectID:     "client-status-1",
		SessionID:     sessionID,
	})
	if err != nil {
		t.Fatalf("AuthorizePayment: %v", err)
	}

	afterConsume, err := s.GetSponsorReservation(ctx, "sres-status-1")
	if err != nil {
		t.Fatalf("GetSponsorReservation after consume: %v", err)
	}
	if afterConsume.Status != OperationStatusConfirmed {
		t.Fatalf("expected post-consume status confirmed, got %s", afterConsume.Status)
	}
	if afterConsume.ConsumedAt.IsZero() {
		t.Fatalf("expected post-consume consumed_at to be set")
	}

	_, err = s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-status-1",
		AmountMicros: 10_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-status-1",
		BytesIngress: 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if _, err := s.SettleSession(ctx, sessionID); err != nil {
		t.Fatalf("SettleSession: %v", err)
	}

	afterSettle, err := s.GetSponsorReservation(ctx, "sres-status-1")
	if err != nil {
		t.Fatalf("GetSponsorReservation after settle: %v", err)
	}
	if afterSettle.Status != afterConsume.Status {
		t.Fatalf("expected sponsor status to persist after settle; got %s want %s", afterSettle.Status, afterConsume.Status)
	}
	if !afterSettle.ConsumedAt.Equal(afterConsume.ConsumedAt) {
		t.Fatalf("expected consumed_at to persist after settle")
	}
}

func TestMemoryServiceSponsorFlowAuthorizeIdempotent(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-2",
		SponsorID:     "sponsor-2",
		SubjectID:     "client-22",
		SessionID:     "sess-22",
		AmountMicros:  333,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	authA, err := s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-2",
		SponsorID:     "sponsor-2",
		SubjectID:     "client-22",
		SessionID:     "sess-22",
	})
	if err != nil {
		t.Fatalf("AuthorizePayment first: %v", err)
	}
	authB, err := s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-2",
		SponsorID:     "sponsor-2",
		SubjectID:     "client-22",
		SessionID:     "sess-22",
	})
	if err != nil {
		t.Fatalf("AuthorizePayment second: %v", err)
	}
	if authA.ReservationID != authB.ReservationID {
		t.Fatalf("expected same reservation id on idempotent auth, got %s vs %s", authA.ReservationID, authB.ReservationID)
	}
	if !authB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on second authorize")
	}
}

func TestMemoryServiceNonSettlementExactReplaysAreIdempotentByRecordID(t *testing.T) {
	adapter := &multiOperationReplayAdapter{}
	s := NewMemoryService(WithChainAdapter(adapter))
	ctx := context.Background()

	rewardRequest := RewardIssue{
		RewardID:          "rew-idem-1",
		ProviderSubjectID: "provider-idem-1",
		SessionID:         "sess-idem-1",
		RewardMicros:      55,
		Currency:          "TDPNC",
	}
	rewardA, err := s.IssueReward(ctx, rewardRequest)
	if err != nil {
		t.Fatalf("IssueReward first: %v", err)
	}
	rewardB, err := s.IssueReward(ctx, rewardRequest)
	if err != nil {
		t.Fatalf("IssueReward second: %v", err)
	}
	if !rewardB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on duplicate reward write")
	}
	if rewardA.RewardID != rewardB.RewardID || rewardA.ProviderSubjectID != rewardB.ProviderSubjectID || rewardA.SessionID != rewardB.SessionID {
		t.Fatalf("expected duplicate reward write to return original record identity")
	}

	reservationRequest := SponsorCreditReservation{
		ReservationID: "sres-idem-1",
		SponsorID:     "sponsor-idem-1",
		SubjectID:     "client-idem-1",
		SessionID:     "sess-idem-1",
		AmountMicros:  300,
		Currency:      "TDPNC",
	}
	reservationA, err := s.ReserveSponsorCredits(ctx, reservationRequest)
	if err != nil {
		t.Fatalf("ReserveSponsorCredits first: %v", err)
	}
	reservationB, err := s.ReserveSponsorCredits(ctx, reservationRequest)
	if err != nil {
		t.Fatalf("ReserveSponsorCredits second: %v", err)
	}
	if !reservationB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on duplicate sponsor reservation")
	}
	if reservationA.ReservationID != reservationB.ReservationID || reservationA.SponsorID != reservationB.SponsorID || reservationA.SubjectID != reservationB.SubjectID {
		t.Fatalf("expected duplicate sponsor reservation write to return original record identity")
	}

	evidenceRequest := SlashEvidence{
		EvidenceID:    "ev-idem-1",
		SubjectID:     "provider-idem-1",
		SessionID:     "sess-idem-1",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("slash-idem-a"),
		SlashMicros:   17,
		Currency:      "TDPNC",
	}
	evidenceA, err := s.SubmitSlashEvidence(ctx, evidenceRequest)
	if err != nil {
		t.Fatalf("SubmitSlashEvidence first: %v", err)
	}
	evidenceB, err := s.SubmitSlashEvidence(ctx, evidenceRequest)
	if err != nil {
		t.Fatalf("SubmitSlashEvidence second: %v", err)
	}
	if !evidenceB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on duplicate slash evidence write")
	}
	if evidenceA.EvidenceID != evidenceB.EvidenceID || evidenceA.SubjectID != evidenceB.SubjectID || evidenceA.EvidenceRef != evidenceB.EvidenceRef {
		t.Fatalf("expected duplicate slash evidence write to return original proof identity")
	}

	if adapter.rewardCalls() != 1 || adapter.sponsorCalls() != 1 || adapter.slashCalls() != 1 {
		t.Fatalf("expected duplicate writes not to resubmit adapter operations, got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
	}
}

func TestMemoryServiceIssueRewardConcurrentDuplicateSubmitsOnce(t *testing.T) {
	adapter := newBlockingRewardAdapter()
	s := NewMemoryService(WithChainAdapter(adapter))
	ctx := context.Background()

	rewardRequest := RewardIssue{
		RewardID:          "rew-concurrent-1",
		ProviderSubjectID: "provider-concurrent-1",
		SessionID:         "sess-concurrent-1",
		RewardMicros:      55,
		Currency:          "TDPNC",
	}

	firstResult := make(chan struct {
		reward RewardIssue
		err    error
	}, 1)
	go func() {
		reward, err := s.IssueReward(ctx, rewardRequest)
		firstResult <- struct {
			reward RewardIssue
			err    error
		}{reward: reward, err: err}
	}()

	select {
	case <-adapter.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first reward adapter submission")
	}

	replayed, err := s.IssueReward(ctx, rewardRequest)
	if err != nil {
		t.Fatalf("IssueReward duplicate while first submit is in flight: %v", err)
	}
	if !replayed.IdempotentReplay {
		t.Fatalf("expected in-flight duplicate reward to return idempotent replay")
	}
	if calls := adapter.rewardCalls(); calls != 1 {
		t.Fatalf("expected only one adapter reward submission before release, got %d", calls)
	}

	close(adapter.release)
	select {
	case result := <-firstResult:
		if result.err != nil {
			t.Fatalf("first IssueReward: %v", result.err)
		}
		if result.reward.RewardID != rewardRequest.RewardID {
			t.Fatalf("reward id=%q want=%q", result.reward.RewardID, rewardRequest.RewardID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first reward issue to finish")
	}
	if calls := adapter.rewardCalls(); calls != 1 {
		t.Fatalf("expected one adapter reward submission after release, got %d", calls)
	}
}

func TestMemoryServiceSubmitSlashEvidenceConcurrentConflictReservesBeforeAdapter(t *testing.T) {
	adapter := newBlockingSlashAdapter()
	s := NewMemoryService(WithChainAdapter(adapter))
	ctx := context.Background()

	observedAt := time.Date(2026, 4, 20, 1, 2, 3, 0, time.UTC)
	evidenceRequest := SlashEvidence{
		EvidenceID:    "ev-concurrent-conflict-1",
		SubjectID:     "provider-concurrent-1",
		SessionID:     "sess-concurrent-1",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("slash-concurrent-a"),
		SlashMicros:   17,
		Currency:      "TDPNC",
		ObservedAt:    observedAt,
	}

	firstResult := make(chan struct {
		evidence SlashEvidence
		err      error
	}, 1)
	go func() {
		evidence, err := s.SubmitSlashEvidence(ctx, evidenceRequest)
		firstResult <- struct {
			evidence SlashEvidence
			err      error
		}{evidence: evidence, err: err}
	}()

	select {
	case <-adapter.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first slash adapter submission")
	}

	conflicting := evidenceRequest
	conflicting.SubjectID = "provider-conflicting"
	conflicting.EvidenceRef = testSHA256Ref("slash-concurrent-b")
	_, err := s.SubmitSlashEvidence(ctx, conflicting)
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected in-flight conflicting slash evidence to fail with conflict, got %v", err)
	}
	if calls := adapter.slashCalls(); calls != 1 {
		t.Fatalf("expected only one adapter slash submission before release, got %d", calls)
	}

	close(adapter.release)
	select {
	case result := <-firstResult:
		if result.err != nil {
			t.Fatalf("first SubmitSlashEvidence: %v", result.err)
		}
		if result.evidence.EvidenceID != evidenceRequest.EvidenceID {
			t.Fatalf("evidence id=%q want=%q", result.evidence.EvidenceID, evidenceRequest.EvidenceID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first slash evidence to finish")
	}
	if calls := adapter.slashCalls(); calls != 1 {
		t.Fatalf("expected one adapter slash submission after release, got %d", calls)
	}
}

func TestMemoryServiceListSlashEvidenceFiltersAndReturnsSnapshot(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	weekStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)

	first, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-list-1",
		SubjectID:     "provider-list",
		SessionID:     "sess-list-1",
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   testSHA256Ref("slash-list-a"),
		SlashMicros:   17,
		Currency:      "TDPNC",
		ObservedAt:    weekStart.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence first: %v", err)
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-list-2",
		SubjectID:     "provider-list",
		SessionID:     "sess-list-2",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("slash-list-b"),
		SlashMicros:   0,
		ObservedAt:    weekStart.AddDate(0, 0, 8),
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence second: %v", err)
	}

	got, err := s.ListSlashEvidence(ctx, SlashEvidenceFilter{
		SubjectID:         "provider-list",
		SessionID:         "sess-list-1",
		ObservedAtOrAfter: weekStart,
		ObservedBefore:    weekStart.AddDate(0, 0, 7),
	})
	if err != nil {
		t.Fatalf("ListSlashEvidence: %v", err)
	}
	if len(got) != 1 || got[0].EvidenceID != first.EvidenceID {
		t.Fatalf("filtered evidence=%+v want only %s", got, first.EvidenceID)
	}
	got[0].SubjectID = "mutated"
	reloaded, err := s.ListSlashEvidence(ctx, SlashEvidenceFilter{SubjectID: "provider-list"})
	if err != nil {
		t.Fatalf("ListSlashEvidence reload: %v", err)
	}
	if len(reloaded) != 2 {
		t.Fatalf("reloaded len=%d want=2 evidence=%+v", len(reloaded), reloaded)
	}
	if reloaded[0].SubjectID != "provider-list" {
		t.Fatalf("list did not return snapshot copy: %+v", reloaded[0])
	}
	if reloaded[1].SlashMicros != 0 || reloaded[1].Currency != "" {
		t.Fatalf("zero-amount slash evidence should not default currency: %+v", reloaded[1])
	}
}

func TestMemoryServiceListSlashEvidenceIncludeFailedPresence(t *testing.T) {
	ctx := context.Background()
	adapter := &slashEvidenceListingAdapter{evidence: []SlashEvidence{
		{
			EvidenceID:    "ev-presence-failed",
			SubjectID:     "provider-presence",
			SessionID:     "sess-presence-failed",
			ViolationType: "invalid-settlement-proof",
			EvidenceRef:   testSHA256Ref("presence-failed"),
			SlashMicros:   1,
			ObservedAt:    time.Date(2026, 4, 20, 1, 0, 0, 0, time.UTC),
			Status:        OperationStatusFailed,
		},
		{
			EvidenceID:    "ev-presence-submitted",
			SubjectID:     "provider-presence",
			SessionID:     "sess-presence-submitted",
			ViolationType: "invalid-settlement-proof",
			EvidenceRef:   testSHA256Ref("presence-submitted"),
			SlashMicros:   1,
			ObservedAt:    time.Date(2026, 4, 20, 2, 0, 0, 0, time.UTC),
			Status:        OperationStatusSubmitted,
		},
	}}
	s := NewMemoryService(WithBlockchainMode(true), WithChainAdapter(adapter))

	unset, err := s.ListSlashEvidence(ctx, SlashEvidenceFilter{SubjectID: "provider-presence"})
	if err != nil {
		t.Fatalf("ListSlashEvidence unset: %v", err)
	}
	if len(unset) != 2 {
		t.Fatalf("unset include_failed len=%d want=2 evidence=%+v", len(unset), unset)
	}

	explicitFalse, err := s.ListSlashEvidence(ctx, SlashEvidenceFilter{
		SubjectID:        "provider-presence",
		IncludeFailed:    false,
		IncludeFailedSet: true,
	})
	if err != nil {
		t.Fatalf("ListSlashEvidence explicit false: %v", err)
	}
	if len(explicitFalse) != 1 || explicitFalse[0].EvidenceID != "ev-presence-submitted" {
		t.Fatalf("explicit false evidence=%+v want only submitted", explicitFalse)
	}
}

func TestMemoryServiceListSlashEvidenceMergesChainEvidence(t *testing.T) {
	ctx := context.Background()
	weekStart := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	chainOnly := SlashEvidence{
		EvidenceID:    "ev-chain-only",
		SubjectID:     "provider-merge",
		SessionID:     "sess-chain",
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   testSHA256Ref("chain-only"),
		ObservedAt:    weekStart.Add(3 * time.Hour),
		Status:        OperationStatusConfirmed,
	}
	duplicateLocal := SlashEvidence{
		EvidenceID:    "ev-local-merge",
		SubjectID:     "provider-merge",
		SessionID:     "sess-local",
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   testSHA256Ref("local-merge"),
		ObservedAt:    weekStart.Add(2 * time.Hour),
		Status:        OperationStatusConfirmed,
	}
	adapter := &slashEvidenceListingAdapter{
		evidence: []SlashEvidence{chainOnly, duplicateLocal},
	}
	s := NewMemoryService(WithChainAdapter(adapter), WithBlockchainMode(true))
	if _, err := s.SubmitSlashEvidence(ctx, duplicateLocal); err != nil {
		t.Fatalf("SubmitSlashEvidence local: %v", err)
	}

	got, err := s.ListSlashEvidence(ctx, SlashEvidenceFilter{
		SubjectID:         "provider-merge",
		ObservedAtOrAfter: weekStart,
		ObservedBefore:    weekStart.AddDate(0, 0, 7),
	})
	if err != nil {
		t.Fatalf("ListSlashEvidence: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("merged evidence len=%d want=2 evidence=%+v", len(got), got)
	}
	if got[0].EvidenceID != duplicateLocal.EvidenceID || got[1].EvidenceID != chainOnly.EvidenceID {
		t.Fatalf("merged evidence order/dedupe mismatch: %+v", got)
	}
	if adapter.filter.SubjectID != "provider-merge" {
		t.Fatalf("adapter filter subject=%q want provider-merge", adapter.filter.SubjectID)
	}
}

func TestMemoryServiceListSlashEvidenceFailsClosedInBlockchainModeWithoutChainLister(t *testing.T) {
	s := NewMemoryService(WithChainAdapter(fakeAdapter{}), WithBlockchainMode(true))
	_, err := s.ListSlashEvidence(context.Background(), SlashEvidenceFilter{SubjectID: "provider-no-lister"})
	if err == nil {
		t.Fatal("expected blockchain-mode slash evidence list to fail without chain lister")
	}
	if !strings.Contains(err.Error(), "chain slash evidence lister") {
		t.Fatalf("error=%q want chain lister requirement", err.Error())
	}
}

func TestMemoryServiceListSlashEvidenceFailsClosedWhenChainListerFails(t *testing.T) {
	s := NewMemoryService(
		WithChainAdapter(&slashEvidenceListingAdapter{err: errFakeAdapter}),
		WithBlockchainMode(true),
	)
	_, err := s.ListSlashEvidence(context.Background(), SlashEvidenceFilter{SubjectID: "provider-lister-fail"})
	if err == nil {
		t.Fatal("expected blockchain-mode slash evidence list to fail on chain query error")
	}
	if !strings.Contains(err.Error(), "list chain slash evidence") {
		t.Fatalf("error=%q want chain list failure context", err.Error())
	}
}

func TestMemoryServiceSubmitSlashEvidenceRejectsDuplicateIncidentDifferentID(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	ref := testSHA256Ref("slash-incident-duplicate")
	upperRef := "sha256:" + strings.ToUpper(strings.TrimPrefix(ref, "sha256:"))

	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-incident-1",
		SubjectID:     "provider-incident",
		SessionID:     "sess-incident",
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   ref,
		SlashMicros:   17,
		Currency:      "TDPNC",
		ObservedAt:    time.Date(2026, 4, 20, 2, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence first: %v", err)
	}
	_, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-incident-2",
		SubjectID:     "provider-incident",
		SessionID:     "sess-incident",
		ViolationType: "invalid-settlement-proof",
		EvidenceRef:   upperRef,
		SlashMicros:   17,
		Currency:      "TDPNC",
		ObservedAt:    time.Date(2026, 4, 20, 3, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "incident conflict") {
		t.Fatalf("expected duplicate incident conflict, got %v", err)
	}
	got, listErr := s.ListSlashEvidence(ctx, SlashEvidenceFilter{SubjectID: "provider-incident"})
	if listErr != nil {
		t.Fatalf("ListSlashEvidence: %v", listErr)
	}
	if len(got) != 1 || got[0].EvidenceID != "ev-incident-1" {
		t.Fatalf("expected exactly original incident evidence, got %+v", got)
	}
}

func TestMemoryServiceNonSettlementConflictingReplaysRejectByRecordID(t *testing.T) {
	adapter := &multiOperationReplayAdapter{}
	s := NewMemoryService(WithChainAdapter(adapter))
	ctx := context.Background()

	_, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-conflict-1",
		ProviderSubjectID: "provider-conflict-1",
		SessionID:         "sess-conflict-1",
		RewardMicros:      55,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward first: %v", err)
	}
	_, err = s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-conflict-1",
		ProviderSubjectID: "provider-conflict-override",
		SessionID:         "sess-conflict-override",
		RewardMicros:      99,
		Currency:          "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected conflicting reward replay to fail with conflict, got %v", err)
	}

	_, err = s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-conflict-1",
		SponsorID:     "sponsor-conflict-1",
		SubjectID:     "client-conflict-1",
		SessionID:     "sess-conflict-sponsor-1",
		AmountMicros:  300,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits first: %v", err)
	}
	_, err = s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-conflict-1",
		SponsorID:     "sponsor-conflict-override",
		SubjectID:     "client-conflict-override",
		SessionID:     "sess-conflict-sponsor-override",
		AmountMicros:  999,
		Currency:      "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected conflicting sponsor reservation replay to fail with conflict, got %v", err)
	}

	_, err = s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-conflict-1",
		SubjectID:     "provider-conflict-1",
		SessionID:     "sess-conflict-slash-1",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("slash-conflict-a"),
		SlashMicros:   17,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence first: %v", err)
	}
	_, err = s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-conflict-1",
		SubjectID:     "provider-conflict-override",
		SessionID:     "sess-conflict-slash-override",
		ViolationType: "sponsor-overdraft-proof",
		EvidenceRef:   testSHA256Ref("slash-conflict-b"),
		SlashMicros:   123,
		Currency:      "TDPNC",
	})
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected conflicting slash evidence replay to fail with conflict, got %v", err)
	}

	if adapter.rewardCalls() != 1 || adapter.sponsorCalls() != 1 || adapter.slashCalls() != 1 {
		t.Fatalf("expected conflicting replays not to resubmit adapter operations, got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
	}
}

func TestMemoryServiceAuthorizePaymentRequiresReservationID(t *testing.T) {
	s := NewMemoryService()
	_, err := s.AuthorizePayment(context.Background(), PaymentProof{
		ReservationID: "   ",
		SponsorID:     "sponsor-1",
		SubjectID:     "client-1",
		SessionID:     "sess-1",
	})
	if err == nil {
		t.Fatalf("expected missing reservation_id to fail")
	}
	if err.Error() != "authorize payment requires reservation_id" {
		t.Fatalf("unexpected error for missing reservation_id: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentRequiresSponsorAndSubject(t *testing.T) {
	s := NewMemoryService()
	tests := []struct {
		name    string
		proof   PaymentProof
		wantErr string
	}{
		{
			name: "missing sponsor_id",
			proof: PaymentProof{
				ReservationID: "sres-binding-missing-sponsor",
				SponsorID:     "   ",
				SubjectID:     "client-1",
				SessionID:     "sess-1",
			},
			wantErr: "authorize payment requires sponsor_id",
		},
		{
			name: "missing subject_id",
			proof: PaymentProof{
				ReservationID: "sres-binding-missing-subject",
				SponsorID:     "sponsor-1",
				SubjectID:     " ",
				SessionID:     "sess-1",
			},
			wantErr: "authorize payment requires subject_id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.AuthorizePayment(context.Background(), tc.proof)
			if err == nil {
				t.Fatalf("expected missing binding field to fail")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("unexpected error for missing binding field: got %v want %s", err, tc.wantErr)
			}
		})
	}
}

func TestMemoryServiceAuthorizePaymentReservationNotFound(t *testing.T) {
	s := NewMemoryService()
	_, err := s.AuthorizePayment(context.Background(), PaymentProof{
		ReservationID: "sres-missing-1",
		SponsorID:     "sponsor-missing-1",
		SubjectID:     "client-missing-1",
		SessionID:     "sess-missing-1",
	})
	if err == nil {
		t.Fatalf("expected unknown reservation to fail")
	}
	if err.Error() != "reservation not found: sres-missing-1" {
		t.Fatalf("unexpected error for unknown reservation: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentRejectsProofFieldMismatches(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-mismatch-1",
		SponsorID:     "sponsor-good-1",
		SubjectID:     "client-good-1",
		SessionID:     "sess-good-1",
		AmountMicros:  700,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	testCases := []struct {
		name    string
		proof   PaymentProof
		wantErr string
	}{
		{
			name: "sponsor mismatch",
			proof: PaymentProof{
				ReservationID: "sres-mismatch-1",
				SponsorID:     "sponsor-bad-1",
				SubjectID:     "client-good-1",
				SessionID:     "sess-good-1",
			},
			wantErr: "reservation sponsor mismatch",
		},
		{
			name: "subject mismatch",
			proof: PaymentProof{
				ReservationID: "sres-mismatch-1",
				SponsorID:     "sponsor-good-1",
				SubjectID:     "client-bad-1",
				SessionID:     "sess-good-1",
			},
			wantErr: "reservation subject mismatch",
		},
		{
			name: "session mismatch",
			proof: PaymentProof{
				ReservationID: "sres-mismatch-1",
				SponsorID:     "sponsor-good-1",
				SubjectID:     "client-good-1",
				SessionID:     "sess-bad-1",
			},
			wantErr: "reservation session mismatch",
		},
		{
			name: "missing session when reservation requires it",
			proof: PaymentProof{
				ReservationID: "sres-mismatch-1",
				SponsorID:     "sponsor-good-1",
				SubjectID:     "client-good-1",
				SessionID:     "   ",
			},
			wantErr: "authorize payment requires session_id",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.AuthorizePayment(ctx, tc.proof)
			if err == nil {
				t.Fatalf("expected authorize mismatch to fail")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("unexpected authorize mismatch error: got %v want %s", err, tc.wantErr)
			}
		})
	}
}

func TestMemoryServiceAuthorizePaymentRejectsUnexpectedSessionBinding(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-empty-session-1",
		SponsorID:     "sponsor-empty-session-1",
		SubjectID:     "client-empty-session-1",
		AmountMicros:  300,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-empty-session-1",
		SponsorID:     "sponsor-empty-session-1",
		SubjectID:     "client-empty-session-1",
		SessionID:     "sess-should-not-be-set",
	})
	if err == nil {
		t.Fatalf("expected session mismatch when reservation has no session")
	}
	if err.Error() != "reservation session mismatch" {
		t.Fatalf("unexpected error for unexpected session binding: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentRejectsExpiredReservation(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	createdAt := time.Now().UTC().Add(-15 * time.Minute)
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-expired-1",
		SponsorID:     "sponsor-expired-1",
		SubjectID:     "client-expired-1",
		SessionID:     "sess-expired-1",
		AmountMicros:  500,
		CreatedAt:     createdAt,
		ExpiresAt:     createdAt.Add(1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-expired-1",
		SponsorID:     "sponsor-expired-1",
		SubjectID:     "client-expired-1",
		SessionID:     "sess-expired-1",
	})
	if err == nil {
		t.Fatalf("expected expired reservation to fail authorization")
	}
	if err.Error() != "reservation expired: sres-expired-1" {
		t.Fatalf("unexpected error for expired reservation: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentRejectsConsumedReservationWithoutPriorAuthRecord(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-consumed-1",
		SponsorID:     "sponsor-consumed-1",
		SubjectID:     "client-consumed-1",
		SessionID:     "sess-consumed-1",
		AmountMicros:  444,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	s.mu.Lock()
	reservation := s.sponsorReservationsByID["sres-consumed-1"]
	reservation.ConsumedAt = time.Now().UTC().Add(-time.Minute)
	s.sponsorReservationsByID["sres-consumed-1"] = reservation
	delete(s.paymentAuthByReservationID, "sres-consumed-1")
	s.mu.Unlock()

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-consumed-1",
		SponsorID:     "sponsor-consumed-1",
		SubjectID:     "client-consumed-1",
		SessionID:     "sess-consumed-1",
	})
	if err == nil {
		t.Fatalf("expected consumed reservation to fail authorization")
	}
	if err.Error() != "reservation already consumed: sres-consumed-1" {
		t.Fatalf("unexpected error for consumed reservation: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentDuplicateProofReplayRejectsMismatchedProof(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-replay-1",
		SponsorID:     "sponsor-replay-1",
		SubjectID:     "client-replay-1",
		SessionID:     "sess-replay-1",
		AmountMicros:  333,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-replay-1",
		SponsorID:     "sponsor-replay-1",
		SubjectID:     "client-replay-1",
		SessionID:     "sess-replay-1",
	})
	if err != nil {
		t.Fatalf("AuthorizePayment first: %v", err)
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-replay-1",
		SponsorID:     "sponsor-other",
		SubjectID:     "client-other",
		SessionID:     "sess-other",
	})
	if err == nil {
		t.Fatalf("expected mismatched duplicate proof replay to fail")
	}
	if err.Error() != "reservation sponsor mismatch" {
		t.Fatalf("unexpected error for mismatched duplicate replay: %v", err)
	}
}

func TestMemoryServiceQuotePriceCurrencyConversion(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1000),
		WithCurrency("USDC"),
		WithCurrencyRate("TDPN", 2, 1),
	)
	ctx := context.Background()
	quote, err := s.QuotePrice(ctx, "client-1", "TDPN")
	if err != nil {
		t.Fatalf("QuotePrice: %v", err)
	}
	if quote.Currency != "TDPN" {
		t.Fatalf("expected TDPN quote currency, got %s", quote.Currency)
	}
	if quote.PricePerMiBMicros != 2000 {
		t.Fatalf("expected converted quote price 2000, got %d", quote.PricePerMiBMicros)
	}
}

func TestMemoryServiceSettleSessionCurrencyConversion(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1_000_000),
		WithCurrency("USDC"),
		WithCurrencyRate("TDPN", 2, 1),
	)
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-conv-1",
		SubjectID:    "client-conv-1",
		AmountMicros: 2100000,
		Currency:     "TDPN",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-conv-1",
		SubjectID:    "client-conv-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-conv-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Currency != "TDPN" {
		t.Fatalf("expected settlement currency TDPN, got %s", settlement.Currency)
	}
	if settlement.ChargedMicros != 2_000_000 {
		t.Fatalf("expected converted charge 2000000, got %d", settlement.ChargedMicros)
	}
}

func TestMemoryServiceSettleSessionRejectsUsageByteOverflow(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	const sessionID = "sess-overflow-bytes-1"

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-overflow-bytes-1",
		AmountMicros: math.MaxInt64,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-overflow-bytes-1",
		BytesIngress: math.MaxInt64,
		BytesEgress:  1,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	_, err = s.SettleSession(ctx, sessionID)
	if err == nil {
		t.Fatalf("expected usage byte overflow to fail settle")
	}
	if !strings.Contains(err.Error(), "usage byte counters overflow") {
		t.Fatalf("unexpected usage byte overflow error: %v", err)
	}
}

func TestMemoryServiceSettleSessionRejectsChargeOverflow(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(math.MaxInt64))
	ctx := context.Background()
	const sessionID = "sess-overflow-charge-1"

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-overflow-charge-1",
		AmountMicros: math.MaxInt64,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-overflow-charge-1",
		BytesIngress: 2 * 1024 * 1024, // 2 MiB
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	_, err = s.SettleSession(ctx, sessionID)
	if err == nil {
		t.Fatalf("expected settlement charge overflow to fail settle")
	}
	if !strings.Contains(err.Error(), "settlement charge overflow") {
		t.Fatalf("unexpected settlement charge overflow error: %v", err)
	}
}

func TestMemoryServiceDualAssetSessionEntitlementEquivalence(t *testing.T) {
	const (
		pricePerMiBMicros = int64(1_000_000) // 1.0 unit per MiB in base settlement currency.
		usageBytes        = int64(2 * 1024 * 1024)
	)

	s := NewMemoryService(
		WithPricePerMiBMicros(pricePerMiBMicros),
		WithCurrency("USDC"),
		WithCurrencyRate("TDPN", 2, 1), // 1 USDC micro == 2 TDPN micros.
	)
	ctx := context.Background()

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-eq-usdc-ok",
		SubjectID:    "client-eq-usdc-ok",
		AmountMicros: 2_000_000,
		Currency:     "USDC",
	}); err != nil {
		t.Fatalf("ReserveFunds usdc success case: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-eq-usdc-ok",
		SubjectID:    "client-eq-usdc-ok",
		BytesIngress: usageBytes,
	}); err != nil {
		t.Fatalf("RecordUsage usdc success case: %v", err)
	}
	usdcSettlement, err := s.SettleSession(ctx, "sess-eq-usdc-ok")
	if err != nil {
		t.Fatalf("SettleSession usdc success case: %v", err)
	}

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-eq-tdpn-ok",
		SubjectID:    "client-eq-tdpn-ok",
		AmountMicros: 4_000_000,
		Currency:     "TDPN",
	}); err != nil {
		t.Fatalf("ReserveFunds tdpn success case: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-eq-tdpn-ok",
		SubjectID:    "client-eq-tdpn-ok",
		BytesIngress: usageBytes,
	}); err != nil {
		t.Fatalf("RecordUsage tdpn success case: %v", err)
	}
	tdpnSettlement, err := s.SettleSession(ctx, "sess-eq-tdpn-ok")
	if err != nil {
		t.Fatalf("SettleSession tdpn success case: %v", err)
	}

	if usdcSettlement.ChargedMicros != 2_000_000 {
		t.Fatalf("expected USDC charged micros 2000000, got %d", usdcSettlement.ChargedMicros)
	}
	if tdpnSettlement.ChargedMicros != 4_000_000 {
		t.Fatalf("expected TDPN charged micros 4000000, got %d", tdpnSettlement.ChargedMicros)
	}

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-eq-usdc-fail",
		SubjectID:    "client-eq-usdc-fail",
		AmountMicros: 1_999_999,
		Currency:     "USDC",
	}); err != nil {
		t.Fatalf("ReserveFunds usdc insufficient case: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-eq-usdc-fail",
		SubjectID:    "client-eq-usdc-fail",
		BytesIngress: usageBytes,
	}); err != nil {
		t.Fatalf("RecordUsage usdc insufficient case: %v", err)
	}
	if _, err := s.SettleSession(ctx, "sess-eq-usdc-fail"); err == nil {
		t.Fatalf("expected USDC insufficient reservation to fail")
	}

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-eq-tdpn-fail",
		SubjectID:    "client-eq-tdpn-fail",
		AmountMicros: 3_999_999,
		Currency:     "TDPN",
	}); err != nil {
		t.Fatalf("ReserveFunds tdpn insufficient case: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-eq-tdpn-fail",
		SubjectID:    "client-eq-tdpn-fail",
		BytesIngress: usageBytes,
	}); err != nil {
		t.Fatalf("RecordUsage tdpn insufficient case: %v", err)
	}
	if _, err := s.SettleSession(ctx, "sess-eq-tdpn-fail"); err == nil {
		t.Fatalf("expected TDPN insufficient reservation to fail")
	}
}

func TestMemoryServiceSubmitSlashEvidenceRejectsEmptySessionID(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-missing-session-1",
		SubjectID:     "provider-missing-session-1",
		SessionID:     "   ",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("ev-missing-session-1"),
		SlashMicros:   1,
	}); err == nil || !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("expected missing session_id to fail, got %v", err)
	}
}

func TestMemoryServiceSubmitSlashEvidenceRequiresObjectiveSchema(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-bad-1",
		SubjectID:     "provider-1",
		SessionID:     "sess-bad-1",
		ViolationType: "manual-review-only",
		EvidenceRef:   "obj://evidence/manual",
		SlashMicros:   1,
	}); err == nil {
		t.Fatalf("expected non-objective violation type to fail")
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-bad-2",
		SubjectID:     "provider-1",
		SessionID:     "sess-bad-2",
		ViolationType: "double-sign",
		EvidenceRef:   "manual-note://not-verifiable",
		SlashMicros:   1,
	}); err == nil {
		t.Fatalf("expected non-objective evidence ref to fail")
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-bad-3",
		SubjectID:     "provider-1",
		SessionID:     "sess-bad-3",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:abcd1234",
		SlashMicros:   1,
	}); err == nil {
		t.Fatalf("expected short sha256 evidence ref to fail")
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-bad-4",
		SubjectID:     "provider-1",
		SessionID:     "sess-bad-4",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
		SlashMicros:   1,
	}); err == nil {
		t.Fatalf("expected non-hex sha256 evidence ref to fail")
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-good-1",
		SubjectID:     "provider-1",
		SessionID:     "sess-good-1",
		ViolationType: "double-sign",
		EvidenceRef:   "obj://validator/double-sign/block-12",
		SlashMicros:   1,
	}); err != nil {
		t.Fatalf("expected objective slash evidence to pass: %v", err)
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-good-2",
		SubjectID:     "provider-1",
		SessionID:     "sess-good-2",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("ev-good-2"),
		SlashMicros:   1,
	}); err != nil {
		t.Fatalf("expected sha256 objective slash evidence to pass: %v", err)
	}
}
