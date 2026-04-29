package keeper

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

// Keeper defaults to in-memory storage and accepts pluggable stores (file-backed/KV adapters).
type Keeper struct {
	mu    sync.RWMutex
	store KeeperStore
}

type distributionAccrualAtomicWriter interface {
	UpsertDistributionWithAccrualWithError(distribution types.DistributionRecord, accrual types.RewardAccrual) error
}

const weeklyEpochSeconds int64 = 7 * 24 * 60 * 60
const weeklyEpochMondayOffsetSeconds int64 = 3 * 24 * 60 * 60

func NewKeeper() Keeper {
	return NewKeeperWithStore(nil)
}

func NewKeeperWithStore(store KeeperStore) Keeper {
	if store == nil {
		store = NewInMemoryStore()
	}

	return Keeper{
		store: store,
	}
}

func (k *Keeper) UpsertAccrual(record types.RewardAccrual) {
	_ = k.UpsertAccrualWithError(record)
}

func (k *Keeper) UpsertAccrualWithError(record types.RewardAccrual) error {
	normalized := normalizeAccrual(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertAccrualLocked(normalized)
}

// CreateAccrual inserts an accrual with idempotency semantics keyed by AccrualID.
func (k *Keeper) CreateAccrual(record types.RewardAccrual) (types.RewardAccrual, error) {
	normalized := normalizeAccrual(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.RewardAccrual{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetAccrual(normalized.AccrualID)
	if ok {
		normalizedExisting := normalizeAccrual(existing)
		if !accrualRecordsEqual(normalizedExisting, normalized) {
			if accrualImmutableFieldsEqual(normalizedExisting, normalized) &&
				accrualStateCanSatisfyReplay(normalizedExisting.OperationState, normalized.OperationState) {
				// Replays may arrive after distribution/finality has advanced the
				// accrual state. Treat them as idempotent without downgrading state.
				return normalizedExisting, nil
			}
			return types.RewardAccrual{}, conflictError("accrual", normalized.AccrualID)
		}
		// Normalize legacy records persisted via compatibility upserts.
		if err := k.upsertAccrualLocked(normalizedExisting); err != nil {
			return types.RewardAccrual{}, err
		}
		return normalizedExisting, nil
	}

	if duplicate, found, err := k.accrualByProviderWeeklyEpochLocked(normalized); err != nil {
		return types.RewardAccrual{}, err
	} else if found {
		return types.RewardAccrual{}, providerWeeklyEpochConflictError(normalized, duplicate)
	}

	if err := k.upsertAccrualLocked(normalized); err != nil {
		return types.RewardAccrual{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetAccrual(accrualID string) (types.RewardAccrual, bool) {
	normalizedID := normalizeAccrual(types.RewardAccrual{AccrualID: accrualID}).AccrualID

	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetAccrual(normalizedID)
	if !ok {
		return types.RewardAccrual{}, false
	}
	return normalizeAccrual(record), true
}

// ListAccruals returns all accrual records ordered by accrual ID ascending.
func (k *Keeper) ListAccruals() []types.RewardAccrual {
	records, err := k.ListAccrualsWithError()
	if err != nil {
		return nil
	}
	return records
}

// ListAccrualsWithError returns all accrual records ordered by accrual ID ascending.
func (k *Keeper) ListAccrualsWithError() ([]types.RewardAccrual, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records, err := k.listAccrualsLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i] = normalizeAccrual(records[i])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].AccrualID < records[j].AccrualID
	})
	return records, nil
}

func (k *Keeper) UpsertDistribution(record types.DistributionRecord) {
	_ = k.UpsertDistributionWithError(record)
}

func (k *Keeper) UpsertDistributionWithError(record types.DistributionRecord) error {
	normalized := normalizeDistribution(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertDistributionLocked(normalized)
}

// RecordDistribution inserts a distribution with idempotency semantics keyed by DistributionID.
func (k *Keeper) RecordDistribution(record types.DistributionRecord) (types.DistributionRecord, error) {
	return k.recordDistribution(record, false)
}

// RecordDistributionWithFinalityAuthority records a distribution or applies an
// authorized status-only finality transition from pending/submitted to a terminal
// status. All immutable distribution fields must match the original record.
func (k *Keeper) RecordDistributionWithFinalityAuthority(record types.DistributionRecord) (types.DistributionRecord, error) {
	return k.recordDistribution(record, true)
}

func (k *Keeper) recordDistribution(record types.DistributionRecord, allowFinalityAuthority bool) (types.DistributionRecord, error) {
	normalized := normalizeDistribution(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.DistributionRecord{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetDistribution(normalized.DistributionID)
	if ok {
		normalizedExisting := normalizeDistribution(existing)
		if !distributionRecordsEqual(normalizedExisting, normalized) {
			if allowFinalityAuthority && distributionFinalityTransitionAllowed(normalizedExisting, normalized) {
				accrual, accrualOK := k.store.GetAccrual(normalizedExisting.AccrualID)
				if !accrualOK {
					return types.DistributionRecord{}, accrualNotFoundError(normalizedExisting.AccrualID)
				}
				normalizedAccrual := normalizeAccrual(accrual)
				if err := k.persistDistributionWithAccrualAdvanceLocked(normalized, normalizedAccrual); err != nil {
					return types.DistributionRecord{}, err
				}
				return normalized, nil
			}
			return types.DistributionRecord{}, conflictError("distribution", normalized.DistributionID)
		}
		accrual, accrualOK := k.store.GetAccrual(normalizedExisting.AccrualID)
		if !accrualOK {
			return types.DistributionRecord{}, accrualNotFoundError(normalizedExisting.AccrualID)
		}
		normalizedAccrual := normalizeAccrual(accrual)
		// Normalize legacy records persisted via compatibility upserts.
		if err := k.persistDistributionWithAccrualAdvanceLocked(normalizedExisting, normalizedAccrual); err != nil {
			return types.DistributionRecord{}, err
		}
		return normalizedExisting, nil
	}

	accrual, accrualOK := k.store.GetAccrual(normalized.AccrualID)
	if !accrualOK {
		return types.DistributionRecord{}, accrualNotFoundError(normalized.AccrualID)
	}
	if byAccrual, found, err := k.distributionByAccrualLocked(normalized.AccrualID); err != nil {
		return types.DistributionRecord{}, err
	} else if found && byAccrual.DistributionID != normalized.DistributionID {
		return types.DistributionRecord{}, conflictError("distribution accrual_id", normalized.AccrualID)
	}
	if distributionStatusIsTerminal(normalized.Status) && !allowFinalityAuthority {
		return types.DistributionRecord{}, fmt.Errorf("distribution status %q requires finality authority", normalized.Status)
	}

	if err := k.persistDistributionWithAccrualAdvanceLocked(normalized, normalizeAccrual(accrual)); err != nil {
		return types.DistributionRecord{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetDistribution(distributionID string) (types.DistributionRecord, bool) {
	normalizedID := normalizeDistribution(types.DistributionRecord{DistributionID: distributionID}).DistributionID

	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetDistribution(normalizedID)
	if !ok {
		return types.DistributionRecord{}, false
	}
	return normalizeDistribution(record), true
}

// ListDistributions returns all distribution records ordered by distribution ID ascending.
func (k *Keeper) ListDistributions() []types.DistributionRecord {
	records, err := k.ListDistributionsWithError()
	if err != nil {
		return nil
	}
	return records
}

// ListDistributionsWithError returns all distribution records ordered by distribution ID ascending.
func (k *Keeper) ListDistributionsWithError() ([]types.DistributionRecord, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records, err := k.listDistributionsLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i] = normalizeDistribution(records[i])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].DistributionID < records[j].DistributionID
	})
	return records, nil
}

func (k *Keeper) UpsertProof(record types.RewardProofRecord) {
	_ = k.UpsertProofWithError(record)
}

func (k *Keeper) UpsertProofWithError(record types.RewardProofRecord) error {
	normalized := normalizeProof(record)
	if err := normalized.ValidateBasic(); err != nil {
		return err
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertProofLocked(normalized)
}

func (k *Keeper) GetProof(proofPath string) (types.RewardProofRecord, bool) {
	normalizedPath := normalizeProof(types.RewardProofRecord{ProofPath: proofPath}).ProofPath
	if normalizedPath == "" {
		return types.RewardProofRecord{}, false
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	proofStore, ok := k.store.(KeeperProofStore)
	if !ok {
		return types.RewardProofRecord{}, false
	}
	record, found := proofStore.GetProof(normalizedPath)
	if !found {
		return types.RewardProofRecord{}, false
	}
	return normalizeProof(record), true
}

func (k *Keeper) GetVerifiedProof(proofPath string) (types.RewardProofRecord, bool) {
	record, ok := k.GetProof(proofPath)
	if !ok {
		return types.RewardProofRecord{}, false
	}
	if err := record.ValidateVerified(); err != nil {
		return types.RewardProofRecord{}, false
	}
	return normalizeProof(record), true
}

func (k *Keeper) ListProofs() []types.RewardProofRecord {
	records, err := k.ListProofsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (k *Keeper) ListProofsWithError() ([]types.RewardProofRecord, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records, err := k.listProofsLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i] = normalizeProof(records[i])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].ProofPath < records[j].ProofPath
	})
	return records, nil
}

func (k *Keeper) persistDistributionWithAccrualAdvanceLocked(
	distribution types.DistributionRecord,
	accrualBefore types.RewardAccrual,
) error {
	accrualAfter := advanceAccrualStateForDistribution(accrualBefore, distribution)

	if atomicWriter, ok := k.store.(distributionAccrualAtomicWriter); ok {
		if err := atomicWriter.UpsertDistributionWithAccrualWithError(distribution, accrualAfter); err != nil {
			return fmt.Errorf(
				"persist distribution %q with accrual %q advance: %w",
				distribution.DistributionID,
				accrualAfter.AccrualID,
				err,
			)
		}
		return nil
	}

	accrualChanged := !accrualRecordsEqual(accrualBefore, accrualAfter)

	if accrualChanged {
		if err := k.upsertAccrualLocked(accrualAfter); err != nil {
			return err
		}
	}

	if err := k.upsertDistributionLocked(distribution); err != nil {
		if accrualChanged {
			if rollbackErr := k.upsertAccrualLocked(accrualBefore); rollbackErr != nil {
				return fmt.Errorf("%w; rollback accrual %q failed: %v", err, accrualBefore.AccrualID, rollbackErr)
			}
		}
		return err
	}
	return nil
}

func advanceAccrualStateForDistribution(record types.RewardAccrual, distribution types.DistributionRecord) types.RewardAccrual {
	normalized := normalizeAccrual(record)
	normalizedDistribution := normalizeDistribution(distribution)

	switch normalizedDistribution.Status {
	case chaintypes.ReconciliationConfirmed, chaintypes.ReconciliationFailed:
		normalized.OperationState = normalizedDistribution.Status
	case chaintypes.ReconciliationSubmitted:
		if normalized.OperationState == chaintypes.ReconciliationPending {
			normalized.OperationState = chaintypes.ReconciliationSubmitted
		}
	}
	return normalized
}

func (k *Keeper) upsertProofLocked(record types.RewardProofRecord) error {
	proofStore, ok := k.store.(KeeperProofStore)
	if !ok {
		return errors.New("proof store is not supported")
	}

	if existing, found := proofStore.GetProof(record.ProofPath); found {
		normalizedExisting := normalizeProof(existing)
		if !proofRecordsEqual(normalizedExisting, record) {
			return conflictError("proof", record.ProofPath)
		}
		record = normalizedExisting
	}

	if writeAwareStore, ok := k.store.(KeeperProofStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertProofWithError(record); err != nil {
			return fmt.Errorf("persist proof %q: %w", record.ProofPath, err)
		}
		return nil
	}

	proofStore.UpsertProof(record)
	return nil
}

func (k *Keeper) upsertAccrualLocked(record types.RewardAccrual) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertAccrualWithError(record); err != nil {
			return fmt.Errorf("persist accrual %q: %w", record.AccrualID, err)
		}
		return nil
	}

	k.store.UpsertAccrual(record)
	return nil
}

func (k *Keeper) upsertDistributionLocked(record types.DistributionRecord) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertDistributionWithError(record); err != nil {
			return fmt.Errorf("persist distribution %q: %w", record.DistributionID, err)
		}
		return nil
	}

	k.store.UpsertDistribution(record)
	return nil
}

func normalizeAccrual(record types.RewardAccrual) types.RewardAccrual {
	normalized := record.Canonicalize()
	if normalized.OperationState == "" {
		normalized.OperationState = chaintypes.ReconciliationPending
	}
	return normalized
}

func normalizeDistribution(record types.DistributionRecord) types.DistributionRecord {
	normalized := record.Canonicalize()
	if normalized.Status == "" {
		normalized.Status = chaintypes.ReconciliationSubmitted
	}
	return normalized
}

func normalizeProof(record types.RewardProofRecord) types.RewardProofRecord {
	return record.Canonicalize()
}

func accrualRecordsEqual(a, b types.RewardAccrual) bool {
	return a.AccrualID == b.AccrualID &&
		a.SessionID == b.SessionID &&
		a.ProviderID == b.ProviderID &&
		a.AssetDenom == b.AssetDenom &&
		a.Amount == b.Amount &&
		a.AccruedAtUnix == b.AccruedAtUnix &&
		a.PayoutStartUnix == b.PayoutStartUnix &&
		a.PayoutEndUnix == b.PayoutEndUnix &&
		a.OperationState == b.OperationState
}

func distributionRecordsEqual(a, b types.DistributionRecord) bool {
	return a.DistributionID == b.DistributionID &&
		a.AccrualID == b.AccrualID &&
		a.PayoutRef == b.PayoutRef &&
		a.DistributedAt == b.DistributedAt &&
		a.Status == b.Status
}

func accrualImmutableFieldsEqual(a, b types.RewardAccrual) bool {
	return a.AccrualID == b.AccrualID &&
		a.SessionID == b.SessionID &&
		a.ProviderID == b.ProviderID &&
		a.AssetDenom == b.AssetDenom &&
		a.Amount == b.Amount &&
		a.AccruedAtUnix == b.AccruedAtUnix &&
		a.PayoutStartUnix == b.PayoutStartUnix &&
		a.PayoutEndUnix == b.PayoutEndUnix
}

func accrualStateCanSatisfyReplay(existing chaintypes.ReconciliationStatus, incoming chaintypes.ReconciliationStatus) bool {
	existing = chaintypes.ReconciliationStatus(strings.ToLower(strings.TrimSpace(string(existing))))
	incoming = chaintypes.ReconciliationStatus(strings.ToLower(strings.TrimSpace(string(incoming))))
	if existing == incoming {
		return true
	}
	switch incoming {
	case "", chaintypes.ReconciliationPending:
		return existing == chaintypes.ReconciliationSubmitted ||
			existing == chaintypes.ReconciliationConfirmed ||
			existing == chaintypes.ReconciliationFailed
	case chaintypes.ReconciliationSubmitted:
		return existing == chaintypes.ReconciliationConfirmed ||
			existing == chaintypes.ReconciliationFailed
	default:
		return false
	}
}

func distributionImmutableFieldsEqual(a, b types.DistributionRecord) bool {
	return a.DistributionID == b.DistributionID &&
		a.AccrualID == b.AccrualID &&
		a.PayoutRef == b.PayoutRef &&
		a.DistributedAt == b.DistributedAt
}

func distributionFinalityTransitionAllowed(existing, next types.DistributionRecord) bool {
	if !distributionImmutableFieldsEqual(existing, next) {
		return false
	}
	if !distributionStatusIsTerminal(next.Status) {
		return false
	}
	switch existing.Status {
	case chaintypes.ReconciliationPending, chaintypes.ReconciliationSubmitted:
		return true
	default:
		return false
	}
}

func distributionStatusIsTerminal(status chaintypes.ReconciliationStatus) bool {
	switch status {
	case chaintypes.ReconciliationConfirmed, chaintypes.ReconciliationFailed:
		return true
	default:
		return false
	}
}

func proofRecordsEqual(a, b types.RewardProofRecord) bool {
	return a.ProofPath == b.ProofPath &&
		a.TrafficProofRef == b.TrafficProofRef &&
		a.TrustContract == b.TrustContract &&
		a.RewardID == b.RewardID &&
		a.ProviderSubjectID == b.ProviderSubjectID &&
		a.SessionID == b.SessionID &&
		a.PayoutStartUnix == b.PayoutStartUnix &&
		a.PayoutEndUnix == b.PayoutEndUnix &&
		a.RewardMicros == b.RewardMicros &&
		a.Currency == b.Currency &&
		a.IssuedAtUnix == b.IssuedAtUnix &&
		a.Verified == b.Verified &&
		a.VerifierID == b.VerifierID &&
		a.VerifiedAtUnix == b.VerifiedAtUnix
}

func (k *Keeper) distributionByAccrualLocked(accrualID string) (types.DistributionRecord, bool, error) {
	accrualID = strings.TrimSpace(accrualID)
	if accrualID == "" {
		return types.DistributionRecord{}, false, nil
	}
	records, err := k.listDistributionsLocked()
	if err != nil {
		return types.DistributionRecord{}, false, err
	}
	for _, record := range records {
		normalized := normalizeDistribution(record)
		if normalized.AccrualID == accrualID {
			return normalized, true, nil
		}
	}
	return types.DistributionRecord{}, false, nil
}

func (k *Keeper) accrualByProviderWeeklyEpochLocked(record types.RewardAccrual) (types.RewardAccrual, bool, error) {
	record = normalizeAccrual(record)
	if record.ProviderID == "" {
		return types.RewardAccrual{}, false, nil
	}

	records, err := k.listAccrualsLocked()
	if err != nil {
		return types.RewardAccrual{}, false, err
	}
	for _, existing := range records {
		normalized := normalizeAccrual(existing)
		if normalized.AccrualID == record.AccrualID || normalized.ProviderID != record.ProviderID {
			continue
		}
		if accrualsConflictOnWeeklyPayoutPeriod(record, normalized) {
			return normalized, true, nil
		}
	}
	return types.RewardAccrual{}, false, nil
}

func (k *Keeper) listAccrualsLocked() ([]types.RewardAccrual, error) {
	if readAwareStore, ok := k.store.(KeeperStoreWithReadErrors); ok {
		records, err := readAwareStore.ListAccrualsWithError()
		if err != nil {
			return nil, fmt.Errorf("load accruals: %w", err)
		}
		return records, nil
	}
	return k.store.ListAccruals(), nil
}

func (k *Keeper) listDistributionsLocked() ([]types.DistributionRecord, error) {
	if readAwareStore, ok := k.store.(KeeperStoreWithReadErrors); ok {
		records, err := readAwareStore.ListDistributionsWithError()
		if err != nil {
			return nil, fmt.Errorf("load distributions: %w", err)
		}
		return records, nil
	}
	return k.store.ListDistributions(), nil
}

func (k *Keeper) listProofsLocked() ([]types.RewardProofRecord, error) {
	proofStore, ok := k.store.(KeeperProofStore)
	if !ok {
		return nil, nil
	}
	if readAwareStore, ok := k.store.(KeeperProofStoreWithReadErrors); ok {
		records, err := readAwareStore.ListProofsWithError()
		if err != nil {
			return nil, fmt.Errorf("load proofs: %w", err)
		}
		return records, nil
	}
	return proofStore.ListProofs(), nil
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func providerWeeklyEpochConflictError(record types.RewardAccrual, existing types.RewardAccrual) error {
	return fmt.Errorf(
		"accrual provider %q weekly epoch already exists with conflicting fields: existing_accrual_id=%q existing_period=%s new_accrual_id=%q new_period=%s",
		record.ProviderID,
		existing.AccrualID,
		weeklyPayoutPeriodDescription(existing),
		record.AccrualID,
		weeklyPayoutPeriodDescription(record),
	)
}

func weeklyPayoutEpoch(record types.RewardAccrual) (int64, bool) {
	period, ok := weeklyPayoutPeriod(record)
	if !ok {
		return 0, false
	}
	return period.epoch, true
}

func weeklyEpoch(unixSeconds int64) (int64, bool) {
	if unixSeconds <= 0 {
		return 0, false
	}
	return (unixSeconds + weeklyEpochMondayOffsetSeconds) / weeklyEpochSeconds, true
}

type payoutPeriodIdentity struct {
	startUnix int64
	endUnix   int64
	epoch     int64
}

func weeklyPayoutPeriod(record types.RewardAccrual) (payoutPeriodIdentity, bool) {
	record = normalizeAccrual(record)
	if record.PayoutStartUnix <= 0 || record.PayoutEndUnix <= 0 {
		return payoutPeriodIdentity{}, false
	}
	if record.PayoutEndUnix-record.PayoutStartUnix != weeklyEpochSeconds {
		return payoutPeriodIdentity{}, false
	}
	epoch, ok := weeklyEpoch(record.PayoutStartUnix)
	if !ok {
		return payoutPeriodIdentity{}, false
	}
	return payoutPeriodIdentity{
		startUnix: record.PayoutStartUnix,
		endUnix:   record.PayoutEndUnix,
		epoch:     epoch,
	}, true
}

func accrualsConflictOnWeeklyPayoutPeriod(candidate types.RewardAccrual, existing types.RewardAccrual) bool {
	candidatePeriod, candidateHasPeriod := weeklyPayoutPeriod(candidate)
	existingPeriod, existingHasPeriod := weeklyPayoutPeriod(existing)

	if candidateHasPeriod && existingHasPeriod {
		return candidatePeriod.startUnix == existingPeriod.startUnix &&
			candidatePeriod.endUnix == existingPeriod.endUnix
	}

	// Once a provider has explicit weekly payout accounting, an omitted period
	// cannot prove it is outside that accounting window and must fail closed.
	return candidateHasPeriod != existingHasPeriod
}

func weeklyPayoutPeriodDescription(record types.RewardAccrual) string {
	period, ok := weeklyPayoutPeriod(record)
	if !ok {
		return "missing"
	}
	return fmt.Sprintf("%d-%d", period.startUnix, period.endUnix)
}

func accrualNotFoundError(accrualID string) error {
	return fmt.Errorf("accrual %q not found", accrualID)
}
