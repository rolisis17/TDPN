package keeper

import (
	"fmt"
	"slices"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

// Keeper defaults to in-memory storage and accepts pluggable stores (file-backed/KV adapters).
type Keeper struct {
	mu    sync.RWMutex
	store KeeperStore
}

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

func (k *Keeper) UpsertReservation(record types.CreditReservation) {
	_ = k.UpsertReservationWithError(record)
}

func (k *Keeper) UpsertReservationWithError(record types.CreditReservation) error {
	normalized := normalizeReservation(record)
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertReservationLocked(normalized)
}

// CreateReservation inserts a reservation with idempotency semantics keyed by ReservationID.
func (k *Keeper) CreateReservation(record types.CreditReservation) (types.CreditReservation, error) {
	normalized := normalizeReservation(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.CreditReservation{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetReservation(normalized.ReservationID)
	if ok {
		normalizedExisting := normalizeReservation(existing)
		if !reservationRecordsEqual(normalizedExisting, normalized) {
			return types.CreditReservation{}, conflictError("reservation", normalized.ReservationID)
		}
		// Normalize legacy records persisted via compatibility upserts.
		if err := k.upsertReservationLocked(normalizedExisting); err != nil {
			return types.CreditReservation{}, err
		}
		return normalizedExisting, nil
	}
	if existingByBusinessKey, found, err := k.reservationByBusinessKeyLocked(normalized.SessionID, normalized.SponsorID, normalized.AssetDenom); err != nil {
		return types.CreditReservation{}, err
	} else if found {
		if existingByBusinessKey.ReservationID == normalized.ReservationID {
			if err := k.upsertReservationLocked(existingByBusinessKey); err != nil {
				return types.CreditReservation{}, err
			}
			return existingByBusinessKey, nil
		}
		return types.CreditReservation{}, reservationBusinessKeyConflictError(normalized, existingByBusinessKey.ReservationID)
	}

	if err := k.upsertReservationLocked(normalized); err != nil {
		return types.CreditReservation{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetReservation(reservationID string) (types.CreditReservation, bool) {
	normalizedReservationID := normalizeReservation(types.CreditReservation{ReservationID: reservationID}).ReservationID

	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetReservation(normalizedReservationID)
	if !ok {
		return types.CreditReservation{}, false
	}
	return normalizeReservation(record), true
}

func (k *Keeper) ListReservations() []types.CreditReservation {
	records, err := k.ListReservationsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (k *Keeper) ListReservationsWithError() ([]types.CreditReservation, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records, err := k.listReservationsLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i] = normalizeReservation(records[i])
	}
	slices.SortFunc(records, func(a, b types.CreditReservation) int {
		return compareByID(a.ReservationID, b.ReservationID)
	})
	return records, nil
}

func (k *Keeper) UpsertSettlement(record types.SettlementRecord) {
	_ = k.UpsertSettlementWithError(record)
}

func (k *Keeper) UpsertSettlementWithError(record types.SettlementRecord) error {
	normalized := normalizeSettlement(record)
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertSettlementLocked(normalized)
}

// FinalizeSettlement inserts a settlement with idempotency semantics keyed by SettlementID.
func (k *Keeper) FinalizeSettlement(record types.SettlementRecord) (types.SettlementRecord, error) {
	normalized := normalizeSettlement(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.SettlementRecord{}, err
	}

	if normalized.ReservationID == "" {
		return types.SettlementRecord{}, reservationIDRequiredError()
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	reservation, ok := k.store.GetReservation(normalized.ReservationID)
	if !ok {
		return types.SettlementRecord{}, reservationNotFoundError(normalized.ReservationID)
	}
	normalizedReservation := normalizeReservation(reservation)
	if normalized.SessionID != normalizedReservation.SessionID {
		return types.SettlementRecord{}, sessionMismatchError(normalized.SessionID, normalizedReservation.SessionID)
	}
	if normalized.AssetDenom != normalizedReservation.AssetDenom {
		return types.SettlementRecord{}, assetDenomMismatchError(normalized.AssetDenom, normalizedReservation.AssetDenom)
	}
	if normalized.BilledAmount > normalizedReservation.Amount {
		return types.SettlementRecord{}, overchargeError(normalized.BilledAmount, normalizedReservation.Amount)
	}

	existing, ok := k.store.GetSettlement(normalized.SettlementID)
	if ok {
		normalizedExisting := normalizeSettlement(existing)
		if !settlementRecordsEqual(normalizedExisting, normalized) {
			return types.SettlementRecord{}, conflictError("settlement", normalized.SettlementID)
		}

		updatedReservation := reservationAfterSettlement(normalizedReservation)
		if err := k.persistFinalizedSettlementLocked(normalizedExisting, normalizedReservation, updatedReservation); err != nil {
			return types.SettlementRecord{}, err
		}
		return normalizedExisting, nil
	}
	settlements, err := k.listSettlementsLocked()
	if err != nil {
		return types.SettlementRecord{}, err
	}
	for _, existingSettlement := range settlements {
		normalizedExistingSettlement := normalizeSettlement(existingSettlement)
		if normalizedExistingSettlement.ReservationID == normalized.ReservationID &&
			normalizedExistingSettlement.SettlementID != normalized.SettlementID {
			return types.SettlementRecord{}, reservationAlreadySettledError(normalized.ReservationID, normalizedExistingSettlement.SettlementID)
		}
		if normalizedExistingSettlement.SettlementID == normalized.SettlementID {
			continue
		}
		existingReservationForSettlement, found := k.store.GetReservation(normalizedExistingSettlement.ReservationID)
		if !found {
			continue
		}
		normalizedExistingReservation := normalizeReservation(existingReservationForSettlement)
		if reservationBusinessKeyEqual(normalizedExistingReservation, normalizedReservation) &&
			normalizedExistingReservation.ReservationID != normalizedReservation.ReservationID {
			return types.SettlementRecord{}, reservationBusinessKeyAlreadySettledError(
				normalizedReservation,
				normalizedExistingReservation.ReservationID,
				normalizedExistingSettlement.SettlementID,
			)
		}
	}

	updatedReservation := reservationAfterSettlement(normalizedReservation)
	if err := k.persistFinalizedSettlementLocked(normalized, normalizedReservation, updatedReservation); err != nil {
		return types.SettlementRecord{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetSettlement(settlementID string) (types.SettlementRecord, bool) {
	normalizedSettlementID := normalizeSettlement(types.SettlementRecord{SettlementID: settlementID}).SettlementID

	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetSettlement(normalizedSettlementID)
	if !ok {
		return types.SettlementRecord{}, false
	}
	return normalizeSettlement(record), true
}

func (k *Keeper) ListSettlements() []types.SettlementRecord {
	records, err := k.ListSettlementsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (k *Keeper) ListSettlementsWithError() ([]types.SettlementRecord, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records, err := k.listSettlementsLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i] = normalizeSettlement(records[i])
	}
	slices.SortFunc(records, func(a, b types.SettlementRecord) int {
		return compareByID(a.SettlementID, b.SettlementID)
	})
	return records, nil
}

func reservationAfterSettlement(record types.CreditReservation) types.CreditReservation {
	normalized := normalizeReservation(record)
	if normalized.Status == chaintypes.ReconciliationPending || normalized.Status == chaintypes.ReconciliationSubmitted {
		normalized.Status = chaintypes.ReconciliationConfirmed
	}
	return normalized
}

func (k *Keeper) upsertReservationLocked(record types.CreditReservation) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertReservationWithError(record); err != nil {
			return fmt.Errorf("persist reservation %q: %w", record.ReservationID, err)
		}
		return nil
	}

	k.store.UpsertReservation(record)
	return nil
}

func (k *Keeper) upsertSettlementLocked(record types.SettlementRecord) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertSettlementWithError(record); err != nil {
			return fmt.Errorf("persist settlement %q: %w", record.SettlementID, err)
		}
		return nil
	}

	k.store.UpsertSettlement(record)
	return nil
}

func (k *Keeper) persistFinalizedSettlementLocked(
	settlement types.SettlementRecord,
	previousReservation types.CreditReservation,
	updatedReservation types.CreditReservation,
) error {
	if atomicStore, ok := k.store.(KeeperStoreWithAtomicFinalize); ok {
		if err := atomicStore.UpsertSettlementAndAdvanceReservationWithError(settlement, updatedReservation); err != nil {
			return fmt.Errorf("persist settlement %q: %w", settlement.SettlementID, err)
		}
		return nil
	}

	reservationChanged := !reservationRecordsEqual(previousReservation, updatedReservation)
	if reservationChanged {
		if err := k.upsertReservationLocked(updatedReservation); err != nil {
			return err
		}
	}

	if err := k.upsertSettlementLocked(settlement); err != nil {
		if reservationChanged {
			if rollbackErr := k.upsertReservationLocked(previousReservation); rollbackErr != nil {
				return fmt.Errorf(
					"persist settlement %q failed: %v (rollback reservation %q failed: %w)",
					settlement.SettlementID,
					err,
					previousReservation.ReservationID,
					rollbackErr,
				)
			}
		}
		return err
	}

	return nil
}

func normalizeReservation(record types.CreditReservation) types.CreditReservation {
	record = record.Canonicalize()
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeSettlement(record types.SettlementRecord) types.SettlementRecord {
	record = record.Canonicalize()
	if record.OperationState == "" {
		record.OperationState = chaintypes.ReconciliationSubmitted
	}
	return record
}

func reservationRecordsEqual(a, b types.CreditReservation) bool {
	return a.ReservationID == b.ReservationID &&
		a.SponsorID == b.SponsorID &&
		a.SessionID == b.SessionID &&
		a.AssetDenom == b.AssetDenom &&
		a.Amount == b.Amount &&
		a.Status == b.Status &&
		a.CreatedAtUnix == b.CreatedAtUnix
}

func reservationBusinessKeyEqual(a, b types.CreditReservation) bool {
	return a.SessionID == b.SessionID &&
		a.SponsorID == b.SponsorID &&
		a.AssetDenom == b.AssetDenom
}

func settlementRecordsEqual(a, b types.SettlementRecord) bool {
	return a.SettlementID == b.SettlementID &&
		a.ReservationID == b.ReservationID &&
		a.SessionID == b.SessionID &&
		a.BilledAmount == b.BilledAmount &&
		a.UsageBytes == b.UsageBytes &&
		a.AssetDenom == b.AssetDenom &&
		a.SettledAtUnix == b.SettledAtUnix &&
		a.OperationState == b.OperationState
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func reservationIDRequiredError() error {
	return fmt.Errorf("reservation id is required")
}

func reservationNotFoundError(reservationID string) error {
	return fmt.Errorf("reservation %q not found", reservationID)
}

func sessionMismatchError(settlementSessionID, reservationSessionID string) error {
	return fmt.Errorf("settlement session %q does not match reservation session %q", settlementSessionID, reservationSessionID)
}

func assetDenomMismatchError(settlementAssetDenom, reservationAssetDenom string) error {
	return fmt.Errorf("settlement asset denom %q does not match reservation asset denom %q", settlementAssetDenom, reservationAssetDenom)
}

func overchargeError(billedAmount, reservedAmount int64) error {
	return fmt.Errorf("billed amount %d exceeds reserved amount %d", billedAmount, reservedAmount)
}

func reservationAlreadySettledError(reservationID, settlementID string) error {
	return fmt.Errorf("reservation %q already settled by settlement %q", reservationID, settlementID)
}

func reservationBusinessKeyConflictError(record types.CreditReservation, existingReservationID string) error {
	return fmt.Errorf(
		"reservation business key %q already exists with conflicting fields (existing reservation %q)",
		reservationBusinessKeyID(record.SessionID, record.SponsorID, record.AssetDenom),
		existingReservationID,
	)
}

func reservationBusinessKeyAlreadySettledError(
	record types.CreditReservation,
	existingReservationID string,
	settlementID string,
) error {
	return fmt.Errorf(
		"reservation business key %q already settled by settlement %q (reservation %q)",
		reservationBusinessKeyID(record.SessionID, record.SponsorID, record.AssetDenom),
		settlementID,
		existingReservationID,
	)
}

func reservationBusinessKeyID(sessionID, sponsorID, assetDenom string) string {
	return fmt.Sprintf("session=%q sponsor=%q asset=%q", sessionID, sponsorID, assetDenom)
}

func (k *Keeper) reservationByBusinessKeyLocked(sessionID, sponsorID, assetDenom string) (types.CreditReservation, bool, error) {
	reservations, err := k.listReservationsLocked()
	if err != nil {
		return types.CreditReservation{}, false, err
	}
	for _, existingReservation := range reservations {
		normalizedExisting := normalizeReservation(existingReservation)
		if normalizedExisting.SessionID != sessionID ||
			normalizedExisting.SponsorID != sponsorID ||
			normalizedExisting.AssetDenom != assetDenom {
			continue
		}
		return normalizedExisting, true, nil
	}
	return types.CreditReservation{}, false, nil
}

func (k *Keeper) listReservationsLocked() ([]types.CreditReservation, error) {
	if readAwareStore, ok := k.store.(KeeperStoreWithReadErrors); ok {
		records, err := readAwareStore.ListReservationsWithError()
		if err != nil {
			return nil, fmt.Errorf("load reservations: %w", err)
		}
		return records, nil
	}
	return k.store.ListReservations(), nil
}

func (k *Keeper) listSettlementsLocked() ([]types.SettlementRecord, error) {
	if readAwareStore, ok := k.store.(KeeperStoreWithReadErrors); ok {
		records, err := readAwareStore.ListSettlementsWithError()
		if err != nil {
			return nil, fmt.Errorf("load settlements: %w", err)
		}
		return records, nil
	}
	return k.store.ListSettlements(), nil
}

func compareByID(a, b string) int {
	if a == b {
		return 0
	}
	if a < b {
		return -1
	}
	return 1
}
