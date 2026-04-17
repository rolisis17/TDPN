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
	normalized := normalizeReservation(record)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertReservation(normalized)
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
		k.store.UpsertReservation(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertReservation(normalized)
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
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := k.store.ListReservations()
	for i := range records {
		records[i] = normalizeReservation(records[i])
	}
	slices.SortFunc(records, func(a, b types.CreditReservation) int {
		return compareByID(a.ReservationID, b.ReservationID)
	})
	return records
}

func (k *Keeper) UpsertSettlement(record types.SettlementRecord) {
	normalized := normalizeSettlement(record)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertSettlement(normalized)
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
		// Normalize legacy records persisted via compatibility upserts.
		k.store.UpsertSettlement(normalizedExisting)
		k.advanceReservationForSettlementLocked(normalizedExisting.ReservationID)
		return normalizedExisting, nil
	}

	k.store.UpsertSettlement(normalized)
	k.advanceReservationForSettlementLocked(normalized.ReservationID)
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
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := k.store.ListSettlements()
	for i := range records {
		records[i] = normalizeSettlement(records[i])
	}
	slices.SortFunc(records, func(a, b types.SettlementRecord) int {
		return compareByID(a.SettlementID, b.SettlementID)
	})
	return records
}

func (k *Keeper) advanceReservationForSettlementLocked(reservationID string) {
	normalizedReservationID := normalizeReservation(types.CreditReservation{ReservationID: reservationID}).ReservationID
	if normalizedReservationID == "" {
		return
	}
	reservation, ok := k.store.GetReservation(normalizedReservationID)
	if !ok {
		return
	}

	normalized := normalizeReservation(reservation)
	if normalized.Status == chaintypes.ReconciliationPending || normalized.Status == chaintypes.ReconciliationSubmitted {
		normalized.Status = chaintypes.ReconciliationConfirmed
	}
	k.store.UpsertReservation(normalized)
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

func compareByID(a, b string) int {
	if a == b {
		return 0
	}
	if a < b {
		return -1
	}
	return 1
}
