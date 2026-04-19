package keeper

import (
	"fmt"
	"math"
	"sort"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
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

func (k *Keeper) UpsertAuthorization(record types.SponsorAuthorization) {
	_ = k.UpsertAuthorizationWithError(record)
}

func (k *Keeper) UpsertAuthorizationWithError(record types.SponsorAuthorization) error {
	record = normalizeAuthorization(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertAuthorizationLocked(record)
}

// CreateAuthorization inserts an authorization with idempotency semantics keyed by AuthorizationID.
func (k *Keeper) CreateAuthorization(record types.SponsorAuthorization) (types.SponsorAuthorization, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.SponsorAuthorization{}, err
	}

	normalized := normalizeAuthorization(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetAuthorization(normalized.AuthorizationID)
	if ok {
		normalizedExisting := normalizeAuthorization(existing)
		if !authorizationRecordsEqual(normalizedExisting, normalized) {
			return types.SponsorAuthorization{}, conflictError("authorization", normalized.AuthorizationID)
		}
		// Normalize legacy records persisted via compatibility upserts.
		if err := k.upsertAuthorizationLocked(normalizedExisting); err != nil {
			return types.SponsorAuthorization{}, err
		}
		return normalizedExisting, nil
	}
	if compatibilityRecord, found := k.authorizationByCanonicalIDLocked(normalized.AuthorizationID); found {
		if !authorizationRecordsEqual(compatibilityRecord, normalized) {
			return types.SponsorAuthorization{}, conflictError("authorization", normalized.AuthorizationID)
		}
		return compatibilityRecord, nil
	}

	if err := k.upsertAuthorizationLocked(normalized); err != nil {
		return types.SponsorAuthorization{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetAuthorization(authID string) (types.SponsorAuthorization, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetAuthorization(authID)
	if ok {
		return normalizeAuthorization(record), true
	}

	canonicalAuthID := canonicalAuthorizationID(authID)
	if canonicalAuthID == authID {
		return types.SponsorAuthorization{}, false
	}
	record, ok = k.store.GetAuthorization(canonicalAuthID)
	if !ok {
		return types.SponsorAuthorization{}, false
	}
	return normalizeAuthorization(record), true
}

func (k *Keeper) ListAuthorizations() []types.SponsorAuthorization {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := append([]types.SponsorAuthorization(nil), k.store.ListAuthorizations()...)
	for i := range records {
		records[i] = normalizeAuthorization(records[i])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].AuthorizationID < records[j].AuthorizationID
	})
	return records
}

func (k *Keeper) UpsertDelegation(record types.DelegatedSessionCredit) {
	_ = k.UpsertDelegationWithError(record)
}

func (k *Keeper) UpsertDelegationWithError(record types.DelegatedSessionCredit) error {
	record = normalizeDelegation(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertDelegationLocked(record)
}

// DelegateSessionCredit inserts delegated credits with idempotency semantics keyed by ReservationID.
func (k *Keeper) DelegateSessionCredit(record types.DelegatedSessionCredit) (types.DelegatedSessionCredit, error) {
	return k.DelegateSessionCreditAtUnix(record, 0)
}

// DelegateSessionCreditAtUnix inserts delegated credits with idempotency semantics keyed by ReservationID.
// currentTimeUnix is required for deterministic expiry checks when authorizations have ExpiresAtUnix set.
func (k *Keeper) DelegateSessionCreditAtUnix(record types.DelegatedSessionCredit, currentTimeUnix int64) (types.DelegatedSessionCredit, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.DelegatedSessionCredit{}, err
	}

	normalized := normalizeDelegation(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	authorization, ok := k.store.GetAuthorization(normalized.AuthorizationID)
	if !ok {
		if compatibilityAuthorization, found := k.authorizationByCanonicalIDLocked(normalized.AuthorizationID); found {
			authorization = compatibilityAuthorization
			ok = true
		}
	}
	if !ok {
		return types.DelegatedSessionCredit{}, authorizationNotFoundError(normalized.AuthorizationID)
	}
	normalizedAuthorization := normalizeAuthorization(authorization)
	if !authorizationRecordsEqual(authorization, normalizedAuthorization) {
		// Normalize legacy records persisted via compatibility upserts.
		if err := k.upsertAuthorizationLocked(normalizedAuthorization); err != nil {
			return types.DelegatedSessionCredit{}, err
		}
	}
	authorization = normalizedAuthorization
	if authorization.SponsorID != normalized.SponsorID || authorization.AppID != normalized.AppID {
		return types.DelegatedSessionCredit{}, authorizationLinkageMismatchError(normalized.AuthorizationID)
	}
	if authorization.ExpiresAtUnix > 0 {
		if currentTimeUnix <= 0 {
			return types.DelegatedSessionCredit{}, authorizationCurrentTimeRequiredError(normalized.AuthorizationID)
		}
		if authorization.ExpiresAtUnix <= currentTimeUnix {
			return types.DelegatedSessionCredit{}, authorizationExpiredError(normalized.AuthorizationID)
		}
	}

	existing, ok := k.store.GetDelegation(normalized.ReservationID)
	if ok {
		normalizedExisting := normalizeDelegation(existing)
		if !delegationRecordsEqual(normalizedExisting, normalized) {
			return types.DelegatedSessionCredit{}, conflictError("delegation", normalized.ReservationID)
		}
		// Normalize legacy records persisted via compatibility upserts.
		if err := k.upsertDelegationLocked(normalizedExisting); err != nil {
			return types.DelegatedSessionCredit{}, err
		}
		return normalizedExisting, nil
	}
	if compatibilityDelegation, found := k.delegationByCanonicalIDLocked(normalized.ReservationID); found {
		if !delegationRecordsEqual(compatibilityDelegation, normalized) {
			return types.DelegatedSessionCredit{}, conflictError("delegation", normalized.ReservationID)
		}
		return compatibilityDelegation, nil
	}
	delegatedCredits, overflowed := delegatedCreditsByAuthorization(k.store.ListDelegations(), normalized.AuthorizationID)
	if overflowed {
		return types.DelegatedSessionCredit{}, authorizationCreditsExceededError(normalized.AuthorizationID, authorization.MaxCredits)
	}
	projectedCredits, overflowed := checkedAddInt64(delegatedCredits, normalized.Credits)
	if overflowed || projectedCredits > authorization.MaxCredits {
		return types.DelegatedSessionCredit{}, authorizationCreditsExceededError(normalized.AuthorizationID, authorization.MaxCredits)
	}

	if err := k.upsertDelegationLocked(normalized); err != nil {
		return types.DelegatedSessionCredit{}, err
	}
	return normalized, nil
}

func (k *Keeper) upsertAuthorizationLocked(record types.SponsorAuthorization) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertAuthorizationWithError(record); err != nil {
			return fmt.Errorf("persist authorization %q: %w", record.AuthorizationID, err)
		}
		return nil
	}

	k.store.UpsertAuthorization(record)
	return nil
}

func (k *Keeper) upsertDelegationLocked(record types.DelegatedSessionCredit) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertDelegationWithError(record); err != nil {
			return fmt.Errorf("persist delegation %q: %w", record.ReservationID, err)
		}
		return nil
	}

	k.store.UpsertDelegation(record)
	return nil
}

func (k *Keeper) GetDelegation(reservationID string) (types.DelegatedSessionCredit, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetDelegation(reservationID)
	if ok {
		return normalizeDelegation(record), true
	}

	canonicalReservationID := canonicalReservationID(reservationID)
	if canonicalReservationID == reservationID {
		return types.DelegatedSessionCredit{}, false
	}
	record, ok = k.store.GetDelegation(canonicalReservationID)
	if !ok {
		return types.DelegatedSessionCredit{}, false
	}
	return normalizeDelegation(record), true
}

func (k *Keeper) ListDelegations() []types.DelegatedSessionCredit {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := append([]types.DelegatedSessionCredit(nil), k.store.ListDelegations()...)
	for i := range records {
		records[i] = normalizeDelegation(records[i])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].ReservationID < records[j].ReservationID
	})
	return records
}

func normalizeAuthorization(record types.SponsorAuthorization) types.SponsorAuthorization {
	record = types.NormalizeSponsorAuthorization(record)
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeDelegation(record types.DelegatedSessionCredit) types.DelegatedSessionCredit {
	record = types.NormalizeDelegatedSessionCredit(record)
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func authorizationRecordsEqual(a, b types.SponsorAuthorization) bool {
	return a.AuthorizationID == b.AuthorizationID &&
		a.SponsorID == b.SponsorID &&
		a.AppID == b.AppID &&
		a.MaxCredits == b.MaxCredits &&
		a.ExpiresAtUnix == b.ExpiresAtUnix &&
		a.Status == b.Status
}

func delegationRecordsEqual(a, b types.DelegatedSessionCredit) bool {
	return a.ReservationID == b.ReservationID &&
		a.AuthorizationID == b.AuthorizationID &&
		a.SponsorID == b.SponsorID &&
		a.AppID == b.AppID &&
		a.EndUserID == b.EndUserID &&
		a.SessionID == b.SessionID &&
		a.Credits == b.Credits &&
		a.Status == b.Status
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func authorizationNotFoundError(authID string) error {
	return fmt.Errorf("authorization %q not found", authID)
}

func authorizationLinkageMismatchError(authID string) error {
	return fmt.Errorf("delegation sponsor/app linkage does not match authorization %q", authID)
}

func authorizationExpiredError(authID string) error {
	return fmt.Errorf("authorization %q expired", authID)
}

func authorizationCurrentTimeRequiredError(authID string) error {
	return fmt.Errorf("authorization %q current unix time is required for expiry checks", authID)
}

func authorizationCreditsExceededError(authID string, maxCredits int64) error {
	return fmt.Errorf("authorization %q max credits exceeded (%d)", authID, maxCredits)
}

func delegatedCreditsByAuthorization(records []types.DelegatedSessionCredit, authorizationID string) (int64, bool) {
	var total int64
	normalizedAuthorizationID := normalizeDelegation(types.DelegatedSessionCredit{
		AuthorizationID: authorizationID,
	}).AuthorizationID

	for _, record := range records {
		normalizedRecord := normalizeDelegation(record)
		if normalizedRecord.AuthorizationID == normalizedAuthorizationID {
			updatedTotal, overflowed := checkedAddInt64(total, normalizedRecord.Credits)
			if overflowed {
				return 0, true
			}
			total = updatedTotal
		}
	}
	return total, false
}

func checkedAddInt64(left int64, right int64) (int64, bool) {
	if right > 0 && left > math.MaxInt64-right {
		return 0, true
	}
	if right < 0 && left < math.MinInt64-right {
		return 0, true
	}
	return left + right, false
}

func canonicalAuthorizationID(value string) string {
	return normalizeAuthorization(types.SponsorAuthorization{
		AuthorizationID: value,
	}).AuthorizationID
}

func canonicalReservationID(value string) string {
	return normalizeDelegation(types.DelegatedSessionCredit{
		ReservationID: value,
	}).ReservationID
}

func (k *Keeper) authorizationByCanonicalIDLocked(authID string) (types.SponsorAuthorization, bool) {
	canonicalAuthID := canonicalAuthorizationID(authID)
	if canonicalAuthID == "" {
		return types.SponsorAuthorization{}, false
	}
	for _, record := range k.store.ListAuthorizations() {
		normalized := normalizeAuthorization(record)
		if normalized.AuthorizationID == canonicalAuthID {
			return normalized, true
		}
	}
	return types.SponsorAuthorization{}, false
}

func (k *Keeper) delegationByCanonicalIDLocked(reservationID string) (types.DelegatedSessionCredit, bool) {
	canonicalResID := canonicalReservationID(reservationID)
	if canonicalResID == "" {
		return types.DelegatedSessionCredit{}, false
	}
	for _, record := range k.store.ListDelegations() {
		normalized := normalizeDelegation(record)
		if normalized.ReservationID == canonicalResID {
			return normalized, true
		}
	}
	return types.DelegatedSessionCredit{}, false
}
