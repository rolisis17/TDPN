package keeper

import (
	"fmt"
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
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertAuthorization(record)
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
		k.store.UpsertAuthorization(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertAuthorization(normalized)
	return normalized, nil
}

func (k *Keeper) GetAuthorization(authID string) (types.SponsorAuthorization, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetAuthorization(authID)
}

func (k *Keeper) ListAuthorizations() []types.SponsorAuthorization {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := append([]types.SponsorAuthorization(nil), k.store.ListAuthorizations()...)
	sort.Slice(records, func(i, j int) bool {
		return records[i].AuthorizationID < records[j].AuthorizationID
	})
	return records
}

func (k *Keeper) UpsertDelegation(record types.DelegatedSessionCredit) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertDelegation(record)
}

// DelegateSessionCredit inserts delegated credits with idempotency semantics keyed by ReservationID.
func (k *Keeper) DelegateSessionCredit(record types.DelegatedSessionCredit) (types.DelegatedSessionCredit, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.DelegatedSessionCredit{}, err
	}

	normalized := normalizeDelegation(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	if _, ok := k.store.GetAuthorization(normalized.AuthorizationID); !ok {
		return types.DelegatedSessionCredit{}, authorizationNotFoundError(normalized.AuthorizationID)
	}

	existing, ok := k.store.GetDelegation(normalized.ReservationID)
	if ok {
		normalizedExisting := normalizeDelegation(existing)
		if !delegationRecordsEqual(normalizedExisting, normalized) {
			return types.DelegatedSessionCredit{}, conflictError("delegation", normalized.ReservationID)
		}
		// Normalize legacy records persisted via compatibility upserts.
		k.store.UpsertDelegation(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertDelegation(normalized)
	return normalized, nil
}

func (k *Keeper) GetDelegation(reservationID string) (types.DelegatedSessionCredit, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetDelegation(reservationID)
}

func (k *Keeper) ListDelegations() []types.DelegatedSessionCredit {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := append([]types.DelegatedSessionCredit(nil), k.store.ListDelegations()...)
	sort.Slice(records, func(i, j int) bool {
		return records[i].ReservationID < records[j].ReservationID
	})
	return records
}

func normalizeAuthorization(record types.SponsorAuthorization) types.SponsorAuthorization {
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeDelegation(record types.DelegatedSessionCredit) types.DelegatedSessionCredit {
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
