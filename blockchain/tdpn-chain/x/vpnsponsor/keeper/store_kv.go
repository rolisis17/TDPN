package keeper

import (
	"encoding/json"
	"fmt"
	"strings"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

const (
	authorizationPrefix = "authorization/"
	delegationPrefix    = "delegation/"
)

// KVStore adapts KeeperStore onto a generic key/value backend.
type KVStore struct {
	store kvtypes.Store
}

// NewKVStore constructs a vpnsponsor KV-backed store.
func NewKVStore(store kvtypes.Store) *KVStore {
	if store == nil {
		store = kvtypes.NewMapStore()
	}
	return &KVStore{store: store}
}

func (s *KVStore) UpsertAuthorization(record types.SponsorAuthorization) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(authorizationKey(record.AuthorizationID), payload)
}

func (s *KVStore) GetAuthorization(authID string) (types.SponsorAuthorization, bool) {
	payload, ok := s.store.Get(authorizationKey(authID))
	if !ok {
		return types.SponsorAuthorization{}, false
	}

	var record types.SponsorAuthorization
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.SponsorAuthorization{}, false
	}

	return record, true
}

func (s *KVStore) ListAuthorizations() []types.SponsorAuthorization {
	records := make([]types.SponsorAuthorization, 0)
	s.store.IteratePrefix([]byte(authorizationPrefix), func(_ []byte, value []byte) bool {
		var record types.SponsorAuthorization
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func (s *KVStore) ListAuthorizationsWithError() ([]types.SponsorAuthorization, error) {
	records := make([]types.SponsorAuthorization, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(authorizationPrefix), func(key []byte, value []byte) bool {
		var record types.SponsorAuthorization
		if err := json.Unmarshal(value, &record); err != nil {
			decodeErr = fmt.Errorf("decode authorization %q: %w", strings.TrimPrefix(string(key), authorizationPrefix), err)
			return false
		}
		records = append(records, record)
		return true
	})
	if decodeErr != nil {
		return nil, decodeErr
	}
	return records, nil
}

func (s *KVStore) UpsertDelegation(record types.DelegatedSessionCredit) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(delegationKey(record.ReservationID), payload)
}

func (s *KVStore) GetDelegation(reservationID string) (types.DelegatedSessionCredit, bool) {
	payload, ok := s.store.Get(delegationKey(reservationID))
	if !ok {
		return types.DelegatedSessionCredit{}, false
	}

	var record types.DelegatedSessionCredit
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.DelegatedSessionCredit{}, false
	}

	return record, true
}

func (s *KVStore) ListDelegations() []types.DelegatedSessionCredit {
	records := make([]types.DelegatedSessionCredit, 0)
	s.store.IteratePrefix([]byte(delegationPrefix), func(_ []byte, value []byte) bool {
		var record types.DelegatedSessionCredit
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func (s *KVStore) ListDelegationsWithError() ([]types.DelegatedSessionCredit, error) {
	records := make([]types.DelegatedSessionCredit, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(delegationPrefix), func(key []byte, value []byte) bool {
		var record types.DelegatedSessionCredit
		if err := json.Unmarshal(value, &record); err != nil {
			decodeErr = fmt.Errorf("decode delegation %q: %w", strings.TrimPrefix(string(key), delegationPrefix), err)
			return false
		}
		records = append(records, record)
		return true
	})
	if decodeErr != nil {
		return nil, decodeErr
	}
	return records, nil
}

func authorizationKey(authID string) []byte {
	return []byte(authorizationPrefix + authID)
}

func delegationKey(reservationID string) []byte {
	return []byte(delegationPrefix + reservationID)
}
