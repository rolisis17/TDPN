package keeper

import (
	"encoding/json"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

const (
	eligibilityPrefix = "eligibility/"
	statusPrefix      = "status/"
)

// KVStore adapts KeeperStore onto a generic key/value backend.
type KVStore struct {
	store kvtypes.Store
}

// NewKVStore builds a vpnvalidator KV-backed store.
func NewKVStore(store kvtypes.Store) *KVStore {
	if store == nil {
		store = kvtypes.NewMapStore()
	}
	return &KVStore{store: store}
}

func (s *KVStore) UpsertEligibility(record types.ValidatorEligibility) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(eligibilityKey(record.ValidatorID), payload)
}

func (s *KVStore) GetEligibility(validatorID string) (types.ValidatorEligibility, bool) {
	payload, ok := s.store.Get(eligibilityKey(validatorID))
	if !ok {
		return types.ValidatorEligibility{}, false
	}

	var record types.ValidatorEligibility
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.ValidatorEligibility{}, false
	}
	return record, true
}

func (s *KVStore) ListEligibilities() []types.ValidatorEligibility {
	records := make([]types.ValidatorEligibility, 0)
	s.store.IteratePrefix([]byte(eligibilityPrefix), func(_ []byte, value []byte) bool {
		var record types.ValidatorEligibility
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func (s *KVStore) UpsertStatusRecord(record types.ValidatorStatusRecord) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(statusKey(record.StatusID), payload)
}

func (s *KVStore) GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool) {
	payload, ok := s.store.Get(statusKey(statusID))
	if !ok {
		return types.ValidatorStatusRecord{}, false
	}

	var record types.ValidatorStatusRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.ValidatorStatusRecord{}, false
	}
	return record, true
}

func (s *KVStore) ListStatusRecords() []types.ValidatorStatusRecord {
	records := make([]types.ValidatorStatusRecord, 0)
	s.store.IteratePrefix([]byte(statusPrefix), func(_ []byte, value []byte) bool {
		var record types.ValidatorStatusRecord
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func eligibilityKey(validatorID string) []byte {
	return []byte(eligibilityPrefix + validatorID)
}

func statusKey(statusID string) []byte {
	return []byte(statusPrefix + statusID)
}
