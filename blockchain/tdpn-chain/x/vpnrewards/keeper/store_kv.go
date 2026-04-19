package keeper

import (
	"encoding/json"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

const (
	accrualPrefix      = "accrual/"
	distributionPrefix = "distribution/"
)

// KVStore adapts KeeperStore onto a generic key/value backend.
type KVStore struct {
	store kvtypes.Store
}

// NewKVStore constructs a vpnrewards KV-backed store.
func NewKVStore(store kvtypes.Store) *KVStore {
	if store == nil {
		store = kvtypes.NewMapStore()
	}
	return &KVStore{store: store}
}

func (s *KVStore) UpsertAccrual(record types.RewardAccrual) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(accrualKey(record.AccrualID), payload)
}

func (s *KVStore) GetAccrual(accrualID string) (types.RewardAccrual, bool) {
	payload, ok := s.store.Get(accrualKey(accrualID))
	if !ok {
		return types.RewardAccrual{}, false
	}

	var record types.RewardAccrual
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.RewardAccrual{}, false
	}

	return record, true
}

func (s *KVStore) ListAccruals() []types.RewardAccrual {
	records := make([]types.RewardAccrual, 0)
	s.store.IteratePrefix([]byte(accrualPrefix), func(_ []byte, value []byte) bool {
		var record types.RewardAccrual
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func (s *KVStore) UpsertDistribution(record types.DistributionRecord) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(distributionKey(record.DistributionID), payload)
}

func (s *KVStore) GetDistribution(distributionID string) (types.DistributionRecord, bool) {
	payload, ok := s.store.Get(distributionKey(distributionID))
	if !ok {
		return types.DistributionRecord{}, false
	}

	var record types.DistributionRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.DistributionRecord{}, false
	}

	return record, true
}

func (s *KVStore) ListDistributions() []types.DistributionRecord {
	records := make([]types.DistributionRecord, 0)
	s.store.IteratePrefix([]byte(distributionPrefix), func(_ []byte, value []byte) bool {
		var record types.DistributionRecord
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func accrualKey(accrualID string) []byte {
	return []byte(accrualPrefix + accrualID)
}

func distributionKey(distributionID string) []byte {
	return []byte(distributionPrefix + distributionID)
}
