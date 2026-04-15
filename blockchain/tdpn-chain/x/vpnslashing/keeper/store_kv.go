package keeper

import (
	"encoding/json"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

const (
	evidencePrefix = "evidence/"
	penaltyPrefix  = "penalty/"
)

// KVStore adapts KeeperStore onto a generic key/value backend.
type KVStore struct {
	store kvtypes.Store
}

// NewKVStore constructs a vpnslashing KV-backed store.
func NewKVStore(store kvtypes.Store) *KVStore {
	if store == nil {
		store = kvtypes.NewMapStore()
	}
	return &KVStore{store: store}
}

func (s *KVStore) UpsertEvidence(record types.SlashEvidence) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(evidenceKey(record.EvidenceID), payload)
}

func (s *KVStore) GetEvidence(evidenceID string) (types.SlashEvidence, bool) {
	payload, ok := s.store.Get(evidenceKey(evidenceID))
	if !ok {
		return types.SlashEvidence{}, false
	}

	var record types.SlashEvidence
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.SlashEvidence{}, false
	}

	return record, true
}

func (s *KVStore) ListEvidence() []types.SlashEvidence {
	records := make([]types.SlashEvidence, 0)
	s.store.IteratePrefix([]byte(evidencePrefix), func(_ []byte, value []byte) bool {
		var record types.SlashEvidence
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func (s *KVStore) UpsertPenalty(record types.PenaltyDecision) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(penaltyKey(record.PenaltyID), payload)
}

func (s *KVStore) GetPenalty(penaltyID string) (types.PenaltyDecision, bool) {
	payload, ok := s.store.Get(penaltyKey(penaltyID))
	if !ok {
		return types.PenaltyDecision{}, false
	}

	var record types.PenaltyDecision
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.PenaltyDecision{}, false
	}

	return record, true
}

func (s *KVStore) ListPenalties() []types.PenaltyDecision {
	records := make([]types.PenaltyDecision, 0)
	s.store.IteratePrefix([]byte(penaltyPrefix), func(_ []byte, value []byte) bool {
		var record types.PenaltyDecision
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func evidenceKey(evidenceID string) []byte {
	return []byte(evidencePrefix + evidenceID)
}

func penaltyKey(penaltyID string) []byte {
	return []byte(penaltyPrefix + penaltyID)
}
