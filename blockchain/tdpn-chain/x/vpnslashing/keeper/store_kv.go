package keeper

import (
	"encoding/json"
	"strings"

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
	record, ok := decodeEvidenceRecord(strings.TrimSpace(evidenceID), payload)
	if !ok {
		return types.SlashEvidence{}, false
	}
	return record, true
}

func (s *KVStore) ListEvidence() []types.SlashEvidence {
	records := make([]types.SlashEvidence, 0)
	s.store.IteratePrefix([]byte(evidencePrefix), func(key []byte, value []byte) bool {
		evidenceID := strings.TrimSpace(strings.TrimPrefix(string(key), evidencePrefix))
		if evidenceID == "" {
			return true
		}
		record, ok := decodeEvidenceRecord(evidenceID, value)
		if ok {
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
	record, ok := decodePenaltyRecord(strings.TrimSpace(penaltyID), payload)
	if !ok {
		return types.PenaltyDecision{}, false
	}
	if _, exists := s.GetEvidence(record.EvidenceID); !exists {
		return types.PenaltyDecision{}, false
	}
	return record, true
}

func (s *KVStore) ListPenalties() []types.PenaltyDecision {
	records := make([]types.PenaltyDecision, 0)
	evidenceSet := make(map[string]struct{})
	for _, evidence := range s.ListEvidence() {
		evidenceSet[strings.TrimSpace(evidence.EvidenceID)] = struct{}{}
	}
	s.store.IteratePrefix([]byte(penaltyPrefix), func(key []byte, value []byte) bool {
		penaltyID := strings.TrimSpace(strings.TrimPrefix(string(key), penaltyPrefix))
		if penaltyID == "" {
			return true
		}
		record, ok := decodePenaltyRecord(penaltyID, value)
		if !ok {
			return true
		}
		if _, exists := evidenceSet[strings.TrimSpace(record.EvidenceID)]; !exists {
			return true
		}
		records = append(records, record)
		return true
	})
	return records
}

func decodeEvidenceRecord(expectedID string, payload []byte) (types.SlashEvidence, bool) {
	var record types.SlashEvidence
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.SlashEvidence{}, false
	}
	record = normalizeEvidence(record)
	expectedID = strings.TrimSpace(expectedID)
	if expectedID != "" && strings.TrimSpace(record.EvidenceID) != expectedID {
		return types.SlashEvidence{}, false
	}
	if err := record.ValidateBasic(); err != nil {
		return types.SlashEvidence{}, false
	}
	return record, true
}

func decodePenaltyRecord(expectedID string, payload []byte) (types.PenaltyDecision, bool) {
	var record types.PenaltyDecision
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.PenaltyDecision{}, false
	}
	record = normalizePenalty(record)
	expectedID = strings.TrimSpace(expectedID)
	if expectedID != "" && strings.TrimSpace(record.PenaltyID) != expectedID {
		return types.PenaltyDecision{}, false
	}
	if err := record.ValidateBasic(); err != nil {
		return types.PenaltyDecision{}, false
	}
	return record, true
}

func evidenceKey(evidenceID string) []byte {
	return []byte(evidencePrefix + evidenceID)
}

func penaltyKey(penaltyID string) []byte {
	return []byte(penaltyPrefix + penaltyID)
}
