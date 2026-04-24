package keeper

import (
	"encoding/json"
	"fmt"
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
	record, err := decodeEvidenceRecord(strings.TrimSpace(evidenceID), payload)
	if err != nil {
		return types.SlashEvidence{}, false
	}
	return record, true
}

func (s *KVStore) ListEvidence() []types.SlashEvidence {
	records, err := s.ListEvidenceWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListEvidenceWithError() ([]types.SlashEvidence, error) {
	records := make([]types.SlashEvidence, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(evidencePrefix), func(key []byte, value []byte) bool {
		evidenceID, err := parsePrefixedID(key, evidencePrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode evidence key %q: %w", string(key), err)
			return false
		}
		record, err := decodeEvidenceRecord(evidenceID, value)
		if err != nil {
			decodeErr = fmt.Errorf("decode evidence %q: %w", evidenceID, err)
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
	record, err := decodePenaltyRecord(strings.TrimSpace(penaltyID), payload)
	if err != nil {
		return types.PenaltyDecision{}, false
	}
	if _, exists := s.GetEvidence(record.EvidenceID); !exists {
		return types.PenaltyDecision{}, false
	}
	return record, true
}

func (s *KVStore) ListPenalties() []types.PenaltyDecision {
	records, err := s.ListPenaltiesWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListPenaltiesWithError() ([]types.PenaltyDecision, error) {
	records := make([]types.PenaltyDecision, 0)
	var decodeErr error
	evidenceSet := make(map[string]struct{})
	evidenceRecords, err := s.ListEvidenceWithError()
	if err != nil {
		return nil, err
	}
	for _, evidence := range evidenceRecords {
		evidenceSet[strings.TrimSpace(evidence.EvidenceID)] = struct{}{}
	}
	s.store.IteratePrefix([]byte(penaltyPrefix), func(key []byte, value []byte) bool {
		penaltyID, err := parsePrefixedID(key, penaltyPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode penalty key %q: %w", string(key), err)
			return false
		}
		record, err := decodePenaltyRecord(penaltyID, value)
		if err != nil {
			decodeErr = fmt.Errorf("decode penalty %q: %w", penaltyID, err)
			return false
		}
		if _, exists := evidenceSet[strings.TrimSpace(record.EvidenceID)]; !exists {
			decodeErr = fmt.Errorf("penalty %q references missing evidence %q", penaltyID, strings.TrimSpace(record.EvidenceID))
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

func decodeEvidenceRecord(expectedID string, payload []byte) (types.SlashEvidence, error) {
	var record types.SlashEvidence
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.SlashEvidence{}, err
	}
	record = normalizeEvidence(record)
	expectedID = strings.TrimSpace(expectedID)
	if expectedID != "" && strings.TrimSpace(record.EvidenceID) != expectedID {
		return types.SlashEvidence{}, fmt.Errorf("evidence key/value id mismatch: key=%q payload=%q", expectedID, strings.TrimSpace(record.EvidenceID))
	}
	if err := record.ValidateBasic(); err != nil {
		return types.SlashEvidence{}, err
	}
	return record, nil
}

func decodePenaltyRecord(expectedID string, payload []byte) (types.PenaltyDecision, error) {
	var record types.PenaltyDecision
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.PenaltyDecision{}, err
	}
	record = normalizePenalty(record)
	expectedID = strings.TrimSpace(expectedID)
	if expectedID != "" && strings.TrimSpace(record.PenaltyID) != expectedID {
		return types.PenaltyDecision{}, fmt.Errorf("penalty key/value id mismatch: key=%q payload=%q", expectedID, strings.TrimSpace(record.PenaltyID))
	}
	if err := record.ValidateBasic(); err != nil {
		return types.PenaltyDecision{}, err
	}
	return record, nil
}

func evidenceKey(evidenceID string) []byte {
	return []byte(evidencePrefix + evidenceID)
}

func penaltyKey(penaltyID string) []byte {
	return []byte(penaltyPrefix + penaltyID)
}

func parsePrefixedID(key []byte, prefix string) (string, error) {
	rawKey := string(key)
	if !strings.HasPrefix(rawKey, prefix) {
		return "", fmt.Errorf("missing prefix %q", prefix)
	}

	suffix := strings.TrimSpace(strings.TrimPrefix(rawKey, prefix))
	if suffix == "" {
		return "", fmt.Errorf("key id is empty")
	}
	if rawKey != prefix+suffix {
		return "", fmt.Errorf("key id is not canonical")
	}
	return suffix, nil
}
