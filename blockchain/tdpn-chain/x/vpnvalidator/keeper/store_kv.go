package keeper

import (
	"encoding/json"
	"fmt"
	"strings"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

const (
	eligibilityPrefix = "eligibility/"
	statusPrefix      = "status/"
	maxKVPayloadBytes = 1 << 20
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
	normalized := normalizeEligibility(record)
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(eligibilityKey(normalized.ValidatorID), payload)
}

func (s *KVStore) GetEligibility(validatorID string) (types.ValidatorEligibility, bool) {
	canonicalValidatorID := canonicalKVToken(validatorID)
	if canonicalValidatorID == "" {
		return types.ValidatorEligibility{}, false
	}

	payload, ok := s.store.Get(eligibilityKey(canonicalValidatorID))
	if !ok {
		return types.ValidatorEligibility{}, false
	}

	record, err := decodeEligibility(payload)
	if err != nil {
		return types.ValidatorEligibility{}, false
	}
	if record.ValidatorID != canonicalValidatorID {
		return types.ValidatorEligibility{}, false
	}
	return record, true
}

func (s *KVStore) ListEligibilities() []types.ValidatorEligibility {
	records, err := s.ListEligibilitiesWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListEligibilitiesWithError() ([]types.ValidatorEligibility, error) {
	records := make([]types.ValidatorEligibility, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(eligibilityPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, eligibilityPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode eligibility key %q: %w", string(key), err)
			return false
		}

		record, err := decodeEligibility(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode eligibility %q: %w", keyID, err)
			return false
		}
		if record.ValidatorID != keyID {
			decodeErr = fmt.Errorf("eligibility key/value id mismatch: key=%q payload=%q", keyID, record.ValidatorID)
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

func (s *KVStore) UpsertStatusRecord(record types.ValidatorStatusRecord) {
	normalized := normalizeStatusRecord(record)
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(statusKey(normalized.StatusID), payload)
}

func (s *KVStore) GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool) {
	canonicalStatusID := canonicalKVToken(statusID)
	if canonicalStatusID == "" {
		return types.ValidatorStatusRecord{}, false
	}

	payload, ok := s.store.Get(statusKey(canonicalStatusID))
	if !ok {
		return types.ValidatorStatusRecord{}, false
	}

	record, err := decodeStatusRecord(payload)
	if err != nil {
		return types.ValidatorStatusRecord{}, false
	}
	if record.StatusID != canonicalStatusID {
		return types.ValidatorStatusRecord{}, false
	}
	return record, true
}

func (s *KVStore) ListStatusRecords() []types.ValidatorStatusRecord {
	records, err := s.ListStatusRecordsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListStatusRecordsWithError() ([]types.ValidatorStatusRecord, error) {
	records := make([]types.ValidatorStatusRecord, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(statusPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, statusPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode status key %q: %w", string(key), err)
			return false
		}

		record, err := decodeStatusRecord(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode status %q: %w", keyID, err)
			return false
		}
		if record.StatusID != keyID {
			decodeErr = fmt.Errorf("status key/value id mismatch: key=%q payload=%q", keyID, record.StatusID)
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

func eligibilityKey(validatorID string) []byte {
	return []byte(eligibilityPrefix + validatorID)
}

func statusKey(statusID string) []byte {
	return []byte(statusPrefix + statusID)
}

func decodeEligibility(payload []byte) (types.ValidatorEligibility, error) {
	if len(payload) == 0 {
		return types.ValidatorEligibility{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.ValidatorEligibility{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.ValidatorEligibility
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.ValidatorEligibility{}, err
	}

	normalized := normalizeEligibility(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.ValidatorEligibility{}, err
	}
	return normalized, nil
}

func decodeStatusRecord(payload []byte) (types.ValidatorStatusRecord, error) {
	if len(payload) == 0 {
		return types.ValidatorStatusRecord{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.ValidatorStatusRecord{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.ValidatorStatusRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.ValidatorStatusRecord{}, err
	}

	normalized := normalizeStatusRecord(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.ValidatorStatusRecord{}, err
	}
	return normalized, nil
}

func parsePrefixedID(key []byte, prefix string) (string, error) {
	rawKey := string(key)
	if !strings.HasPrefix(rawKey, prefix) {
		return "", fmt.Errorf("missing prefix %q", prefix)
	}

	suffix := canonicalKVToken(strings.TrimPrefix(rawKey, prefix))
	if suffix == "" {
		return "", fmt.Errorf("key id is empty")
	}
	if rawKey != prefix+suffix {
		return "", fmt.Errorf("key id is not canonical")
	}
	return suffix, nil
}

func canonicalKVToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
