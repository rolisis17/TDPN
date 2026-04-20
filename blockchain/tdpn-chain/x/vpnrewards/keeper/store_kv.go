package keeper

import (
	"encoding/json"
	"fmt"
	"strings"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

const (
	accrualPrefix      = "accrual/"
	distributionPrefix = "distribution/"
	maxKVPayloadBytes  = 1 << 20
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
	normalized := normalizeAccrual(record)
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(accrualKey(normalized.AccrualID), payload)
}

func (s *KVStore) GetAccrual(accrualID string) (types.RewardAccrual, bool) {
	canonicalAccrualID := canonicalKVToken(accrualID)
	if canonicalAccrualID == "" {
		return types.RewardAccrual{}, false
	}

	payload, ok := s.store.Get(accrualKey(canonicalAccrualID))
	if !ok {
		return types.RewardAccrual{}, false
	}

	record, err := decodeAccrual(payload)
	if err != nil {
		return types.RewardAccrual{}, false
	}
	if record.AccrualID != canonicalAccrualID {
		return types.RewardAccrual{}, false
	}

	return record, true
}

func (s *KVStore) ListAccruals() []types.RewardAccrual {
	records, err := s.ListAccrualsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListAccrualsWithError() ([]types.RewardAccrual, error) {
	records := make([]types.RewardAccrual, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(accrualPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, accrualPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode accrual key %q: %w", string(key), err)
			return false
		}

		record, err := decodeAccrual(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode accrual %q: %w", keyID, err)
			return false
		}
		if record.AccrualID != keyID {
			decodeErr = fmt.Errorf("accrual key/value id mismatch: key=%q payload=%q", keyID, record.AccrualID)
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

func (s *KVStore) UpsertDistribution(record types.DistributionRecord) {
	normalized := normalizeDistribution(record)
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(distributionKey(normalized.DistributionID), payload)
}

func (s *KVStore) GetDistribution(distributionID string) (types.DistributionRecord, bool) {
	canonicalDistributionID := canonicalKVToken(distributionID)
	if canonicalDistributionID == "" {
		return types.DistributionRecord{}, false
	}

	payload, ok := s.store.Get(distributionKey(canonicalDistributionID))
	if !ok {
		return types.DistributionRecord{}, false
	}

	record, err := decodeDistribution(payload)
	if err != nil {
		return types.DistributionRecord{}, false
	}
	if record.DistributionID != canonicalDistributionID {
		return types.DistributionRecord{}, false
	}

	return record, true
}

func (s *KVStore) ListDistributions() []types.DistributionRecord {
	records, err := s.ListDistributionsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListDistributionsWithError() ([]types.DistributionRecord, error) {
	records := make([]types.DistributionRecord, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(distributionPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, distributionPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode distribution key %q: %w", string(key), err)
			return false
		}

		record, err := decodeDistribution(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode distribution %q: %w", keyID, err)
			return false
		}
		if record.DistributionID != keyID {
			decodeErr = fmt.Errorf("distribution key/value id mismatch: key=%q payload=%q", keyID, record.DistributionID)
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

func accrualKey(accrualID string) []byte {
	return []byte(accrualPrefix + accrualID)
}

func distributionKey(distributionID string) []byte {
	return []byte(distributionPrefix + distributionID)
}

func decodeAccrual(payload []byte) (types.RewardAccrual, error) {
	if len(payload) == 0 {
		return types.RewardAccrual{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.RewardAccrual{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.RewardAccrual
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.RewardAccrual{}, err
	}

	normalized := normalizeAccrual(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.RewardAccrual{}, err
	}
	return normalized, nil
}

func decodeDistribution(payload []byte) (types.DistributionRecord, error) {
	if len(payload) == 0 {
		return types.DistributionRecord{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.DistributionRecord{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.DistributionRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.DistributionRecord{}, err
	}

	normalized := normalizeDistribution(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.DistributionRecord{}, err
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
