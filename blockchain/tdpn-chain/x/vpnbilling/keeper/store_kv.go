package keeper

import (
	"encoding/json"
	"fmt"
	"strings"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

const (
	reservationPrefix = "reservation/"
	settlementPrefix  = "settlement/"
	maxKVPayloadBytes = 1 << 20
)

// KVStore adapts KeeperStore onto a generic key/value backend.
type KVStore struct {
	store kvtypes.Store
}

// NewKVStore constructs a vpnbilling KV-backed store.
func NewKVStore(store kvtypes.Store) *KVStore {
	if store == nil {
		store = kvtypes.NewMapStore()
	}
	return &KVStore{store: store}
}

func (s *KVStore) UpsertReservation(record types.CreditReservation) {
	normalized := record.Canonicalize()
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(reservationKey(normalized.ReservationID), payload)
}

func (s *KVStore) GetReservation(reservationID string) (types.CreditReservation, bool) {
	canonicalReservationID := canonicalKVToken(reservationID)
	if canonicalReservationID == "" {
		return types.CreditReservation{}, false
	}

	payload, ok := s.store.Get(reservationKey(canonicalReservationID))
	if !ok {
		return types.CreditReservation{}, false
	}

	record, err := decodeCreditReservation(payload)
	if err != nil {
		return types.CreditReservation{}, false
	}
	if record.ReservationID != canonicalReservationID {
		return types.CreditReservation{}, false
	}

	return record, true
}

func (s *KVStore) ListReservations() []types.CreditReservation {
	records, err := s.ListReservationsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListReservationsWithError() ([]types.CreditReservation, error) {
	records := make([]types.CreditReservation, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(reservationPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, reservationPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode reservation key %q: %w", string(key), err)
			return false
		}

		record, err := decodeCreditReservation(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode reservation %q: %w", keyID, err)
			return false
		}
		if record.ReservationID != keyID {
			decodeErr = fmt.Errorf("reservation key/value id mismatch: key=%q payload=%q", keyID, record.ReservationID)
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

func (s *KVStore) UpsertSettlement(record types.SettlementRecord) {
	normalized := record.Canonicalize()
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(settlementKey(normalized.SettlementID), payload)
}

func (s *KVStore) GetSettlement(settlementID string) (types.SettlementRecord, bool) {
	canonicalSettlementID := canonicalKVToken(settlementID)
	if canonicalSettlementID == "" {
		return types.SettlementRecord{}, false
	}

	payload, ok := s.store.Get(settlementKey(canonicalSettlementID))
	if !ok {
		return types.SettlementRecord{}, false
	}

	record, err := decodeSettlementRecord(payload)
	if err != nil {
		return types.SettlementRecord{}, false
	}
	if record.SettlementID != canonicalSettlementID {
		return types.SettlementRecord{}, false
	}

	return record, true
}

func (s *KVStore) ListSettlements() []types.SettlementRecord {
	records, err := s.ListSettlementsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListSettlementsWithError() ([]types.SettlementRecord, error) {
	records := make([]types.SettlementRecord, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(settlementPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, settlementPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode settlement key %q: %w", string(key), err)
			return false
		}

		record, err := decodeSettlementRecord(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode settlement %q: %w", keyID, err)
			return false
		}
		if record.SettlementID != keyID {
			decodeErr = fmt.Errorf("settlement key/value id mismatch: key=%q payload=%q", keyID, record.SettlementID)
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

func reservationKey(reservationID string) []byte {
	return []byte(reservationPrefix + reservationID)
}

func settlementKey(settlementID string) []byte {
	return []byte(settlementPrefix + settlementID)
}

func decodeCreditReservation(payload []byte) (types.CreditReservation, error) {
	if len(payload) == 0 {
		return types.CreditReservation{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.CreditReservation{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.CreditReservation
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.CreditReservation{}, err
	}

	normalized := record.Canonicalize()
	if err := normalized.ValidateBasic(); err != nil {
		return types.CreditReservation{}, err
	}
	return normalized, nil
}

func decodeSettlementRecord(payload []byte) (types.SettlementRecord, error) {
	if len(payload) == 0 {
		return types.SettlementRecord{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.SettlementRecord{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.SettlementRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.SettlementRecord{}, err
	}

	normalized := record.Canonicalize()
	if err := normalized.ValidateBasic(); err != nil {
		return types.SettlementRecord{}, err
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
