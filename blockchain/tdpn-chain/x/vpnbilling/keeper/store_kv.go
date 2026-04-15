package keeper

import (
	"encoding/json"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

const (
	reservationPrefix = "reservation/"
	settlementPrefix  = "settlement/"
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
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(reservationKey(record.ReservationID), payload)
}

func (s *KVStore) GetReservation(reservationID string) (types.CreditReservation, bool) {
	payload, ok := s.store.Get(reservationKey(reservationID))
	if !ok {
		return types.CreditReservation{}, false
	}

	var record types.CreditReservation
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.CreditReservation{}, false
	}

	return record, true
}

func (s *KVStore) ListReservations() []types.CreditReservation {
	records := make([]types.CreditReservation, 0)
	s.store.IteratePrefix([]byte(reservationPrefix), func(_ []byte, value []byte) bool {
		var record types.CreditReservation
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func (s *KVStore) UpsertSettlement(record types.SettlementRecord) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(settlementKey(record.SettlementID), payload)
}

func (s *KVStore) GetSettlement(settlementID string) (types.SettlementRecord, bool) {
	payload, ok := s.store.Get(settlementKey(settlementID))
	if !ok {
		return types.SettlementRecord{}, false
	}

	var record types.SettlementRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.SettlementRecord{}, false
	}

	return record, true
}

func (s *KVStore) ListSettlements() []types.SettlementRecord {
	records := make([]types.SettlementRecord, 0)
	s.store.IteratePrefix([]byte(settlementPrefix), func(_ []byte, value []byte) bool {
		var record types.SettlementRecord
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func reservationKey(reservationID string) []byte {
	return []byte(reservationPrefix + reservationID)
}

func settlementKey(settlementID string) []byte {
	return []byte(settlementPrefix + settlementID)
}
