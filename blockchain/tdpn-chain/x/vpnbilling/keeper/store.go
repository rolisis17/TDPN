package keeper

import "github.com/tdpn/tdpn-chain/x/vpnbilling/types"

// KeeperStore is the internal persistence seam for vpnbilling keeper state.
// A Cosmos KV-backed implementation can be plugged later without changing keeper callers.
type KeeperStore interface {
	UpsertReservation(record types.CreditReservation)
	GetReservation(reservationID string) (types.CreditReservation, bool)
	ListReservations() []types.CreditReservation
	UpsertSettlement(record types.SettlementRecord)
	GetSettlement(settlementID string) (types.SettlementRecord, bool)
	ListSettlements() []types.SettlementRecord
}

// InMemoryStore is the default keeper store implementation.
type InMemoryStore struct {
	reservations map[string]types.CreditReservation
	settlements  map[string]types.SettlementRecord
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		reservations: make(map[string]types.CreditReservation),
		settlements:  make(map[string]types.SettlementRecord),
	}
}

func (s *InMemoryStore) UpsertReservation(record types.CreditReservation) {
	s.reservations[record.ReservationID] = record
}

func (s *InMemoryStore) GetReservation(reservationID string) (types.CreditReservation, bool) {
	record, ok := s.reservations[reservationID]
	return record, ok
}

func (s *InMemoryStore) ListReservations() []types.CreditReservation {
	records := make([]types.CreditReservation, 0, len(s.reservations))
	for _, record := range s.reservations {
		records = append(records, record)
	}
	return records
}

func (s *InMemoryStore) UpsertSettlement(record types.SettlementRecord) {
	s.settlements[record.SettlementID] = record
}

func (s *InMemoryStore) GetSettlement(settlementID string) (types.SettlementRecord, bool) {
	record, ok := s.settlements[settlementID]
	return record, ok
}

func (s *InMemoryStore) ListSettlements() []types.SettlementRecord {
	records := make([]types.SettlementRecord, 0, len(s.settlements))
	for _, record := range s.settlements {
		records = append(records, record)
	}
	return records
}
