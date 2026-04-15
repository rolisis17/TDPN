package module

import (
	"errors"
	"fmt"

	"github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

var (
	ErrSettlementNotFound = errors.New("vpnbilling: settlement not found")
)

// GetReservationRequest requests a reservation by reservation ID.
type GetReservationRequest struct {
	ReservationID string
}

// GetReservationResponse contains a reservation lookup result.
type GetReservationResponse struct {
	Reservation types.CreditReservation
}

// GetSettlementRequest requests a settlement by settlement ID.
type GetSettlementRequest struct {
	SettlementID string
}

// GetSettlementResponse contains a settlement lookup result.
type GetSettlementResponse struct {
	Settlement types.SettlementRecord
}

// ListReservationsRequest lists all reservations.
type ListReservationsRequest struct{}

// ListReservationsResponse contains all reservations ordered by reservation ID.
type ListReservationsResponse struct {
	Reservations []types.CreditReservation
}

// ListSettlementsRequest lists all settlements.
type ListSettlementsRequest struct{}

// ListSettlementsResponse contains all settlements ordered by settlement ID.
type ListSettlementsResponse struct {
	Settlements []types.SettlementRecord
}

// QueryServer exposes a lightweight Cosmos-style query surface for vpnbilling.
type QueryServer struct {
	keeper *keeper.Keeper
}

func NewQueryServer(k *keeper.Keeper) QueryServer {
	return QueryServer{keeper: k}
}

func (s QueryServer) GetReservation(req GetReservationRequest) (GetReservationResponse, error) {
	if s.keeper == nil {
		return GetReservationResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetReservation(req.ReservationID)
	if !ok {
		return GetReservationResponse{}, fmt.Errorf("%w: reservation_id=%s", ErrReservationNotFound, req.ReservationID)
	}
	return GetReservationResponse{Reservation: record}, nil
}

func (s QueryServer) GetSettlement(req GetSettlementRequest) (GetSettlementResponse, error) {
	if s.keeper == nil {
		return GetSettlementResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetSettlement(req.SettlementID)
	if !ok {
		return GetSettlementResponse{}, fmt.Errorf("%w: settlement_id=%s", ErrSettlementNotFound, req.SettlementID)
	}
	return GetSettlementResponse{Settlement: record}, nil
}

func (s QueryServer) ListReservations(_ ListReservationsRequest) (ListReservationsResponse, error) {
	if s.keeper == nil {
		return ListReservationsResponse{}, ErrNilKeeper
	}
	return ListReservationsResponse{Reservations: s.keeper.ListReservations()}, nil
}

func (s QueryServer) ListSettlements(_ ListSettlementsRequest) (ListSettlementsResponse, error) {
	if s.keeper == nil {
		return ListSettlementsResponse{}, ErrNilKeeper
	}
	return ListSettlementsResponse{Settlements: s.keeper.ListSettlements()}, nil
}
