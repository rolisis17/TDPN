package app

import (
	"context"
	"errors"

	billingmodule "github.com/tdpn/tdpn-chain/x/vpnbilling/module"
	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

// BillingQueryServer exposes phase-1 vpnbilling query operations through the scaffold.
type BillingQueryServer interface {
	GetReservation(context.Context, BillingGetReservationRequest) (BillingGetReservationResponse, error)
	GetSettlement(context.Context, BillingGetSettlementRequest) (BillingGetSettlementResponse, error)
	ListReservations(context.Context, BillingListReservationsRequest) (BillingListReservationsResponse, error)
	ListSettlements(context.Context, BillingListSettlementsRequest) (BillingListSettlementsResponse, error)
}

type BillingGetReservationRequest struct {
	ReservationID string
}

type BillingGetReservationResponse struct {
	Reservation billingtypes.CreditReservation
	Found       bool
}

type BillingGetSettlementRequest struct {
	SettlementID string
}

type BillingGetSettlementResponse struct {
	Settlement billingtypes.SettlementRecord
	Found      bool
}

type BillingListReservationsRequest struct{}

type BillingListReservationsResponse struct {
	Reservations []billingtypes.CreditReservation
}

type BillingListSettlementsRequest struct{}

type BillingListSettlementsResponse struct {
	Settlements []billingtypes.SettlementRecord
}

type billingQueryServer struct {
	queryServer billingmodule.QueryServer
}

func (m billingQueryServer) GetReservation(_ context.Context, req BillingGetReservationRequest) (BillingGetReservationResponse, error) {
	resp, err := m.queryServer.GetReservation(billingmodule.GetReservationRequest{ReservationID: req.ReservationID})
	if err != nil {
		if errors.Is(err, billingmodule.ErrNilKeeper) {
			return BillingGetReservationResponse{}, errBillingKeeperNotWired
		}
		if errors.Is(err, billingmodule.ErrReservationNotFound) {
			return BillingGetReservationResponse{Found: false}, nil
		}
		return BillingGetReservationResponse{}, err
	}
	return BillingGetReservationResponse{
		Reservation: resp.Reservation,
		Found:       true,
	}, nil
}

func (m billingQueryServer) GetSettlement(_ context.Context, req BillingGetSettlementRequest) (BillingGetSettlementResponse, error) {
	resp, err := m.queryServer.GetSettlement(billingmodule.GetSettlementRequest{SettlementID: req.SettlementID})
	if err != nil {
		if errors.Is(err, billingmodule.ErrNilKeeper) {
			return BillingGetSettlementResponse{}, errBillingKeeperNotWired
		}
		if errors.Is(err, billingmodule.ErrSettlementNotFound) {
			return BillingGetSettlementResponse{Found: false}, nil
		}
		return BillingGetSettlementResponse{}, err
	}
	return BillingGetSettlementResponse{
		Settlement: resp.Settlement,
		Found:      true,
	}, nil
}

func (m billingQueryServer) ListReservations(_ context.Context, _ BillingListReservationsRequest) (BillingListReservationsResponse, error) {
	resp, err := m.queryServer.ListReservations(billingmodule.ListReservationsRequest{})
	if err != nil {
		if errors.Is(err, billingmodule.ErrNilKeeper) {
			return BillingListReservationsResponse{}, errBillingKeeperNotWired
		}
		return BillingListReservationsResponse{}, err
	}
	return BillingListReservationsResponse{
		Reservations: resp.Reservations,
	}, nil
}

func (m billingQueryServer) ListSettlements(_ context.Context, _ BillingListSettlementsRequest) (BillingListSettlementsResponse, error) {
	resp, err := m.queryServer.ListSettlements(billingmodule.ListSettlementsRequest{})
	if err != nil {
		if errors.Is(err, billingmodule.ErrNilKeeper) {
			return BillingListSettlementsResponse{}, errBillingKeeperNotWired
		}
		return BillingListSettlementsResponse{}, err
	}
	return BillingListSettlementsResponse{
		Settlements: resp.Settlements,
	}, nil
}
