package app

import (
	"context"
	"errors"

	billingmodule "github.com/tdpn/tdpn-chain/x/vpnbilling/module"
	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

var (
	errBillingKeeperNotWired = errors.New("vpnbilling keeper is not wired")
)

// BillingMsgServer captures phase-1 vpnbilling stateful operations without Cosmos SDK dependencies.
type BillingMsgServer interface {
	CreateReservation(context.Context, BillingCreateReservationRequest) (BillingCreateReservationResponse, error)
	FinalizeSettlement(context.Context, BillingFinalizeSettlementRequest) (BillingFinalizeSettlementResponse, error)
}

type BillingCreateReservationRequest struct {
	Record billingtypes.CreditReservation
}

type BillingCreateReservationResponse struct {
	Reservation billingtypes.CreditReservation
	Replay      bool
}

type BillingFinalizeSettlementRequest struct {
	Record billingtypes.SettlementRecord
}

type BillingFinalizeSettlementResponse struct {
	Settlement billingtypes.SettlementRecord
	Replay     bool
}

type billingMsgServer struct {
	msgServer billingmodule.MsgServer
}

func (m billingMsgServer) CreateReservation(_ context.Context, req BillingCreateReservationRequest) (BillingCreateReservationResponse, error) {
	resp, err := m.msgServer.ReserveCredits(billingmodule.ReserveCreditsRequest{Reservation: req.Record})
	if err != nil {
		if errors.Is(err, billingmodule.ErrNilKeeper) {
			return BillingCreateReservationResponse{}, errBillingKeeperNotWired
		}
		return BillingCreateReservationResponse{}, err
	}
	return BillingCreateReservationResponse{
		Reservation: resp.Reservation,
		Replay:      resp.Idempotent,
	}, nil
}

func (m billingMsgServer) FinalizeSettlement(_ context.Context, req BillingFinalizeSettlementRequest) (BillingFinalizeSettlementResponse, error) {
	resp, err := m.msgServer.FinalizeUsage(billingmodule.FinalizeUsageRequest{Settlement: req.Record})
	if err != nil {
		if errors.Is(err, billingmodule.ErrNilKeeper) {
			return BillingFinalizeSettlementResponse{}, errBillingKeeperNotWired
		}
		return BillingFinalizeSettlementResponse{}, err
	}
	return BillingFinalizeSettlementResponse{
		Settlement: resp.Settlement,
		Replay:     resp.Idempotent,
	}, nil
}
