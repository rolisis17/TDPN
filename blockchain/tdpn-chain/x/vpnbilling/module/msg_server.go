package module

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

var (
	ErrNilKeeper           = errors.New("vpnbilling: keeper is nil")
	ErrInvalidReservation  = errors.New("vpnbilling: invalid reservation")
	ErrInvalidSettlement   = errors.New("vpnbilling: invalid settlement")
	ErrReservationConflict = errors.New("vpnbilling: reservation conflict")
	ErrSettlementConflict  = errors.New("vpnbilling: settlement conflict")
	ErrReservationNotFound = errors.New("vpnbilling: reservation not found")
)

// ReserveCreditsRequest captures an intent to reserve prepaid credits for a session.
type ReserveCreditsRequest struct {
	Reservation types.CreditReservation
}

// ReserveCreditsResponse returns the persisted reservation plus idempotency flags.
type ReserveCreditsResponse struct {
	Reservation types.CreditReservation
	Existed     bool
	Idempotent  bool
}

// FinalizeUsageRequest captures an intent to finalize billable usage.
type FinalizeUsageRequest struct {
	Settlement types.SettlementRecord
}

// FinalizeUsageResponse returns the persisted settlement plus idempotency flags.
type FinalizeUsageResponse struct {
	Settlement types.SettlementRecord
	Existed    bool
	Idempotent bool
}

// MsgServer exposes a lightweight Cosmos-style message surface for vpnbilling.
type MsgServer struct {
	keeper *keeper.Keeper
}

func NewMsgServer(k *keeper.Keeper) MsgServer {
	return MsgServer{keeper: k}
}

func (s MsgServer) ReserveCredits(req ReserveCreditsRequest) (ReserveCreditsResponse, error) {
	if s.keeper == nil {
		return ReserveCreditsResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Reservation.ReservationID != "" {
		_, existed = s.keeper.GetReservation(req.Reservation.ReservationID)
	}

	record, err := s.keeper.CreateReservation(req.Reservation)
	resp := ReserveCreditsResponse{
		Reservation: record,
		Existed:     existed,
		Idempotent:  existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrReservationConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidReservation, err)
	}
	return resp, nil
}

func (s MsgServer) FinalizeUsage(req FinalizeUsageRequest) (FinalizeUsageResponse, error) {
	if s.keeper == nil {
		return FinalizeUsageResponse{}, ErrNilKeeper
	}
	if err := req.Settlement.ValidateBasic(); err != nil {
		return FinalizeUsageResponse{}, fmt.Errorf("%w: %v", ErrInvalidSettlement, err)
	}
	if strings.TrimSpace(req.Settlement.ReservationID) == "" {
		return FinalizeUsageResponse{}, fmt.Errorf("%w: reservation id is required", ErrInvalidSettlement)
	}
	if _, ok := s.keeper.GetReservation(req.Settlement.ReservationID); !ok {
		return FinalizeUsageResponse{}, fmt.Errorf("%w: reservation_id=%s", ErrReservationNotFound, req.Settlement.ReservationID)
	}

	existed := false
	if req.Settlement.SettlementID != "" {
		_, existed = s.keeper.GetSettlement(req.Settlement.SettlementID)
	}

	record, err := s.keeper.FinalizeSettlement(req.Settlement)
	resp := FinalizeUsageResponse{
		Settlement: record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrSettlementConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidSettlement, err)
	}
	return resp, nil
}
