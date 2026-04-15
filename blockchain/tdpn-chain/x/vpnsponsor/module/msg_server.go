package module

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

var (
	ErrNilKeeper             = errors.New("vpnsponsor: keeper is nil")
	ErrInvalidAuthorization  = errors.New("vpnsponsor: invalid authorization")
	ErrInvalidDelegation     = errors.New("vpnsponsor: invalid delegation")
	ErrAuthorizationConflict = errors.New("vpnsponsor: authorization conflict")
	ErrDelegationConflict    = errors.New("vpnsponsor: delegation conflict")
	ErrAuthorizationNotFound = errors.New("vpnsponsor: authorization not found")
)

// AuthorizeSponsorRequest captures an intent to create or replay sponsor authorization.
type AuthorizeSponsorRequest struct {
	Authorization types.SponsorAuthorization
}

// AuthorizeSponsorResponse returns persisted authorization plus replay hints.
type AuthorizeSponsorResponse struct {
	Authorization types.SponsorAuthorization
	Existed       bool
	Idempotent    bool
}

// DelegateCreditRequest captures an intent to delegate sponsor credits to a session.
type DelegateCreditRequest struct {
	Delegation types.DelegatedSessionCredit
}

// DelegateCreditResponse returns persisted delegation plus replay hints.
type DelegateCreditResponse struct {
	Delegation types.DelegatedSessionCredit
	Existed    bool
	Idempotent bool
}

// MsgServer exposes a lightweight Cosmos-style message surface for vpnsponsor.
type MsgServer struct {
	keeper *keeper.Keeper
}

func NewMsgServer(k *keeper.Keeper) MsgServer {
	return MsgServer{keeper: k}
}

func (s MsgServer) AuthorizeSponsor(req AuthorizeSponsorRequest) (AuthorizeSponsorResponse, error) {
	if s.keeper == nil {
		return AuthorizeSponsorResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Authorization.AuthorizationID != "" {
		_, existed = s.keeper.GetAuthorization(req.Authorization.AuthorizationID)
	}

	record, err := s.keeper.CreateAuthorization(req.Authorization)
	resp := AuthorizeSponsorResponse{
		Authorization: record,
		Existed:       existed,
		Idempotent:    existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrAuthorizationConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidAuthorization, err)
	}
	return resp, nil
}

func (s MsgServer) DelegateCredit(req DelegateCreditRequest) (DelegateCreditResponse, error) {
	if s.keeper == nil {
		return DelegateCreditResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Delegation.ReservationID != "" {
		_, existed = s.keeper.GetDelegation(req.Delegation.ReservationID)
	}

	if strings.TrimSpace(req.Delegation.AuthorizationID) != "" {
		if _, ok := s.keeper.GetAuthorization(req.Delegation.AuthorizationID); !ok {
			return DelegateCreditResponse{
				Delegation: req.Delegation,
				Existed:    existed,
			}, fmt.Errorf("%w: authorization_id=%s", ErrAuthorizationNotFound, req.Delegation.AuthorizationID)
		}
	}

	record, err := s.keeper.DelegateSessionCredit(req.Delegation)
	resp := DelegateCreditResponse{
		Delegation: record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrDelegationConflict, err)
		}
		if strings.Contains(err.Error(), "not found") {
			return resp, fmt.Errorf("%w: %v", ErrAuthorizationNotFound, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidDelegation, err)
	}
	return resp, nil
}
