package module

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

var (
	ErrNilKeeper              = errors.New("vpnsponsor: keeper is nil")
	ErrInvalidAuthorization   = errors.New("vpnsponsor: invalid authorization")
	ErrInvalidDelegation      = errors.New("vpnsponsor: invalid delegation")
	ErrAuthorizationConflict  = errors.New("vpnsponsor: authorization conflict")
	ErrDelegationConflict     = errors.New("vpnsponsor: delegation conflict")
	ErrAuthorizationNotFound  = errors.New("vpnsponsor: authorization not found")
	ErrUnauthorizedDelegation = errors.New("vpnsponsor: unauthorized delegation")
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
	Delegation      types.DelegatedSessionCredit
	CurrentTimeUnix int64
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

type currentTimeUnixContextKey struct{}

func NewMsgServer(k *keeper.Keeper) MsgServer {
	return MsgServer{keeper: k}
}

// WithCurrentTimeUnix stores an explicit unix timestamp in context for deterministic expiry checks.
func WithCurrentTimeUnix(ctx context.Context, currentTimeUnix int64) context.Context {
	return context.WithValue(ctx, currentTimeUnixContextKey{}, currentTimeUnix)
}

// CurrentTimeUnixFromContext extracts an explicit unix timestamp from context.
// It accepts either int64 unix seconds or time.Time values.
func CurrentTimeUnixFromContext(ctx context.Context) int64 {
	if ctx == nil {
		return 0
	}
	raw := ctx.Value(currentTimeUnixContextKey{})
	switch value := raw.(type) {
	case int64:
		return value
	case time.Time:
		return value.Unix()
	default:
		return 0
	}
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

	// Preserve keeper-level replay semantics: only enforce linked authorization
	// subject checks for new delegations.
	if !existed && strings.TrimSpace(req.Delegation.AuthorizationID) != "" {
		authorization, ok := s.keeper.GetAuthorization(req.Delegation.AuthorizationID)
		if !ok {
			return DelegateCreditResponse{
				Delegation: req.Delegation,
				Existed:    existed,
			}, fmt.Errorf("%w: authorization_id=%s", ErrAuthorizationNotFound, req.Delegation.AuthorizationID)
		}
		if strings.TrimSpace(authorization.SponsorID) == "" || strings.TrimSpace(authorization.AppID) == "" {
			return DelegateCreditResponse{
				Delegation: req.Delegation,
				Existed:    existed,
			}, fmt.Errorf("%w: authorization_id=%s has no sponsor/app subject", ErrUnauthorizedDelegation, req.Delegation.AuthorizationID)
		}
	}

	record, err := s.keeper.DelegateSessionCreditAtUnix(req.Delegation, req.CurrentTimeUnix)
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
