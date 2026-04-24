package module

import (
	"errors"
	"fmt"

	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

var (
	ErrDelegationNotFound = errors.New("vpnsponsor: delegation not found")
)

const maxQueryListResults = 1000

// GetAuthorizationRequest requests sponsor authorization by authorization ID.
type GetAuthorizationRequest struct {
	AuthorizationID string
}

// GetAuthorizationResponse contains an authorization lookup result.
type GetAuthorizationResponse struct {
	Authorization types.SponsorAuthorization
}

// GetDelegationRequest requests delegated credits by reservation ID.
type GetDelegationRequest struct {
	ReservationID string
}

// GetDelegationResponse contains a delegation lookup result.
type GetDelegationResponse struct {
	Delegation types.DelegatedSessionCredit
}

// ListAuthorizationsRequest requests the full authorization read-model.
type ListAuthorizationsRequest struct{}

// ListAuthorizationsResponse contains all authorizations sorted by AuthorizationID.
type ListAuthorizationsResponse struct {
	Authorizations []types.SponsorAuthorization
}

// ListDelegationsRequest requests the full delegation read-model.
type ListDelegationsRequest struct{}

// ListDelegationsResponse contains all delegations sorted by ReservationID.
type ListDelegationsResponse struct {
	Delegations []types.DelegatedSessionCredit
}

// QueryServer exposes a lightweight Cosmos-style query surface for vpnsponsor.
type QueryServer struct {
	keeper *keeper.Keeper
}

func NewQueryServer(k *keeper.Keeper) QueryServer {
	return QueryServer{keeper: k}
}

func (s QueryServer) GetAuthorization(req GetAuthorizationRequest) (GetAuthorizationResponse, error) {
	if s.keeper == nil {
		return GetAuthorizationResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetAuthorization(req.AuthorizationID)
	if !ok {
		return GetAuthorizationResponse{}, fmt.Errorf("%w: authorization_id=%s", ErrAuthorizationNotFound, req.AuthorizationID)
	}
	return GetAuthorizationResponse{Authorization: record}, nil
}

func (s QueryServer) GetDelegation(req GetDelegationRequest) (GetDelegationResponse, error) {
	if s.keeper == nil {
		return GetDelegationResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetDelegation(req.ReservationID)
	if !ok {
		return GetDelegationResponse{}, fmt.Errorf("%w: reservation_id=%s", ErrDelegationNotFound, req.ReservationID)
	}
	return GetDelegationResponse{Delegation: record}, nil
}

func (s QueryServer) ListAuthorizations(_ ListAuthorizationsRequest) (ListAuthorizationsResponse, error) {
	if s.keeper == nil {
		return ListAuthorizationsResponse{}, ErrNilKeeper
	}

	records, err := s.keeper.ListAuthorizationsWithError()
	if err != nil {
		return ListAuthorizationsResponse{}, err
	}
	return ListAuthorizationsResponse{
		Authorizations: clampAuthorizations(records),
	}, nil
}

func (s QueryServer) ListDelegations(_ ListDelegationsRequest) (ListDelegationsResponse, error) {
	if s.keeper == nil {
		return ListDelegationsResponse{}, ErrNilKeeper
	}

	records, err := s.keeper.ListDelegationsWithError()
	if err != nil {
		return ListDelegationsResponse{}, err
	}
	return ListDelegationsResponse{
		Delegations: clampDelegations(records),
	}, nil
}

func clampAuthorizations(records []types.SponsorAuthorization) []types.SponsorAuthorization {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}

func clampDelegations(records []types.DelegatedSessionCredit) []types.DelegatedSessionCredit {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}
