package app

import (
	"context"
	"errors"

	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

// SponsorQueryServer exposes phase-1 vpnsponsor query operations through the scaffold.
type SponsorQueryServer interface {
	GetAuthorization(context.Context, SponsorGetAuthorizationRequest) (SponsorGetAuthorizationResponse, error)
	GetDelegation(context.Context, SponsorGetDelegationRequest) (SponsorGetDelegationResponse, error)
	ListAuthorizations(context.Context, SponsorListAuthorizationsRequest) (SponsorListAuthorizationsResponse, error)
	ListDelegations(context.Context, SponsorListDelegationsRequest) (SponsorListDelegationsResponse, error)
}

type SponsorGetAuthorizationRequest struct {
	AuthorizationID string
}

type SponsorGetAuthorizationResponse struct {
	Authorization sponsortypes.SponsorAuthorization
	Found         bool
}

type SponsorGetDelegationRequest struct {
	ReservationID string
}

type SponsorGetDelegationResponse struct {
	Delegation sponsortypes.DelegatedSessionCredit
	Found      bool
}

type SponsorListAuthorizationsRequest struct{}

type SponsorListAuthorizationsResponse struct {
	Authorizations []sponsortypes.SponsorAuthorization
}

type SponsorListDelegationsRequest struct{}

type SponsorListDelegationsResponse struct {
	Delegations []sponsortypes.DelegatedSessionCredit
}

type sponsorQueryServer struct {
	queryServer sponsormodule.QueryServer
}

func (m sponsorQueryServer) GetAuthorization(_ context.Context, req SponsorGetAuthorizationRequest) (SponsorGetAuthorizationResponse, error) {
	resp, err := m.queryServer.GetAuthorization(sponsormodule.GetAuthorizationRequest{AuthorizationID: req.AuthorizationID})
	if err != nil {
		if errors.Is(err, sponsormodule.ErrNilKeeper) {
			return SponsorGetAuthorizationResponse{}, errSponsorKeeperNotWired
		}
		if errors.Is(err, sponsormodule.ErrAuthorizationNotFound) {
			return SponsorGetAuthorizationResponse{Found: false}, nil
		}
		return SponsorGetAuthorizationResponse{}, err
	}
	return SponsorGetAuthorizationResponse{
		Authorization: resp.Authorization,
		Found:         true,
	}, nil
}

func (m sponsorQueryServer) GetDelegation(_ context.Context, req SponsorGetDelegationRequest) (SponsorGetDelegationResponse, error) {
	resp, err := m.queryServer.GetDelegation(sponsormodule.GetDelegationRequest{ReservationID: req.ReservationID})
	if err != nil {
		if errors.Is(err, sponsormodule.ErrNilKeeper) {
			return SponsorGetDelegationResponse{}, errSponsorKeeperNotWired
		}
		if errors.Is(err, sponsormodule.ErrDelegationNotFound) {
			return SponsorGetDelegationResponse{Found: false}, nil
		}
		return SponsorGetDelegationResponse{}, err
	}
	return SponsorGetDelegationResponse{
		Delegation: resp.Delegation,
		Found:      true,
	}, nil
}

func (m sponsorQueryServer) ListAuthorizations(_ context.Context, _ SponsorListAuthorizationsRequest) (SponsorListAuthorizationsResponse, error) {
	resp, err := m.queryServer.ListAuthorizations(sponsormodule.ListAuthorizationsRequest{})
	if err != nil {
		if errors.Is(err, sponsormodule.ErrNilKeeper) {
			return SponsorListAuthorizationsResponse{}, errSponsorKeeperNotWired
		}
		return SponsorListAuthorizationsResponse{}, err
	}
	return SponsorListAuthorizationsResponse{
		Authorizations: resp.Authorizations,
	}, nil
}

func (m sponsorQueryServer) ListDelegations(_ context.Context, _ SponsorListDelegationsRequest) (SponsorListDelegationsResponse, error) {
	resp, err := m.queryServer.ListDelegations(sponsormodule.ListDelegationsRequest{})
	if err != nil {
		if errors.Is(err, sponsormodule.ErrNilKeeper) {
			return SponsorListDelegationsResponse{}, errSponsorKeeperNotWired
		}
		return SponsorListDelegationsResponse{}, err
	}
	return SponsorListDelegationsResponse{
		Delegations: resp.Delegations,
	}, nil
}
