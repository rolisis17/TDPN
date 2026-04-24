package app

import (
	"context"
	"errors"

	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

var (
	errSponsorKeeperNotWired = errors.New("vpnsponsor keeper is not wired")
)

// SponsorMsgServer exposes phase-1 vpnsponsor operations through the scaffold.
type SponsorMsgServer interface {
	CreateAuthorization(context.Context, SponsorCreateAuthorizationRequest) (SponsorCreateAuthorizationResponse, error)
	DelegateCredit(context.Context, SponsorDelegateCreditRequest) (SponsorDelegateCreditResponse, error)
}

type SponsorCreateAuthorizationRequest struct {
	Record sponsortypes.SponsorAuthorization
}

type SponsorCreateAuthorizationResponse struct {
	Authorization sponsortypes.SponsorAuthorization
	Replay        bool
}

type SponsorDelegateCreditRequest struct {
	Record sponsortypes.DelegatedSessionCredit
}

type SponsorDelegateCreditResponse struct {
	Delegation sponsortypes.DelegatedSessionCredit
	Replay     bool
}

type sponsorMsgServer struct {
	msgServer sponsormodule.MsgServer
}

func (m sponsorMsgServer) CreateAuthorization(_ context.Context, req SponsorCreateAuthorizationRequest) (SponsorCreateAuthorizationResponse, error) {
	resp, err := m.msgServer.AuthorizeSponsor(sponsormodule.AuthorizeSponsorRequest{Authorization: req.Record})
	if err != nil {
		if errors.Is(err, sponsormodule.ErrNilKeeper) {
			return SponsorCreateAuthorizationResponse{}, errSponsorKeeperNotWired
		}
		return SponsorCreateAuthorizationResponse{}, err
	}
	return SponsorCreateAuthorizationResponse{
		Authorization: resp.Authorization,
		Replay:        resp.Idempotent,
	}, nil
}

func (m sponsorMsgServer) DelegateCredit(ctx context.Context, req SponsorDelegateCreditRequest) (SponsorDelegateCreditResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return SponsorDelegateCreditResponse{}, err
		}
	}
	currentTimeUnix := sponsormodule.CurrentTimeUnixFromContext(ctx)

	resp, err := m.msgServer.DelegateCredit(sponsormodule.DelegateCreditRequest{
		Delegation:      req.Record,
		CurrentTimeUnix: currentTimeUnix,
	})
	if err != nil {
		if errors.Is(err, sponsormodule.ErrNilKeeper) {
			return SponsorDelegateCreditResponse{}, errSponsorKeeperNotWired
		}
		return SponsorDelegateCreditResponse{}, err
	}
	return SponsorDelegateCreditResponse{
		Delegation: resp.Delegation,
		Replay:     resp.Idempotent,
	}, nil
}
