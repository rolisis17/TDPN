package module

import (
	"context"
	"errors"
	"time"

	sponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

var _ sponsorpb.MsgServer = (*GRPCMsgServerAdapter)(nil)
var _ sponsorpb.QueryServer = (*GRPCQueryServerAdapter)(nil)

// GRPCMsgServerAdapter adapts module MsgServer to protobuf gRPC MsgServer.
type GRPCMsgServerAdapter struct {
	sponsorpb.UnimplementedMsgServer
	server MsgServer
}

func NewGRPCMsgServerAdapter(k *keeper.Keeper) *GRPCMsgServerAdapter {
	return &GRPCMsgServerAdapter{
		server: NewMsgServer(k),
	}
}

func (a *GRPCMsgServerAdapter) CreateAuthorization(_ context.Context, req *sponsorpb.MsgCreateAuthorizationRequest) (*sponsorpb.MsgCreateAuthorizationResponse, error) {
	resp, err := a.server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: fromProtoAuthorization(req.GetAuthorization()),
	})
	if err != nil {
		return nil, err
	}

	return &sponsorpb.MsgCreateAuthorizationResponse{
		Authorization: toProtoAuthorization(resp.Authorization),
	}, nil
}

func (a *GRPCMsgServerAdapter) DelegateSessionCredit(ctx context.Context, req *sponsorpb.MsgDelegateSessionCreditRequest) (*sponsorpb.MsgDelegateSessionCreditResponse, error) {
	currentTimeUnix := CurrentTimeUnixFromContext(ctx)
	if currentTimeUnix <= 0 {
		// gRPC client context values do not propagate over the transport; use server time when unset.
		currentTimeUnix = time.Now().Unix()
	}

	resp, err := a.server.DelegateCredit(DelegateCreditRequest{
		Delegation:      fromProtoDelegation(req.GetDelegation()),
		CurrentTimeUnix: currentTimeUnix,
	})
	if err != nil {
		return nil, err
	}

	return &sponsorpb.MsgDelegateSessionCreditResponse{
		Delegation: toProtoDelegation(resp.Delegation),
	}, nil
}

// GRPCQueryServerAdapter adapts module QueryServer to protobuf gRPC QueryServer.
type GRPCQueryServerAdapter struct {
	sponsorpb.UnimplementedQueryServer
	server QueryServer
}

func NewGRPCQueryServerAdapter(k *keeper.Keeper) *GRPCQueryServerAdapter {
	return &GRPCQueryServerAdapter{
		server: NewQueryServer(k),
	}
}

func (a *GRPCQueryServerAdapter) SponsorAuthorization(_ context.Context, req *sponsorpb.QuerySponsorAuthorizationRequest) (*sponsorpb.QuerySponsorAuthorizationResponse, error) {
	resp, err := a.server.GetAuthorization(GetAuthorizationRequest{
		AuthorizationID: req.GetAuthorizationId(),
	})
	if err != nil {
		if errors.Is(err, ErrAuthorizationNotFound) {
			return &sponsorpb.QuerySponsorAuthorizationResponse{Found: false}, nil
		}
		return nil, err
	}

	return &sponsorpb.QuerySponsorAuthorizationResponse{
		Authorization: toProtoAuthorization(resp.Authorization),
		Found:         true,
	}, nil
}

func (a *GRPCQueryServerAdapter) DelegatedSessionCredit(_ context.Context, req *sponsorpb.QueryDelegatedSessionCreditRequest) (*sponsorpb.QueryDelegatedSessionCreditResponse, error) {
	resp, err := a.server.GetDelegation(GetDelegationRequest{
		ReservationID: req.GetReservationId(),
	})
	if err != nil {
		if errors.Is(err, ErrDelegationNotFound) {
			return &sponsorpb.QueryDelegatedSessionCreditResponse{Found: false}, nil
		}
		return nil, err
	}

	return &sponsorpb.QueryDelegatedSessionCreditResponse{
		Delegation: toProtoDelegation(resp.Delegation),
		Found:      true,
	}, nil
}

func (a *GRPCQueryServerAdapter) ListSponsorAuthorizations(_ context.Context, _ *sponsorpb.QueryListSponsorAuthorizationsRequest) (*sponsorpb.QueryListSponsorAuthorizationsResponse, error) {
	resp, err := a.server.ListAuthorizations(ListAuthorizationsRequest{})
	if err != nil {
		return nil, err
	}

	records := make([]*sponsorpb.SponsorAuthorization, 0, len(resp.Authorizations))
	for _, authorization := range resp.Authorizations {
		records = append(records, toProtoAuthorization(authorization))
	}
	return &sponsorpb.QueryListSponsorAuthorizationsResponse{
		Authorizations: records,
	}, nil
}

func (a *GRPCQueryServerAdapter) ListDelegatedSessionCredits(_ context.Context, _ *sponsorpb.QueryListDelegatedSessionCreditsRequest) (*sponsorpb.QueryListDelegatedSessionCreditsResponse, error) {
	resp, err := a.server.ListDelegations(ListDelegationsRequest{})
	if err != nil {
		return nil, err
	}

	records := make([]*sponsorpb.DelegatedSessionCredit, 0, len(resp.Delegations))
	for _, delegation := range resp.Delegations {
		records = append(records, toProtoDelegation(delegation))
	}
	return &sponsorpb.QueryListDelegatedSessionCreditsResponse{
		Delegations: records,
	}, nil
}

func fromProtoAuthorization(pb *sponsorpb.SponsorAuthorization) sponsortypes.SponsorAuthorization {
	if pb == nil {
		return sponsortypes.SponsorAuthorization{}
	}

	return sponsortypes.SponsorAuthorization{
		AuthorizationID: pb.GetAuthorizationId(),
		SponsorID:       pb.GetSponsorId(),
		AppID:           pb.GetAppId(),
		MaxCredits:      pb.GetMaxCredits(),
		ExpiresAtUnix:   pb.GetExpiresAtUnix(),
	}
}

func toProtoAuthorization(record sponsortypes.SponsorAuthorization) *sponsorpb.SponsorAuthorization {
	return &sponsorpb.SponsorAuthorization{
		AuthorizationId: record.AuthorizationID,
		SponsorId:       record.SponsorID,
		AppId:           record.AppID,
		MaxCredits:      record.MaxCredits,
		ExpiresAtUnix:   record.ExpiresAtUnix,
	}
}

func fromProtoDelegation(pb *sponsorpb.DelegatedSessionCredit) sponsortypes.DelegatedSessionCredit {
	if pb == nil {
		return sponsortypes.DelegatedSessionCredit{}
	}

	return sponsortypes.DelegatedSessionCredit{
		ReservationID:   pb.GetReservationId(),
		AuthorizationID: pb.GetAuthorizationId(),
		SponsorID:       pb.GetSponsorId(),
		AppID:           pb.GetAppId(),
		EndUserID:       pb.GetEndUserId(),
		SessionID:       pb.GetSessionId(),
		Credits:         pb.GetCredits(),
		Status:          statusFromProto(pb.GetStatus()),
	}
}

func toProtoDelegation(record sponsortypes.DelegatedSessionCredit) *sponsorpb.DelegatedSessionCredit {
	return &sponsorpb.DelegatedSessionCredit{
		ReservationId:   record.ReservationID,
		AuthorizationId: record.AuthorizationID,
		SponsorId:       record.SponsorID,
		AppId:           record.AppID,
		EndUserId:       record.EndUserID,
		SessionId:       record.SessionID,
		Credits:         record.Credits,
		Status:          statusToProto(record.Status),
	}
}

func statusFromProto(status sponsorpb.ReconciliationStatus) chaintypes.ReconciliationStatus {
	switch status {
	case sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING:
		return chaintypes.ReconciliationPending
	case sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED:
		return chaintypes.ReconciliationSubmitted
	case sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED:
		return chaintypes.ReconciliationConfirmed
	case sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED:
		return chaintypes.ReconciliationFailed
	default:
		return ""
	}
}

func statusToProto(status chaintypes.ReconciliationStatus) sponsorpb.ReconciliationStatus {
	switch status {
	case chaintypes.ReconciliationPending:
		return sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING
	case chaintypes.ReconciliationSubmitted:
		return sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED
	case chaintypes.ReconciliationConfirmed:
		return sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED
	case chaintypes.ReconciliationFailed:
		return sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED
	default:
		return sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED
	}
}
