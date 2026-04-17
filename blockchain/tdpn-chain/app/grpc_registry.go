package app

import (
	"errors"

	vpnbillingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	vpngovernancepb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpngovernance/v1"
	vpnrewardspb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1"
	vpnslashingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1"
	vpnsponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
	vpnvalidatorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnvalidator/v1"
	billingmodule "github.com/tdpn/tdpn-chain/x/vpnbilling/module"
	governancemodule "github.com/tdpn/tdpn-chain/x/vpngovernance/module"
	rewardsmodule "github.com/tdpn/tdpn-chain/x/vpnrewards/module"
	slashingmodule "github.com/tdpn/tdpn-chain/x/vpnslashing/module"
	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
	validatormodule "github.com/tdpn/tdpn-chain/x/vpnvalidator/module"
	"google.golang.org/grpc"
)

var (
	errNilGRPCRegistrar = errors.New("grpc registrar is nil")
	errNilChainScaffold = errors.New("chain scaffold is nil")
)

// RegisterGRPCServices wires all module Msg/Query gRPC services to the given registrar.
func (s *ChainScaffold) RegisterGRPCServices(registrar grpc.ServiceRegistrar) error {
	if registrar == nil {
		return errNilGRPCRegistrar
	}
	if s == nil {
		return errNilChainScaffold
	}

	vpnbillingpb.RegisterMsgServer(registrar, billingmodule.NewProtoMsgServerAdapter(s.BillingModule.Keeper))
	vpnbillingpb.RegisterQueryServer(registrar, billingmodule.NewProtoQueryServerAdapter(s.BillingModule.Keeper))

	vpnrewardspb.RegisterMsgServer(registrar, rewardsmodule.NewGRPCMsgAdapter(rewardsmodule.NewMsgServer(s.RewardsModule.Keeper)))
	vpnrewardspb.RegisterQueryServer(registrar, rewardsmodule.NewGRPCQueryAdapter(rewardsmodule.NewQueryServer(s.RewardsModule.Keeper)))

	vpnslashingpb.RegisterMsgServer(registrar, slashingmodule.NewGRPCMsgAdapter(slashingmodule.NewMsgServer(s.SlashingModule.Keeper)))
	vpnslashingpb.RegisterQueryServer(registrar, slashingmodule.NewGRPCQueryAdapter(slashingmodule.NewQueryServer(s.SlashingModule.Keeper)))

	vpnsponsorpb.RegisterMsgServer(registrar, sponsormodule.NewGRPCMsgServerAdapter(s.SponsorModule.Keeper))
	vpnsponsorpb.RegisterQueryServer(registrar, sponsormodule.NewGRPCQueryServerAdapter(s.SponsorModule.Keeper))
	vpnvalidatorpb.RegisterMsgServer(registrar, validatormodule.NewGRPCMsgServerAdapter(s.ValidatorModule.Keeper))
	vpnvalidatorpb.RegisterQueryServer(registrar, validatormodule.NewGRPCQueryServerAdapter(s.ValidatorModule.Keeper))
	vpngovernancepb.RegisterMsgServer(registrar, governancemodule.NewProtoMsgServerAdapter(s.GovernanceModule.Keeper))
	vpngovernancepb.RegisterQueryServer(registrar, governancemodule.NewProtoQueryServerAdapter(s.GovernanceModule.Keeper))

	return nil
}
