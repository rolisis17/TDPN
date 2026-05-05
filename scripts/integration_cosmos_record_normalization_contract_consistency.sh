#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

assert_literal() {
  local file_path="$1"
  local required_literal="$2"
  local check_label="$3"

  if [[ ! -f "$file_path" ]]; then
    echo "cosmos normalization contract missing file: $file_path ($check_label)"
    exit 1
  fi

  if ! rg -Fq -- "$required_literal" "$file_path"; then
    echo "cosmos normalization contract missing token: $check_label"
    echo "  file: $file_path"
    echo "  required literal: $required_literal"
    exit 1
  fi
}

need_cmd rg

declare -a checks=(
  "blockchain/tdpn-chain/x/vpnbilling/types/records.go|func (r CreditReservation) Canonicalize() CreditReservation|vpnbilling credit reservation canonicalizer"
  "blockchain/tdpn-chain/x/vpnbilling/types/records.go|func (r SettlementRecord) Canonicalize() SettlementRecord|vpnbilling settlement canonicalizer"
  "blockchain/tdpn-chain/x/vpnbilling/types/records.go|func canonicalToken(value string) string|vpnbilling canonical token helper"
  "blockchain/tdpn-chain/x/vpnbilling/keeper/keeper.go|func normalizeReservation(record types.CreditReservation) types.CreditReservation|vpnbilling reservation normalizer"
  "blockchain/tdpn-chain/x/vpnbilling/keeper/keeper.go|record = record.Canonicalize()|vpnbilling keeper canonicalization invocation"
  "blockchain/tdpn-chain/x/vpnbilling/keeper/keeper.go|func normalizeSettlement(record types.SettlementRecord) types.SettlementRecord|vpnbilling settlement normalizer"
  "blockchain/tdpn-chain/x/vpnbilling/module/proto_grpc_adapters_test.go|func TestProtoGrpcAdaptersCanonicalizeReserveOnWriteAndMixedCaseQuery(t *testing.T) {|vpnbilling proto grpc adapter reserve canonicalization coverage"
  "blockchain/tdpn-chain/x/vpnbilling/module/proto_grpc_adapters_test.go|func TestProtoGrpcAdaptersCanonicalizeFinalizeUsageOnWriteAndMixedCaseQuery(t *testing.T) {|vpnbilling proto grpc adapter settlement canonicalization coverage"

  "blockchain/tdpn-chain/x/vpnrewards/types/records.go|func (r RewardAccrual) Canonicalize() RewardAccrual|vpnrewards accrual canonicalizer"
  "blockchain/tdpn-chain/x/vpnrewards/types/records.go|func (r DistributionRecord) Canonicalize() DistributionRecord|vpnrewards distribution canonicalizer"
  "blockchain/tdpn-chain/x/vpnrewards/types/records.go|func canonicalIdentifier(value string) string|vpnrewards canonical identifier helper"
  "blockchain/tdpn-chain/x/vpnrewards/types/records.go|func canonicalStatus(value chaintypes.ReconciliationStatus, defaultValue chaintypes.ReconciliationStatus) chaintypes.ReconciliationStatus|vpnrewards canonical status helper"
  "blockchain/tdpn-chain/x/vpnrewards/keeper/keeper.go|func normalizeAccrual(record types.RewardAccrual) types.RewardAccrual|vpnrewards accrual normalizer"
  "blockchain/tdpn-chain/x/vpnrewards/keeper/keeper.go|normalized := record.Canonicalize()|vpnrewards keeper canonicalization invocation"
  "blockchain/tdpn-chain/x/vpnrewards/keeper/keeper.go|func normalizeDistribution(record types.DistributionRecord) types.DistributionRecord|vpnrewards distribution normalizer"
  "blockchain/tdpn-chain/x/vpnrewards/module/grpc_adapter_test.go|func TestGRPCAdaptersAccrualCanonicalWriteAndMixedCaseQuery(t *testing.T) {|vpnrewards grpc adapter accrual canonicalization coverage"
  "blockchain/tdpn-chain/x/vpnrewards/module/grpc_adapter_test.go|func TestGRPCAdaptersDistributionCanonicalWriteAndMixedCaseQuery(t *testing.T) {|vpnrewards grpc adapter distribution canonicalization coverage"

  "blockchain/tdpn-chain/x/vpnsponsor/types/records.go|func NormalizeSponsorAuthorization(record SponsorAuthorization) SponsorAuthorization|vpnsponsor authorization normalization helper"
  "blockchain/tdpn-chain/x/vpnsponsor/types/records.go|func NormalizeDelegatedSessionCredit(record DelegatedSessionCredit) DelegatedSessionCredit|vpnsponsor delegation normalization helper"
  "blockchain/tdpn-chain/x/vpnsponsor/types/records.go|func normalizeCaseInsensitiveIdentity(value string) string|vpnsponsor case-insensitive normalization helper"
  "blockchain/tdpn-chain/x/vpnsponsor/types/records.go|func normalizeCaseSensitiveIdentity(value string) string|vpnsponsor case-sensitive normalization helper"
  "blockchain/tdpn-chain/x/vpnsponsor/keeper/keeper.go|func normalizeAuthorization(record types.SponsorAuthorization) types.SponsorAuthorization|vpnsponsor authorization normalizer"
  "blockchain/tdpn-chain/x/vpnsponsor/keeper/keeper.go|func normalizeDelegation(record types.DelegatedSessionCredit) types.DelegatedSessionCredit|vpnsponsor delegation normalizer"
  "blockchain/tdpn-chain/x/vpnsponsor/module/grpc_adapter_test.go|func TestGRPCAdaptersCanonicalizeAuthorizationWriteAndMixedCaseQuery(t *testing.T) {|vpnsponsor grpc adapter authorization canonicalization coverage"
  "blockchain/tdpn-chain/x/vpnsponsor/module/grpc_adapter_test.go|func TestGRPCAdaptersCanonicalizeDelegationWriteAndMixedCaseQuery(t *testing.T) {|vpnsponsor grpc adapter delegation canonicalization coverage"

  "blockchain/tdpn-chain/x/vpnslashing/types/records.go|func NormalizeViolationType(value string) string|vpnslashing violation type canonicalizer"
  "blockchain/tdpn-chain/x/vpnslashing/types/records.go|var objectiveViolationTypeSet = map[string]struct{}{|vpnslashing violation allowlist"
  "blockchain/tdpn-chain/x/vpnslashing/keeper/keeper.go|record.ViolationType = types.NormalizeViolationType(record.ViolationType)|vpnslashing keeper violation normalization"
  "blockchain/tdpn-chain/x/vpnslashing/keeper/keeper.go|func normalizeEvidence(record types.SlashEvidence) types.SlashEvidence|vpnslashing evidence normalizer"
  "blockchain/tdpn-chain/x/vpnslashing/keeper/keeper.go|func normalizePenalty(record types.PenaltyDecision) types.PenaltyDecision|vpnslashing penalty normalizer"

  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|func normalizeEligibility(record types.ValidatorEligibility) types.ValidatorEligibility|vpnvalidator eligibility normalizer"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|normalized := normalizeEligibility(record)|vpnvalidator eligibility normalization invocation"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|canonicalID := canonicalValidatorID(validatorID)|vpnvalidator canonical lookup fallback for eligibility id"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|func selectCompatibilityEligibilityRecord(records []types.ValidatorEligibility, canonicalValidatorID string) (types.ValidatorEligibility, bool)|vpnvalidator compatibility lookup fallback selector"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|func dedupeCanonicalEligibilities(records []types.ValidatorEligibility) []types.ValidatorEligibility|vpnvalidator canonical dedupe helper for eligibilities"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|func canonicalValidatorID(validatorID string) string|vpnvalidator canonical eligibility lookup helper"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|normalizedExisting := normalizeEligibility(existing)|vpnvalidator canonical dedupe seed for eligibility"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|if !eligibilityRecordsEqual(normalizedExisting, normalized) {|vpnvalidator canonical dedupe guard for eligibility"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|func normalizeStatusRecord(record types.ValidatorStatusRecord) types.ValidatorStatusRecord|vpnvalidator status normalizer"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|normalized := normalizeStatusRecord(record)|vpnvalidator status normalization invocation"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|canonicalID := canonicalStatusID(statusID)|vpnvalidator canonical lookup fallback for status id"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|func selectCompatibilityStatusRecord(records []types.ValidatorStatusRecord, canonicalStatusID string) (types.ValidatorStatusRecord, bool)|vpnvalidator compatibility lookup fallback selector for status"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|func dedupeCanonicalStatusRecords(records []types.ValidatorStatusRecord) []types.ValidatorStatusRecord|vpnvalidator canonical dedupe helper for statuses"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|func canonicalStatusID(statusID string) string|vpnvalidator canonical status lookup helper"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|normalizedExisting := normalizeStatusRecord(existing)|vpnvalidator canonical dedupe seed for status"
  "blockchain/tdpn-chain/x/vpnvalidator/keeper/keeper.go|if !statusRecordEqual(normalizedExisting, normalized) {|vpnvalidator canonical dedupe guard for status"
  "blockchain/tdpn-chain/x/vpnvalidator/module/grpc_adapter_test.go|func TestGRPCAdaptersEligibilityCanonicalWriteAndMixedCaseQuery(t *testing.T) {|vpnvalidator grpc adapter eligibility canonicalization coverage"
  "blockchain/tdpn-chain/x/vpnvalidator/module/grpc_adapter_test.go|func TestGRPCAdaptersStatusCanonicalWriteAndMixedCaseQuery(t *testing.T) {|vpnvalidator grpc adapter status canonicalization coverage"

  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func normalizePolicy(record types.GovernancePolicy) types.GovernancePolicy|vpngovernance policy normalizer"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalized := normalizePolicy(record)|vpngovernance policy normalization invocation"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalizedID := canonicalPolicyID(policyID)|vpngovernance canonical lookup fallback for policy id"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func (k *Keeper) getPolicyByIDCompatibleLocked(rawID, canonicalID string) (types.GovernancePolicy, bool)|vpngovernance compatibility lookup helper for policy id"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func dedupeAndSortPolicies(records []types.GovernancePolicy) []types.GovernancePolicy|vpngovernance canonical dedupe helper for policies"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalizedExisting := normalizePolicy(existing)|vpngovernance canonical dedupe seed for policy"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|if !policyRecordsEqual(normalizedExisting, normalized) {|vpngovernance canonical dedupe guard for policy"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func normalizeDecision(record types.GovernanceDecision) types.GovernanceDecision|vpngovernance decision normalizer"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalized := normalizeDecision(record)|vpngovernance decision normalization invocation"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalizedID := canonicalDecisionID(decisionID)|vpngovernance canonical lookup fallback for decision id"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func (k *Keeper) getDecisionByIDCompatibleLocked(rawID, canonicalID string) (types.GovernanceDecision, bool)|vpngovernance compatibility lookup helper for decision id"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func dedupeAndSortDecisions(records []types.GovernanceDecision) []types.GovernanceDecision|vpngovernance canonical dedupe helper for decisions"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalizedExisting := normalizeDecision(existing)|vpngovernance canonical dedupe seed for decision"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|if !decisionRecordsEqual(normalizedExisting, normalized) {|vpngovernance canonical dedupe guard for decision"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func normalizeAuditAction(record types.GovernanceAuditAction) types.GovernanceAuditAction|vpngovernance audit action normalizer"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalized := normalizeAuditAction(record)|vpngovernance audit action normalization invocation"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalizedID := canonicalAuditActionID(actionID)|vpngovernance canonical lookup fallback for audit action id"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func (k *Keeper) getAuditActionByIDCompatibleLocked(rawID, canonicalID string) (types.GovernanceAuditAction, bool)|vpngovernance compatibility lookup helper for audit action id"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|func dedupeAndSortAuditActions(records []types.GovernanceAuditAction) []types.GovernanceAuditAction|vpngovernance canonical dedupe helper for audit actions"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|normalizedExisting := normalizeAuditAction(existing)|vpngovernance canonical dedupe seed for audit action"
  "blockchain/tdpn-chain/x/vpngovernance/keeper/keeper.go|if !auditActionRecordsEqual(normalizedExisting, normalized) {|vpngovernance canonical dedupe guard for audit action"
  "blockchain/tdpn-chain/x/vpngovernance/module/proto_grpc_adapters_test.go|func TestProtoGrpcAdaptersCanonicalizePolicyIDOnWriteAndMixedCaseQuery(t *testing.T) {|vpngovernance proto grpc adapter policy canonicalization coverage"
  "blockchain/tdpn-chain/x/vpngovernance/module/proto_grpc_adapters_test.go|func TestProtoGrpcAdaptersCanonicalizeDecisionIDOnWriteAndMixedCaseQuery(t *testing.T) {|vpngovernance proto grpc adapter decision canonicalization coverage"
  "blockchain/tdpn-chain/x/vpngovernance/module/proto_grpc_adapters_test.go|func TestProtoGrpcAdaptersCanonicalizeAuditActionIDOnWriteAndMixedCaseQuery(t *testing.T) {|vpngovernance proto grpc adapter audit canonicalization coverage"
  "blockchain/tdpn-chain/app/grpc_registry_test.go|func TestRegisterGRPCServicesBillingAndSponsorRoundTrip(t *testing.T) {|app grpc registry billing/rewards/sponsor canonicalization roundtrip coverage"
  "blockchain/tdpn-chain/app/grpc_registry_test.go|reservationCanonicalID := \"res-grpc-canon-1\"|app grpc registry billing canonicalization token"
  "blockchain/tdpn-chain/app/grpc_registry_test.go|accrualCanonicalID := \"accrual-grpc-canon-1\"|app grpc registry rewards canonicalization token"
  "blockchain/tdpn-chain/app/grpc_registry_test.go|authorizationCanonicalID := \"auth-grpc-canon-1\"|app grpc registry sponsor canonicalization token"
  "blockchain/tdpn-chain/app/grpc_registry_test.go|func TestRegisterGRPCServicesValidatorAndGovernanceRoundTrip(t *testing.T) {|app grpc registry validator/governance canonicalization roundtrip coverage"
  "blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go|func TestRunTDPNDGRPCModeRealScaffoldBillingAndSponsorRoundTrip(t *testing.T) {|tdpnd runtime non-auth billing/sponsor roundtrip coverage"
  "blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go|func assertBillingRewardsSponsorCanonicalizationRoundTrip(|tdpnd runtime shared billing/rewards/sponsor canonicalization helper"
  "blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go|billingReserveResp, err := billingMsg.ReserveCredits(rpcCtx, &vpnbillingpb.MsgReserveCreditsRequest{|tdpnd runtime non-auth billing reserve evidence"
  "blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go|rewardAccrualResp, err := rewardsMsg.RecordAccrual(rpcCtx, &vpnrewardspb.MsgRecordAccrualRequest{|tdpnd runtime non-auth rewards accrual evidence"
  "blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go|sponsorDelegateResp, err := sponsorMsg.DelegateSessionCredit(delegateCtx, &vpnsponsorpb.MsgDelegateSessionCreditRequest{|tdpnd runtime non-auth sponsor delegation evidence"
  "blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go|func TestRunTDPNDGRPCModeAuthBillingRewardsSponsorCanonicalizationRoundTrip(t *testing.T) {|tdpnd runtime auth billing/rewards/sponsor canonicalization roundtrip coverage"
  "blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go|assertBillingRewardsSponsorCanonicalizationRoundTrip(|tdpnd runtime auth billing/rewards/sponsor helper invocation"
  "blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go|func TestRunTDPNDGRPCModeRealScaffoldValidatorAndGovernanceRoundTrip(t *testing.T) {|tdpnd runtime non-auth validator/governance canonicalization roundtrip coverage"
  "scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh|BILLING_RESERVE_WRITE_PAYLOAD='{\"reservation\":{\"reservation_id\":|tdpnd grpc live smoke billing canonicalization payload token"
  "scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh|REWARDS_ACCRUAL_WRITE_PAYLOAD='{\"accrual\":{\"accrual_id\":|tdpnd grpc live smoke rewards canonicalization payload token"
  "scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh|SPONSOR_AUTHORIZATION_WRITE_PAYLOAD='{\"authorization\":{\"authorization_id\":|tdpnd grpc live smoke sponsor canonicalization payload token"
  "scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh|assert_grpc_call_patterns \"\${PORT}\" \"tdpn.vpnbilling.v1.Msg/ReserveCredits\" \"\${BILLING_RESERVE_WRITE_PAYLOAD}\"|tdpnd grpc live smoke billing canonicalization assertion token"
  "scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh|assert_grpc_call_patterns \"\${PORT}\" \"tdpn.vpnrewards.v1.Msg/RecordAccrual\" \"\${REWARDS_ACCRUAL_WRITE_PAYLOAD}\"|tdpnd grpc live smoke rewards canonicalization assertion token"
  "scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh|assert_grpc_call_patterns \"\${PORT}\" \"tdpn.vpnsponsor.v1.Msg/CreateAuthorization\" \"\${SPONSOR_AUTHORIZATION_WRITE_PAYLOAD}\"|tdpnd grpc live smoke sponsor canonicalization assertion token"
  "scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh|BILLING_RESERVE_WRITE_PAYLOAD='{\"reservation\":{\"reservation_id\":|tdpnd grpc auth live smoke billing canonicalization payload token"
  "scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh|REWARDS_ACCRUAL_WRITE_PAYLOAD='{\"accrual\":{\"accrual_id\":|tdpnd grpc auth live smoke rewards canonicalization payload token"
  "scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh|SPONSOR_AUTHORIZATION_WRITE_PAYLOAD='{\"authorization\":{\"authorization_id\":|tdpnd grpc auth live smoke sponsor canonicalization payload token"
  "scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh|billing_reserve_output=\"\$(run_authorized_grpc_call \"\${PORT}\" \"tdpn.vpnbilling.v1.Msg/ReserveCredits\" \"\${BILLING_RESERVE_WRITE_PAYLOAD}\")\"|tdpnd grpc auth live smoke billing canonicalization assertion token"
  "scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh|rewards_accrual_output=\"\$(run_authorized_grpc_call \"\${PORT}\" \"tdpn.vpnrewards.v1.Msg/RecordAccrual\" \"\${REWARDS_ACCRUAL_WRITE_PAYLOAD}\")\"|tdpnd grpc auth live smoke rewards canonicalization assertion token"
  "scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh|sponsor_authorization_output=\"\$(run_authorized_grpc_call \"\${PORT}\" \"tdpn.vpnsponsor.v1.Msg/CreateAuthorization\" \"\${SPONSOR_AUTHORIZATION_WRITE_PAYLOAD}\")\"|tdpnd grpc auth live smoke sponsor canonicalization assertion token"
  "scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh|sponsor_delegation_output=\"\$(run_authorized_grpc_call \"\${PORT}\" \"tdpn.vpnsponsor.v1.Msg/DelegateSessionCredit\" \"\${SPONSOR_DELEGATION_WRITE_PAYLOAD}\")\"|tdpnd grpc auth live smoke sponsor delegation canonicalization assertion token"
  "scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh|# Canonicalization path coverage: mixed-case and whitespace IDs should persist in canonical form.|tdpnd settlement bridge live smoke canonicalization section token"
  "scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh|post_expect_status \"\${BASE_URL}/x/vpnbilling/settlements\" '{\"SettlementID\":\"  SET-CANON-LIVE-1|tdpnd settlement bridge live smoke billing canonicalization write token"
  "scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh|post_expect_status \"\${BASE_URL}/x/vpnrewards/issues\" '{\"RewardID\":\"  REWARD-CANON-LIVE-1|tdpnd settlement bridge live smoke rewards canonicalization write token"
  "scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh|post_expect_status \"\${BASE_URL}/x/vpnsponsor/reservations\" '{\"ReservationID\":\"  RES-CANON-LIVE-1|tdpnd settlement bridge live smoke sponsor canonicalization write token"
  "scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh|get_expect_status \"\${BASE_URL}/x/vpnbilling/settlements/set-canon-live-1\" \"200\"|tdpnd settlement bridge live smoke billing canonicalization query token"
  "scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh|get_expect_status \"\${BASE_URL}/x/vpnrewards/accruals/reward-canon-live-1\" \"200\"|tdpnd settlement bridge live smoke rewards canonicalization query token"
  "scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh|get_expect_status \"\${BASE_URL}/x/vpnsponsor/delegations/res-canon-live-1\" \"200\"|tdpnd settlement bridge live smoke sponsor canonicalization query token"
  "scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh|TestRunTDPNDGRPCModeRealScaffoldBillingAndSponsorRoundTrip|tdpnd grpc runtime smoke selector includes billing/sponsor roundtrip"
  "scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh|TestRunTDPNDGRPCModeRealScaffoldValidatorAndGovernanceRoundTrip|tdpnd grpc runtime smoke selector includes non-auth canonicalization roundtrip"
  "blockchain/tdpn-chain/cmd/tdpnd/comet_runtime_test.go|func TestRunTDPNDMixedCometGRPCQueryDispatchAvailability(t *testing.T) {|tdpnd comet mixed-mode query-dispatch coverage test token"
  "blockchain/tdpn-chain/cmd/tdpnd/comet_runtime_test.go|func TestRunTDPNDMixedCometGRPCAuthEnforcementAndHealth(t *testing.T) {|tdpnd comet mixed-mode auth enforcement coverage test token"
  "blockchain/tdpn-chain/cmd/tdpnd/comet_runtime_test.go|expected reflection disabled in mixed auth mode|tdpnd comet mixed-mode auth reflection-disabled coverage token"
  "scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh|assert_grpc_query_dispatch() {|tdpnd comet runtime smoke grpc query-dispatch helper token"
  "scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh|assert_grpc_query_unauthenticated \"\${GRPC_PORT}\" \"tdpn.vpnbilling.v1.Query/ListCreditReservations\"|tdpnd comet runtime smoke unauthenticated query assertion token"
  "scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh|assert_grpc_query_dispatch_with_token \"\${GRPC_PORT}\" \"tdpn.vpnbilling.v1.Query/ListCreditReservations\" \"reservations\"|tdpnd comet runtime smoke authenticated query assertion token"
  "scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh|assert_grpc_reflection_disabled \"\${GRPC_PORT}\"|tdpnd comet runtime smoke reflection-disabled assertion token"
  "scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh|TestRunTDPNDMixedCometGRPCAuth.*|tdpnd comet runtime smoke fallback auth test-run regex token"
  "scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh|TestRunTDPNDMixedCometGRPCQueryDispatchAvailability|tdpnd comet runtime smoke fallback query-dispatch test-run token"
  "scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh|TestRunTDPNDMixedCometGRPCSettlementLifecycle|tdpnd comet runtime smoke fallback mixed-mode test-run token"

  "scripts/blockchain_fastlane.sh|5) scripts/integration_cosmos_record_normalization_contract_consistency.sh|blockchain fastlane usage includes normalization contract stage"
  "scripts/blockchain_fastlane.sh|BLOCKCHAIN_FASTLANE_INTEGRATION_COSMOS_RECORD_NORMALIZATION_CONTRACT_CONSISTENCY_SCRIPT|blockchain fastlane normalization stage env wiring token"
  "scripts/blockchain_fastlane.sh|[\"integration_cosmos_record_normalization_contract_consistency\"]=\"\$integration_cosmos_record_normalization_contract_consistency_script\"|blockchain fastlane normalization stage script map token"
  "scripts/blockchain_fastlane.sh|[\"integration_cosmos_record_normalization_contract_consistency\"]=\"1\"|blockchain fastlane normalization stage mandatory-enable token"
  "scripts/integration_blockchain_fastlane.sh|\"BLOCKCHAIN_FASTLANE_INTEGRATION_COSMOS_RECORD_NORMALIZATION_CONTRACT_CONSISTENCY_SCRIPT\"|integration blockchain fastlane normalization stage env assertion token"
  "scripts/integration_blockchain_fastlane.sh|\"integration_cosmos_record_normalization_contract_consistency\"|integration blockchain fastlane normalization stage-id assertion token"
  "scripts/integration_blockchain_fastlane.sh|integration_cosmos_record_normalization_contract_consistency=49|integration blockchain fastlane normalization stage fail-matrix token"
  "scripts/ci_blockchain_parallel_sweep.sh|bash scripts/integration_cosmos_record_normalization_contract_consistency.sh && \\|ci blockchain parallel sweep phase lane normalization stage token"
  "scripts/integration_ci_blockchain_parallel_sweep.sh|\"bash scripts/integration_cosmos_record_normalization_contract_consistency.sh\"|integration ci blockchain parallel sweep normalization stage assertion token"
  "scripts/check_roadmap_consistency.sh|\"bash scripts/integration_cosmos_record_normalization_contract_consistency.sh\"|roadmap consistency phase lane normalization stage token"
  "scripts/check_roadmap_consistency.sh|if ! rg -Fq \"scripts/integration_cosmos_record_normalization_contract_consistency.sh\" \"\$full_plan\"; then|roadmap consistency full plan normalization stage token"
)

for check in "${checks[@]}"; do
  IFS='|' read -r file_path required_literal check_label <<<"$check"
  assert_literal "$file_path" "$required_literal" "$check_label"
done

echo "cosmos record normalization contract consistency check ok"
