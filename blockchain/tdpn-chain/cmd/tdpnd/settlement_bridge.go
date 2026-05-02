package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	urlpkg "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	billingmodule "github.com/tdpn/tdpn-chain/x/vpnbilling/module"
	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
	rewardmodule "github.com/tdpn/tdpn-chain/x/vpnrewards/module"
	rewardtypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
	slashingmodule "github.com/tdpn/tdpn-chain/x/vpnslashing/module"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
	validatormodule "github.com/tdpn/tdpn-chain/x/vpnvalidator/module"
	validatortypes "github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

type settlementBridgeScaffold interface {
	BillingMsgServer() app.BillingMsgServer
	BillingQueryServer() app.BillingQueryServer
	RewardsMsgServer() app.RewardsMsgServer
	RewardsQueryServer() app.RewardsQueryServer
	SponsorMsgServer() app.SponsorMsgServer
	SponsorQueryServer() app.SponsorQueryServer
	SlashingMsgServer() app.SlashingMsgServer
	SlashingQueryServer() app.SlashingQueryServer
	ValidatorMsgServer() app.ValidatorMsgServer
	ValidatorQueryServer() app.ValidatorQueryServer
	GovernanceMsgServer() app.GovernanceMsgServer
	GovernanceQueryServer() app.GovernanceQueryServer
}

type settlementBridgeHandler struct {
	scaffold              settlementBridgeScaffold
	authToken             string
	authPrincipal         string
	rewardProofAuthToken  string
	finalityAuthToken     string
	rewardProofVerifierID string
	listenAddr            string
}

const (
	rewardProofAuthorizationHeader = "X-GPM-Reward-Proof-Authorization"
	finalityAuthorizationHeader    = "X-GPM-Finality-Authorization"
)

type loopbackHostCheckFunc func(string) bool

type bridgeEnvelope struct {
	OK     bool   `json:"ok"`
	Replay bool   `json:"replay,omitempty"`
	ID     string `json:"id,omitempty"`
	Error  string `json:"error,omitempty"`
}

type settlementBillingReservationPayload struct {
	ReservationID string    `json:"ReservationID"`
	SessionID     string    `json:"SessionID"`
	SubjectID     string    `json:"SubjectID"`
	AmountMicros  int64     `json:"AmountMicros"`
	Currency      string    `json:"Currency"`
	CreatedAt     time.Time `json:"CreatedAt"`
	Status        string    `json:"Status"`
}

type settlementSessionPayload struct {
	SettlementID  string    `json:"SettlementID"`
	ReservationID string    `json:"ReservationID,omitempty"`
	SessionID     string    `json:"SessionID"`
	SubjectID     string    `json:"SubjectID"`
	ChargedMicros int64     `json:"ChargedMicros"`
	Currency      string    `json:"Currency"`
	SettledAt     time.Time `json:"SettledAt"`
	Status        string    `json:"Status"`
}

type settlementRewardPayload struct {
	RewardID              string    `json:"RewardID"`
	ProviderSubjectID     string    `json:"ProviderSubjectID"`
	SessionID             string    `json:"SessionID"`
	SettlementReferenceID string    `json:"SettlementReferenceID"`
	TrafficProofRef       string    `json:"TrafficProofRef"`
	PayoutPeriodStart     time.Time `json:"PayoutPeriodStart"`
	PayoutPeriodEnd       time.Time `json:"PayoutPeriodEnd"`
	RewardMicros          int64     `json:"RewardMicros"`
	Currency              string    `json:"Currency"`
	IssuedAt              time.Time `json:"IssuedAt"`
	Status                string    `json:"Status"`
}

type settlementRewardProofPayload struct {
	ProofPath         string    `json:"ProofPath"`
	TrafficProofRef   string    `json:"TrafficProofRef"`
	TrustContract     string    `json:"TrustContract"`
	RewardID          string    `json:"RewardID"`
	ProviderSubjectID string    `json:"ProviderSubjectID"`
	SessionID         string    `json:"SessionID"`
	PayoutPeriodStart time.Time `json:"PayoutPeriodStart"`
	PayoutPeriodEnd   time.Time `json:"PayoutPeriodEnd"`
	RewardMicros      int64     `json:"RewardMicros"`
	Currency          string    `json:"Currency"`
	IssuedAt          time.Time `json:"IssuedAt"`
	Verified          bool      `json:"Verified"`
	VerifierID        string    `json:"VerifierID"`
	VerifiedAt        time.Time `json:"VerifiedAt"`
}

type settlementSponsorReservationPayload struct {
	ReservationID string    `json:"ReservationID"`
	SponsorID     string    `json:"SponsorID"`
	SubjectID     string    `json:"SubjectID"`
	AppID         string    `json:"AppID,omitempty"`
	EndUserID     string    `json:"EndUserID,omitempty"`
	SessionID     string    `json:"SessionID"`
	AmountMicros  int64     `json:"AmountMicros"`
	Currency      string    `json:"Currency"`
	CreatedAt     time.Time `json:"CreatedAt"`
	ExpiresAt     time.Time `json:"ExpiresAt"`
	Status        string    `json:"Status"`
}

type settlementSlashEvidencePayload struct {
	EvidenceID    string    `json:"EvidenceID"`
	SubjectID     string    `json:"SubjectID"`
	SessionID     string    `json:"SessionID"`
	ViolationType string    `json:"ViolationType"`
	EvidenceRef   string    `json:"EvidenceRef"`
	SlashMicros   int64     `json:"SlashMicros"`
	Currency      string    `json:"Currency"`
	ObservedAt    time.Time `json:"ObservedAt"`
	Status        string    `json:"Status"`
}

type settlementSlashPenaltyPayload struct {
	PenaltyID       string    `json:"PenaltyID"`
	EvidenceID      string    `json:"EvidenceID"`
	SlashBasisPoint uint32    `json:"SlashBasisPoint"`
	SlashMicros     int64     `json:"SlashMicros"`
	Currency        string    `json:"Currency"`
	Jailed          bool      `json:"Jailed"`
	AppliedAt       time.Time `json:"AppliedAt"`
}

type settlementValidatorEligibilityPayload struct {
	ValidatorID     string    `json:"ValidatorID"`
	OperatorAddress string    `json:"OperatorAddress"`
	Eligible        bool      `json:"Eligible"`
	PolicyReason    string    `json:"PolicyReason"`
	UpdatedAt       time.Time `json:"UpdatedAt"`
	Status          string    `json:"Status"`
}

type settlementValidatorStatusPayload struct {
	StatusID         string    `json:"StatusID"`
	ValidatorID      string    `json:"ValidatorID"`
	ConsensusAddress string    `json:"ConsensusAddress"`
	LifecycleStatus  string    `json:"LifecycleStatus"`
	EvidenceHeight   int64     `json:"EvidenceHeight"`
	EvidenceRef      string    `json:"EvidenceRef"`
	RecordedAt       time.Time `json:"RecordedAt"`
	Status           string    `json:"Status"`
}

type settlementValidatorEpochSelectionPreviewPayload struct {
	Policy     validatortypes.EpochSelectionPolicy      `json:"Policy"`
	Candidates []validatortypes.EpochValidatorCandidate `json:"Candidates"`
}

type settlementValidatorEpochSelectionPreviewResponse struct {
	OK      bool                                `json:"ok"`
	Preview validatortypes.EpochSelectionResult `json:"preview"`
}

type settlementGovernancePolicyPayload struct {
	PolicyID    string    `json:"PolicyID"`
	Title       string    `json:"Title"`
	Description string    `json:"Description"`
	Version     uint64    `json:"Version"`
	ActivatedAt time.Time `json:"ActivatedAt"`
	Status      string    `json:"Status"`
}

type settlementGovernanceDecisionPayload struct {
	DecisionID string    `json:"DecisionID"`
	PolicyID   string    `json:"PolicyID"`
	ProposalID string    `json:"ProposalID"`
	Outcome    string    `json:"Outcome"`
	Decider    string    `json:"Decider"`
	Reason     string    `json:"Reason"`
	DecidedAt  time.Time `json:"DecidedAt"`
	Status     string    `json:"Status"`
}

type settlementGovernanceAuditActionPayload struct {
	ActionID        string    `json:"ActionID"`
	Action          string    `json:"Action"`
	Actor           string    `json:"Actor"`
	Reason          string    `json:"Reason"`
	EvidencePointer string    `json:"EvidencePointer"`
	Timestamp       time.Time `json:"Timestamp"`
}

const settlementBridgeMaxJSONBodyBytes int64 = 1 << 20 // 1 MiB
const settlementBridgeMaxEpochSelectionPreviewCandidates = 2048
const sponsorReservationCurrencyMetadataPrefix = "bridge-sponsor-currency:"

type settlementSponsorAuthorizationResponse struct {
	sponsortypes.SponsorAuthorization
	Currency string `json:"Currency,omitempty"`
}

type settlementSponsorDelegationResponse struct {
	sponsortypes.DelegatedSessionCredit
	Currency string `json:"Currency,omitempty"`
}

func runSettlementHTTPMode(
	ctx context.Context,
	scaffold settlementBridgeScaffold,
	cfg settlementHTTPConfig,
	deps runtimeDeps,
) error {
	listener, err := deps.ListenHTTP("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listen settlement http on %q: %w", cfg.listenAddr, err)
	}
	defer listener.Close()

	handler := &settlementBridgeHandler{
		scaffold:              scaffold,
		authToken:             cfg.authToken,
		authPrincipal:         canonicalBridgePrincipal(cfg.authPrincipal),
		rewardProofAuthToken:  cfg.rewardProofAuthToken,
		finalityAuthToken:     cfg.finalityAuthToken,
		rewardProofVerifierID: canonicalBridgePrincipal(cfg.rewardProofVerifierID),
		listenAddr:            listener.Addr().String(),
	}
	server := &http.Server{
		Handler:           handler.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.Serve(listener)
	}()

	select {
	case err := <-serveErrCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve settlement http: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
			_ = server.Close()
		}
		err := <-serveErrCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve settlement http: %w", err)
		}
		return nil
	}
}

func (h *settlementBridgeHandler) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/x/vpnbilling/reservations", h.handleBillingReservations)
	mux.HandleFunc("/x/vpnbilling/reservations/", h.handleBillingReservations)
	mux.HandleFunc("/x/vpnbilling/settlements", h.handleBillingSettlement)
	mux.HandleFunc("/x/vpnbilling/settlements/", h.handleBillingSettlement)
	mux.HandleFunc("/x/vpnrewards/accruals", h.handleRewardAccruals)
	mux.HandleFunc("/x/vpnrewards/accruals/", h.handleRewardAccruals)
	mux.HandleFunc("/x/vpnrewards/distributions", h.handleRewardDistributions)
	mux.HandleFunc("/x/vpnrewards/distributions/", h.handleRewardDistributions)
	mux.HandleFunc("/x/vpnrewards/proofs", h.handleRewardProofs)
	mux.HandleFunc("/x/vpnrewards/proofs/", h.handleRewardProofs)
	mux.HandleFunc("/x/vpnrewards/issues", h.handleRewardIssue)
	mux.HandleFunc("/x/vpnsponsor/authorizations", h.handleSponsorAuthorizations)
	mux.HandleFunc("/x/vpnsponsor/authorizations/", h.handleSponsorAuthorizations)
	mux.HandleFunc("/x/vpnsponsor/delegations", h.handleSponsorDelegations)
	mux.HandleFunc("/x/vpnsponsor/delegations/", h.handleSponsorDelegations)
	mux.HandleFunc("/x/vpnsponsor/reservations", h.handleSponsorReservation)
	mux.HandleFunc("/x/vpnslashing/evidence", h.handleSlashEvidence)
	mux.HandleFunc("/x/vpnslashing/evidence/", h.handleSlashEvidence)
	mux.HandleFunc("/x/vpnslashing/penalties", h.handleSlashPenalties)
	mux.HandleFunc("/x/vpnslashing/penalties/", h.handleSlashPenalties)
	mux.HandleFunc("/x/vpnvalidator/eligibilities", h.handleValidatorEligibilities)
	mux.HandleFunc("/x/vpnvalidator/eligibilities/", h.handleValidatorEligibilities)
	mux.HandleFunc("/x/vpnvalidator/status-records", h.handleValidatorStatusRecords)
	mux.HandleFunc("/x/vpnvalidator/status-records/", h.handleValidatorStatusRecords)
	mux.HandleFunc("/x/vpnvalidator/epoch-selection-preview", h.handleValidatorEpochSelectionPreview)
	mux.HandleFunc("/x/vpnvalidator/epoch-selection-preview/", h.handleValidatorEpochSelectionPreview)
	mux.HandleFunc("/x/vpngovernance/policies", h.handleGovernancePolicies)
	mux.HandleFunc("/x/vpngovernance/policies/", h.handleGovernancePolicies)
	mux.HandleFunc("/x/vpngovernance/decisions", h.handleGovernanceDecisions)
	mux.HandleFunc("/x/vpngovernance/decisions/", h.handleGovernanceDecisions)
	mux.HandleFunc("/x/vpngovernance/audit-actions", h.handleGovernanceAuditActions)
	mux.HandleFunc("/x/vpngovernance/audit-actions/", h.handleGovernanceAuditActions)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthBypassAllowed := r.URL.Path == "/health" && (h.authToken == "" || isLoopbackRemoteAddr(r.RemoteAddr))
		if !healthBypassAllowed && !h.authorizeRequest(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (h *settlementBridgeHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"status": "ok",
		"mode":   "settlement-http-bridge",
	})
}

func (h *settlementBridgeHandler) handleBillingSettlement(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		settlementID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnbilling/settlements")
		if !ok {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		if hasID {
			resp, err := h.scaffold.BillingQueryServer().GetSettlement(r.Context(), app.BillingGetSettlementRequest{
				SettlementID: settlementID,
			})
			if err != nil {
				writeBridgeError(w, err)
				return
			}
			if !resp.Found {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":         true,
				"settlement": resp.Settlement,
			})
			return
		}

		resp, err := h.scaffold.BillingQueryServer().ListSettlements(r.Context(), app.BillingListSettlementsRequest{})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":          true,
			"settlements": resp.Settlements,
		})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementSessionPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	settlementID := canonicalBridgeIdentifier(payload.SettlementID)
	sessionID := canonicalBridgeIdentifier(payload.SessionID)
	subjectID := canonicalBridgeIdentifier(payload.SubjectID)
	if authenticatedPrincipal := h.authenticatedPrincipal(); authenticatedPrincipal != "" {
		boundSubjectID, ok := bindIdentityFieldToAuthenticatedCaller(subjectID, authenticatedPrincipal)
		if !ok {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{
				OK:    false,
				Error: "SubjectID must match authenticated caller",
			})
			return
		}
		subjectID = boundSubjectID
	}
	currency, currencyErr := validateBridgeCurrency(payload.Currency)
	if currencyErr != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: currencyErr.Error()})
		return
	}
	reservationID := canonicalBridgeIdentifier(payload.ReservationID)
	if settlementID == "" || reservationID == "" || sessionID == "" || subjectID == "" || currency == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{
			OK:    false,
			Error: "SettlementID, ReservationID, SessionID, SubjectID, and Currency are required",
		})
		return
	}
	if isSponsorReservationCurrencyMetadataID(reservationID) {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "reservation not found"})
		return
	}

	createdUnix := unixOrZero(payload.SettledAt)
	if payload.ChargedMicros <= 0 {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "ChargedMicros must be > 0"})
		return
	}
	chargedAmount := payload.ChargedMicros
	existingReservation, err := h.scaffold.BillingQueryServer().GetReservation(r.Context(), app.BillingGetReservationRequest{
		ReservationID: reservationID,
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}
	if !existingReservation.Found {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "reservation not found"})
		return
	}
	record := existingReservation.Reservation
	recordDenom := strings.TrimSpace(record.AssetDenom)
	if strings.TrimSpace(record.SessionID) != sessionID ||
		strings.TrimSpace(record.SponsorID) != subjectID ||
		!strings.EqualFold(recordDenom, currency) {
		writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: "reservation fields do not match settlement"})
		return
	}
	if chargedAmount > record.Amount {
		writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: "charged amount exceeds reserved amount"})
		return
	}
	if canonicalBridgeReconciliationStatus(record.Status) != chaintypes.ReconciliationConfirmed {
		writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: "reservation Status must be confirmed"})
		return
	}
	operationState, err := bridgeSettlementOperationState(payload.Status)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	if operationState != chaintypes.ReconciliationConfirmed {
		writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: "settlement Status must be confirmed"})
		return
	}
	if !h.authorizeScopedBearerToken(
		w,
		r,
		h.finalityAuthToken,
		finalityAuthorizationHeader,
		"billing settlement finality requires configured settlement finality token",
		"missing or invalid settlement finality bearer token",
	) {
		return
	}

	resp, err := h.scaffold.BillingMsgServer().FinalizeSettlement(r.Context(), app.BillingFinalizeSettlementRequest{
		Record: billingtypes.SettlementRecord{
			SettlementID:   settlementID,
			ReservationID:  reservationID,
			SessionID:      sessionID,
			BilledAmount:   chargedAmount,
			UsageBytes:     0,
			AssetDenom:     recordDenom,
			SettledAtUnix:  createdUnix,
			OperationState: operationState,
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Settlement.SettlementID,
	})
}

func (h *settlementBridgeHandler) handleBillingReservations(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		reservationID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnbilling/reservations")
		if !ok {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		if hasID {
			if isSponsorReservationCurrencyMetadataID(reservationID) {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			resp, err := h.scaffold.BillingQueryServer().GetReservation(r.Context(), app.BillingGetReservationRequest{
				ReservationID: reservationID,
			})
			if err != nil {
				writeBridgeError(w, err)
				return
			}
			if !resp.Found {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":          true,
				"reservation": resp.Reservation,
			})
			return
		}

		resp, err := h.scaffold.BillingQueryServer().ListReservations(r.Context(), app.BillingListReservationsRequest{})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"reservations": visibleBillingReservations(resp.Reservations),
		})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementBillingReservationPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	reservationID := strings.TrimSpace(payload.ReservationID)
	sessionID := strings.TrimSpace(payload.SessionID)
	subjectID := strings.TrimSpace(payload.SubjectID)
	if authenticatedPrincipal := h.authenticatedPrincipal(); authenticatedPrincipal != "" {
		boundSubjectID, ok := bindIdentityFieldToAuthenticatedCaller(subjectID, authenticatedPrincipal)
		if !ok {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{
				OK:    false,
				Error: "SubjectID must match authenticated caller",
			})
			return
		}
		subjectID = boundSubjectID
	}
	currency := strings.TrimSpace(payload.Currency)
	if reservationID == "" || sessionID == "" || subjectID == "" || currency == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{
			OK:    false,
			Error: "ReservationID, SessionID, SubjectID, and Currency are required",
		})
		return
	}
	if isSponsorReservationCurrencyMetadataID(reservationID) {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "ReservationID uses a reserved bridge metadata prefix"})
		return
	}
	if payload.AmountMicros <= 0 {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "AmountMicros must be > 0"})
		return
	}
	reservationStatus, err := bridgeCallerReservationStatus(payload.Status)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	record := billingtypes.CreditReservation{
		ReservationID: reservationID,
		SponsorID:     subjectID,
		SessionID:     sessionID,
		AssetDenom:    currency,
		Amount:        payload.AmountMicros,
		CreatedAtUnix: unixOrZero(payload.CreatedAt),
		Status:        reservationStatus,
	}
	if reservationStatus == chaintypes.ReconciliationConfirmed {
		if !h.authorizeScopedBearerToken(
			w,
			r,
			h.finalityAuthToken,
			finalityAuthorizationHeader,
			"billing reservation finality requires configured settlement finality token",
			"missing or invalid settlement finality bearer token",
		) {
			return
		}
		resp, err := h.scaffold.BillingMsgServer().ConfirmReservation(r.Context(), app.BillingConfirmReservationRequest{
			Record: record,
		})
		if err != nil {
			if errors.Is(err, billingmodule.ErrReservationNotFound) {
				writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "reservation Status confirmed requires an existing pending or submitted reservation"})
				return
			}
			if errors.Is(err, billingmodule.ErrReservationConflict) {
				writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
				return
			}
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, bridgeEnvelope{
			OK:     true,
			Replay: resp.Replay,
			ID:     resp.Reservation.ReservationID,
		})
		return
	}

	resp, err := h.scaffold.BillingMsgServer().CreateReservation(r.Context(), app.BillingCreateReservationRequest{
		Record: record,
	})
	if err != nil {
		if errors.Is(err, billingmodule.ErrReservationConflict) {
			writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Reservation.ReservationID,
	})
}

func (h *settlementBridgeHandler) handleRewardIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementRewardPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	providerSubjectID := strings.TrimSpace(payload.ProviderSubjectID)
	if authenticatedPrincipal := h.authenticatedPrincipal(); authenticatedPrincipal != "" {
		boundProviderSubjectID, ok := bindIdentityFieldToAuthenticatedCaller(providerSubjectID, authenticatedPrincipal)
		if !ok {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{
				OK:    false,
				Error: "ProviderSubjectID must match authenticated caller",
			})
			return
		}
		providerSubjectID = boundProviderSubjectID
	}
	if err := validateSettlementRewardMetadata(payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	if statusCode, message, err := h.validateSettlementRewardEvidence(r.Context(), payload, providerSubjectID); err != nil {
		writeBridgeError(w, err)
		return
	} else if message != "" {
		writeJSON(w, statusCode, bridgeEnvelope{OK: false, Error: message})
		return
	}

	distributionStatus := canonicalBridgeReconciliationStatus(chaintypes.ReconciliationSubmitted)
	if strings.TrimSpace(payload.Status) != "" {
		status, ok := parseBridgeReconciliationStatus(payload.Status)
		if !ok {
			writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "invalid reward status"})
			return
		}
		distributionStatus = status
	}
	allowFinalityAuthority := false
	if distributionStatus == chaintypes.ReconciliationConfirmed || distributionStatus == chaintypes.ReconciliationFailed {
		if strings.TrimSpace(h.authToken) == "" {
			writeJSON(w, http.StatusServiceUnavailable, bridgeEnvelope{OK: false, Error: "reward finality requires authenticated settlement bridge mode"})
			return
		}
		if canonicalBridgePrincipal(h.rewardProofVerifierID) == "" {
			writeJSON(w, http.StatusServiceUnavailable, bridgeEnvelope{OK: false, Error: "reward finality requires configured reward proof verifier id"})
			return
		}
		if !h.authorizeScopedBearerToken(
			w,
			r,
			h.finalityAuthToken,
			finalityAuthorizationHeader,
			"reward finality requires configured settlement finality token",
			"missing or invalid settlement finality bearer token",
		) {
			return
		}
		allowFinalityAuthority = true
	}

	accrualID := strings.TrimSpace(payload.RewardID)
	distributionID := "dist:" + accrualID
	issuedUnix := unixOrZero(payload.IssuedAt)
	accruedUnix := settlementRewardAccruedAtUnix(payload)

	_, err := h.scaffold.RewardsMsgServer().CreateAccrual(r.Context(), app.RewardsCreateAccrualRequest{
		Record: rewardtypes.RewardAccrual{
			AccrualID:       accrualID,
			SessionID:       payload.SessionID,
			ProviderID:      providerSubjectID,
			AssetDenom:      payload.Currency,
			Amount:          payload.RewardMicros,
			AccruedAtUnix:   accruedUnix,
			PayoutStartUnix: unixOrZero(payload.PayoutPeriodStart),
			PayoutEndUnix:   unixOrZero(payload.PayoutPeriodEnd),
			OperationState:  chaintypes.ReconciliationPending,
		},
	})
	if err != nil {
		if errors.Is(err, rewardmodule.ErrAccrualConflict) {
			writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		writeBridgeError(w, err)
		return
	}

	distributionCtx := r.Context()
	if allowFinalityAuthority {
		distributionCtx = app.WithRewardsFinalityAuthority(distributionCtx)
	}
	resp, err := h.scaffold.RewardsMsgServer().RecordDistribution(distributionCtx, app.RewardsRecordDistributionRequest{
		Record: rewardtypes.DistributionRecord{
			DistributionID: distributionID,
			AccrualID:      accrualID,
			PayoutRef:      settlementRewardPayoutRef(payload),
			DistributedAt:  issuedUnix,
			Status:         distributionStatus,
		},
		AllowFinalityAuthority: allowFinalityAuthority,
	})
	if err != nil {
		if errors.Is(err, rewardmodule.ErrDistributionConflict) {
			writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Distribution.DistributionID,
	})
}

func (h *settlementBridgeHandler) handleRewardAccruals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}

	accrualID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnrewards/accruals")
	if !ok {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}
	if hasID {
		resp, err := h.scaffold.RewardsQueryServer().GetAccrual(r.Context(), app.RewardsGetAccrualRequest{
			AccrualID: accrualID,
		})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		if !resp.Found {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"accrual": resp.Accrual,
		})
		return
	}

	resp, err := h.scaffold.RewardsQueryServer().ListAccruals(r.Context(), app.RewardsListAccrualsRequest{})
	if err != nil {
		writeBridgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"accruals": resp.Accruals,
	})
}

func (h *settlementBridgeHandler) handleRewardDistributions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}

	distributionID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnrewards/distributions")
	if !ok {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}
	if hasID {
		resp, err := h.scaffold.RewardsQueryServer().GetDistribution(r.Context(), app.RewardsGetDistributionRequest{
			DistributionID: distributionID,
		})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		if !resp.Found {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"distribution": resp.Distribution,
		})
		return
	}

	resp, err := h.scaffold.RewardsQueryServer().ListDistributions(r.Context(), app.RewardsListDistributionsRequest{})
	if err != nil {
		writeBridgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"distributions": resp.Distributions,
	})
}

func (h *settlementBridgeHandler) handleRewardProofs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.handleRewardProofRegistration(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}

	proofPath, ok := getEscapedProofPath(r, "/x/vpnrewards/proofs")
	if !ok {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}

	resp, err := h.scaffold.RewardsQueryServer().GetProof(r.Context(), app.RewardsGetProofRequest{
		ProofPath: proofPath,
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}
	if !resp.Found {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"proof": rewardProofBridgePayload(resp.Proof),
	})
}

func (h *settlementBridgeHandler) handleRewardProofRegistration(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/x/vpnrewards/proofs" {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}
	if strings.TrimSpace(h.authToken) == "" {
		writeJSON(w, http.StatusServiceUnavailable, bridgeEnvelope{OK: false, Error: "reward proof registration requires authenticated settlement bridge mode"})
		return
	}
	if !h.authorizeScopedBearerToken(
		w,
		r,
		h.rewardProofAuthToken,
		rewardProofAuthorizationHeader,
		"reward proof registration requires configured reward proof verifier token",
		"missing or invalid reward proof verifier bearer token",
	) {
		return
	}
	verifierID := canonicalBridgePrincipal(h.rewardProofVerifierID)
	if verifierID == "" {
		writeJSON(w, http.StatusServiceUnavailable, bridgeEnvelope{OK: false, Error: "reward proof verifier id is not configured"})
		return
	}

	var payload settlementRewardProofPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	if !payload.Verified {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "verified reward proof registration requires Verified=true from the trusted verifier path"})
		return
	}
	if requestedVerifier := canonicalBridgePrincipal(payload.VerifierID); requestedVerifier != "" && requestedVerifier != verifierID {
		writeJSON(w, http.StatusForbidden, bridgeEnvelope{OK: false, Error: "VerifierID must match configured settlement reward proof verifier"})
		return
	}
	providerSubjectID := strings.TrimSpace(payload.ProviderSubjectID)
	if authenticatedPrincipal := h.authenticatedPrincipal(); authenticatedPrincipal != "" {
		boundProviderSubjectID, ok := bindIdentityFieldToAuthenticatedCaller(providerSubjectID, authenticatedPrincipal)
		if !ok {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{
				OK:    false,
				Error: "ProviderSubjectID must match authenticated caller",
			})
			return
		}
		providerSubjectID = boundProviderSubjectID
	}
	if err := validateSettlementRewardProofMetadata(payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	proof := rewardtypes.RewardProofRecord{
		ProofPath:         strings.TrimSpace(payload.ProofPath),
		TrafficProofRef:   strings.TrimSpace(payload.TrafficProofRef),
		TrustContract:     strings.TrimSpace(payload.TrustContract),
		RewardID:          strings.TrimSpace(payload.RewardID),
		ProviderSubjectID: providerSubjectID,
		SessionID:         strings.TrimSpace(payload.SessionID),
		PayoutStartUnix:   unixOrZero(payload.PayoutPeriodStart),
		PayoutEndUnix:     unixOrZero(payload.PayoutPeriodEnd),
		RewardMicros:      payload.RewardMicros,
		Currency:          strings.TrimSpace(payload.Currency),
		IssuedAtUnix:      unixOrZero(payload.IssuedAt),
		Verified:          true,
		VerifierID:        verifierID,
		VerifiedAtUnix:    unixOrZero(payload.VerifiedAt),
	}
	if proof.VerifiedAtUnix <= 0 {
		proof.VerifiedAtUnix = time.Now().UTC().Unix()
	}
	if proof.ProofPath == "" {
		if proofPath, ok := rewardtypes.ProofPathFromTrafficProofRef(proof.TrafficProofRef); ok {
			proof.ProofPath = proofPath
		}
	}
	resp, err := h.scaffold.RewardsMsgServer().RegisterProof(r.Context(), app.RewardsRegisterProofRequest{
		Record: proof,
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Proof.ProofPath,
	})
}

func (h *settlementBridgeHandler) handleSponsorReservation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementSponsorReservationPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	createdUnix := unixOrZero(payload.CreatedAt)
	expiresUnix := unixOrZero(payload.ExpiresAt)
	subjectID := strings.TrimSpace(payload.SubjectID)
	reservationID := strings.TrimSpace(payload.ReservationID)
	sponsorID := strings.TrimSpace(payload.SponsorID)
	if authenticatedPrincipal := h.authenticatedPrincipal(); authenticatedPrincipal != "" {
		boundSponsorID, ok := bindIdentityFieldToAuthenticatedCaller(sponsorID, authenticatedPrincipal)
		if !ok {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{
				OK:    false,
				Error: "SponsorID must match authenticated caller",
			})
			return
		}
		sponsorID = boundSponsorID
	}
	appID := strings.TrimSpace(payload.AppID)
	endUserID := strings.TrimSpace(payload.EndUserID)
	if reservationID == "" || sponsorID == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{
			OK:    false,
			Error: "ReservationID and SponsorID are required",
		})
		return
	}
	if isSponsorReservationCurrencyMetadataID(reservationID) {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "ReservationID uses a reserved bridge metadata prefix"})
		return
	}
	if appID == "" {
		appID = subjectID
	}
	if endUserID == "" {
		endUserID = subjectID
	}
	if appID == "" {
		appID = endUserID
	}
	if endUserID == "" {
		endUserID = appID
	}
	if appID == "" || endUserID == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{
			OK:    false,
			Error: "SubjectID or AppID/EndUserID is required",
		})
		return
	}
	sessionID := strings.TrimSpace(payload.SessionID)
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{
			OK:    false,
			Error: "SessionID is required",
		})
		return
	}
	currency, err := validateBridgeCurrency(payload.Currency)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	if statusCode, message, err := h.validateSponsorReservationCurrency(r.Context(), reservationID, currency); err != nil {
		writeBridgeError(w, err)
		return
	} else if message != "" {
		writeJSON(w, statusCode, bridgeEnvelope{OK: false, Error: message})
		return
	}

	authorizationID := "auth:" + reservationID
	if payload.AmountMicros <= 0 {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "AmountMicros must be > 0"})
		return
	}
	credits := payload.AmountMicros
	nowUnix := time.Now().Unix()
	if expiresUnix <= nowUnix {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "ExpiresAt must be in the future"})
		return
	}
	maxCredits := credits
	authorizationRecord := sponsortypes.SponsorAuthorization{
		AuthorizationID: authorizationID,
		SponsorID:       sponsorID,
		AppID:           appID,
		MaxCredits:      maxCredits,
		ExpiresAtUnix:   expiresUnix,
		Status:          chaintypes.ReconciliationPending,
	}
	delegationRecord := sponsortypes.DelegatedSessionCredit{
		ReservationID:   reservationID,
		AuthorizationID: authorizationID,
		SponsorID:       sponsorID,
		AppID:           appID,
		EndUserID:       endUserID,
		SessionID:       sessionID,
		Credits:         credits,
		Status:          chaintypes.ReconciliationPending,
	}
	if statusCode, message, err := h.validateSponsorReservationOperation(r.Context(), authorizationRecord, delegationRecord); err != nil {
		writeBridgeError(w, err)
		return
	} else if message != "" {
		writeJSON(w, statusCode, bridgeEnvelope{OK: false, Error: message})
		return
	}
	if err := h.persistSponsorReservationCurrency(r.Context(), settlementSponsorReservationCurrencyRecord{
		ReservationID: reservationID,
		SponsorID:     sponsorID,
		SessionID:     sessionID,
		Currency:      currency,
		AmountMicros:  payload.AmountMicros,
		CreatedAtUnix: createdUnix,
	}); err != nil {
		if errors.Is(err, billingmodule.ErrReservationConflict) {
			writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		writeBridgeError(w, err)
		return
	}

	_, err = h.scaffold.SponsorMsgServer().CreateAuthorization(r.Context(), app.SponsorCreateAuthorizationRequest{
		Record: authorizationRecord,
	})
	if err != nil {
		if errors.Is(err, sponsormodule.ErrAuthorizationConflict) {
			writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		writeBridgeError(w, err)
		return
	}

	delegateCtx := sponsormodule.WithCurrentTimeUnix(r.Context(), nowUnix)
	resp, err := h.scaffold.SponsorMsgServer().DelegateCredit(delegateCtx, app.SponsorDelegateCreditRequest{
		Record: delegationRecord,
	})
	if err != nil {
		if errors.Is(err, sponsormodule.ErrDelegationConflict) {
			writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Delegation.ReservationID,
	})
	_ = createdUnix // maintained for payload completeness and future auditing extensions.
}

func (h *settlementBridgeHandler) handleSponsorAuthorizations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}

	authorizationID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnsponsor/authorizations")
	if !ok {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}
	if hasID {
		resp, err := h.scaffold.SponsorQueryServer().GetAuthorization(r.Context(), app.SponsorGetAuthorizationRequest{
			AuthorizationID: authorizationID,
		})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		if !resp.Found {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"authorization": h.enrichSponsorAuthorization(r.Context(), resp.Authorization),
		})
		return
	}

	resp, err := h.scaffold.SponsorQueryServer().ListAuthorizations(r.Context(), app.SponsorListAuthorizationsRequest{})
	if err != nil {
		writeBridgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"authorizations": h.enrichSponsorAuthorizations(r.Context(), resp.Authorizations),
	})
}

func (h *settlementBridgeHandler) handleSponsorDelegations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}

	reservationID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnsponsor/delegations")
	if !ok {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}
	if hasID {
		resp, err := h.scaffold.SponsorQueryServer().GetDelegation(r.Context(), app.SponsorGetDelegationRequest{
			ReservationID: reservationID,
		})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		if !resp.Found {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"delegation": h.enrichSponsorDelegation(r.Context(), resp.Delegation),
		})
		return
	}

	resp, err := h.scaffold.SponsorQueryServer().ListDelegations(r.Context(), app.SponsorListDelegationsRequest{})
	if err != nil {
		writeBridgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"delegations": h.enrichSponsorDelegations(r.Context(), resp.Delegations),
	})
}

func (h *settlementBridgeHandler) handleSlashEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		evidenceID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnslashing/evidence")
		if !ok {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		if hasID {
			resp, err := h.scaffold.SlashingQueryServer().GetEvidence(r.Context(), app.SlashingGetEvidenceRequest{
				EvidenceID: evidenceID,
			})
			if err != nil {
				writeBridgeError(w, err)
				return
			}
			if !resp.Found {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":       true,
				"evidence": resp.Evidence,
			})
			return
		}

		listReq, err := slashingListEvidenceRequestFromQuery(r.URL.Query())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		resp, err := h.scaffold.SlashingQueryServer().ListEvidence(r.Context(), listReq)
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"evidence": resp.Evidence,
		})
		return
	}
	if r.Method == http.MethodPatch {
		h.handleSlashEvidenceFinality(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementSlashEvidencePayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	evidenceID := strings.TrimSpace(payload.EvidenceID)
	if evidenceID == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "evidence_id is required"})
		return
	}
	subjectID := strings.TrimSpace(payload.SubjectID)
	if authenticatedPrincipal := h.authenticatedPrincipal(); authenticatedPrincipal != "" {
		boundSubjectID, ok := bindIdentityFieldToAuthenticatedCaller(subjectID, authenticatedPrincipal)
		if !ok {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{
				OK:    false,
				Error: "SubjectID must match authenticated caller",
			})
			return
		}
		subjectID = boundSubjectID
	}
	if subjectID == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "subject_id is required"})
		return
	}
	sessionID := strings.TrimSpace(payload.SessionID)
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "session_id is required"})
		return
	}
	normalizedViolationType, err := normalizeBridgeObjectiveViolationType(payload.ViolationType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	payload.ViolationType = normalizedViolationType
	proofHash := strings.TrimSpace(payload.EvidenceRef)
	if proofHash == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "evidence_ref is required"})
		return
	}
	if err := validateBridgeSlashEvidenceRef(proofHash); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	if err := validateSettlementSlashMetadata(payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	proofHash = settlementSlashProofHash(payload, proofHash)

	resp, err := h.scaffold.SlashingMsgServer().SubmitEvidence(r.Context(), app.SlashingSubmitEvidenceRequest{
		Record: slashingtypes.SlashEvidence{
			EvidenceID:      evidenceID,
			SessionID:       sessionID,
			ProviderID:      subjectID,
			ViolationType:   normalizedViolationType,
			Kind:            slashingtypes.EvidenceKindObjective,
			ProofHash:       proofHash,
			SlashAmount:     payload.SlashMicros,
			SlashDenom:      payload.Currency,
			SubmittedAtUnix: unixOrZero(payload.ObservedAt),
			Status:          chaintypes.ReconciliationSubmitted,
		},
	})
	if err != nil {
		if errors.Is(err, slashingmodule.ErrEvidenceConflict) {
			writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Evidence.EvidenceID,
	})
}

func (h *settlementBridgeHandler) handleSlashEvidenceFinality(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeRequest(w, r) {
		return
	}
	if strings.TrimSpace(h.authToken) == "" {
		writeJSON(w, http.StatusServiceUnavailable, bridgeEnvelope{OK: false, Error: "slash evidence finality requires authenticated settlement bridge mode"})
		return
	}
	if !h.authorizeScopedBearerToken(
		w,
		r,
		h.finalityAuthToken,
		finalityAuthorizationHeader,
		"slash evidence finality requires configured settlement finality token",
		"missing or invalid settlement finality bearer token",
	) {
		return
	}
	evidenceID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnslashing/evidence")
	if !ok || !hasID {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}

	var payload settlementSlashEvidencePayload
	payloadFields, err := decodeSettlementSlashEvidenceFinalityJSON(r, &payload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	if payload.EvidenceID != "" && slashingtypes.NormalizeEvidenceID(payload.EvidenceID) != slashingtypes.NormalizeEvidenceID(evidenceID) {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "EvidenceID must match path evidence id"})
		return
	}
	status, ok := parseBridgeReconciliationStatus(payload.Status)
	if !ok || status != chaintypes.ReconciliationConfirmed {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "Status must be confirmed"})
		return
	}

	existing, err := h.scaffold.SlashingQueryServer().GetEvidence(r.Context(), app.SlashingGetEvidenceRequest{
		EvidenceID: evidenceID,
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}
	if !existing.Found {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: slashingmodule.ErrEvidenceNotFound.Error()})
		return
	}
	if err := validateSlashEvidenceFinalityMaterial(payload, payloadFields, existing.Evidence); err != nil {
		writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	resp, err := h.scaffold.SlashingMsgServer().ConfirmEvidence(r.Context(), app.SlashingConfirmEvidenceRequest{
		EvidenceID: evidenceID,
	})
	if err != nil {
		if errors.Is(err, slashingmodule.ErrEvidenceNotFound) {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: err.Error()})
			return
		}
		writeBridgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Evidence.EvidenceID,
	})
}

func (h *settlementBridgeHandler) handleSlashPenalties(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.handleSlashPenaltyPost(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}

	penaltyID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnslashing/penalties")
	if !ok {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}
	if hasID {
		resp, err := h.scaffold.SlashingQueryServer().GetPenalty(r.Context(), app.SlashingGetPenaltyRequest{
			PenaltyID: penaltyID,
		})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		if !resp.Found {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"penalty": resp.Penalty,
		})
		return
	}

	resp, err := h.scaffold.SlashingQueryServer().ListPenalties(r.Context(), app.SlashingListPenaltiesRequest{})
	if err != nil {
		writeBridgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"penalties": resp.Penalties,
	})
}

func (h *settlementBridgeHandler) handleSlashPenaltyPost(w http.ResponseWriter, r *http.Request) {
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementSlashPenaltyPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	penaltyID := strings.TrimSpace(payload.PenaltyID)
	if penaltyID == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "penalty_id is required"})
		return
	}
	evidenceID := strings.TrimSpace(payload.EvidenceID)
	if evidenceID == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "evidence_id is required"})
		return
	}
	currency := strings.TrimSpace(payload.Currency)
	if payload.SlashMicros < 0 {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "slash_micros cannot be negative"})
		return
	}
	if payload.SlashMicros > 0 && currency == "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "currency is required when slash_micros is provided"})
		return
	}
	if payload.SlashMicros == 0 && currency != "" {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: "slash_micros must be > 0 when currency is provided"})
		return
	}

	resp, err := h.scaffold.SlashingMsgServer().ApplyPenalty(r.Context(), app.SlashingApplyPenaltyRequest{
		Record: slashingtypes.PenaltyDecision{
			PenaltyID:       penaltyID,
			EvidenceID:      evidenceID,
			SlashBasisPoint: payload.SlashBasisPoint,
			SlashAmount:     payload.SlashMicros,
			SlashDenom:      currency,
			Jailed:          payload.Jailed,
			AppliedAtUnix:   unixOrZero(payload.AppliedAt),
		},
	})
	if err != nil {
		switch {
		case errors.Is(err, slashingmodule.ErrPenaltyConflict):
			writeJSON(w, http.StatusConflict, bridgeEnvelope{OK: false, Error: err.Error()})
		case errors.Is(err, slashingmodule.ErrEvidenceNotFound):
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: err.Error()})
		default:
			writeBridgeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Penalty.PenaltyID,
	})
}

func (h *settlementBridgeHandler) handleValidatorEligibilities(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		validatorID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnvalidator/eligibilities")
		if !ok {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		if hasID {
			resp, err := h.scaffold.ValidatorQueryServer().GetEligibility(r.Context(), app.ValidatorGetEligibilityRequest{
				ValidatorID: validatorID,
			})
			if err != nil {
				writeBridgeError(w, err)
				return
			}
			if !resp.Found {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":          true,
				"eligibility": resp.Eligibility,
			})
			return
		}

		resp, err := h.scaffold.ValidatorQueryServer().ListEligibilities(r.Context(), app.ValidatorListEligibilitiesRequest{})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"eligibilities": resp.Eligibilities,
		})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementValidatorEligibilityPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	resp, err := h.scaffold.ValidatorMsgServer().SetEligibility(r.Context(), app.ValidatorSetEligibilityRequest{
		Record: validatortypes.ValidatorEligibility{
			ValidatorID:     payload.ValidatorID,
			OperatorAddress: payload.OperatorAddress,
			Eligible:        payload.Eligible,
			PolicyReason:    payload.PolicyReason,
			UpdatedAtUnix:   unixOrZero(payload.UpdatedAt),
			Status:          chaintypes.ReconciliationSubmitted,
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Eligibility.ValidatorID,
	})
}

func (h *settlementBridgeHandler) handleValidatorStatusRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		statusID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnvalidator/status-records")
		if !ok {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		if hasID {
			resp, err := h.scaffold.ValidatorQueryServer().GetStatusRecord(r.Context(), app.ValidatorGetStatusRecordRequest{
				StatusID: statusID,
			})
			if err != nil {
				writeBridgeError(w, err)
				return
			}
			if !resp.Found {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":     true,
				"status": resp.Record,
			})
			return
		}

		resp, err := h.scaffold.ValidatorQueryServer().ListStatusRecords(r.Context(), app.ValidatorListStatusRecordsRequest{})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"records": resp.Records,
		})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementValidatorStatusPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	if err := validateBridgeValidatorStatusEvidenceRef(payload.EvidenceRef); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	resp, err := h.scaffold.ValidatorMsgServer().RecordStatus(r.Context(), app.ValidatorRecordStatusRequest{
		Record: validatortypes.ValidatorStatusRecord{
			StatusID:         payload.StatusID,
			ValidatorID:      payload.ValidatorID,
			ConsensusAddress: payload.ConsensusAddress,
			LifecycleStatus:  strings.ToLower(strings.TrimSpace(payload.LifecycleStatus)),
			EvidenceHeight:   payload.EvidenceHeight,
			EvidenceRef:      payload.EvidenceRef,
			RecordedAtUnix:   unixOrZero(payload.RecordedAt),
			Status:           chaintypes.ReconciliationSubmitted,
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Status.StatusID,
	})
}

func (h *settlementBridgeHandler) handleValidatorEpochSelectionPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementValidatorEpochSelectionPreviewPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	if len(payload.Candidates) > settlementBridgeMaxEpochSelectionPreviewCandidates {
		writeJSON(
			w,
			http.StatusBadRequest,
			bridgeEnvelope{
				OK:    false,
				Error: fmt.Sprintf("candidate set too large: max=%d got=%d", settlementBridgeMaxEpochSelectionPreviewCandidates, len(payload.Candidates)),
			},
		)
		return
	}

	queryServer, err := h.validatorEpochSelectionPreviewQueryServer()
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	resp, err := queryServer.PreviewEpochSelection(validatormodule.PreviewEpochSelectionRequest{
		Policy:     payload.Policy,
		Candidates: payload.Candidates,
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, settlementValidatorEpochSelectionPreviewResponse{
		OK:      true,
		Preview: normalizeEpochSelectionResult(resp.Result),
	})
}

func (h *settlementBridgeHandler) handleGovernancePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		policyID, hasID, ok := getEntityID(r.URL.Path, "/x/vpngovernance/policies")
		if !ok {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		if hasID {
			resp, err := h.scaffold.GovernanceQueryServer().GetPolicy(r.Context(), app.GovernanceGetPolicyRequest{
				PolicyID: policyID,
			})
			if err != nil {
				writeBridgeError(w, err)
				return
			}
			if !resp.Found {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":     true,
				"policy": resp.Policy,
			})
			return
		}

		resp, err := h.scaffold.GovernanceQueryServer().ListPolicies(r.Context(), app.GovernanceListPoliciesRequest{})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"policies": resp.Policies,
		})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementGovernancePolicyPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	resp, err := h.scaffold.GovernanceMsgServer().CreatePolicy(r.Context(), app.GovernanceCreatePolicyRequest{
		Record: governancetypes.GovernancePolicy{
			PolicyID:        payload.PolicyID,
			Title:           payload.Title,
			Description:     payload.Description,
			Version:         payload.Version,
			ActivatedAtUnix: unixOrZero(payload.ActivatedAt),
			Status:          chaintypes.ReconciliationSubmitted,
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Policy.PolicyID,
	})
}

func (h *settlementBridgeHandler) handleGovernanceDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		decisionID, hasID, ok := getEntityID(r.URL.Path, "/x/vpngovernance/decisions")
		if !ok {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		if hasID {
			resp, err := h.scaffold.GovernanceQueryServer().GetDecision(r.Context(), app.GovernanceGetDecisionRequest{
				DecisionID: decisionID,
			})
			if err != nil {
				writeBridgeError(w, err)
				return
			}
			if !resp.Found {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":       true,
				"decision": resp.Decision,
			})
			return
		}

		resp, err := h.scaffold.GovernanceQueryServer().ListDecisions(r.Context(), app.GovernanceListDecisionsRequest{})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"decisions": resp.Decisions,
		})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementGovernanceDecisionPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	decider := strings.TrimSpace(payload.Decider)
	if authenticatedPrincipal := h.authenticatedPrincipal(); authenticatedPrincipal != "" {
		boundDecider, ok := bindIdentityFieldToAuthenticatedCaller(decider, authenticatedPrincipal)
		if !ok {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{
				OK:    false,
				Error: "Decider must match authenticated caller",
			})
			return
		}
		decider = boundDecider
	}
	resp, err := h.scaffold.GovernanceMsgServer().RecordDecision(r.Context(), app.GovernanceRecordDecisionRequest{
		Record: governancetypes.GovernanceDecision{
			DecisionID:    payload.DecisionID,
			PolicyID:      payload.PolicyID,
			ProposalID:    payload.ProposalID,
			Outcome:       strings.ToLower(strings.TrimSpace(payload.Outcome)),
			Decider:       decider,
			Reason:        payload.Reason,
			DecidedAtUnix: unixOrZero(payload.DecidedAt),
			Status:        chaintypes.ReconciliationSubmitted,
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Decision.DecisionID,
	})
}

func (h *settlementBridgeHandler) handleGovernanceAuditActions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		actionID, hasID, ok := getEntityID(r.URL.Path, "/x/vpngovernance/audit-actions")
		if !ok {
			writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
			return
		}
		if hasID {
			resp, err := h.scaffold.GovernanceQueryServer().GetAuditAction(r.Context(), app.GovernanceGetAuditActionRequest{
				ActionID: actionID,
			})
			if err != nil {
				writeBridgeError(w, err)
				return
			}
			if !resp.Found {
				writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":     true,
				"action": resp.Action,
			})
			return
		}

		resp, err := h.scaffold.GovernanceQueryServer().ListAuditActions(r.Context(), app.GovernanceListAuditActionsRequest{})
		if err != nil {
			writeBridgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"actions": resp.Actions,
		})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}
	if !h.authorizePOST(w, r) {
		return
	}

	var payload settlementGovernanceAuditActionPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}
	actor := strings.TrimSpace(payload.Actor)
	if authenticatedPrincipal := h.authenticatedPrincipal(); authenticatedPrincipal != "" {
		boundActor, ok := bindIdentityFieldToAuthenticatedCaller(actor, authenticatedPrincipal)
		if !ok {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{
				OK:    false,
				Error: "Actor must match authenticated caller",
			})
			return
		}
		actor = boundActor
	}
	resp, err := h.scaffold.GovernanceMsgServer().RecordAuditAction(r.Context(), app.GovernanceRecordAuditActionRequest{
		Record: governancetypes.GovernanceAuditAction{
			ActionID:        payload.ActionID,
			Action:          payload.Action,
			Actor:           actor,
			Reason:          payload.Reason,
			EvidencePointer: payload.EvidencePointer,
			TimestampUnix:   unixOrZero(payload.Timestamp),
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, bridgeEnvelope{
		OK:     true,
		Replay: resp.Replay,
		ID:     resp.Action.ActionID,
	})
}

func (h *settlementBridgeHandler) authorizePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return false
	}
	return h.authorizeRequest(w, r)
}

func (h *settlementBridgeHandler) authorizeRequest(w http.ResponseWriter, r *http.Request) bool {
	if h.authToken == "" {
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{OK: false, Error: "unauthenticated mode only allows loopback clients"})
			return false
		}
		if !isAllowedUnauthenticatedOrigin(r.Header.Get("Origin"), h.listenAddr) {
			writeJSON(w, http.StatusForbidden, bridgeEnvelope{OK: false, Error: "cross-origin requests are not allowed in unauthenticated mode"})
			return false
		}
		return true
	}
	if !hasValidBearerTokenHeader(r.Header.Get("Authorization"), h.authToken) {
		writeJSON(w, http.StatusUnauthorized, bridgeEnvelope{OK: false, Error: "missing or invalid bearer token"})
		return false
	}
	return true
}

func (h *settlementBridgeHandler) authorizeScopedBearerToken(w http.ResponseWriter, r *http.Request, token, headerName, missingConfigMessage, invalidTokenMessage string) bool {
	if strings.TrimSpace(token) == "" {
		writeJSON(w, http.StatusServiceUnavailable, bridgeEnvelope{OK: false, Error: missingConfigMessage})
		return false
	}
	if !hasValidBearerTokenHeader(r.Header.Get(headerName), token) {
		writeJSON(w, http.StatusUnauthorized, bridgeEnvelope{OK: false, Error: invalidTokenMessage})
		return false
	}
	return true
}

func isAllowedUnauthenticatedOrigin(rawOrigin, listenAddr string) bool {
	return isAllowedUnauthenticatedOriginWithLoopbackCheck(rawOrigin, listenAddr, isLoopbackHost)
}

func canonicalBridgePrincipal(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func canonicalBridgeIdentifier(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func bindIdentityFieldToAuthenticatedCaller(rawFieldValue, authenticatedPrincipal string) (string, bool) {
	principal := canonicalBridgePrincipal(authenticatedPrincipal)
	if principal == "" {
		return strings.TrimSpace(rawFieldValue), true
	}
	rawFieldValue = canonicalBridgePrincipal(rawFieldValue)
	if rawFieldValue == "" || rawFieldValue == principal {
		return principal, true
	}
	return "", false
}

func (h *settlementBridgeHandler) authenticatedPrincipal() string {
	if h == nil || h.authToken == "" {
		return ""
	}
	return canonicalBridgePrincipal(h.authPrincipal)
}
func isAllowedUnauthenticatedOriginWithLoopbackCheck(rawOrigin, listenAddr string, isLoopbackHostCheck loopbackHostCheckFunc) bool {
	if isLoopbackHostCheck == nil {
		return false
	}
	rawOrigin = strings.TrimSpace(rawOrigin)
	if rawOrigin == "" {
		return false
	}
	originURL, err := urlpkg.Parse(rawOrigin)
	if err != nil || originURL.Host == "" || (originURL.Scheme != "http" && originURL.Scheme != "https") {
		return false
	}
	originHost := strings.TrimSpace(originURL.Hostname())
	if originHost == "" {
		return false
	}
	if !isLoopbackHostCheck(originHost) {
		return false
	}

	listenPort := listenAddressPortWithLoopbackCheck(listenAddr, isLoopbackHostCheck)
	if listenPort == "" {
		return false
	}
	originPort := originURL.Port()
	if originPort == "" {
		if originURL.Scheme == "https" {
			originPort = "443"
		} else {
			originPort = "80"
		}
	}
	return subtle.ConstantTimeCompare([]byte(originPort), []byte(listenPort)) == 1
}

func isLoopbackOrLocalhost(host string) bool {
	return isLoopbackHost(host)
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	return isLoopbackRemoteAddrWithLoopbackCheck(remoteAddr, isLoopbackHost)
}

func isLoopbackRemoteAddrWithLoopbackCheck(remoteAddr string, isLoopbackHostCheck loopbackHostCheckFunc) bool {
	if isLoopbackHostCheck == nil {
		return false
	}
	addr := strings.TrimSpace(remoteAddr)
	if addr == "" {
		return false
	}
	host := addr
	if parsedHost, _, err := net.SplitHostPort(addr); err == nil {
		host = parsedHost
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	return isLoopbackHostCheck(host)
}

func listenAddressPort(addr string) string {
	return listenAddressPortWithLoopbackCheck(addr, isLoopbackHost)
}

func listenAddressPortWithLoopbackCheck(addr string, isLoopbackHostCheck loopbackHostCheckFunc) string {
	if isLoopbackHostCheck == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host != "" && !isLoopbackHostCheck(host) {
		return ""
	}
	return strings.TrimSpace(port)
}

func (h *settlementBridgeHandler) validatorEpochSelectionPreviewQueryServer() (validatormodule.QueryServer, error) {
	if h == nil || h.scaffold == nil {
		return validatormodule.QueryServer{}, errors.New("vpnvalidator preview query server not wired")
	}

	scaffold, ok := h.scaffold.(*app.ChainScaffold)
	if !ok || scaffold == nil {
		return validatormodule.QueryServer{}, errors.New("vpnvalidator preview query server not wired")
	}

	return validatormodule.NewQueryServer(scaffold.ValidatorModule.Keeper), nil
}

func hasValidBearerTokenHeader(rawHeader, expectedToken string) bool {
	rawHeader = strings.TrimSpace(rawHeader)
	parts := strings.SplitN(rawHeader, " ", 2)
	if len(parts) != 2 {
		return false
	}
	if !strings.EqualFold(parts[0], "bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedToken)) == 1
}

func getEntityID(path, collectionPath string) (id string, hasID bool, ok bool) {
	normalizedPath := strings.TrimSuffix(path, "/")
	if normalizedPath == collectionPath {
		return "", false, true
	}
	prefix := collectionPath + "/"
	if !strings.HasPrefix(normalizedPath, prefix) {
		return "", false, false
	}
	id = strings.TrimSpace(strings.TrimPrefix(normalizedPath, prefix))
	if id == "" || strings.Contains(id, "/") {
		return "", false, false
	}
	return id, true, true
}

func getEscapedProofPath(r *http.Request, collectionPath string) (string, bool) {
	if r == nil || r.URL == nil {
		return "", false
	}
	escapedPath := strings.TrimSuffix(r.URL.EscapedPath(), "/")
	prefix := collectionPath + "/"
	if !strings.HasPrefix(escapedPath, prefix) {
		return "", false
	}
	escapedID := strings.TrimPrefix(escapedPath, prefix)
	if strings.TrimSpace(escapedID) == "" {
		return "", false
	}
	proofPath, err := urlpkg.PathUnescape(escapedID)
	if err != nil {
		return "", false
	}
	proofPath = strings.TrimSpace(proofPath)
	if proofPath == "" || strings.ContainsAny(proofPath, " \t\r\n") {
		return "", false
	}
	return proofPath, true
}

func bridgeCallerReservationStatus(raw string) (chaintypes.ReconciliationStatus, error) {
	if strings.TrimSpace(raw) == "" {
		return chaintypes.ReconciliationPending, nil
	}
	status, ok := parseBridgeReconciliationStatus(raw)
	if !ok {
		return "", fmt.Errorf("reservation Status must be one of: pending, submitted")
	}
	switch status {
	case chaintypes.ReconciliationPending, chaintypes.ReconciliationSubmitted, chaintypes.ReconciliationConfirmed:
		return status, nil
	default:
		return "", fmt.Errorf("reservation Status must be pending, submitted, or confirmed")
	}
}

func bridgeSettlementOperationState(raw string) (chaintypes.ReconciliationStatus, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("Status must be confirmed")
	}
	status, ok := parseBridgeReconciliationStatus(raw)
	if !ok {
		return "", fmt.Errorf("Status must be one of: pending, submitted, confirmed, failed")
	}
	return status, nil
}

func parseBridgeReconciliationStatus(raw string) (chaintypes.ReconciliationStatus, bool) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.TrimPrefix(normalized, "reconciliation_status_")
	switch normalized {
	case string(chaintypes.ReconciliationPending):
		return chaintypes.ReconciliationPending, true
	case string(chaintypes.ReconciliationSubmitted):
		return chaintypes.ReconciliationSubmitted, true
	case string(chaintypes.ReconciliationConfirmed):
		return chaintypes.ReconciliationConfirmed, true
	case string(chaintypes.ReconciliationFailed):
		return chaintypes.ReconciliationFailed, true
	default:
		return "", false
	}
}

func canonicalBridgeReconciliationStatus(status chaintypes.ReconciliationStatus) chaintypes.ReconciliationStatus {
	if parsed, ok := parseBridgeReconciliationStatus(string(status)); ok {
		return parsed
	}
	return chaintypes.ReconciliationStatus(strings.ToLower(strings.TrimSpace(string(status))))
}

type settlementSponsorReservationCurrencyRecord struct {
	ReservationID string
	SponsorID     string
	SessionID     string
	Currency      string
	AmountMicros  int64
	CreatedAtUnix int64
}

func validateBridgeCurrency(raw string) (string, error) {
	currency := strings.ToLower(strings.TrimSpace(raw))
	if currency == "" {
		return "", errors.New("Currency is required")
	}
	if len(currency) > 64 || strings.ContainsAny(currency, " \t\r\n") {
		return "", errors.New("Currency must be a canonical non-empty token")
	}
	return currency, nil
}

func sponsorReservationCurrencyMetadataID(reservationID string) string {
	return sponsorReservationCurrencyMetadataPrefix + strings.ToLower(strings.TrimSpace(reservationID))
}

func isSponsorReservationCurrencyMetadataID(reservationID string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(reservationID)), sponsorReservationCurrencyMetadataPrefix)
}

func visibleBillingReservations(records []billingtypes.CreditReservation) []billingtypes.CreditReservation {
	visible := make([]billingtypes.CreditReservation, 0, len(records))
	for _, record := range records {
		if isSponsorReservationCurrencyMetadataID(record.ReservationID) {
			continue
		}
		visible = append(visible, record)
	}
	return visible
}

func (h *settlementBridgeHandler) validateSponsorReservationCurrency(ctx context.Context, reservationID string, currency string) (int, string, error) {
	existingCurrency, found, err := h.sponsorReservationCurrency(ctx, reservationID)
	if err != nil || !found {
		return 0, "", err
	}
	if existingCurrency != currency {
		return http.StatusConflict, "sponsor reservation currency does not match existing reservation", nil
	}
	return 0, "", nil
}

func (h *settlementBridgeHandler) validateSponsorReservationOperation(
	ctx context.Context,
	authorization sponsortypes.SponsorAuthorization,
	delegation sponsortypes.DelegatedSessionCredit,
) (int, string, error) {
	normalizedAuthorization := normalizeBridgeSponsorAuthorization(authorization)
	if err := normalizedAuthorization.ValidateBasic(); err != nil {
		return http.StatusBadRequest, err.Error(), nil
	}
	normalizedDelegation := normalizeBridgeSponsorDelegation(delegation)
	if err := normalizedDelegation.ValidateBasic(); err != nil {
		return http.StatusBadRequest, err.Error(), nil
	}

	authResp, err := h.scaffold.SponsorQueryServer().GetAuthorization(ctx, app.SponsorGetAuthorizationRequest{
		AuthorizationID: normalizedAuthorization.AuthorizationID,
	})
	if err != nil {
		return 0, "", err
	}
	if authResp.Found && !bridgeSponsorAuthorizationsEqual(normalizeBridgeSponsorAuthorization(authResp.Authorization), normalizedAuthorization) {
		return http.StatusConflict, "vpnsponsor: authorization conflict", nil
	}

	delegationResp, err := h.scaffold.SponsorQueryServer().GetDelegation(ctx, app.SponsorGetDelegationRequest{
		ReservationID: normalizedDelegation.ReservationID,
	})
	if err != nil {
		return 0, "", err
	}
	if delegationResp.Found && !bridgeSponsorDelegationsEqual(normalizeBridgeSponsorDelegation(delegationResp.Delegation), normalizedDelegation) {
		return http.StatusConflict, "vpnsponsor: delegation conflict", nil
	}

	return 0, "", nil
}

func (h *settlementBridgeHandler) persistSponsorReservationCurrency(ctx context.Context, record settlementSponsorReservationCurrencyRecord) error {
	currency, err := validateBridgeCurrency(record.Currency)
	if err != nil {
		return err
	}
	_, found, err := h.sponsorReservationCurrency(ctx, record.ReservationID)
	if err != nil {
		return err
	}
	if found {
		return nil
	}

	_, err = h.scaffold.BillingMsgServer().CreateReservation(ctx, app.BillingCreateReservationRequest{
		Record: billingtypes.CreditReservation{
			ReservationID: sponsorReservationCurrencyMetadataID(record.ReservationID),
			SponsorID:     sponsorReservationCurrencyMetadataID(record.ReservationID),
			SessionID:     strings.TrimSpace(record.SessionID),
			AssetDenom:    currency,
			Amount:        record.AmountMicros,
			CreatedAtUnix: record.CreatedAtUnix,
			Status:        chaintypes.ReconciliationPending,
		},
	})
	return err
}

func (h *settlementBridgeHandler) sponsorReservationCurrency(ctx context.Context, reservationID string) (string, bool, error) {
	resp, err := h.scaffold.BillingQueryServer().GetReservation(ctx, app.BillingGetReservationRequest{
		ReservationID: sponsorReservationCurrencyMetadataID(reservationID),
	})
	if err != nil {
		return "", false, err
	}
	if !resp.Found {
		return "", false, nil
	}
	return strings.TrimSpace(resp.Reservation.AssetDenom), true, nil
}

func normalizeBridgeSponsorAuthorization(record sponsortypes.SponsorAuthorization) sponsortypes.SponsorAuthorization {
	record = sponsortypes.NormalizeSponsorAuthorization(record)
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeBridgeSponsorDelegation(record sponsortypes.DelegatedSessionCredit) sponsortypes.DelegatedSessionCredit {
	record = sponsortypes.NormalizeDelegatedSessionCredit(record)
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func bridgeSponsorAuthorizationsEqual(left, right sponsortypes.SponsorAuthorization) bool {
	return left.AuthorizationID == right.AuthorizationID &&
		left.SponsorID == right.SponsorID &&
		left.AppID == right.AppID &&
		left.MaxCredits == right.MaxCredits &&
		left.ExpiresAtUnix == right.ExpiresAtUnix &&
		left.Status == right.Status
}

func bridgeSponsorDelegationsEqual(left, right sponsortypes.DelegatedSessionCredit) bool {
	return left.ReservationID == right.ReservationID &&
		left.AuthorizationID == right.AuthorizationID &&
		left.SponsorID == right.SponsorID &&
		left.AppID == right.AppID &&
		left.EndUserID == right.EndUserID &&
		left.SessionID == right.SessionID &&
		left.Credits == right.Credits &&
		left.Status == right.Status
}

func (h *settlementBridgeHandler) enrichSponsorAuthorization(ctx context.Context, record sponsortypes.SponsorAuthorization) settlementSponsorAuthorizationResponse {
	enriched := settlementSponsorAuthorizationResponse{SponsorAuthorization: record}
	reservationID := sponsorReservationIDFromAuthorizationID(record.AuthorizationID)
	if reservationID == "" {
		return enriched
	}
	currency, found, err := h.sponsorReservationCurrency(ctx, reservationID)
	if err == nil && found {
		enriched.Currency = currency
	}
	return enriched
}

func (h *settlementBridgeHandler) enrichSponsorAuthorizations(ctx context.Context, records []sponsortypes.SponsorAuthorization) []settlementSponsorAuthorizationResponse {
	enriched := make([]settlementSponsorAuthorizationResponse, 0, len(records))
	for _, record := range records {
		enriched = append(enriched, h.enrichSponsorAuthorization(ctx, record))
	}
	return enriched
}

func (h *settlementBridgeHandler) enrichSponsorDelegation(ctx context.Context, record sponsortypes.DelegatedSessionCredit) settlementSponsorDelegationResponse {
	enriched := settlementSponsorDelegationResponse{DelegatedSessionCredit: record}
	currency, found, err := h.sponsorReservationCurrency(ctx, record.ReservationID)
	if err == nil && found {
		enriched.Currency = currency
	}
	return enriched
}

func (h *settlementBridgeHandler) enrichSponsorDelegations(ctx context.Context, records []sponsortypes.DelegatedSessionCredit) []settlementSponsorDelegationResponse {
	enriched := make([]settlementSponsorDelegationResponse, 0, len(records))
	for _, record := range records {
		enriched = append(enriched, h.enrichSponsorDelegation(ctx, record))
	}
	return enriched
}

func sponsorReservationIDFromAuthorizationID(authorizationID string) string {
	const prefix = "auth:"
	authorizationID = strings.TrimSpace(authorizationID)
	if !strings.HasPrefix(authorizationID, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authorizationID, prefix))
}

func settlementRewardPayoutRef(payload settlementRewardPayload) string {
	rewardID := strings.TrimSpace(payload.RewardID)
	settlementRef := strings.TrimSpace(payload.SettlementReferenceID)
	trafficProofRef := strings.TrimSpace(payload.TrafficProofRef)
	if settlementRef == "" && trafficProofRef == "" && payload.PayoutPeriodStart.IsZero() && payload.PayoutPeriodEnd.IsZero() {
		return rewardID
	}

	ref := struct {
		RewardID              string `json:"RewardID"`
		SettlementReferenceID string `json:"SettlementReferenceID,omitempty"`
		TrafficProofRef       string `json:"TrafficProofRef,omitempty"`
		PayoutPeriodStart     string `json:"PayoutPeriodStart,omitempty"`
		PayoutPeriodEnd       string `json:"PayoutPeriodEnd,omitempty"`
	}{
		RewardID:              rewardID,
		SettlementReferenceID: settlementRef,
		TrafficProofRef:       trafficProofRef,
	}
	if !payload.PayoutPeriodStart.IsZero() {
		ref.PayoutPeriodStart = payload.PayoutPeriodStart.UTC().Format(time.RFC3339)
	}
	if !payload.PayoutPeriodEnd.IsZero() {
		ref.PayoutPeriodEnd = payload.PayoutPeriodEnd.UTC().Format(time.RFC3339)
	}
	encoded, err := json.Marshal(ref)
	if err != nil {
		return rewardID
	}
	return string(encoded)
}

func rewardProofBridgePayload(record rewardtypes.RewardProofRecord) map[string]any {
	proof := map[string]any{
		"proof_path":          record.ProofPath,
		"traffic_proof_ref":   record.TrafficProofRef,
		"trust_contract":      record.TrustContract,
		"reward_id":           record.RewardID,
		"provider_subject_id": record.ProviderSubjectID,
		"session_id":          record.SessionID,
		"reward_micros":       record.RewardMicros,
		"currency":            record.Currency,
		"verified":            record.Verified,
		"verifier_id":         record.VerifierID,
	}
	if record.PayoutStartUnix > 0 {
		proof["payout_period_start"] = time.Unix(record.PayoutStartUnix, 0).UTC().Format(time.RFC3339)
	}
	if record.PayoutEndUnix > 0 {
		proof["payout_period_end"] = time.Unix(record.PayoutEndUnix, 0).UTC().Format(time.RFC3339)
	}
	if record.IssuedAtUnix > 0 {
		proof["issued_at"] = time.Unix(record.IssuedAtUnix, 0).UTC().Format(time.RFC3339)
	}
	if record.VerifiedAtUnix > 0 {
		proof["verified_at_utc"] = time.Unix(record.VerifiedAtUnix, 0).UTC().Format(time.RFC3339)
	}
	return proof
}

func validateSettlementRewardMetadata(payload settlementRewardPayload) error {
	trafficProofRef := strings.TrimSpace(payload.TrafficProofRef)
	if trafficProofRef == "" {
		return errors.New("traffic_proof_ref is required for reward issuance")
	} else if _, ok := rewardtypes.ProofPathFromTrafficProofRef(trafficProofRef); !ok {
		return errors.New("traffic_proof_ref must be a verified objective proof reference (obj://<path>)")
	}

	hasPeriodStart := !payload.PayoutPeriodStart.IsZero()
	hasPeriodEnd := !payload.PayoutPeriodEnd.IsZero()
	if !hasPeriodStart && !hasPeriodEnd {
		return errors.New("payout_period_start and payout_period_end are required for reward issuance")
	}
	if hasPeriodStart != hasPeriodEnd {
		return errors.New("payout_period_start and payout_period_end are required together")
	}

	startUTC := payload.PayoutPeriodStart.UTC()
	if startUTC.Weekday() != time.Monday ||
		startUTC.Hour() != 0 ||
		startUTC.Minute() != 0 ||
		startUTC.Second() != 0 ||
		startUTC.Nanosecond() != 0 {
		return errors.New("payout_period_start must be Monday 00:00:00 UTC")
	}
	if !payload.PayoutPeriodEnd.UTC().Equal(startUTC.AddDate(0, 0, 7)) {
		return errors.New("payout_period_end must be exactly 7 days after payout_period_start")
	}
	return nil
}

func validateSettlementRewardProofMetadata(payload settlementRewardProofPayload) error {
	hasPeriodStart := !payload.PayoutPeriodStart.IsZero()
	hasPeriodEnd := !payload.PayoutPeriodEnd.IsZero()
	if !hasPeriodStart && !hasPeriodEnd {
		return errors.New("payout_period_start and payout_period_end are required for reward proof registration")
	}
	if hasPeriodStart != hasPeriodEnd {
		return errors.New("payout_period_start and payout_period_end are required together")
	}

	startUTC := payload.PayoutPeriodStart.UTC()
	if startUTC.Weekday() != time.Monday ||
		startUTC.Hour() != 0 ||
		startUTC.Minute() != 0 ||
		startUTC.Second() != 0 ||
		startUTC.Nanosecond() != 0 {
		return errors.New("payout_period_start must be Monday 00:00:00 UTC")
	}
	if !payload.PayoutPeriodEnd.UTC().Equal(startUTC.AddDate(0, 0, 7)) {
		return errors.New("payout_period_end must be exactly 7 days after payout_period_start")
	}
	return nil
}

func (h *settlementBridgeHandler) validateSettlementRewardEvidence(
	ctx context.Context,
	payload settlementRewardPayload,
	providerSubjectID string,
) (int, string, error) {
	if statusCode, message, err := h.validateSettlementRewardReference(ctx, payload); err != nil || message != "" {
		return statusCode, message, err
	}
	if statusCode, message, err := h.validateSettlementRewardProofReference(ctx, payload, providerSubjectID); err != nil || message != "" {
		return statusCode, message, err
	}
	return h.validateSettlementRewardSlashHold(ctx, payload, providerSubjectID)
}

func (h *settlementBridgeHandler) validateSettlementRewardReference(
	ctx context.Context,
	payload settlementRewardPayload,
) (int, string, error) {
	settlementRef := strings.TrimSpace(payload.SettlementReferenceID)
	if settlementRef == "" {
		return 0, "", nil
	}
	resp, err := h.scaffold.BillingQueryServer().GetSettlement(ctx, app.BillingGetSettlementRequest{
		SettlementID: settlementRef,
	})
	if err != nil {
		return 0, "", err
	}
	if !resp.Found {
		return http.StatusNotFound, "settlement_reference_id not found", nil
	}
	if strings.TrimSpace(resp.Settlement.SessionID) != strings.TrimSpace(payload.SessionID) {
		return http.StatusConflict, "settlement_reference_id session mismatch", nil
	}
	if resp.Settlement.OperationState != chaintypes.ReconciliationConfirmed {
		return http.StatusConflict, "settlement_reference_id is not confirmed", nil
	}
	return 0, "", nil
}

func (h *settlementBridgeHandler) validateSettlementRewardProofReference(
	ctx context.Context,
	payload settlementRewardPayload,
	providerSubjectID string,
) (int, string, error) {
	trafficProofRef := strings.TrimSpace(payload.TrafficProofRef)
	if trafficProofRef == "" {
		return http.StatusBadRequest, "traffic_proof_ref is required for reward issuance", nil
	}
	proofPath, ok := rewardtypes.ProofPathFromTrafficProofRef(trafficProofRef)
	if !ok {
		return http.StatusBadRequest, "traffic_proof_ref must be a verified objective proof reference (obj://<path>)", nil
	}
	resp, err := h.scaffold.RewardsQueryServer().GetProof(ctx, app.RewardsGetProofRequest{
		ProofPath: proofPath,
	})
	if err != nil {
		return 0, "", err
	}
	if !resp.Found {
		return http.StatusConflict, "traffic_proof_ref is not a verified reward proof", nil
	}
	if err := resp.Proof.ValidateVerified(); err != nil {
		return http.StatusConflict, "traffic_proof_ref is not a verified reward proof", nil
	}
	configuredVerifierID := canonicalBridgePrincipal(h.rewardProofVerifierID)
	if configuredVerifierID != "" && canonicalBridgePrincipal(resp.Proof.VerifierID) != configuredVerifierID {
		return http.StatusConflict, "traffic_proof_ref verifier does not match configured reward proof verifier", nil
	}
	if !settlementRewardProofMatchesPayload(resp.Proof, payload, providerSubjectID) {
		return http.StatusConflict, "traffic_proof_ref does not match reward payload", nil
	}
	return 0, "", nil
}

func (h *settlementBridgeHandler) validateSettlementRewardSlashHold(
	ctx context.Context,
	payload settlementRewardPayload,
	providerSubjectID string,
) (int, string, error) {
	if held, err := h.rewardSlashHoldMatches(ctx, providerSubjectID, strings.TrimSpace(payload.SessionID), 0, 0); err != nil {
		return 0, "", err
	} else if held {
		return http.StatusConflict, "reward payout is held by slash evidence for provider/session", nil
	}
	if !payload.PayoutPeriodStart.IsZero() && !payload.PayoutPeriodEnd.IsZero() {
		held, err := h.rewardSlashHoldMatches(
			ctx,
			providerSubjectID,
			"",
			payload.PayoutPeriodStart.UTC().Unix(),
			payload.PayoutPeriodEnd.UTC().Unix(),
		)
		if err != nil {
			return 0, "", err
		}
		if held {
			return http.StatusConflict, "reward payout is held by slash evidence for provider/week", nil
		}
	}
	return 0, "", nil
}

func (h *settlementBridgeHandler) rewardSlashHoldMatches(
	ctx context.Context,
	providerSubjectID string,
	sessionID string,
	submittedAtOrAfterUnix int64,
	submittedBeforeUnix int64,
) (bool, error) {
	resp, err := h.scaffold.SlashingQueryServer().ListEvidence(ctx, app.SlashingListEvidenceRequest{
		ProviderID:             providerSubjectID,
		SessionID:              strings.TrimSpace(sessionID),
		SubmittedAtOrAfterUnix: submittedAtOrAfterUnix,
		SubmittedBeforeUnix:    submittedBeforeUnix,
		IncludeFailed:          false,
		IncludeFailedSet:       true,
		IncludeZeroSubmitted:   true,
	})
	if err != nil {
		return false, err
	}
	return len(resp.Evidence) > 0, nil
}

func settlementRewardProofMatchesPayload(
	proof rewardtypes.RewardProofRecord,
	payload settlementRewardPayload,
	providerSubjectID string,
) bool {
	proof = proof.Canonicalize()
	return proof.TrafficProofRef == strings.TrimSpace(payload.TrafficProofRef) &&
		proof.RewardID == strings.TrimSpace(payload.RewardID) &&
		proof.ProviderSubjectID == strings.TrimSpace(providerSubjectID) &&
		proof.SessionID == strings.TrimSpace(payload.SessionID) &&
		proof.PayoutStartUnix == unixOrZero(payload.PayoutPeriodStart) &&
		proof.PayoutEndUnix == unixOrZero(payload.PayoutPeriodEnd) &&
		proof.RewardMicros == payload.RewardMicros &&
		proof.Currency == strings.TrimSpace(payload.Currency) &&
		proof.IssuedAtUnix == unixOrZero(payload.IssuedAt)
}

func settlementRewardAccruedAtUnix(payload settlementRewardPayload) int64 {
	if !payload.PayoutPeriodStart.IsZero() {
		return payload.PayoutPeriodStart.UTC().Unix()
	}
	return unixOrZero(payload.IssuedAt)
}

func validateSettlementSlashMetadata(payload settlementSlashEvidencePayload) error {
	if payload.SlashMicros < 0 {
		return errors.New("slash_micros cannot be negative")
	}
	currency := strings.TrimSpace(payload.Currency)
	if payload.SlashMicros > 0 && currency == "" {
		return errors.New("currency is required when slash_micros is provided")
	}
	if payload.SlashMicros == 0 && currency != "" {
		return errors.New("slash_micros must be > 0 when currency is provided")
	}
	if currency != "" {
		if _, err := validateBridgeCurrency(currency); err != nil {
			return err
		}
	}
	return nil
}

func decodeSettlementSlashEvidenceFinalityJSON(r *http.Request, out *settlementSlashEvidencePayload) (map[string]bool, error) {
	defer r.Body.Close()
	if r.ContentLength > settlementBridgeMaxJSONBodyBytes {
		return nil, fmt.Errorf("invalid JSON payload: request body too large (max %d bytes)", settlementBridgeMaxJSONBodyBytes)
	}
	limitedBody := &io.LimitedReader{
		R: r.Body,
		N: settlementBridgeMaxJSONBodyBytes + 1,
	}
	body, err := io.ReadAll(limitedBody)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON payload: %w", err)
	}
	if limitedBody.N <= 0 {
		return nil, fmt.Errorf("invalid JSON payload: request body too large (max %d bytes)", settlementBridgeMaxJSONBodyBytes)
	}

	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return nil, fmt.Errorf("invalid JSON payload: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid JSON payload: %w", err)
	}
	if len(trailing) > 0 {
		return nil, errors.New("invalid JSON payload: trailing data after JSON value")
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON payload: %w", err)
	}
	fields := make(map[string]bool, len(raw))
	for key := range raw {
		fields[key] = true
	}
	return fields, nil
}

func slashEvidenceFinalityFieldPresent(fields map[string]bool, names ...string) bool {
	for _, name := range names {
		if fields[name] {
			return true
		}
	}
	return false
}

func validateSlashEvidenceFinalityMaterial(payload settlementSlashEvidencePayload, fields map[string]bool, existing slashingtypes.SlashEvidence) error {
	if slashEvidenceFinalityFieldPresent(fields, "SubjectID", "subject_id", "ProviderID", "provider_id") {
		if got, want := slashingtypes.NormalizeProviderID(payload.SubjectID), existing.ProviderID; got != want {
			return fmt.Errorf("slash evidence finality material mismatch: subject_id got %q want %q", got, want)
		}
	}
	if slashEvidenceFinalityFieldPresent(fields, "SessionID", "session_id") {
		if got, want := slashingtypes.NormalizeSessionID(payload.SessionID), existing.SessionID; got != want {
			return fmt.Errorf("slash evidence finality material mismatch: session_id got %q want %q", got, want)
		}
	}
	if slashEvidenceFinalityFieldPresent(fields, "ViolationType", "violation_type") {
		got, err := normalizeBridgeObjectiveViolationType(payload.ViolationType)
		if err != nil {
			return err
		}
		if want := existing.ViolationType; got != want {
			return fmt.Errorf("slash evidence finality material mismatch: violation_type got %q want %q", got, want)
		}
	}
	if slashEvidenceFinalityFieldPresent(fields, "EvidenceRef", "evidence_ref", "ProofHash", "proof_hash") {
		got := strings.TrimSpace(payload.EvidenceRef)
		if err := validateBridgeSlashEvidenceRef(got); err != nil {
			return err
		}
		got = canonicalBridgeSlashEvidenceRef(got)
		want := canonicalBridgeSlashEvidenceRef(slashingtypes.CanonicalObjectiveEvidenceProofRef(existing.ProofHash))
		if got != want {
			return fmt.Errorf("slash evidence finality material mismatch: evidence_ref got %q want %q", got, want)
		}
	}
	if slashEvidenceFinalityFieldPresent(fields, "SlashMicros", "slash_micros") {
		if payload.SlashMicros != existing.SlashAmount {
			return fmt.Errorf("slash evidence finality material mismatch: slash_micros got %d want %d", payload.SlashMicros, existing.SlashAmount)
		}
	}
	if slashEvidenceFinalityFieldPresent(fields, "Currency", "currency") {
		if got, want := slashingtypes.NormalizeSlashDenom(payload.Currency), existing.SlashDenom; got != want {
			return fmt.Errorf("slash evidence finality material mismatch: currency got %q want %q", got, want)
		}
	}
	if slashEvidenceFinalityFieldPresent(fields, "ObservedAt", "observed_at") {
		if got, want := unixOrZero(payload.ObservedAt), existing.SubmittedAtUnix; got != want {
			return fmt.Errorf("slash evidence finality material mismatch: observed_at got %d want %d", got, want)
		}
	}
	return nil
}

func canonicalBridgeSlashEvidenceRef(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "sha256:") {
		return "sha256:" + strings.ToLower(value[len("sha256:"):])
	}
	return value
}

func settlementSlashProofHash(payload settlementSlashEvidencePayload, proofHash string) string {
	currency := strings.TrimSpace(payload.Currency)
	if payload.SlashMicros == 0 && currency == "" {
		return proofHash
	}

	values := urlpkg.Values{}
	values.Set("currency", currency)
	values.Set("evidence_ref", strings.TrimSpace(proofHash))
	values.Set("slash_micros", strconv.FormatInt(payload.SlashMicros, 10))
	return "obj://settlement-slash/" + urlpkg.PathEscape(strings.TrimSpace(payload.EvidenceID)) + "?" + values.Encode()
}

func normalizeEpochSelectionResult(result validatortypes.EpochSelectionResult) validatortypes.EpochSelectionResult {
	if result.StableSeats == nil {
		result.StableSeats = []validatortypes.EpochValidatorCandidate{}
	}
	if result.RotatingSeats == nil {
		result.RotatingSeats = []validatortypes.EpochValidatorCandidate{}
	}
	return result
}

func validateBridgeSlashEvidenceRef(proofHash string) error {
	if !chaintypes.IsObjectiveEvidenceFormat(proofHash) {
		return errors.New("proof hash must use objective format (sha256:<value> or obj://<value>)")
	}
	return nil
}

var bridgeObjectiveViolationTypeSet = map[string]struct{}{
	"double-sign":              {},
	"downtime-proof":           {},
	"invalid-settlement-proof": {},
	"session-replay-proof":     {},
	"sponsor-overdraft-proof":  {},
}

const bridgeObjectiveViolationTypeError = "violation_type must be one of: double-sign, downtime-proof, invalid-settlement-proof, session-replay-proof, sponsor-overdraft-proof"

func slashingListEvidenceRequestFromQuery(values urlpkg.Values) (app.SlashingListEvidenceRequest, error) {
	req := app.SlashingListEvidenceRequest{
		ProviderID:    strings.TrimSpace(firstQueryValue(values, "subject_id", "provider_id")),
		SessionID:     strings.TrimSpace(values.Get("session_id")),
		ViolationType: strings.TrimSpace(values.Get("violation_type")),
	}
	var err error
	req.SubmittedAtOrAfterUnix, err = parseBridgeUnixQueryTime(firstQueryValue(values, "observed_at_or_after", "submitted_at_or_after"))
	if err != nil {
		return app.SlashingListEvidenceRequest{}, fmt.Errorf("invalid observed_at_or_after: %w", err)
	}
	req.SubmittedBeforeUnix, err = parseBridgeUnixQueryTime(firstQueryValue(values, "observed_before", "submitted_before"))
	if err != nil {
		return app.SlashingListEvidenceRequest{}, fmt.Errorf("invalid observed_before: %w", err)
	}
	if _, ok := values["include_failed"]; ok {
		includeFailed, err := parseBridgeStrictBoolQuery(values.Get("include_failed"))
		if err != nil {
			return app.SlashingListEvidenceRequest{}, fmt.Errorf("invalid include_failed: %w", err)
		}
		req.IncludeFailed = includeFailed
		req.IncludeFailedSet = true
	}
	req.IncludeZeroSubmitted = parseBridgeBoolQuery(firstQueryValue(values, "include_zero_observed", "include_zero_submitted"))
	return req, nil
}

func firstQueryValue(values urlpkg.Values, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func parseBridgeUnixQueryTime(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return 0, err
	}
	return parsed.UTC().Unix(), nil
}

func parseBridgeBoolQuery(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func parseBridgeStrictBoolQuery(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("must be a boolean")
	}
}

func normalizeBridgeObjectiveViolationType(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return "", errors.New("violation_type is required")
	}
	if _, ok := bridgeObjectiveViolationTypeSet[normalized]; !ok {
		return "", errors.New(bridgeObjectiveViolationTypeError)
	}
	return normalized, nil
}

func validateBridgeValidatorStatusEvidenceRef(evidenceRef string) error {
	return (validatortypes.ValidatorStatusRecord{
		StatusID:        "bridge-validation",
		ValidatorID:     "bridge-validation",
		LifecycleStatus: validatortypes.ValidatorLifecycleActive,
		EvidenceRef:     evidenceRef,
	}).ValidateBasic()
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	if r.ContentLength > settlementBridgeMaxJSONBodyBytes {
		return fmt.Errorf("invalid JSON payload: request body too large (max %d bytes)", settlementBridgeMaxJSONBodyBytes)
	}
	limitedBody := &io.LimitedReader{
		R: r.Body,
		N: settlementBridgeMaxJSONBodyBytes + 1,
	}
	decoder := json.NewDecoder(limitedBody)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		if limitedBody.N <= 0 {
			return fmt.Errorf("invalid JSON payload: request body too large (max %d bytes)", settlementBridgeMaxJSONBodyBytes)
		}
		return fmt.Errorf("invalid JSON payload: %w", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	if len(trailing) > 0 {
		return fmt.Errorf("invalid JSON payload: trailing data after JSON value")
	}
	if limitedBody.N <= 0 {
		return fmt.Errorf("invalid JSON payload: request body too large (max %d bytes)", settlementBridgeMaxJSONBodyBytes)
	}
	return nil
}

func writeBridgeError(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	if strings.Contains(strings.ToLower(err.Error()), "not wired") {
		code = http.StatusInternalServerError
	} else if strings.Contains(strings.ToLower(err.Error()), "conflicting fields") {
		code = http.StatusConflict
	}
	writeJSON(w, code, bridgeEnvelope{
		OK:    false,
		Error: err.Error(),
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(body)
}

func unixOrZero(ts time.Time) int64 {
	if ts.IsZero() {
		return 0
	}
	return ts.Unix()
}
