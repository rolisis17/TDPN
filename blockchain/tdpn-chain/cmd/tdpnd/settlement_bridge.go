package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tdpn/tdpn-chain/app"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
	rewardtypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
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
	scaffold  settlementBridgeScaffold
	authToken string
}

type bridgeEnvelope struct {
	OK     bool   `json:"ok"`
	Replay bool   `json:"replay,omitempty"`
	ID     string `json:"id,omitempty"`
	Error  string `json:"error,omitempty"`
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
	RewardID          string    `json:"RewardID"`
	ProviderSubjectID string    `json:"ProviderSubjectID"`
	SessionID         string    `json:"SessionID"`
	RewardMicros      int64     `json:"RewardMicros"`
	Currency          string    `json:"Currency"`
	IssuedAt          time.Time `json:"IssuedAt"`
	Status            string    `json:"Status"`
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
	ObservedAt    time.Time `json:"ObservedAt"`
	Status        string    `json:"Status"`
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
		scaffold:  scaffold,
		authToken: cfg.authToken,
	}
	server := &http.Server{
		Handler:      handler.routes(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
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
	return mux
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

	reservationID := strings.TrimSpace(payload.ReservationID)
	if reservationID == "" {
		reservationID = strings.TrimSpace(payload.SettlementID)
	}
	if reservationID == "" {
		reservationID = strings.TrimSpace(payload.SessionID)
	}
	createdUnix := unixOrZero(payload.SettledAt)
	reservationAmount := payload.ChargedMicros
	if reservationAmount <= 0 {
		reservationAmount = 1
	}

	_, err := h.scaffold.BillingMsgServer().CreateReservation(r.Context(), app.BillingCreateReservationRequest{
		Record: billingtypes.CreditReservation{
			ReservationID: reservationID,
			SponsorID:     payload.SubjectID,
			SessionID:     payload.SessionID,
			AssetDenom:    payload.Currency,
			Amount:        reservationAmount,
			CreatedAtUnix: createdUnix,
			Status:        mapReconciliationStatus(payload.Status, chaintypes.ReconciliationPending),
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	resp, err := h.scaffold.BillingMsgServer().FinalizeSettlement(r.Context(), app.BillingFinalizeSettlementRequest{
		Record: billingtypes.SettlementRecord{
			SettlementID:   payload.SettlementID,
			ReservationID:  reservationID,
			SessionID:      payload.SessionID,
			BilledAmount:   payload.ChargedMicros,
			UsageBytes:     0,
			AssetDenom:     payload.Currency,
			SettledAtUnix:  createdUnix,
			OperationState: mapReconciliationStatus(payload.Status, chaintypes.ReconciliationSubmitted),
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
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, bridgeEnvelope{OK: false, Error: "method not allowed"})
		return
	}

	reservationID, hasID, ok := getEntityID(r.URL.Path, "/x/vpnbilling/reservations")
	if !ok {
		writeJSON(w, http.StatusNotFound, bridgeEnvelope{OK: false, Error: "not found"})
		return
	}
	if hasID {
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
		"reservations": resp.Reservations,
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

	accrualID := strings.TrimSpace(payload.RewardID)
	distributionID := "dist:" + accrualID
	issuedUnix := unixOrZero(payload.IssuedAt)

	_, err := h.scaffold.RewardsMsgServer().CreateAccrual(r.Context(), app.RewardsCreateAccrualRequest{
		Record: rewardtypes.RewardAccrual{
			AccrualID:      accrualID,
			SessionID:      payload.SessionID,
			ProviderID:     payload.ProviderSubjectID,
			AssetDenom:     payload.Currency,
			Amount:         payload.RewardMicros,
			AccruedAtUnix:  issuedUnix,
			OperationState: mapReconciliationStatus(payload.Status, chaintypes.ReconciliationPending),
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	resp, err := h.scaffold.RewardsMsgServer().RecordDistribution(r.Context(), app.RewardsRecordDistributionRequest{
		Record: rewardtypes.DistributionRecord{
			DistributionID: distributionID,
			AccrualID:      accrualID,
			PayoutRef:      payload.RewardID,
			DistributedAt:  issuedUnix,
			Status:         mapReconciliationStatus(payload.Status, chaintypes.ReconciliationSubmitted),
		},
	})
	if err != nil {
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

	authorizationID := "auth:" + strings.TrimSpace(payload.ReservationID)
	maxCredits := payload.AmountMicros
	if maxCredits <= 0 {
		maxCredits = 1
	}
	createdUnix := unixOrZero(payload.CreatedAt)
	expiresUnix := unixOrZero(payload.ExpiresAt)
	subjectID := strings.TrimSpace(payload.SubjectID)
	appID := strings.TrimSpace(payload.AppID)
	endUserID := strings.TrimSpace(payload.EndUserID)
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

	_, err := h.scaffold.SponsorMsgServer().CreateAuthorization(r.Context(), app.SponsorCreateAuthorizationRequest{
		Record: sponsortypes.SponsorAuthorization{
			AuthorizationID: authorizationID,
			SponsorID:       payload.SponsorID,
			AppID:           appID,
			MaxCredits:      maxCredits,
			ExpiresAtUnix:   expiresUnix,
			Status:          mapReconciliationStatus(payload.Status, chaintypes.ReconciliationPending),
		},
	})
	if err != nil {
		writeBridgeError(w, err)
		return
	}

	resp, err := h.scaffold.SponsorMsgServer().DelegateCredit(r.Context(), app.SponsorDelegateCreditRequest{
		Record: sponsortypes.DelegatedSessionCredit{
			ReservationID:   payload.ReservationID,
			AuthorizationID: authorizationID,
			SponsorID:       payload.SponsorID,
			AppID:           appID,
			EndUserID:       endUserID,
			SessionID:       payload.SessionID,
			Credits:         payload.AmountMicros,
			Status:          mapReconciliationStatus(payload.Status, chaintypes.ReconciliationPending),
		},
	})
	if err != nil {
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
			"authorization": resp.Authorization,
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
		"authorizations": resp.Authorizations,
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
			"delegation": resp.Delegation,
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
		"delegations": resp.Delegations,
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

		resp, err := h.scaffold.SlashingQueryServer().ListEvidence(r.Context(), app.SlashingListEvidenceRequest{})
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
	proofHash := strings.TrimSpace(payload.EvidenceRef)
	if err := validateBridgeSlashEvidenceRef(proofHash); err != nil {
		writeJSON(w, http.StatusBadRequest, bridgeEnvelope{OK: false, Error: err.Error()})
		return
	}

	resp, err := h.scaffold.SlashingMsgServer().SubmitEvidence(r.Context(), app.SlashingSubmitEvidenceRequest{
		Record: slashingtypes.SlashEvidence{
			EvidenceID:      payload.EvidenceID,
			SessionID:       payload.SessionID,
			ProviderID:      payload.SubjectID,
			Kind:            slashingtypes.EvidenceKindObjective,
			ProofHash:       proofHash,
			SubmittedAtUnix: unixOrZero(payload.ObservedAt),
			Status:          mapReconciliationStatus(payload.Status, chaintypes.ReconciliationSubmitted),
		},
	})
	if err != nil {
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
			Status:          mapReconciliationStatus(payload.Status, chaintypes.ReconciliationSubmitted),
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
			Status:           mapReconciliationStatus(payload.Status, chaintypes.ReconciliationSubmitted),
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
			Status:          mapReconciliationStatus(payload.Status, chaintypes.ReconciliationSubmitted),
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

	resp, err := h.scaffold.GovernanceMsgServer().RecordDecision(r.Context(), app.GovernanceRecordDecisionRequest{
		Record: governancetypes.GovernanceDecision{
			DecisionID:    payload.DecisionID,
			PolicyID:      payload.PolicyID,
			ProposalID:    payload.ProposalID,
			Outcome:       strings.ToLower(strings.TrimSpace(payload.Outcome)),
			Decider:       payload.Decider,
			Reason:        payload.Reason,
			DecidedAtUnix: unixOrZero(payload.DecidedAt),
			Status:        mapReconciliationStatus(payload.Status, chaintypes.ReconciliationSubmitted),
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

	resp, err := h.scaffold.GovernanceMsgServer().RecordAuditAction(r.Context(), app.GovernanceRecordAuditActionRequest{
		Record: governancetypes.GovernanceAuditAction{
			ActionID:        payload.ActionID,
			Action:          payload.Action,
			Actor:           payload.Actor,
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
	if h.authToken == "" {
		return true
	}
	if !hasValidBearerTokenHeader(r.Header.Get("Authorization"), h.authToken) {
		writeJSON(w, http.StatusUnauthorized, bridgeEnvelope{OK: false, Error: "missing or invalid bearer token"})
		return false
	}
	return true
}

func (h *settlementBridgeHandler) validatorEpochSelectionPreviewQueryServer() (validatormodule.QueryServer, error) {
	if h == nil || h.scaffold == nil {
		return validatormodule.QueryServer{}, errors.New("vpnvalidator preview query server not wired")
	}

	scaffold, ok := h.scaffold.(*app.ChainScaffold)
	if !ok || scaffold == nil {
		return validatormodule.QueryServer{}, errors.New("vpnvalidator preview query server not wired")
	}

	return validatormodule.NewQueryServer(&scaffold.ValidatorModule.Keeper), nil
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

func mapReconciliationStatus(raw string, fallback chaintypes.ReconciliationStatus) chaintypes.ReconciliationStatus {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(chaintypes.ReconciliationPending):
		return chaintypes.ReconciliationPending
	case string(chaintypes.ReconciliationSubmitted):
		return chaintypes.ReconciliationSubmitted
	case string(chaintypes.ReconciliationConfirmed):
		return chaintypes.ReconciliationConfirmed
	case string(chaintypes.ReconciliationFailed):
		return chaintypes.ReconciliationFailed
	default:
		return fallback
	}
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
	return (slashingtypes.SlashEvidence{
		EvidenceID: "bridge-validation",
		Kind:       slashingtypes.EvidenceKindObjective,
		ProofHash:  proofHash,
	}).ValidateBasic()
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
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	return nil
}

func writeBridgeError(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	if strings.Contains(strings.ToLower(err.Error()), "not wired") {
		code = http.StatusInternalServerError
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
