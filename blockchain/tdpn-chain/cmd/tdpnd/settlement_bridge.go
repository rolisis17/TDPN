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
	rewardtypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
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

	_, err := h.scaffold.SponsorMsgServer().CreateAuthorization(r.Context(), app.SponsorCreateAuthorizationRequest{
		Record: sponsortypes.SponsorAuthorization{
			AuthorizationID: authorizationID,
			SponsorID:       payload.SponsorID,
			AppID:           payload.SubjectID,
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
			AppID:           payload.SubjectID,
			EndUserID:       payload.SubjectID,
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
	if proofHash == "" {
		proofHash = strings.TrimSpace(payload.ViolationType)
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
