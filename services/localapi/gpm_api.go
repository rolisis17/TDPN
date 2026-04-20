package localapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	urlpkg "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	gpmChallengeTTL                = 5 * time.Minute
	gpmSessionTTL                  = 12 * time.Hour
	gpmManifestHTTPTimeout         = 6 * time.Second
	gpmManifestBodyLimit           = 1 << 20
	gpmAuthSignatureMaxLen         = 8 * 1024
	gpmAuthSignatureEnvelopeMaxLen = 16 * 1024
	gpmAuthVerifierOutputLimit     = 8 * 1024
)

type gpmRuntimeState struct {
	mu         sync.RWMutex
	challenges map[string]gpmWalletChallenge
	sessions   map[string]gpmSession
	operators  map[string]gpmOperatorApplication
}

type gpmWalletChallenge struct {
	ChallengeID    string    `json:"challenge_id"`
	WalletAddress  string    `json:"wallet_address"`
	WalletProvider string    `json:"wallet_provider"`
	Message        string    `json:"message"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type gpmSession struct {
	Token              string    `json:"token"`
	WalletAddress      string    `json:"wallet_address"`
	WalletProvider     string    `json:"wallet_provider"`
	Role               string    `json:"role"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	BootstrapDirectory string    `json:"bootstrap_directory,omitempty"`
	InviteKey          string    `json:"invite_key,omitempty"`
	PathProfile        string    `json:"path_profile,omitempty"`
	ChainOperatorID    string    `json:"chain_operator_id,omitempty"`
}

type gpmOperatorApplication struct {
	WalletAddress   string    `json:"wallet_address"`
	ChainOperatorID string    `json:"chain_operator_id"`
	ServerLabel     string    `json:"server_label,omitempty"`
	Status          string    `json:"status"`
	Reason          string    `json:"reason,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type gpmBootstrapManifest struct {
	Version              int            `json:"version"`
	GeneratedAtUTC       string         `json:"generated_at_utc"`
	ExpiresAtUTC         string         `json:"expires_at_utc"`
	BootstrapDirectories []string       `json:"bootstrap_directories"`
	RelayPolicy          map[string]any `json:"relay_policy,omitempty"`
}

type gpmBootstrapManifestCacheFile struct {
	Version           int                  `json:"version"`
	FetchedAtUTC      string               `json:"fetched_at_utc"`
	SourceURL         string               `json:"source_url"`
	SignatureVerified bool                 `json:"signature_verified"`
	Manifest          gpmBootstrapManifest `json:"manifest"`
}

type gpmAuthChallengeRequest struct {
	WalletAddress  string `json:"wallet_address"`
	WalletProvider string `json:"wallet_provider"`
}

type gpmAuthVerifyRequest struct {
	WalletAddress          string          `json:"wallet_address"`
	WalletProvider         string          `json:"wallet_provider"`
	ChallengeID            string          `json:"challenge_id"`
	Signature              string          `json:"signature"`
	SignatureKind          *string         `json:"signature_kind,omitempty"`
	SignaturePublicKey     string          `json:"signature_public_key,omitempty"`
	SignaturePublicKeyType *string         `json:"signature_public_key_type,omitempty"`
	PublicKey              string          `json:"public_key,omitempty"`
	PublicKeyType          *string         `json:"public_key_type,omitempty"`
	SignatureSource        *string         `json:"signature_source,omitempty"`
	ChainID                string          `json:"chain_id,omitempty"`
	SignedMessage          *string         `json:"signed_message,omitempty"`
	SignatureEnvelope      json.RawMessage `json:"signature_envelope,omitempty"`
}

type gpmAuthSignatureVerifier func(challenge gpmWalletChallenge, walletAddress string, walletProvider string, signature string) error

type gpmAuthSignatureMetadata struct {
	SignatureKind             string
	SignaturePublicKey        string
	SignaturePublicKeyType    string
	SignatureSource           string
	ChainID                   string
	SignedMessage             string
	SignatureEnvelope         string
	HasSignatureKind          bool
	HasSignaturePublicKeyType bool
	HasSignatureSource        bool
	HasSignedMessage          bool
	HasSignatureEnvelope      bool
}

type gpmSessionStatusRequest struct {
	SessionToken string `json:"session_token"`
	Action       string `json:"action,omitempty"`
}

type gpmClientRegisterRequest struct {
	SessionToken       string `json:"session_token"`
	BootstrapDirectory string `json:"bootstrap_directory,omitempty"`
	InviteKey          string `json:"invite_key,omitempty"`
	PathProfile        string `json:"path_profile,omitempty"`
}

type gpmClientStatusRequest struct {
	SessionToken string `json:"session_token"`
}

type gpmServerStatusRequest struct {
	SessionToken  string `json:"session_token,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
}

type gpmOperatorApplyRequest struct {
	SessionToken    string `json:"session_token"`
	ChainOperatorID string `json:"chain_operator_id"`
	ServerLabel     string `json:"server_label,omitempty"`
}

type gpmOperatorStatusRequest struct {
	SessionToken  string `json:"session_token,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
}

type gpmOperatorListRequest struct {
	SessionToken string `json:"session_token"`
	Status       string `json:"status,omitempty"`
	Limit        *int   `json:"limit,omitempty"`
	Search       string `json:"search,omitempty"`
	Cursor       string `json:"cursor,omitempty"`
}

type gpmOperatorApproveRequest struct {
	WalletAddress  string `json:"wallet_address"`
	Approved       bool   `json:"approved"`
	Reason         string `json:"reason,omitempty"`
	IfUpdatedAtUTC string `json:"if_updated_at_utc,omitempty"`
	SessionToken   string `json:"session_token,omitempty"`
	AdminToken     string `json:"admin_token,omitempty"`
}

type gpmServiceMutationRequest struct {
	SessionToken string `json:"session_token,omitempty"`
}

func newGPMRuntimeState() *gpmRuntimeState {
	return &gpmRuntimeState{
		challenges: map[string]gpmWalletChallenge{},
		sessions:   map[string]gpmSession{},
		operators:  map[string]gpmOperatorApplication{},
	}
}

func (st *gpmRuntimeState) putChallenge(challenge gpmWalletChallenge) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.challenges[challenge.ChallengeID] = challenge
}

func (st *gpmRuntimeState) popValidChallenge(challengeID string, now time.Time) (gpmWalletChallenge, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	challenge, ok := st.challenges[challengeID]
	if !ok {
		return gpmWalletChallenge{}, false
	}
	delete(st.challenges, challengeID)
	if now.After(challenge.ExpiresAt) {
		return gpmWalletChallenge{}, false
	}
	return challenge, true
}

func (st *gpmRuntimeState) putSession(session gpmSession) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sessions[session.Token] = session
}

func (st *gpmRuntimeState) getSession(token string, now time.Time) (gpmSession, bool) {
	st.mu.RLock()
	session, ok := st.sessions[token]
	st.mu.RUnlock()
	if !ok {
		return gpmSession{}, false
	}
	if now.After(session.ExpiresAt) {
		st.mu.Lock()
		delete(st.sessions, token)
		st.mu.Unlock()
		return gpmSession{}, false
	}
	return session, true
}

func (st *gpmRuntimeState) replaceSessionToken(oldToken string, session gpmSession) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.sessions, oldToken)
	st.sessions[session.Token] = session
}

func (st *gpmRuntimeState) deleteSession(token string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.sessions[token]; !ok {
		return false
	}
	delete(st.sessions, token)
	return true
}

func (st *gpmRuntimeState) upsertOperator(app gpmOperatorApplication) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.operators[app.WalletAddress] = app
}

func (st *gpmRuntimeState) getOperator(walletAddress string) (gpmOperatorApplication, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	app, ok := st.operators[walletAddress]
	return app, ok
}

func (st *gpmRuntimeState) listOperators() []gpmOperatorApplication {
	st.mu.RLock()
	defer st.mu.RUnlock()
	applications := make([]gpmOperatorApplication, 0, len(st.operators))
	for _, app := range st.operators {
		applications = append(applications, app)
	}
	return applications
}

func (st *gpmRuntimeState) reconcileSessionRole(token string) (gpmSession, bool, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	session, ok := st.sessions[token]
	if !ok {
		return gpmSession{}, false, false
	}
	if strings.EqualFold(strings.TrimSpace(session.Role), "admin") {
		return session, false, true
	}

	nextRole := "client"
	nextChainOperatorID := ""
	walletAddress := normalizeWalletAddress(session.WalletAddress)
	if walletAddress != "" {
		if app, appOK := st.operators[walletAddress]; appOK && strings.EqualFold(strings.TrimSpace(app.Status), "approved") {
			nextRole = "operator"
			nextChainOperatorID = strings.TrimSpace(app.ChainOperatorID)
		}
	}

	roleChanged := !strings.EqualFold(strings.TrimSpace(session.Role), nextRole)
	chainChanged := strings.TrimSpace(session.ChainOperatorID) != nextChainOperatorID
	if !roleChanged && !chainChanged {
		return session, false, true
	}

	session.Role = nextRole
	session.ChainOperatorID = nextChainOperatorID
	st.sessions[token] = session
	return session, true, true
}

func (st *gpmRuntimeState) applyOperatorDecisionToSessions(walletAddress string, approved bool, chainOperatorID string) bool {
	normalizedWalletAddress := normalizeWalletAddress(walletAddress)
	nextRole := "client"
	nextChainOperatorID := ""
	if approved {
		nextRole = "operator"
		nextChainOperatorID = strings.TrimSpace(chainOperatorID)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	changed := false
	for token, session := range st.sessions {
		if normalizeWalletAddress(session.WalletAddress) != normalizedWalletAddress {
			continue
		}
		roleChanged := !strings.EqualFold(strings.TrimSpace(session.Role), nextRole)
		chainChanged := strings.TrimSpace(session.ChainOperatorID) != nextChainOperatorID
		if !roleChanged && !chainChanged {
			continue
		}
		session.Role = nextRole
		session.ChainOperatorID = nextChainOperatorID
		st.sessions[token] = session
		changed = true
	}
	return changed
}

func (s *Service) getGPMSession(token string, now time.Time) (gpmSession, bool) {
	if s == nil || s.gpmState == nil {
		return gpmSession{}, false
	}
	return s.gpmState.getSession(token, now)
}

func (s *Service) reconcileGPMSessionRole(token string, session gpmSession, reason string) (gpmSession, bool) {
	if s == nil || s.gpmState == nil {
		return session, false
	}
	reconciled, changed, ok := s.gpmState.reconcileSessionRole(token)
	if !ok {
		return session, false
	}
	if changed {
		s.persistGPMStateBestEffort(reason)
	}
	return reconciled, changed
}

func (s *Service) resolveGPMServiceMutationToken(r *http.Request) (string, error) {
	var in gpmServiceMutationRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		return "", err
	}
	token := strings.TrimSpace(in.SessionToken)
	if token == "" {
		token = parseBearerToken(r.Header.Get("Authorization"))
	}
	return token, nil
}

func (s *Service) requireGPMServiceMutationAuth(w http.ResponseWriter, r *http.Request) bool {
	token, err := s.resolveGPMServiceMutationToken(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return false
	}
	if strings.TrimSpace(token) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session token is required"})
		return false
	}
	session, ok := s.getGPMSession(token, time.Now().UTC())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid or expired session"})
		return false
	}
	role := strings.ToLower(strings.TrimSpace(session.Role))
	if role != "operator" && role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("session role %q is not permitted; operator or admin required", role),
		})
		return false
	}
	if role == "operator" {
		walletAddress := normalizeWalletAddress(session.WalletAddress)
		app, ok := s.gpmState.getOperator(walletAddress)
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":    false,
				"error": "operator application is not approved; submit and obtain approval before server lifecycle actions",
			})
			return false
		}
		status := strings.ToLower(strings.TrimSpace(app.Status))
		if status != "approved" {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("operator application status %q is not approved", status),
			})
			return false
		}
		sessionChainOperatorID := strings.TrimSpace(session.ChainOperatorID)
		approvedChainOperatorID := strings.TrimSpace(app.ChainOperatorID)
		if !gpmOperatorChainIDsCompatible(sessionChainOperatorID, approvedChainOperatorID) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":    false,
				"error": "operator session is out of sync with approved application; refresh or rotate session",
			})
			return false
		}
	}
	return true
}

func (s *Service) resolveConnectSecretsFromSession(sessionToken string) (string, string, string, error) {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return "", "", "", errors.New("session token is empty")
	}
	session, ok := s.gpmState.getSession(sessionToken, time.Now().UTC())
	if !ok {
		return "", "", "", errors.New("session token is missing or expired")
	}
	if strings.TrimSpace(session.BootstrapDirectory) == "" || strings.TrimSpace(session.InviteKey) == "" {
		return "", "", "", errors.New("session is not fully registered for connect")
	}
	return session.BootstrapDirectory, session.InviteKey, strings.TrimSpace(session.PathProfile), nil
}

func (s *Service) handleGPMBootstrapManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	manifest, source, signatureVerified, err := s.resolveBootstrapManifest(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"source":             source,
		"signature_verified": signatureVerified,
		"manifest":           manifest,
	})
}

func (s *Service) handleGPMAuthChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmAuthChallengeRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	in.WalletAddress = normalizeWalletAddress(in.WalletAddress)
	in.WalletProvider = normalizeWalletProvider(in.WalletProvider)
	if in.WalletAddress == "" || in.WalletProvider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "wallet_address and wallet_provider are required (wallet_provider: keplr|leap)",
		})
		return
	}
	challengeID, err := randomHex(24)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to create challenge"})
		return
	}
	expires := time.Now().UTC().Add(gpmChallengeTTL)
	challenge := gpmWalletChallenge{
		ChallengeID:    "gpm-chal-" + challengeID,
		WalletAddress:  in.WalletAddress,
		WalletProvider: in.WalletProvider,
		Message:        "Global Private Mesh authentication challenge: " + challengeID,
		ExpiresAt:      expires,
	}
	s.gpmState.putChallenge(challenge)
	s.appendGPMAudit("auth_challenge_issued", map[string]any{
		"wallet_address":  challenge.WalletAddress,
		"wallet_provider": challenge.WalletProvider,
		"challenge_id":    challenge.ChallengeID,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"challenge_id":    challenge.ChallengeID,
		"message":         challenge.Message,
		"expires_at_utc":  expires.Format(time.RFC3339),
		"wallet_provider": challenge.WalletProvider,
	})
}

func (s *Service) handleGPMAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmAuthVerifyRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	in.WalletAddress = normalizeWalletAddress(in.WalletAddress)
	in.WalletProvider = normalizeWalletProvider(in.WalletProvider)
	in.ChallengeID = strings.TrimSpace(in.ChallengeID)
	signature := strings.TrimSpace(in.Signature)
	signaturePublicKey := strings.TrimSpace(in.SignaturePublicKey)
	if signaturePublicKey == "" {
		signaturePublicKey = strings.TrimSpace(in.PublicKey)
	}
	signatureMetadata := gpmAuthSignatureMetadata{
		SignaturePublicKey: signaturePublicKey,
		ChainID:            strings.TrimSpace(in.ChainID),
	}
	if in.SignatureKind != nil {
		signatureMetadata.SignatureKind = strings.TrimSpace(*in.SignatureKind)
		signatureMetadata.HasSignatureKind = true
	}
	canonicalPublicKeyType := ""
	if in.SignaturePublicKeyType != nil {
		canonicalPublicKeyType = strings.TrimSpace(*in.SignaturePublicKeyType)
	}
	legacyPublicKeyType := ""
	if in.PublicKeyType != nil {
		legacyPublicKeyType = strings.TrimSpace(*in.PublicKeyType)
	}
	switch {
	case canonicalPublicKeyType != "":
		signatureMetadata.SignaturePublicKeyType = canonicalPublicKeyType
		signatureMetadata.HasSignaturePublicKeyType = true
	case legacyPublicKeyType != "":
		signatureMetadata.SignaturePublicKeyType = legacyPublicKeyType
		signatureMetadata.HasSignaturePublicKeyType = true
	case in.SignaturePublicKeyType != nil:
		signatureMetadata.SignaturePublicKeyType = canonicalPublicKeyType
		signatureMetadata.HasSignaturePublicKeyType = true
	case in.PublicKeyType != nil:
		signatureMetadata.SignaturePublicKeyType = legacyPublicKeyType
		signatureMetadata.HasSignaturePublicKeyType = true
	}
	if in.SignatureSource != nil {
		signatureMetadata.SignatureSource = strings.TrimSpace(*in.SignatureSource)
		signatureMetadata.HasSignatureSource = true
	}
	if in.SignedMessage != nil {
		signatureMetadata.SignedMessage = *in.SignedMessage
		signatureMetadata.HasSignedMessage = true
	}
	if signatureEnvelope, ok := normalizeOptionalJSONStringOrScalar(in.SignatureEnvelope); ok {
		signatureMetadata.SignatureEnvelope = signatureEnvelope
		signatureMetadata.HasSignatureEnvelope = true
	}
	if in.WalletAddress == "" || in.WalletProvider == "" || in.ChallengeID == "" || signature == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "wallet_address, wallet_provider, challenge_id and signature are required",
		})
		return
	}
	challenge, ok := s.gpmState.popValidChallenge(in.ChallengeID, time.Now().UTC())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid or expired challenge"})
		return
	}
	if subtleEqual(challenge.WalletAddress, in.WalletAddress) == false || subtleEqual(challenge.WalletProvider, in.WalletProvider) == false {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "challenge identity mismatch"})
		return
	}
	if err := s.verifyGPMAuthSignature(r.Context(), challenge, in.WalletAddress, in.WalletProvider, signature, signatureMetadata); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	now := time.Now().UTC()
	token, err := randomBase64URL(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to mint session"})
		return
	}
	session := gpmSession{
		Token:          token,
		WalletAddress:  challenge.WalletAddress,
		WalletProvider: challenge.WalletProvider,
		Role:           s.gpmRoleDefault,
		CreatedAt:      now,
		ExpiresAt:      now.Add(gpmSessionTTL),
	}
	if app, ok := s.gpmState.getOperator(challenge.WalletAddress); ok && app.Status == "approved" {
		session.Role = "operator"
		session.ChainOperatorID = app.ChainOperatorID
	}
	s.gpmState.putSession(session)
	s.persistGPMStateBestEffort("auth_verify")
	s.appendGPMAudit("auth_verified", map[string]any{
		"wallet_address":  session.WalletAddress,
		"wallet_provider": session.WalletProvider,
		"role":            session.Role,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"session_token": session.Token,
		"session":       serializeGPMSession(session),
	})
}

func (s *Service) handleGPMSessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var in gpmSessionStatusRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	action := normalizeGPMSessionAction(in.Action)
	if action == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "action must be one of: status, refresh, revoke",
		})
		return
	}
	if action == "status" {
		if !s.requireCommandReadAuth(w, r) {
			return
		}
	} else if !s.requireMutationAuth(w, r) {
		return
	}
	token := strings.TrimSpace(in.SessionToken)
	if token == "" {
		token = strings.TrimSpace(parseBearerToken(r.Header.Get("Authorization")))
	}
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token is required"})
		return
	}
	session, ok := s.gpmState.getSession(token, time.Now().UTC())
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	now := time.Now().UTC()
	switch action {
	case "status":
		session, sessionReconciled := s.reconcileGPMSessionRole(token, session, "session_status_reconcile")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                 true,
			"action":             "status",
			"session":            serializeGPMSession(session),
			"session_reconciled": sessionReconciled,
		})
		return
	case "refresh":
		session, sessionReconciled := s.reconcileGPMSessionRole(token, session, "session_refresh_reconcile")
		newToken, err := randomBase64URL(32)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to refresh session"})
			return
		}
		refreshed := session
		refreshed.Token = newToken
		refreshed.CreatedAt = now
		refreshed.ExpiresAt = now.Add(gpmSessionTTL)
		s.gpmState.replaceSessionToken(token, refreshed)
		s.persistGPMStateBestEffort("session_refresh")
		s.appendGPMAudit("session_refreshed", map[string]any{
			"wallet_address":  refreshed.WalletAddress,
			"wallet_provider": refreshed.WalletProvider,
			"role":            refreshed.Role,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                 true,
			"action":             "refresh",
			"session_token":      refreshed.Token,
			"session":            serializeGPMSession(refreshed),
			"session_reconciled": sessionReconciled,
		})
		return
	case "revoke":
		if !s.gpmState.deleteSession(token) {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
			return
		}
		s.persistGPMStateBestEffort("session_revoke")
		s.appendGPMAudit("session_revoked", map[string]any{
			"wallet_address":  session.WalletAddress,
			"wallet_provider": session.WalletProvider,
			"role":            session.Role,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"action":  "revoke",
			"revoked": true,
		})
		return
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "action must be one of: status, refresh, revoke",
		})
		return
	}
}

func (s *Service) handleGPMAuditRecent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}

	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			if parsed < 1 {
				parsed = 1
			}
			if parsed > 200 {
				parsed = 200
			}
			limit = parsed
		}
	}

	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "offset must be a non-negative integer"})
			return
		}
		offset = parsed
	}

	eventFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("event")))
	walletFilter := ""
	if raw := strings.TrimSpace(r.URL.Query().Get("wallet_address")); raw != "" {
		walletFilter = normalizeWalletAddress(raw)
		if walletFilter == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet_address filter must be a valid wallet address"})
			return
		}
	}
	orderFilter, validOrder := normalizeGPMAuditOrder(r.URL.Query().Get("order"))
	if !validOrder {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "order must be one of: desc, asc"})
		return
	}

	result, err := s.readGPMAuditRecent(gpmAuditRecentQuery{
		Limit:         limit,
		Offset:        offset,
		Event:         eventFilter,
		WalletAddress: walletFilter,
		Order:         orderFilter,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	count := len(result.Entries)
	nextOffset := offset + count
	hasMore := nextOffset < result.Total
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"total":       result.Total,
		"count":       count,
		"limit":       limit,
		"offset":      offset,
		"has_more":    hasMore,
		"next_offset": nextOffset,
		"filters": map[string]any{
			"event":          eventFilter,
			"wallet_address": walletFilter,
			"order":          orderFilter,
		},
		"entries": result.Entries,
	})
}

func (s *Service) handleGPMClientRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmClientRegisterRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	session, ok := s.gpmState.getSession(strings.TrimSpace(in.SessionToken), time.Now().UTC())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	manifest, source, signatureVerified, err := s.resolveBootstrapManifest(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	bootstrapDirectory := strings.TrimSpace(in.BootstrapDirectory)
	if bootstrapDirectory == "" {
		bootstrapDirectory = strings.TrimSpace(manifest.BootstrapDirectories[0])
	}
	if err := validateBootstrapDirectoryURL(bootstrapDirectory); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if !slices.Contains(manifest.BootstrapDirectories, bootstrapDirectory) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "bootstrap_directory must come from trusted manifest bootstrap_directories",
		})
		return
	}
	inviteKey := strings.TrimSpace(in.InviteKey)
	if inviteKey == "" {
		inviteKey = firstNonEmpty(
			os.Getenv("GPM_COMPAT_INVITE_KEY"),
			os.Getenv("TDPN_COMPAT_INVITE_KEY"),
			os.Getenv("CAMPAIGN_SUBJECT"),
			os.Getenv("INVITE_KEY"),
			"wallet:"+session.WalletAddress,
		)
	}
	if err := validateInviteKey(inviteKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	pathProfile := normalizeGPMPathProfile(in.PathProfile)
	session.BootstrapDirectory = bootstrapDirectory
	session.InviteKey = inviteKey
	session.PathProfile = pathProfile
	s.gpmState.putSession(session)
	s.persistGPMStateBestEffort("client_register")
	s.appendGPMAudit("client_registered", map[string]any{
		"wallet_address":      session.WalletAddress,
		"wallet_provider":     session.WalletProvider,
		"bootstrap_directory": bootstrapDirectory,
		"path_profile":        pathProfile,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"source":             source,
		"signature_verified": signatureVerified,
		"profile": map[string]any{
			"wallet_address":      session.WalletAddress,
			"wallet_provider":     session.WalletProvider,
			"path_profile":        pathProfile,
			"bootstrap_directory": bootstrapDirectory,
			"compat_subject_hint": inviteKey,
		},
		"session": serializeGPMSession(session),
	})
}

func (s *Service) handleGPMClientStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	var in gpmClientStatusRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	sessionToken := strings.TrimSpace(in.SessionToken)
	if sessionToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token is required"})
		return
	}
	session, ok := s.gpmState.getSession(sessionToken, time.Now().UTC())
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	status := "not_registered"
	if strings.TrimSpace(session.BootstrapDirectory) != "" && strings.TrimSpace(session.InviteKey) != "" {
		status = "registered"
	}
	registration := map[string]any{
		"wallet_address":      session.WalletAddress,
		"status":              status,
		"bootstrap_directory": strings.TrimSpace(session.BootstrapDirectory),
	}
	if profile := strings.TrimSpace(session.PathProfile); profile != "" {
		registration["path_profile"] = profile
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"registration": registration,
	})
}

func (s *Service) handleGPMServerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	var in gpmServerStatusRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}

	sessionToken := strings.TrimSpace(in.SessionToken)
	var (
		session        gpmSession
		sessionPresent bool
	)
	if sessionToken != "" {
		resolved, ok := s.gpmState.getSession(sessionToken, time.Now().UTC())
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
			return
		}
		session = resolved
		sessionPresent = true
	}

	walletAddress := normalizeWalletAddress(in.WalletAddress)
	if walletAddress == "" && sessionPresent {
		walletAddress = normalizeWalletAddress(session.WalletAddress)
	}
	if walletAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet_address or session_token is required"})
		return
	}

	role := "client"
	sessionChainOperatorID := ""
	if sessionPresent {
		if normalizedRole := strings.ToLower(strings.TrimSpace(session.Role)); normalizedRole != "" {
			role = normalizedRole
		}
		sessionChainOperatorID = strings.TrimSpace(session.ChainOperatorID)
	}

	operatorApplicationStatus := "not_submitted"
	chainOperatorID := ""
	if app, ok := s.gpmState.getOperator(walletAddress); ok {
		status := strings.ToLower(strings.TrimSpace(app.Status))
		switch status {
		case "approved", "pending", "rejected":
			operatorApplicationStatus = status
		default:
			operatorApplicationStatus = "pending"
		}
		chainOperatorID = strings.TrimSpace(app.ChainOperatorID)
	}

	tabVisible := role == "operator" || role == "admin"
	clientRegistrationReady := sessionPresent &&
		strings.TrimSpace(session.BootstrapDirectory) != "" &&
		strings.TrimSpace(session.InviteKey) != ""
	clientTabVisible := true
	clientLockReason := ""
	if role == "operator" || role == "admin" {
		clientTabVisible = clientRegistrationReady
		if !clientTabVisible {
			clientLockReason = "client registration is required for client tab access; complete /v1/gpm/onboarding/client/register with bootstrap_directory and invite_key"
		}
	}
	serviceMutationsConfigured := strings.TrimSpace(s.serviceStart) != "" &&
		strings.TrimSpace(s.serviceStop) != "" &&
		strings.TrimSpace(s.serviceRestart) != ""

	lifecycleActionsUnlocked := role == "admin" ||
		(role == "operator" &&
			operatorApplicationStatus == "approved" &&
			gpmOperatorChainIDsCompatible(sessionChainOperatorID, chainOperatorID))

	lockReason := ""
	unlockActions := []string{}
	if !lifecycleActionsUnlocked {
		switch role {
		case "admin":
			// no-op; currently unreachable due lifecycleActionsUnlocked check.
		case "operator":
			switch operatorApplicationStatus {
			case "approved":
				lockReason = "operator session is out of sync with approved application; refresh or rotate session"
				unlockActions = append(unlockActions,
					"Refresh or rotate session via /v1/gpm/session",
					"Sign in again if session/application chain IDs are still out of sync",
				)
			case "pending":
				lockReason = "operator application status \"pending\" is not approved"
				unlockActions = append(unlockActions,
					"Wait for operator approval",
					"Check /v1/gpm/onboarding/operator/status until status is approved",
				)
			case "rejected":
				lockReason = "operator application status \"rejected\" is not approved"
				unlockActions = append(unlockActions,
					"Re-apply with /v1/gpm/onboarding/operator/apply",
					"Obtain approval before using server lifecycle actions",
				)
			default:
				lockReason = "operator application is not approved; submit and obtain approval before server lifecycle actions"
				unlockActions = append(unlockActions,
					"Submit operator application via /v1/gpm/onboarding/operator/apply",
					"Obtain approval before using server lifecycle actions",
				)
			}
		default:
			lockReason = fmt.Sprintf("session role %q is not permitted; operator or admin required", role)
			unlockActions = append(unlockActions,
				"Sign in with an operator/admin session",
				"Or apply for operator role and refresh session after approval",
			)
		}
	}
	endpointPosture, endpointWarnings := gpmServerEndpointDiagnosticsFromEnv()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"readiness": map[string]any{
			"wallet_address":               walletAddress,
			"role":                         role,
			"session_present":              sessionPresent,
			"operator_application_status":  operatorApplicationStatus,
			"chain_operator_id":            chainOperatorID,
			"session_chain_operator_id":    sessionChainOperatorID,
			"tab_visible":                  tabVisible,
			"client_tab_visible":           clientTabVisible,
			"lifecycle_actions_unlocked":   lifecycleActionsUnlocked,
			"service_mutations_configured": serviceMutationsConfigured,
			"client_lock_reason":           clientLockReason,
			"lock_reason":                  lockReason,
			"unlock_actions":               unlockActions,
			"endpoint_posture":             endpointPosture,
			"endpoint_warnings":            endpointWarnings,
		},
	})
}

type gpmEndpointDiagnosticEntry struct {
	Scheme     string
	Host       string
	RemoteHTTP bool
}

func gpmServerEndpointDiagnosticsFromEnv() (map[string]any, []string) {
	serverMode := strings.ToLower(strings.TrimSpace(os.Getenv("EASY_NODE_SERVER_MODE")))
	coreIssuerURL := strings.TrimSpace(os.Getenv("CORE_ISSUER_URL"))
	issuerURLs := splitCSVEnvURLs(os.Getenv("ISSUER_URLS"))
	trustURLs := splitCSVEnvURLs(os.Getenv("DIRECTORY_ISSUER_TRUST_URLS"))

	endpoints := map[string]gpmEndpointDiagnosticEntry{}
	issuerSet := map[string]struct{}{}
	trustSet := map[string]struct{}{}

	coreKey := ""
	if key, entry, ok := gpmEndpointDiagnosticKey(coreIssuerURL); ok {
		coreKey = key
		endpoints[key] = entry
	}
	for _, rawURL := range issuerURLs {
		if key, entry, ok := gpmEndpointDiagnosticKey(rawURL); ok {
			issuerSet[key] = struct{}{}
			endpoints[key] = entry
		}
	}
	for _, rawURL := range trustURLs {
		if key, entry, ok := gpmEndpointDiagnosticKey(rawURL); ok {
			trustSet[key] = struct{}{}
			endpoints[key] = entry
		}
	}

	httpCount := 0
	httpsCount := 0
	hasRemoteHTTP := false
	for _, entry := range endpoints {
		switch entry.Scheme {
		case "http":
			httpCount++
			if entry.RemoteHTTP {
				hasRemoteHTTP = true
			}
		case "https":
			httpsCount++
		}
	}
	mixedScheme := httpCount > 0 && httpsCount > 0

	endpointPosture := map[string]any{
		"server_mode":     serverMode,
		"total_urls":      len(endpoints),
		"http_urls":       httpCount,
		"https_urls":      httpsCount,
		"mixed_scheme":    mixedScheme,
		"has_remote_http": hasRemoteHTTP,
	}

	warnings := make([]string, 0, 8)
	switch serverMode {
	case "provider":
		if coreIssuerURL == "" {
			warnings = append(warnings, "provider mode requires CORE_ISSUER_URL; set CORE_ISSUER_URL to the authority issuer endpoint")
		}
		if len(issuerURLs) == 0 {
			warnings = append(warnings, "provider mode requires ISSUER_URLS; set ISSUER_URLS to one or more authority issuer endpoints (CSV)")
		}
	case "authority":
		if len(issuerURLs) == 0 {
			warnings = append(warnings, "authority mode requires ISSUER_URLS; set ISSUER_URLS so providers can discover issuer endpoints")
		}
		if len(trustURLs) == 0 {
			warnings = append(warnings, "authority mode requires DIRECTORY_ISSUER_TRUST_URLS; set DIRECTORY_ISSUER_TRUST_URLS for provider/authority trust alignment")
		}
	}
	if coreKey != "" && len(issuerSet) > 0 {
		if _, ok := issuerSet[coreKey]; !ok {
			warnings = append(warnings, "CORE_ISSUER_URL is not present in ISSUER_URLS; align issuer endpoints so provider/authority peering stays consistent")
		}
	}
	if coreKey != "" && len(trustSet) > 0 {
		if _, ok := trustSet[coreKey]; !ok {
			warnings = append(warnings, "CORE_ISSUER_URL is not present in DIRECTORY_ISSUER_TRUST_URLS; align trust endpoints with CORE_ISSUER_URL")
		}
	}
	if mixedScheme {
		warnings = append(warnings, "mixed HTTP/HTTPS endpoint posture detected; use HTTPS consistently for issuer/trust endpoints")
	}
	if hasRemoteHTTP {
		warnings = append(warnings, "remote HTTP endpoint detected; migrate remote issuer/trust endpoints to HTTPS")
	}
	return endpointPosture, warnings
}

func splitCSVEnvURLs(raw string) []string {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func gpmEndpointDiagnosticKey(rawURL string) (string, gpmEndpointDiagnosticEntry, bool) {
	parsed, err := parseAbsoluteHTTPURL(rawURL)
	if err != nil {
		return "", gpmEndpointDiagnosticEntry{}, false
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return "", gpmEndpointDiagnosticEntry{}, false
	}
	port := strings.TrimSpace(parsed.Port())
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := strings.TrimSpace(parsed.Path)
	path = strings.TrimSuffix(path, "/")
	key := fmt.Sprintf("%s://%s:%s%s", scheme, host, port, path)
	entry := gpmEndpointDiagnosticEntry{
		Scheme:     scheme,
		Host:       host,
		RemoteHTTP: scheme == "http" && !isLoopbackEndpointHost(host),
	}
	return key, entry, true
}

func isLoopbackEndpointHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Service) handleGPMOperatorApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmOperatorApplyRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	session, ok := s.gpmState.getSession(strings.TrimSpace(in.SessionToken), time.Now().UTC())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	chainOperatorID := strings.TrimSpace(in.ChainOperatorID)
	if chainOperatorID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "chain_operator_id is required"})
		return
	}
	app := gpmOperatorApplication{
		WalletAddress:   session.WalletAddress,
		ChainOperatorID: chainOperatorID,
		ServerLabel:     strings.TrimSpace(in.ServerLabel),
		Status:          "pending",
		UpdatedAt:       time.Now().UTC(),
	}
	s.gpmState.upsertOperator(app)
	s.persistGPMStateBestEffort("operator_apply")
	s.appendGPMAudit("operator_application_submitted", map[string]any{
		"wallet_address":    app.WalletAddress,
		"chain_operator_id": app.ChainOperatorID,
		"status":            app.Status,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "application": serializeGPMOperator(app)})
}

func (s *Service) handleGPMOperatorStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	var in gpmOperatorStatusRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	walletAddress := normalizeWalletAddress(in.WalletAddress)
	if walletAddress == "" && strings.TrimSpace(in.SessionToken) != "" {
		if session, ok := s.gpmState.getSession(strings.TrimSpace(in.SessionToken), time.Now().UTC()); ok {
			walletAddress = session.WalletAddress
		}
	}
	if walletAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet_address or session_token is required"})
		return
	}
	app, ok := s.gpmState.getOperator(walletAddress)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
			"application": map[string]any{
				"wallet_address": walletAddress,
				"status":         "not_submitted",
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "application": serializeGPMOperator(app)})
}

func (s *Service) handleGPMOperatorList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	var in gpmOperatorListRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	sessionToken := strings.TrimSpace(in.SessionToken)
	if sessionToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token is required"})
		return
	}
	session, ok := s.gpmState.getSession(sessionToken, time.Now().UTC())
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	if strings.ToLower(strings.TrimSpace(session.Role)) != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin session role is required"})
		return
	}

	statusFilter, validStatus := normalizeGPMOperatorListStatus(in.Status)
	if !validStatus {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "status must be one of: pending, approved, rejected"})
		return
	}
	searchFilter := strings.ToLower(strings.TrimSpace(in.Search))

	cursorRaw := strings.TrimSpace(in.Cursor)
	cursorEnabled := cursorRaw != ""
	var cursorUpdatedAt time.Time
	var cursorWalletAddress string
	if cursorEnabled {
		var ok bool
		cursorUpdatedAt, cursorWalletAddress, ok = parseGPMOperatorListCursor(cursorRaw)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "cursor must be in the format <updated_at_utc>|<wallet_address>",
			})
			return
		}
	}

	limit := 100
	if in.Limit != nil {
		limit = *in.Limit
		if limit < 1 {
			limit = 1
		}
		if limit > 500 {
			limit = 500
		}
	}

	applications := s.gpmState.listOperators()
	filtered := make([]gpmOperatorApplication, 0, len(applications))
	for _, app := range applications {
		status := strings.ToLower(strings.TrimSpace(app.Status))
		if statusFilter != "" && status != statusFilter {
			continue
		}
		if searchFilter != "" {
			haystack := strings.ToLower(strings.Join([]string{
				strings.TrimSpace(app.WalletAddress),
				strings.TrimSpace(app.ChainOperatorID),
				strings.TrimSpace(app.ServerLabel),
				strings.TrimSpace(app.Status),
				strings.TrimSpace(app.Reason),
			}, " "))
			if !strings.Contains(haystack, searchFilter) {
				continue
			}
		}
		if cursorEnabled && compareGPMOperatorListSortKey(
			app.UpdatedAt,
			strings.TrimSpace(app.WalletAddress),
			cursorUpdatedAt,
			cursorWalletAddress,
		) <= 0 {
			continue
		}
		filtered = append(filtered, app)
	}
	slices.SortFunc(filtered, func(a, b gpmOperatorApplication) int {
		return compareGPMOperatorListSortKey(
			a.UpdatedAt,
			strings.TrimSpace(a.WalletAddress),
			b.UpdatedAt,
			strings.TrimSpace(b.WalletAddress),
		)
	})
	total := len(filtered)
	hasMore := false
	nextCursor := ""
	if len(filtered) > limit {
		hasMore = true
		filtered = filtered[:limit]
		last := filtered[len(filtered)-1]
		nextCursor = formatGPMOperatorListCursor(last.UpdatedAt, strings.TrimSpace(last.WalletAddress))
	}

	out := make([]map[string]any, 0, len(filtered))
	for _, app := range filtered {
		out = append(out, serializeGPMOperator(app))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"count":        len(out),
		"total":        total,
		"has_more":     hasMore,
		"next_cursor":  nextCursor,
		"applications": out,
		"request": map[string]any{
			"status": statusFilter,
			"search": searchFilter,
			"limit":  limit,
			"cursor": cursorRaw,
		},
	})
}

func (s *Service) handleGPMOperatorApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmOperatorApproveRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	sessionToken := strings.TrimSpace(in.SessionToken)
	sessionAuth := false
	decisionAuth := ""
	if sessionToken != "" {
		session, ok := s.gpmState.getSession(sessionToken, time.Now().UTC())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid or expired admin session token"})
			return
		}
		role := strings.ToLower(strings.TrimSpace(session.Role))
		if role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin session role is required for operator approval"})
			return
		}
		sessionAuth = true
		decisionAuth = "admin_session"
	}
	if !sessionAuth {
		if strings.TrimSpace(s.gpmApprovalToken) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "admin session_token is required when GPM_APPROVAL_ADMIN_TOKEN is unset"})
			return
		}
		if subtleEqual(strings.TrimSpace(in.AdminToken), strings.TrimSpace(s.gpmApprovalToken)) == false {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid approval admin token"})
			return
		}
		decisionAuth = "legacy_admin_token"
	}
	walletAddress := normalizeWalletAddress(in.WalletAddress)
	if walletAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet_address is required"})
		return
	}
	app, ok := s.gpmState.getOperator(walletAddress)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "operator application not found"})
		return
	}
	ifUpdatedAtRaw := strings.TrimSpace(in.IfUpdatedAtUTC)
	if ifUpdatedAtRaw != "" {
		ifUpdatedAtUTC, err := time.Parse(time.RFC3339, ifUpdatedAtRaw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "if_updated_at_utc must be a valid RFC3339 timestamp",
			})
			return
		}
		currentUpdatedAtUTC := app.UpdatedAt.UTC()
		if !ifUpdatedAtUTC.Equal(currentUpdatedAtUTC) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok":                     false,
				"error":                  "operator application is stale; refresh and retry with latest updated_at_utc",
				"current_updated_at_utc": currentUpdatedAtUTC.Format(time.RFC3339),
				"wallet_address":         app.WalletAddress,
			})
			return
		}
	}
	decision := "approved"
	if !in.Approved {
		decision = "rejected"
	}
	reason := strings.TrimSpace(in.Reason)
	if decision == "rejected" && reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "reason is required when approved is false"})
		return
	}
	if decision == "approved" && strings.TrimSpace(app.ChainOperatorID) == "" {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "cannot approve operator application without chain_operator_id"})
		return
	}
	app.Status = decision
	app.Reason = reason
	app.UpdatedAt = time.Now().UTC()
	s.gpmState.upsertOperator(app)

	// Keep wallet sessions synchronized with the operator decision.
	s.gpmState.applyOperatorDecisionToSessions(walletAddress, in.Approved, app.ChainOperatorID)
	s.persistGPMStateBestEffort("operator_approve")
	s.appendGPMAudit("operator_application_decided", map[string]any{
		"wallet_address":    app.WalletAddress,
		"chain_operator_id": app.ChainOperatorID,
		"approved":          in.Approved,
		"status":            app.Status,
		"reason":            app.Reason,
		"decision_auth":     decisionAuth,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"decision":      decision,
		"decision_auth": decisionAuth,
		"application":   serializeGPMOperator(app),
	})
}

func serializeGPMSession(session gpmSession) map[string]any {
	return map[string]any{
		"wallet_address":      session.WalletAddress,
		"wallet_provider":     session.WalletProvider,
		"role":                session.Role,
		"created_at_utc":      session.CreatedAt.Format(time.RFC3339),
		"expires_at_utc":      session.ExpiresAt.Format(time.RFC3339),
		"bootstrap_directory": strings.TrimSpace(session.BootstrapDirectory),
		"path_profile":        strings.TrimSpace(session.PathProfile),
		"chain_operator_id":   strings.TrimSpace(session.ChainOperatorID),
	}
}

func serializeGPMOperator(app gpmOperatorApplication) map[string]any {
	return map[string]any{
		"wallet_address":    app.WalletAddress,
		"chain_operator_id": app.ChainOperatorID,
		"server_label":      app.ServerLabel,
		"status":            app.Status,
		"reason":            app.Reason,
		"updated_at_utc":    app.UpdatedAt.Format(time.RFC3339),
	}
}

func normalizeWalletAddress(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > 256 {
		return ""
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r == ':' || r == '-' || r == '_' || r == '.' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) >= 0 {
		return ""
	}
	return value
}

func normalizeWalletProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "keplr":
		return "keplr"
	case "leap":
		return "leap"
	default:
		return ""
	}
}

func normalizeGPMSessionAction(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "status":
		return "status"
	case "refresh":
		return "refresh"
	case "revoke":
		return "revoke"
	default:
		return ""
	}
}

func normalizeGPMAuditOrder(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "desc":
		return "desc", true
	case "asc":
		return "asc", true
	default:
		return "", false
	}
}

func normalizeGPMOperatorListStatus(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", true
	case "pending":
		return "pending", true
	case "approved":
		return "approved", true
	case "rejected":
		return "rejected", true
	default:
		return "", false
	}
}

func compareGPMOperatorListSortKey(aUpdatedAt time.Time, aWalletAddress string, bUpdatedAt time.Time, bWalletAddress string) int {
	switch {
	case aUpdatedAt.After(bUpdatedAt):
		return -1
	case aUpdatedAt.Before(bUpdatedAt):
		return 1
	default:
		return strings.Compare(strings.TrimSpace(aWalletAddress), strings.TrimSpace(bWalletAddress))
	}
}

func formatGPMOperatorListCursor(updatedAt time.Time, walletAddress string) string {
	return updatedAt.UTC().Format(time.RFC3339Nano) + "|" + strings.TrimSpace(walletAddress)
}

func parseGPMOperatorListCursor(raw string) (time.Time, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", false
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(parts[0]))
	if err != nil {
		return time.Time{}, "", false
	}
	walletAddress := normalizeWalletAddress(parts[1])
	if walletAddress == "" {
		return time.Time{}, "", false
	}
	return updatedAt.UTC(), walletAddress, true
}

func normalizeGPMPathProfile(raw string) string {
	if profile := normalizePathProfile(raw); profile != "" {
		return profile
	}
	return "2hop"
}

func gpmOperatorChainIDsCompatible(sessionChainOperatorID string, approvedChainOperatorID string) bool {
	sessionChainOperatorID = strings.TrimSpace(sessionChainOperatorID)
	approvedChainOperatorID = strings.TrimSpace(approvedChainOperatorID)
	if sessionChainOperatorID != "" && approvedChainOperatorID != "" && !subtleEqual(sessionChainOperatorID, approvedChainOperatorID) {
		return false
	}
	return true
}

func subtleEqual(a string, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func normalizeOptionalJSONStringOrScalar(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", false
	}
	var asString string
	if err := json.Unmarshal(trimmed, &asString); err == nil {
		return asString, true
	}
	var asAny any
	if err := json.Unmarshal(trimmed, &asAny); err != nil {
		return "", false
	}
	canonical, err := json.Marshal(asAny)
	if err != nil {
		return string(trimmed), true
	}
	return string(canonical), true
}

func defaultGPMAuthSignatureVerifier(challenge gpmWalletChallenge, walletAddress string, walletProvider string, signature string) error {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return errors.New("signature is required")
	}
	if len(signature) < 8 {
		return errors.New("signature is too short")
	}
	if len(signature) > gpmAuthSignatureMaxLen {
		return fmt.Errorf("signature is too long (max=%d)", gpmAuthSignatureMaxLen)
	}
	for _, r := range signature {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("signature contains invalid whitespace/control characters")
		}
	}
	if subtleEqual(challenge.ChallengeID, signature) || subtleEqual(challenge.Message, signature) {
		return errors.New("signature failed challenge proof validation")
	}
	if !subtleEqual(challenge.WalletAddress, walletAddress) || !subtleEqual(challenge.WalletProvider, walletProvider) {
		return errors.New("challenge identity mismatch")
	}
	return nil
}

func validateGPMAuthSignatureMetadata(challenge gpmWalletChallenge, signatureMetadata gpmAuthSignatureMetadata) error {
	if signatureMetadata.HasSignedMessage && !subtleEqual(challenge.Message, signatureMetadata.SignedMessage) {
		return errors.New("signed_message does not match issued challenge message")
	}
	if signatureMetadata.HasSignatureKind {
		switch signatureMetadata.SignatureKind {
		case "sign_arbitrary", "eip191":
		default:
			return errors.New("unsupported signature_kind")
		}
	}
	if signatureMetadata.HasSignatureSource {
		switch signatureMetadata.SignatureSource {
		case "wallet_extension", "manual":
		default:
			return errors.New("unsupported signature_source")
		}
	}
	if signatureMetadata.HasSignaturePublicKeyType {
		switch signatureMetadata.SignaturePublicKeyType {
		case "secp256k1", "ed25519":
		default:
			return errors.New("unsupported signature_public_key_type")
		}
	}
	if signatureMetadata.HasSignatureEnvelope && len(signatureMetadata.SignatureEnvelope) > gpmAuthSignatureEnvelopeMaxLen {
		return fmt.Errorf("signature_envelope is too long (max=%d)", gpmAuthSignatureEnvelopeMaxLen)
	}
	return nil
}

func (s *Service) validateGPMAuthSignaturePolicy(signatureMetadata gpmAuthSignatureMetadata) error {
	if s.gpmAuthVerifyRequireMetadata {
		missing := make([]string, 0, 3)
		if !signatureMetadata.HasSignatureKind {
			missing = append(missing, "signature_kind")
		}
		if !signatureMetadata.HasSignatureSource {
			missing = append(missing, "signature_source")
		}
		if !signatureMetadata.HasSignedMessage {
			missing = append(missing, "signed_message")
		}
		if len(missing) > 0 {
			return fmt.Errorf("signature metadata fields are required by policy: %s", strings.Join(missing, ", "))
		}
	}
	if s.gpmAuthVerifyRequireWalletExt {
		if !signatureMetadata.HasSignatureSource {
			return errors.New("signature_source must be explicitly provided as wallet_extension by policy")
		}
		if signatureMetadata.SignatureSource != "wallet_extension" {
			return errors.New("signature_source must be wallet_extension by policy")
		}
	}
	return nil
}

func (s *Service) verifyGPMAuthSignature(ctx context.Context, challenge gpmWalletChallenge, walletAddress string, walletProvider string, signature string, signatureMetadata gpmAuthSignatureMetadata) error {
	if err := s.validateGPMAuthSignaturePolicy(signatureMetadata); err != nil {
		return err
	}
	if err := validateGPMAuthSignatureMetadata(challenge, signatureMetadata); err != nil {
		return err
	}
	verifier := s.gpmAuthSignatureVerifier
	if verifier == nil {
		verifier = defaultGPMAuthSignatureVerifier
	}
	if err := verifier(challenge, walletAddress, walletProvider, signature); err != nil {
		return err
	}
	if s.gpmAuthVerifyRequireCommand && strings.TrimSpace(s.gpmAuthVerifyCommand) == "" {
		return errors.New("signature verifier command is required by policy")
	}
	if err := s.runGPMAuthVerifierCommand(ctx, challenge, walletAddress, walletProvider, signature, signatureMetadata); err != nil {
		return err
	}
	return nil
}

func (s *Service) runGPMAuthVerifierCommand(ctx context.Context, challenge gpmWalletChallenge, walletAddress string, walletProvider string, signature string, signatureMetadata gpmAuthSignatureMetadata) error {
	commandRaw := strings.TrimSpace(s.gpmAuthVerifyCommand)
	if commandRaw == "" {
		return nil
	}
	commandName, commandArgs, err := buildLifecycleCommandWithPlatform(commandRaw, runtime.GOOS)
	if err != nil {
		return fmt.Errorf("configured auth verifier command rejected: %w", err)
	}
	timeout := s.commandTimeout
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, commandName, commandArgs...)
	cmd.Env = append(os.Environ(),
		"GPM_AUTH_VERIFY_CHALLENGE_ID="+strings.TrimSpace(challenge.ChallengeID),
		"GPM_AUTH_VERIFY_MESSAGE="+strings.TrimSpace(challenge.Message),
		"GPM_AUTH_VERIFY_WALLET_ADDRESS="+strings.TrimSpace(walletAddress),
		"GPM_AUTH_VERIFY_WALLET_PROVIDER="+strings.TrimSpace(walletProvider),
		"GPM_AUTH_VERIFY_SIGNATURE="+strings.TrimSpace(signature),
		"GPM_AUTH_VERIFY_SIGNATURE_KIND="+signatureMetadata.SignatureKind,
		"GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY="+signatureMetadata.SignaturePublicKey,
		"GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY_TYPE="+signatureMetadata.SignaturePublicKeyType,
		"GPM_AUTH_VERIFY_SIGNATURE_SOURCE="+signatureMetadata.SignatureSource,
		"GPM_AUTH_VERIFY_CHAIN_ID="+signatureMetadata.ChainID,
		"GPM_AUTH_VERIFY_SIGNED_MESSAGE="+signatureMetadata.SignedMessage,
		"GPM_AUTH_VERIFY_SIGNATURE_ENVELOPE="+signatureMetadata.SignatureEnvelope,
	)
	outputBuffer := newBoundedOutputBuffer(gpmAuthVerifierOutputLimit)
	cmd.Stdout = outputBuffer
	cmd.Stderr = outputBuffer
	err = cmd.Run()
	if err == nil {
		return nil
	}
	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return errors.New("signature verifier command timed out")
	}
	output := strings.TrimSpace(outputBuffer.String())
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if output != "" {
			return fmt.Errorf("signature verifier command rejected signature: %s", output)
		}
		return fmt.Errorf("signature verifier command rejected signature (rc=%d)", exitErr.ExitCode())
	}
	if output != "" {
		return fmt.Errorf("signature verifier command failed: %s", output)
	}
	return errors.New("signature verifier command failed")
}

func randomHex(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomBase64URL(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Service) resolveBootstrapManifest(ctx context.Context) (gpmBootstrapManifest, string, bool, error) {
	manifestURL := strings.TrimSpace(s.gpmManifestURL)
	if manifestURL == "" {
		return gpmBootstrapManifest{}, "", false, errors.New("gpm manifest url is not configured")
	}
	pinnedHost, err := s.pinnedGPMMainDomainHost()
	if err != nil {
		return gpmBootstrapManifest{}, "", false, err
	}
	if pinnedHost != "" {
		manifestHost, err := normalizeHTTPHost(manifestURL)
		if err != nil {
			return gpmBootstrapManifest{}, "", false, fmt.Errorf("gpm manifest url is invalid for pinned gpm main domain host %q: %w", pinnedHost, err)
		}
		if manifestHost != pinnedHost {
			return gpmBootstrapManifest{}, "", false, fmt.Errorf("gpm manifest url host mismatch: got %q, pinned gpm main domain host %q; update GPM_MAIN_DOMAIN or GPM_BOOTSTRAP_MANIFEST_URL", manifestHost, pinnedHost)
		}
	}
	manifest, signatureVerified, err := s.fetchRemoteManifest(ctx, manifestURL)
	if err == nil {
		_ = s.writeBootstrapManifestCache(manifest, signatureVerified)
		return manifest, "remote", signatureVerified, nil
	}
	cacheManifest, cacheSignatureVerified, cacheErr := s.readBootstrapManifestCache()
	if cacheErr != nil {
		return gpmBootstrapManifest{}, "", false, fmt.Errorf("manifest fetch failed (%v) and cache fallback failed (%v)", err, cacheErr)
	}
	return cacheManifest, "cache", cacheSignatureVerified, nil
}

func (s *Service) fetchRemoteManifest(ctx context.Context, manifestURL string) (gpmBootstrapManifest, bool, error) {
	client := &http.Client{Timeout: gpmManifestHTTPTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gpmBootstrapManifest{}, false, fmt.Errorf("manifest endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, gpmManifestBodyLimit+1))
	if err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	if len(body) > gpmManifestBodyLimit {
		return gpmBootstrapManifest{}, false, errors.New("manifest response too large")
	}
	var manifest gpmBootstrapManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return gpmBootstrapManifest{}, false, fmt.Errorf("invalid manifest json: %w", err)
	}
	if err := validateBootstrapManifest(manifest); err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	manifest = normalizeBootstrapManifest(manifest)
	signatureVerified := false
	hmacKey := strings.TrimSpace(s.gpmManifestHMACKey)
	if hmacKey != "" {
		received := strings.TrimSpace(resp.Header.Get("X-GPM-Signature"))
		if received == "" {
			return gpmBootstrapManifest{}, false, errors.New("manifest signature header missing")
		}
		expected := computeManifestHMAC(body, hmacKey)
		if !subtleEqual(received, expected) {
			return gpmBootstrapManifest{}, false, errors.New("manifest signature verification failed")
		}
		signatureVerified = true
	}
	return manifest, signatureVerified, nil
}

func validateBootstrapManifest(manifest gpmBootstrapManifest) error {
	if manifest.Version <= 0 {
		return errors.New("manifest version must be > 0")
	}
	if len(manifest.BootstrapDirectories) == 0 {
		return errors.New("manifest bootstrap_directories is empty")
	}
	generatedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(manifest.GeneratedAtUTC))
	if err != nil {
		return fmt.Errorf("manifest generated_at_utc invalid: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(manifest.ExpiresAtUTC))
	if err != nil {
		return fmt.Errorf("manifest expires_at_utc invalid: %w", err)
	}
	if !expiresAt.After(generatedAt) {
		return errors.New("manifest expires_at_utc must be after generated_at_utc")
	}
	if !expiresAt.After(time.Now().UTC()) {
		return errors.New("manifest is expired")
	}
	for _, dir := range manifest.BootstrapDirectories {
		dir = strings.TrimSpace(dir)
		if err := validateBootstrapDirectoryURL(dir); err != nil {
			return fmt.Errorf("manifest bootstrap directory invalid: %w", err)
		}
	}
	return nil
}

func normalizeBootstrapManifest(manifest gpmBootstrapManifest) gpmBootstrapManifest {
	normalized := make([]string, 0, len(manifest.BootstrapDirectories))
	for _, dir := range manifest.BootstrapDirectories {
		trimmed := strings.TrimSpace(dir)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	manifest.BootstrapDirectories = normalized
	return manifest
}

func computeManifestHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) writeBootstrapManifestCache(manifest gpmBootstrapManifest, signatureVerified bool) error {
	cachePath := strings.TrimSpace(s.gpmManifestCache)
	if cachePath == "" {
		return nil
	}
	if !filepath.IsAbs(cachePath) {
		cachePath = filepath.Clean(cachePath)
	}
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return err
	}
	cache := gpmBootstrapManifestCacheFile{
		Version:           1,
		FetchedAtUTC:      time.Now().UTC().Format(time.RFC3339),
		SourceURL:         s.gpmManifestURL,
		SignatureVerified: signatureVerified || strings.TrimSpace(s.gpmManifestHMACKey) == "",
		Manifest:          manifest,
	}
	body, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, body, 0o600)
}

func (s *Service) readBootstrapManifestCache() (gpmBootstrapManifest, bool, error) {
	cachePath := strings.TrimSpace(s.gpmManifestCache)
	if cachePath == "" {
		return gpmBootstrapManifest{}, false, errors.New("manifest cache path is empty")
	}
	body, err := os.ReadFile(cachePath)
	if err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	var cache gpmBootstrapManifestCacheFile
	if err := json.Unmarshal(body, &cache); err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	if err := validateBootstrapManifest(cache.Manifest); err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	fetchedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(cache.FetchedAtUTC))
	if err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	if time.Since(fetchedAt) > s.gpmManifestMaxAge {
		return gpmBootstrapManifest{}, false, errors.New("cached manifest is stale")
	}
	pinnedHost, err := s.pinnedGPMMainDomainHost()
	if err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	if pinnedHost != "" {
		cacheSourceHost, hostErr := normalizeHTTPHost(strings.TrimSpace(cache.SourceURL))
		if hostErr != nil {
			return gpmBootstrapManifest{}, false, fmt.Errorf("cached manifest source url is invalid for pinned gpm main domain host %q: %w", pinnedHost, hostErr)
		}
		if cacheSourceHost != pinnedHost {
			return gpmBootstrapManifest{}, false, fmt.Errorf("cached manifest source host mismatch: got %q, pinned gpm main domain host %q; clear the cache or refresh it from the pinned domain", cacheSourceHost, pinnedHost)
		}
	}
	if strings.TrimSpace(s.gpmManifestHMACKey) != "" && !cache.SignatureVerified {
		return gpmBootstrapManifest{}, false, errors.New("cached manifest is not signature-verified")
	}
	return normalizeBootstrapManifest(cache.Manifest), cache.SignatureVerified, nil
}

func (s *Service) pinnedGPMMainDomainHost() (string, error) {
	mainDomain := strings.TrimSpace(s.gpmMainDomain)
	if mainDomain == "" {
		return "", nil
	}
	return normalizeHTTPHost(mainDomain)
}

func normalizeHTTPHost(raw string) (string, error) {
	parsed, err := parseAbsoluteHTTPURL(raw)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return "", errors.New("url host is empty")
	}
	port := strings.TrimSpace(parsed.Port())
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return net.JoinHostPort(host, port), nil
}

func parseAbsoluteHTTPURL(raw string) (*urlpkg.URL, error) {
	parsed, err := urlpkg.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if !parsed.IsAbs() {
		return nil, errors.New("url is not absolute")
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return nil, errors.New("unsupported url scheme")
	}
	return parsed, nil
}
