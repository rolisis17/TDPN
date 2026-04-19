package localapi

import (
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
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	gpmChallengeTTL        = 5 * time.Minute
	gpmSessionTTL          = 12 * time.Hour
	gpmManifestHTTPTimeout = 6 * time.Second
	gpmManifestBodyLimit   = 1 << 20
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
	WalletAddress  string `json:"wallet_address"`
	WalletProvider string `json:"wallet_provider"`
	ChallengeID    string `json:"challenge_id"`
	Signature      string `json:"signature"`
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
}

type gpmOperatorApproveRequest struct {
	WalletAddress string `json:"wallet_address"`
	Approved      bool   `json:"approved"`
	Reason        string `json:"reason,omitempty"`
	SessionToken  string `json:"session_token,omitempty"`
	AdminToken    string `json:"admin_token,omitempty"`
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

func (s *Service) getGPMSession(token string, now time.Time) (gpmSession, bool) {
	if s == nil || s.gpmState == nil {
		return gpmSession{}, false
	}
	return s.gpmState.getSession(token, now)
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

func (s *Service) resolveConnectSecretsFromSession(sessionToken string) (string, string, error) {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return "", "", errors.New("session token is empty")
	}
	session, ok := s.gpmState.getSession(sessionToken, time.Now().UTC())
	if !ok {
		return "", "", errors.New("session token is missing or expired")
	}
	if strings.TrimSpace(session.BootstrapDirectory) == "" || strings.TrimSpace(session.InviteKey) == "" {
		return "", "", errors.New("session is not fully registered for connect")
	}
	return session.BootstrapDirectory, session.InviteKey, nil
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
	if len(signature) < 8 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "signature is too short"})
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
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"action":  "status",
			"session": serializeGPMSession(session),
		})
		return
	case "refresh":
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
			"ok":            true,
			"action":        "refresh",
			"session_token": refreshed.Token,
			"session":       serializeGPMSession(refreshed),
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
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	entries, err := s.readGPMAuditRecent(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"count":   len(entries),
		"entries": entries,
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
			"lifecycle_actions_unlocked":   lifecycleActionsUnlocked,
			"service_mutations_configured": serviceMutationsConfigured,
			"lock_reason":                  lockReason,
			"unlock_actions":               unlockActions,
		},
	})
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
		filtered = append(filtered, app)
	}
	slices.SortFunc(filtered, func(a, b gpmOperatorApplication) int {
		switch {
		case a.UpdatedAt.After(b.UpdatedAt):
			return -1
		case a.UpdatedAt.Before(b.UpdatedAt):
			return 1
		default:
			return strings.Compare(a.WalletAddress, b.WalletAddress)
		}
	})
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	out := make([]map[string]any, 0, len(filtered))
	for _, app := range filtered {
		out = append(out, serializeGPMOperator(app))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"count":        len(out),
		"applications": out,
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
	if in.Approved {
		app.Status = "approved"
	} else {
		app.Status = "rejected"
	}
	app.Reason = strings.TrimSpace(in.Reason)
	app.UpdatedAt = time.Now().UTC()
	s.gpmState.upsertOperator(app)

	// Lift session role to operator when approved.
	s.gpmState.mu.Lock()
	for token, session := range s.gpmState.sessions {
		if subtleEqual(session.WalletAddress, walletAddress) {
			if in.Approved {
				session.Role = "operator"
				session.ChainOperatorID = app.ChainOperatorID
			}
			s.gpmState.sessions[token] = session
		}
	}
	s.gpmState.mu.Unlock()
	s.persistGPMStateBestEffort("operator_approve")
	s.appendGPMAudit("operator_application_decided", map[string]any{
		"wallet_address":    app.WalletAddress,
		"chain_operator_id": app.ChainOperatorID,
		"approved":          in.Approved,
		"status":            app.Status,
		"reason":            app.Reason,
	})

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "application": serializeGPMOperator(app)})
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
