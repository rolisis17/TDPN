package localapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	urlpkg "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	gpmChallengeMaxEntries         = 4096
	gpmManifestHTTPTimeout         = 6 * time.Second
	gpmManifestBodyLimit           = 1 << 20
	gpmManifestCacheBodyLimit      = 2 << 20
	gpmManifestCacheFutureSkew     = 2 * time.Minute
	gpmAuthSignatureMaxLen         = 8 * 1024
	gpmAuthSignatureEnvelopeMaxLen = 16 * 1024
	gpmAuthVerifierOutputLimit     = 8 * 1024
)

var (
	errConnectSessionTokenEmpty            = errors.New("session token is empty")
	errConnectSessionTokenInvalidOrExpired = errors.New("session token is missing or expired")
	errConnectSessionNotRegistered         = errors.New("session is not fully registered for connect")
	errConnectSessionBootstrapTrustError   = errors.New("session bootstrap trust revalidation failed")
	errConnectSessionBootstrapRevoked      = errors.New("session bootstrap directories are no longer trusted")

	secp256k1FieldPrime   = mustBigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	secp256k1CurveOrder   = mustBigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	secp256k1GeneratorX   = mustBigIntFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	secp256k1GeneratorY   = mustBigIntFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	secp256k1SqrtExponent = new(big.Int).Div(
		new(big.Int).Add(new(big.Int).Set(secp256k1FieldPrime), big.NewInt(1)),
		big.NewInt(4),
	)
)

func mustBigIntFromHex(raw string) *big.Int {
	value, ok := new(big.Int).SetString(strings.TrimSpace(raw), 16)
	if !ok {
		panic(fmt.Sprintf("invalid bigint literal %q", raw))
	}
	return value
}

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
	Token                string    `json:"token"`
	WalletAddress        string    `json:"wallet_address"`
	WalletProvider       string    `json:"wallet_provider"`
	Role                 string    `json:"role"`
	CreatedAt            time.Time `json:"created_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	BootstrapDirectory   string    `json:"bootstrap_directory,omitempty"`
	BootstrapDirectories []string  `json:"bootstrap_directories,omitempty"`
	InviteKey            string    `json:"invite_key,omitempty"`
	PathProfile          string    `json:"path_profile,omitempty"`
	ChainOperatorID      string    `json:"chain_operator_id,omitempty"`
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
	Version               int                  `json:"version"`
	FetchedAtUTC          string               `json:"fetched_at_utc"`
	SourceURL             string               `json:"source_url"`
	SignatureVerified     bool                 `json:"signature_verified"`
	ManifestSignature     string               `json:"manifest_signature,omitempty"`
	ManifestPayloadBase64 string               `json:"manifest_payload_base64,omitempty"`
	Manifest              gpmBootstrapManifest `json:"manifest"`
}

type gpmTrustedBootstrapManifestCache struct {
	Manifest          gpmBootstrapManifest
	SignatureVerified bool
	FetchedAtUTC      time.Time
	SourceURL         string
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

type gpmOnboardingOverviewRequest struct {
	SessionToken string `json:"session_token"`
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

func (st *gpmRuntimeState) putChallenge(challenge gpmWalletChallenge, now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneExpiredChallengesLocked(now)
	if gpmChallengeMaxEntries > 0 && len(st.challenges) >= gpmChallengeMaxEntries {
		return false
	}
	st.challenges[challenge.ChallengeID] = challenge
	return true
}

func (st *gpmRuntimeState) pruneExpiredChallengesLocked(now time.Time) {
	for challengeID, challenge := range st.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(st.challenges, challengeID)
		}
	}
}

func (st *gpmRuntimeState) popValidChallenge(challengeID string, now time.Time) (gpmWalletChallenge, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pruneExpiredChallengesLocked(now)
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
		bound, reason := gpmStrictOperatorChainBinding(sessionChainOperatorID, approvedChainOperatorID)
		if !bound {
			errorMessage := "operator session is out of sync with approved application; refresh or rotate session"
			if strings.TrimSpace(reason) != "" {
				errorMessage = fmt.Sprintf("%s (%s)", errorMessage, reason)
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":    false,
				"error": errorMessage,
			})
			return false
		}
	}
	return true
}

func (s *Service) resolveConnectSecretsFromSession(ctx context.Context, sessionToken string) ([]string, string, string, error) {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return nil, "", "", errConnectSessionTokenEmpty
	}
	session, ok := s.gpmState.getSession(sessionToken, time.Now().UTC())
	if !ok {
		return nil, "", "", errConnectSessionTokenInvalidOrExpired
	}
	bootstrapDirectories := sessionConnectBootstrapDirectories(session)
	inviteKey := strings.TrimSpace(session.InviteKey)
	if len(bootstrapDirectories) == 0 || inviteKey == "" {
		return nil, "", "", errConnectSessionNotRegistered
	}
	revalidatedBootstrapDirectories, err := s.revalidateSessionBootstrapDirectoriesForConnect(ctx, bootstrapDirectories)
	if err != nil {
		return nil, "", "", err
	}
	if len(revalidatedBootstrapDirectories) == 0 {
		return nil, "", "", errConnectSessionBootstrapRevoked
	}
	return revalidatedBootstrapDirectories, inviteKey, strings.TrimSpace(session.PathProfile), nil
}

func (s *Service) revalidateSessionBootstrapDirectoriesForConnect(ctx context.Context, sessionBootstrapDirectories []string) ([]string, error) {
	sessionBootstrapDirectories = normalizeBootstrapDirectories(sessionBootstrapDirectories)
	if len(sessionBootstrapDirectories) == 0 {
		return nil, nil
	}
	manifest, _, _, err := s.resolveBootstrapManifest(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errConnectSessionBootstrapTrustError, err)
	}
	trustedDirectories := normalizeBootstrapDirectories(manifest.BootstrapDirectories)
	if len(trustedDirectories) == 0 {
		return nil, nil
	}
	trustedSet := make(map[string]struct{}, len(trustedDirectories))
	for _, trustedDirectory := range trustedDirectories {
		trustedSet[trustedDirectory] = struct{}{}
	}
	revalidated := make([]string, 0, len(sessionBootstrapDirectories))
	for _, sessionDirectory := range sessionBootstrapDirectories {
		if _, ok := trustedSet[sessionDirectory]; ok {
			revalidated = append(revalidated, sessionDirectory)
		}
	}
	return normalizeBootstrapDirectories(revalidated), nil
}

func (s *Service) handleGPMBootstrapManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	manifest, source, signatureVerified, manifestSourceURL, remoteRefreshWarning, err := s.resolveBootstrapManifestWithTelemetry(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	pinnedHost, pinnedHostErr := s.pinnedGPMMainDomainHost()
	if pinnedHostErr != nil {
		pinnedHost = ""
	}
	payload := map[string]any{
		"ok":                           true,
		"source":                       source,
		"signature_verified":           signatureVerified,
		"manifest":                     manifest,
		"trust_status":                 buildGPMBootstrapManifestTrustStatus(source, signatureVerified),
		"manifest_expires_at_utc":      strings.TrimSpace(manifest.ExpiresAtUTC),
		"manifest_expires_in_sec":      secondsUntilRFC3339(manifest.ExpiresAtUTC),
		"manifest_generated_at_utc":    strings.TrimSpace(manifest.GeneratedAtUTC),
		"manifest_source_url":          strings.TrimSpace(manifestSourceURL),
		"pinned_main_domain_host":      strings.TrimSpace(pinnedHost),
		"signature_required_by_policy": s.gpmManifestRequireSignature,
		"https_required_by_policy":     s.gpmManifestRequireHTTPS,
		"cache_max_age_sec":            int64(s.gpmManifestMaxAge / time.Second),
		"remote_refresh_interval_sec":  int64(s.gpmManifestRemoteRefreshIntvl / time.Second),
	}
	if source == "cache" && strings.TrimSpace(remoteRefreshWarning) != "" {
		payload["remote_refresh_warning"] = strings.TrimSpace(remoteRefreshWarning)
	}
	writeJSON(w, http.StatusOK, payload)
}

func buildGPMBootstrapManifestTrustStatus(source string, signatureVerified bool) string {
	source = strings.TrimSpace(source)
	switch source {
	case "cache":
		if signatureVerified {
			return "trusted_cache"
		}
		return "trusted_cache_compat"
	case "remote":
		if signatureVerified {
			return "trusted_remote"
		}
		return "trusted_remote_compat"
	default:
		if signatureVerified {
			return "trusted"
		}
		return "trusted_compat"
	}
}

func secondsUntilRFC3339(raw string) int64 {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	seconds := int64(time.Until(parsed).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
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
	now := time.Now().UTC()
	expires := now.Add(gpmChallengeTTL)
	challenge := gpmWalletChallenge{
		ChallengeID:    "gpm-chal-" + challengeID,
		WalletAddress:  in.WalletAddress,
		WalletProvider: in.WalletProvider,
		Message:        "Global Private Mesh authentication challenge: " + challengeID,
		ExpiresAt:      expires,
	}
	if !s.gpmState.putChallenge(challenge, now) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "authentication challenge queue is temporarily saturated; retry shortly",
		})
		return
	}
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
	session.BootstrapDirectories = normalizeBootstrapDirectories(manifest.BootstrapDirectories)
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
	registrationState := s.buildGPMClientRegistration(r.Context(), session)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"registration": registrationState.Registration,
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
	readiness := s.buildGPMServerReadiness(walletAddress, session, sessionPresent, "", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"readiness": readiness,
	})
}

func (s *Service) handleGPMOnboardingOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	var in gpmOnboardingOverviewRequest
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
	walletAddress := normalizeWalletAddress(session.WalletAddress)
	if walletAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet_address or session_token is required"})
		return
	}
	registrationState := s.buildGPMClientRegistration(r.Context(), session)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"session":      serializeGPMSession(session),
		"registration": registrationState.Registration,
		"readiness": s.buildGPMServerReadiness(
			walletAddress,
			session,
			true,
			registrationState.Status,
			registrationState.StatusReason,
		),
	})
}

type gpmClientRegistrationState struct {
	Registration map[string]any
	Status       string
	StatusReason string
}

func (s *Service) buildGPMClientRegistration(ctx context.Context, session gpmSession) gpmClientRegistrationState {
	registration := map[string]any{
		"wallet_address":        session.WalletAddress,
		"status":                "not_registered",
		"bootstrap_directory":   strings.TrimSpace(session.BootstrapDirectory),
		"bootstrap_directories": sessionTrustedBootstrapDirectories(session),
	}
	if profile := strings.TrimSpace(session.PathProfile); profile != "" {
		registration["path_profile"] = profile
	}

	state := gpmClientRegistrationState{
		Registration: registration,
		Status:       "not_registered",
	}
	if strings.TrimSpace(session.BootstrapDirectory) == "" || strings.TrimSpace(session.InviteKey) == "" {
		return state
	}

	revalidatedBootstrapDirectories, err := s.revalidateSessionBootstrapDirectoriesForConnect(ctx, sessionConnectBootstrapDirectories(session))
	if err != nil {
		state.Status = "degraded"
		state.StatusReason = "failed to revalidate session bootstrap directories against the trusted manifest"
		registration["status"] = state.Status
		registration["status_reason"] = state.StatusReason
		registration["bootstrap_directory"] = ""
		registration["bootstrap_directories"] = []string{}
		return state
	}
	if len(revalidatedBootstrapDirectories) == 0 {
		state.StatusReason = "registered bootstrap directories are no longer trusted by the current manifest; re-register the client profile"
		registration["status_reason"] = state.StatusReason
		registration["bootstrap_directory"] = ""
		registration["bootstrap_directories"] = []string{}
		return state
	}

	state.Status = "registered"
	registration["status"] = state.Status
	registration["bootstrap_directory"] = revalidatedBootstrapDirectories[0]
	registration["bootstrap_directories"] = revalidatedBootstrapDirectories
	return state
}

func (s *Service) buildGPMServerReadiness(walletAddress string, session gpmSession, sessionPresent bool, clientRegistrationStatusOverride string, clientRegistrationReasonOverride string) map[string]any {
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
	clientRegistrationStatus := strings.ToLower(strings.TrimSpace(clientRegistrationStatusOverride))
	clientRegistrationReason := strings.TrimSpace(clientRegistrationReasonOverride)
	clientRegistrationReady := false
	if clientRegistrationStatus == "" {
		clientRegistrationReady = sessionPresent &&
			strings.TrimSpace(session.BootstrapDirectory) != "" &&
			strings.TrimSpace(session.InviteKey) != ""
		if clientRegistrationReady {
			clientRegistrationStatus = "registered"
		} else {
			clientRegistrationStatus = "not_registered"
		}
	} else {
		clientRegistrationReady = clientRegistrationStatus == "registered"
	}
	clientTabVisible := true
	clientLockReason := ""
	if role == "operator" || role == "admin" {
		clientTabVisible = clientRegistrationReady
		if !clientTabVisible {
			clientLockReason = "client registration is required for client tab access; complete /v1/gpm/onboarding/client/register with bootstrap_directory and invite_key"
			if clientRegistrationReason != "" {
				clientLockReason = clientRegistrationReason
			}
		}
	}
	serviceMutationsConfigured := strings.TrimSpace(s.serviceStart) != "" &&
		strings.TrimSpace(s.serviceStop) != "" &&
		strings.TrimSpace(s.serviceRestart) != ""

	strictChainBound := false
	strictChainBindingReason := ""
	if role == "operator" && operatorApplicationStatus == "approved" {
		strictChainBound, strictChainBindingReason = gpmStrictOperatorChainBinding(sessionChainOperatorID, chainOperatorID)
	}

	lifecycleActionsUnlocked := role == "admin" ||
		(role == "operator" &&
			operatorApplicationStatus == "approved" &&
			strictChainBound)

	chainBindingStatus := "not_applicable"
	chainBindingOK := false
	chainBindingReason := ""
	if role == "operator" {
		switch operatorApplicationStatus {
		case "approved":
			if strictChainBound {
				chainBindingStatus = "bound"
				chainBindingOK = true
			} else {
				chainBindingStatus = "mismatch"
				chainBindingReason = strictChainBindingReason
			}
		case "pending":
			chainBindingStatus = "pending_approval"
			chainBindingReason = "operator application is pending approval"
		case "rejected":
			chainBindingStatus = "pending_approval"
			chainBindingReason = "operator application is rejected; re-approval is required before chain binding"
		case "not_submitted":
			chainBindingStatus = "pending_approval"
			chainBindingReason = "operator application has not been submitted"
		default:
			chainBindingStatus = "unknown"
			chainBindingReason = fmt.Sprintf("unexpected operator application status %q for chain binding", operatorApplicationStatus)
		}
	}

	lockReason := ""
	unlockActions := []string{}
	if !lifecycleActionsUnlocked {
		switch role {
		case "admin":
			// no-op; currently unreachable due lifecycleActionsUnlocked check.
		case "operator":
			switch operatorApplicationStatus {
			case "approved":
				lockReason = "operator session is out of sync with approved application"
				if strings.TrimSpace(strictChainBindingReason) != "" {
					lockReason = fmt.Sprintf("%s: %s", lockReason, strictChainBindingReason)
				}
				switch {
				case strings.Contains(strictChainBindingReason, "session chain_operator_id is missing"):
					unlockActions = append(unlockActions,
						"Refresh or rotate session via /v1/gpm/session",
						"Sign in again to mint a session with chain_operator_id",
					)
				case strings.Contains(strictChainBindingReason, "application chain_operator_id is missing"):
					unlockActions = append(unlockActions,
						"Have an admin approve/re-approve operator application with chain_operator_id",
						"Check /v1/gpm/onboarding/operator/status until approved chain_operator_id is present",
					)
				default:
					unlockActions = append(unlockActions,
						"Refresh or rotate session via /v1/gpm/session",
						"Sign in again if session/application chain IDs are still out of sync",
					)
				}
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
	return map[string]any{
		"wallet_address":               walletAddress,
		"role":                         role,
		"session_present":              sessionPresent,
		"operator_application_status":  operatorApplicationStatus,
		"chain_operator_id":            chainOperatorID,
		"session_chain_operator_id":    sessionChainOperatorID,
		"tab_visible":                  tabVisible,
		"client_tab_visible":           clientTabVisible,
		"client_registration_status":   clientRegistrationStatus,
		"client_registration_reason":   clientRegistrationReason,
		"lifecycle_actions_unlocked":   lifecycleActionsUnlocked,
		"chain_binding_status":         chainBindingStatus,
		"chain_binding_ok":             chainBindingOK,
		"chain_binding_reason":         chainBindingReason,
		"service_mutations_configured": serviceMutationsConfigured,
		"client_lock_reason":           clientLockReason,
		"lock_reason":                  lockReason,
		"unlock_actions":               unlockActions,
		"endpoint_posture":             endpointPosture,
		"endpoint_warnings":            endpointWarnings,
	}
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
		if s.gpmOperatorApprovalRequireSession {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":    false,
				"error": "admin session_token is required by operator approval policy; legacy admin_token fallback is disabled",
			})
			return
		}
		if strings.TrimSpace(s.gpmApprovalToken) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "admin session_token is required when approval admin token env is unset (GPM_APPROVAL_ADMIN_TOKEN; legacy aliases: TDPN_APPROVAL_ADMIN_TOKEN, GPM_OPERATOR_APPROVAL_TOKEN, TDPN_OPERATOR_APPROVAL_TOKEN)"})
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
		"wallet_address":        session.WalletAddress,
		"wallet_provider":       session.WalletProvider,
		"role":                  session.Role,
		"created_at_utc":        session.CreatedAt.Format(time.RFC3339),
		"expires_at_utc":        session.ExpiresAt.Format(time.RFC3339),
		"bootstrap_directory":   strings.TrimSpace(session.BootstrapDirectory),
		"bootstrap_directories": sessionTrustedBootstrapDirectories(session),
		"path_profile":          strings.TrimSpace(session.PathProfile),
		"chain_operator_id":     strings.TrimSpace(session.ChainOperatorID),
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

func gpmStrictOperatorChainBinding(sessionChainOperatorID string, approvedChainOperatorID string) (bool, string) {
	sessionChainOperatorID = strings.TrimSpace(sessionChainOperatorID)
	approvedChainOperatorID = strings.TrimSpace(approvedChainOperatorID)
	switch {
	case sessionChainOperatorID == "" && approvedChainOperatorID == "":
		return false, "operator session chain_operator_id is missing and approved operator application chain_operator_id is missing"
	case sessionChainOperatorID == "":
		return false, "operator session chain_operator_id is missing"
	case approvedChainOperatorID == "":
		return false, "approved operator application chain_operator_id is missing"
	case !subtleEqual(sessionChainOperatorID, approvedChainOperatorID):
		return false, "operator session chain_operator_id does not match approved operator application chain_operator_id"
	default:
		return true, ""
	}
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

func decodeGPMAuthProofMaterial(raw string, expectedLen int, fieldName string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("%s is required", fieldName)
	}
	hexCandidates := []string{value}
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		hexCandidates = append(hexCandidates, value[2:])
	}
	for _, candidate := range hexCandidates {
		if candidate == "" {
			continue
		}
		decoded, err := hex.DecodeString(candidate)
		if err == nil && len(decoded) == expectedLen {
			return decoded, nil
		}
	}
	base64Encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range base64Encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) == expectedLen {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("%s must decode to %d bytes (hex or base64)", fieldName, expectedLen)
}

func decodeGPMAuthProofMaterialFlexible(raw string, fieldName string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("%s is required", fieldName)
	}
	hexCandidates := []string{value}
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		hexCandidates = append(hexCandidates, value[2:])
	}
	for _, candidate := range hexCandidates {
		if candidate == "" {
			continue
		}
		hexVariants := []string{candidate}
		if len(candidate)%2 == 1 {
			hexVariants = append(hexVariants, "0"+candidate)
		}
		for _, variant := range hexVariants {
			decoded, err := hex.DecodeString(variant)
			if err == nil && len(decoded) > 0 {
				return decoded, nil
			}
		}
	}
	base64Encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range base64Encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) > 0 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("%s must be hex or base64", fieldName)
}

type secp256k1Point struct {
	X        *big.Int
	Y        *big.Int
	Infinity bool
}

func secp256k1PointInfinity() secp256k1Point {
	return secp256k1Point{Infinity: true}
}

func newSecp256k1Point(x *big.Int, y *big.Int) secp256k1Point {
	return secp256k1Point{
		X: new(big.Int).Set(x),
		Y: new(big.Int).Set(y),
	}
}

func secp256k1IsOnCurve(x *big.Int, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(secp256k1FieldPrime) >= 0 || y.Cmp(secp256k1FieldPrime) >= 0 {
		return false
	}
	// secp256k1: y^2 = x^3 + 7 mod p
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, secp256k1FieldPrime)

	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, big.NewInt(7))
	rhs.Mod(rhs, secp256k1FieldPrime)

	return lhs.Cmp(rhs) == 0
}

func secp256k1RecoverYFromX(x *big.Int, odd bool) (*big.Int, error) {
	if x == nil || x.Sign() < 0 || x.Cmp(secp256k1FieldPrime) >= 0 {
		return nil, errors.New("signature_public_key has invalid secp256k1 X coordinate")
	}
	ySquared := new(big.Int).Mul(x, x)
	ySquared.Mul(ySquared, x)
	ySquared.Add(ySquared, big.NewInt(7))
	ySquared.Mod(ySquared, secp256k1FieldPrime)

	y := new(big.Int).Exp(ySquared, secp256k1SqrtExponent, secp256k1FieldPrime)

	// Verify that y is a valid square root.
	check := new(big.Int).Mul(y, y)
	check.Mod(check, secp256k1FieldPrime)
	if check.Cmp(ySquared) != 0 {
		return nil, errors.New("signature_public_key has invalid secp256k1 compressed point")
	}

	if (y.Bit(0) == 1) != odd {
		y.Sub(secp256k1FieldPrime, y)
	}
	return y, nil
}

func decodeGPMAuthSecp256k1PublicKey(publicKeyRaw string) (*big.Int, *big.Int, error) {
	publicKey, err := decodeGPMAuthProofMaterialFlexible(publicKeyRaw, "signature_public_key")
	if err != nil {
		return nil, nil, err
	}

	var x *big.Int
	var y *big.Int

	switch len(publicKey) {
	case 33:
		prefix := publicKey[0]
		if prefix != 0x02 && prefix != 0x03 {
			return nil, nil, errors.New("signature_public_key compressed secp256k1 key must start with 0x02 or 0x03")
		}
		x = new(big.Int).SetBytes(publicKey[1:])
		y, err = secp256k1RecoverYFromX(x, prefix == 0x03)
		if err != nil {
			return nil, nil, err
		}
	case 64:
		x = new(big.Int).SetBytes(publicKey[:32])
		y = new(big.Int).SetBytes(publicKey[32:])
	case 65:
		if publicKey[0] != 0x04 {
			return nil, nil, errors.New("signature_public_key uncompressed secp256k1 key must start with 0x04")
		}
		x = new(big.Int).SetBytes(publicKey[1:33])
		y = new(big.Int).SetBytes(publicKey[33:])
	default:
		return nil, nil, fmt.Errorf(
			"signature_public_key must decode to 33, 64, or 65 bytes for secp256k1 (got %d)",
			len(publicKey),
		)
	}

	if !secp256k1IsOnCurve(x, y) {
		return nil, nil, errors.New("signature_public_key is not a valid secp256k1 point")
	}
	return x, y, nil
}

type secp256k1ASN1Signature struct {
	R *big.Int
	S *big.Int
}

func validateGPMAuthSecp256k1SignatureScalars(r *big.Int, s *big.Int) error {
	if r == nil || r.Sign() <= 0 || r.Cmp(secp256k1CurveOrder) >= 0 {
		return errors.New("signature contains invalid secp256k1 r value")
	}
	if s == nil || s.Sign() <= 0 || s.Cmp(secp256k1CurveOrder) >= 0 {
		return errors.New("signature contains invalid secp256k1 s value")
	}
	return nil
}

func decodeGPMAuthSecp256k1Signature(signatureRaw string) (*big.Int, *big.Int, error) {
	signature, err := decodeGPMAuthProofMaterialFlexible(signatureRaw, "signature")
	if err != nil {
		return nil, nil, err
	}

	if len(signature) == 65 {
		// Common wallet signatures append a recovery byte (v).
		signature = signature[:64]
	}

	if len(signature) == 64 {
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if err := validateGPMAuthSecp256k1SignatureScalars(r, s); err != nil {
			return nil, nil, err
		}
		return r, s, nil
	}

	var derSig secp256k1ASN1Signature
	rest, err := asn1.Unmarshal(signature, &derSig)
	if err == nil && len(rest) == 0 {
		if err := validateGPMAuthSecp256k1SignatureScalars(derSig.R, derSig.S); err != nil {
			return nil, nil, err
		}
		return derSig.R, derSig.S, nil
	}

	return nil, nil, errors.New("signature must decode to 64-byte r||s (or 65-byte with recovery id) or ASN.1 DER for secp256k1")
}

func secp256k1PointDouble(point secp256k1Point) secp256k1Point {
	if point.Infinity || point.Y.Sign() == 0 {
		return secp256k1PointInfinity()
	}

	num := new(big.Int).Mul(point.X, point.X)
	num.Mul(num, big.NewInt(3))
	num.Mod(num, secp256k1FieldPrime)

	den := new(big.Int).Mul(point.Y, big.NewInt(2))
	den.Mod(den, secp256k1FieldPrime)
	denInv := new(big.Int).ModInverse(den, secp256k1FieldPrime)
	if denInv == nil {
		return secp256k1PointInfinity()
	}

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, secp256k1FieldPrime)

	x3 := new(big.Int).Mul(lambda, lambda)
	twoX := new(big.Int).Mul(point.X, big.NewInt(2))
	x3.Sub(x3, twoX)
	x3.Mod(x3, secp256k1FieldPrime)
	if x3.Sign() < 0 {
		x3.Add(x3, secp256k1FieldPrime)
	}

	y3 := new(big.Int).Sub(point.X, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, point.Y)
	y3.Mod(y3, secp256k1FieldPrime)
	if y3.Sign() < 0 {
		y3.Add(y3, secp256k1FieldPrime)
	}

	return secp256k1Point{X: x3, Y: y3}
}

func secp256k1PointAdd(pointA secp256k1Point, pointB secp256k1Point) secp256k1Point {
	if pointA.Infinity {
		return pointB
	}
	if pointB.Infinity {
		return pointA
	}

	if pointA.X.Cmp(pointB.X) == 0 {
		sumY := new(big.Int).Add(pointA.Y, pointB.Y)
		sumY.Mod(sumY, secp256k1FieldPrime)
		if sumY.Sign() == 0 {
			return secp256k1PointInfinity()
		}
		return secp256k1PointDouble(pointA)
	}

	num := new(big.Int).Sub(pointB.Y, pointA.Y)
	num.Mod(num, secp256k1FieldPrime)

	den := new(big.Int).Sub(pointB.X, pointA.X)
	den.Mod(den, secp256k1FieldPrime)
	denInv := new(big.Int).ModInverse(den, secp256k1FieldPrime)
	if denInv == nil {
		return secp256k1PointInfinity()
	}

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, secp256k1FieldPrime)

	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, pointA.X)
	x3.Sub(x3, pointB.X)
	x3.Mod(x3, secp256k1FieldPrime)
	if x3.Sign() < 0 {
		x3.Add(x3, secp256k1FieldPrime)
	}

	y3 := new(big.Int).Sub(pointA.X, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, pointA.Y)
	y3.Mod(y3, secp256k1FieldPrime)
	if y3.Sign() < 0 {
		y3.Add(y3, secp256k1FieldPrime)
	}

	return secp256k1Point{X: x3, Y: y3}
}

func secp256k1ScalarMult(point secp256k1Point, scalar *big.Int) secp256k1Point {
	if point.Infinity || scalar == nil || scalar.Sign() <= 0 {
		return secp256k1PointInfinity()
	}
	result := secp256k1PointInfinity()
	addend := point

	for bit := 0; bit < scalar.BitLen(); bit++ {
		if scalar.Bit(bit) == 1 {
			result = secp256k1PointAdd(result, addend)
		}
		addend = secp256k1PointDouble(addend)
	}
	return result
}

func secp256k1VerifyDigest(publicKeyX *big.Int, publicKeyY *big.Int, digest []byte, r *big.Int, s *big.Int) bool {
	if !secp256k1IsOnCurve(publicKeyX, publicKeyY) {
		return false
	}
	if err := validateGPMAuthSecp256k1SignatureScalars(r, s); err != nil {
		return false
	}

	hashInt := new(big.Int).SetBytes(digest)
	orderBits := secp256k1CurveOrder.BitLen()
	if len(digest)*8 > orderBits {
		hashInt.Rsh(hashInt, uint(len(digest)*8-orderBits))
	}

	sInv := new(big.Int).ModInverse(s, secp256k1CurveOrder)
	if sInv == nil {
		return false
	}

	u1 := new(big.Int).Mul(hashInt, sInv)
	u1.Mod(u1, secp256k1CurveOrder)
	u2 := new(big.Int).Mul(r, sInv)
	u2.Mod(u2, secp256k1CurveOrder)

	generator := newSecp256k1Point(secp256k1GeneratorX, secp256k1GeneratorY)
	publicKey := newSecp256k1Point(publicKeyX, publicKeyY)
	point := secp256k1PointAdd(
		secp256k1ScalarMult(generator, u1),
		secp256k1ScalarMult(publicKey, u2),
	)
	if point.Infinity || point.X == nil {
		return false
	}

	v := new(big.Int).Mod(point.X, secp256k1CurveOrder)
	return v.Cmp(r) == 0
}

func verifyGPMAuthSignatureSecp256k1(publicKeyRaw string, signatureRaw string, message string) error {
	publicKeyX, publicKeyY, err := decodeGPMAuthSecp256k1PublicKey(publicKeyRaw)
	if err != nil {
		return err
	}
	r, s, err := decodeGPMAuthSecp256k1Signature(signatureRaw)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(message))
	if !secp256k1VerifyDigest(publicKeyX, publicKeyY, hash[:], r, s) {
		return errors.New("secp256k1 signature verification failed")
	}
	return nil
}

func verifyGPMAuthSignatureEd25519(publicKeyRaw string, signatureRaw string, message string) error {
	publicKey, err := decodeGPMAuthProofMaterial(publicKeyRaw, ed25519.PublicKeySize, "signature_public_key")
	if err != nil {
		return err
	}
	signature, err := decodeGPMAuthProofMaterial(signatureRaw, ed25519.SignatureSize, "signature")
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(message), signature) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

func (s *Service) verifyGPMAuthSignatureCryptographicProof(signature string, signatureMetadata gpmAuthSignatureMetadata) error {
	hasPublicKey := strings.TrimSpace(signatureMetadata.SignaturePublicKey) != ""
	hasPublicKeyType := strings.TrimSpace(signatureMetadata.SignaturePublicKeyType) != ""
	hasSignedMessage := signatureMetadata.HasSignedMessage && signatureMetadata.SignedMessage != ""
	requireCryptoProof := s.gpmAuthVerifyRequireCryptoProof
	if !requireCryptoProof && !s.gpmAuthVerifyRequireCommand && strings.TrimSpace(s.gpmAuthVerifyCommand) == "" {
		// Fail closed when no cryptographic proof policy override and no external verifier path exists.
		if !hasPublicKey || !hasPublicKeyType || !hasSignedMessage {
			missing := make([]string, 0, 3)
			if !hasPublicKey {
				missing = append(missing, "signature_public_key")
			}
			if !hasPublicKeyType {
				missing = append(missing, "signature_public_key_type")
			}
			if !hasSignedMessage {
				missing = append(missing, "signed_message")
			}
			return fmt.Errorf(
				"cryptographic proof metadata is required when no external verifier is configured: %s",
				strings.Join(missing, ", "),
			)
		}
	}
	if !hasPublicKey && !hasPublicKeyType && !hasSignedMessage {
		if requireCryptoProof {
			return errors.New("cryptographic proof metadata is required by policy: signature_public_key, signature_public_key_type, signed_message")
		}
		return nil
	}
	if !hasPublicKey || !hasPublicKeyType || !hasSignedMessage {
		if requireCryptoProof {
			missing := make([]string, 0, 3)
			if !hasPublicKey {
				missing = append(missing, "signature_public_key")
			}
			if !hasPublicKeyType {
				missing = append(missing, "signature_public_key_type")
			}
			if !hasSignedMessage {
				missing = append(missing, "signed_message")
			}
			return fmt.Errorf("cryptographic proof metadata is required by policy: %s", strings.Join(missing, ", "))
		}
		return nil
	}
	switch signatureMetadata.SignaturePublicKeyType {
	case "secp256k1":
		return verifyGPMAuthSignatureSecp256k1(signatureMetadata.SignaturePublicKey, signature, signatureMetadata.SignedMessage)
	case "ed25519":
		return verifyGPMAuthSignatureEd25519(signatureMetadata.SignaturePublicKey, signature, signatureMetadata.SignedMessage)
	default:
		if requireCryptoProof {
			return fmt.Errorf(
				"signature_public_key_type %q is not supported for strict cryptographic proof policy",
				signatureMetadata.SignaturePublicKeyType,
			)
		}
		return nil
	}
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
	if err := s.verifyGPMAuthSignatureCryptographicProof(signature, signatureMetadata); err != nil {
		return err
	}
	if s.gpmAuthVerifyRequireCommand && strings.TrimSpace(s.gpmAuthVerifyCommand) == "" {
		s.appendGPMAuthVerifyFailureAudit(challenge, walletAddress, walletProvider, "verifier_command_required", "policy")
		return errors.New("signature verifier command is required by policy")
	}
	if err := s.runGPMAuthVerifierCommand(ctx, challenge, walletAddress, walletProvider, signature, signatureMetadata); err != nil {
		s.appendGPMAuthVerifyFailureAudit(challenge, walletAddress, walletProvider, "verifier_command_error", "external_verifier")
		return err
	}
	return nil
}

func (s *Service) appendGPMAuthVerifyFailureAudit(challenge gpmWalletChallenge, walletAddress string, walletProvider string, failureReasonCode string, failureReasonCategory string) {
	s.appendGPMAudit("auth_verify_failed", map[string]any{
		"wallet_address":          strings.TrimSpace(walletAddress),
		"wallet_provider":         strings.TrimSpace(walletProvider),
		"challenge_id":            strings.TrimSpace(challenge.ChallengeID),
		"failure_reason_code":     strings.TrimSpace(failureReasonCode),
		"failure_reason_category": strings.TrimSpace(failureReasonCategory),
	})
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
	manifest, source, signatureVerified, _, _, err := s.resolveBootstrapManifestWithTelemetry(ctx)
	return manifest, source, signatureVerified, err
}

func (s *Service) resolveBootstrapManifestWithTelemetry(ctx context.Context) (gpmBootstrapManifest, string, bool, string, string, error) {
	manifestURL := strings.TrimSpace(s.gpmManifestURL)
	// Cache-first policy: use a valid trusted cache artifact when available and only
	// attempt a bounded remote refresh when cache is missing/stale/invalid.
	cacheEntry, cacheErr := s.readTrustedBootstrapManifestCache()
	if cacheErr == nil {
		cacheSourceURL := strings.TrimSpace(cacheEntry.SourceURL)
		if cacheSourceURL == "" {
			cacheSourceURL = manifestURL
		}
		if !s.shouldAttemptRemoteManifestRefresh(cacheEntry.FetchedAtUTC) {
			return cacheEntry.Manifest, "cache", cacheEntry.SignatureVerified, cacheSourceURL, "", nil
		}
		manifest, signatureVerified, manifestBody, manifestSignature, err := s.fetchRemoteManifestWithPolicy(ctx, manifestURL)
		if err != nil {
			if failClosed, cacheAge, maxAllowedCacheAge := s.shouldFailClosedOnManifestRefreshFailure(cacheEntry.FetchedAtUTC); failClosed {
				return gpmBootstrapManifest{}, "", false, cacheSourceURL, "", fmt.Errorf(
					"periodic remote manifest refresh failed and cached manifest age (%ds) exceeds configured refresh-failure fallback max cache age (%ds): %w",
					int64(cacheAge/time.Second),
					int64(maxAllowedCacheAge/time.Second),
					err,
				)
			}
			return cacheEntry.Manifest, "cache", cacheEntry.SignatureVerified, cacheSourceURL, "periodic remote refresh failed; serving last trusted cached manifest", nil
		}
		_ = s.writeBootstrapManifestCache(manifest, signatureVerified, manifestBody, manifestSignature)
		return manifest, "remote", signatureVerified, manifestURL, "", nil
	}

	manifest, signatureVerified, manifestBody, manifestSignature, err := s.fetchRemoteManifestWithPolicy(ctx, manifestURL)
	if err != nil {
		return gpmBootstrapManifest{}, "", false, manifestURL, "", fmt.Errorf("manifest cache read failed (%v) and remote manifest refresh failed (%v)", cacheErr, err)
	}
	_ = s.writeBootstrapManifestCache(manifest, signatureVerified, manifestBody, manifestSignature)
	return manifest, "remote", signatureVerified, manifestURL, "", nil
}

func (s *Service) shouldAttemptRemoteManifestRefresh(fetchedAt time.Time) bool {
	refreshInterval := s.gpmManifestRemoteRefreshIntvl
	if refreshInterval <= 0 {
		return false
	}
	cacheAge := sanitizedManifestCacheAge(fetchedAt, time.Now().UTC())
	return cacheAge >= refreshInterval
}

func (s *Service) shouldFailClosedOnManifestRefreshFailure(fetchedAt time.Time) (bool, time.Duration, time.Duration) {
	maxAllowedCacheAge := s.gpmManifestRefreshFailureMaxCacheAge
	if maxAllowedCacheAge <= 0 {
		return false, 0, maxAllowedCacheAge
	}
	cacheAge := sanitizedManifestCacheAge(fetchedAt, time.Now().UTC())
	return cacheAge > maxAllowedCacheAge, cacheAge, maxAllowedCacheAge
}

func sanitizedManifestCacheAge(fetchedAt time.Time, now time.Time) time.Duration {
	cacheAge := now.Sub(fetchedAt)
	if cacheAge < 0 {
		return 0
	}
	return cacheAge
}

func (s *Service) fetchRemoteManifestWithPolicy(ctx context.Context, manifestURL string) (gpmBootstrapManifest, bool, []byte, string, error) {
	manifestURL = strings.TrimSpace(manifestURL)
	if manifestURL == "" {
		return gpmBootstrapManifest{}, false, nil, "", errors.New("gpm manifest url is not configured")
	}
	pinnedHost, err := s.pinnedGPMMainDomainHost()
	if err != nil {
		return gpmBootstrapManifest{}, false, nil, "", err
	}
	if err := s.validateManifestSourceURLPolicy(manifestURL, pinnedHost, "gpm manifest url"); err != nil {
		return gpmBootstrapManifest{}, false, nil, "", err
	}
	if pinnedHost != "" {
		manifestHost, hostErr := normalizeHTTPHost(manifestURL)
		if hostErr != nil {
			return gpmBootstrapManifest{}, false, nil, "", fmt.Errorf("gpm manifest url is invalid for pinned gpm main domain host %q: %w", pinnedHost, hostErr)
		}
		if manifestHost != pinnedHost {
			return gpmBootstrapManifest{}, false, nil, "", fmt.Errorf("gpm manifest url host mismatch: got %q, pinned gpm main domain host %q; update GPM_MAIN_DOMAIN or GPM_BOOTSTRAP_MANIFEST_URL", manifestHost, pinnedHost)
		}
	}
	return s.fetchRemoteManifest(ctx, manifestURL)
}

func (s *Service) fetchRemoteManifest(ctx context.Context, manifestURL string) (gpmBootstrapManifest, bool, []byte, string, error) {
	client := &http.Client{
		Timeout: gpmManifestHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("manifest endpoint redirect is not allowed")
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return gpmBootstrapManifest{}, false, nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return gpmBootstrapManifest{}, false, nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gpmBootstrapManifest{}, false, nil, "", fmt.Errorf("manifest endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, gpmManifestBodyLimit+1))
	if err != nil {
		return gpmBootstrapManifest{}, false, nil, "", err
	}
	if len(body) > gpmManifestBodyLimit {
		return gpmBootstrapManifest{}, false, nil, "", errors.New("manifest response too large")
	}
	var manifest gpmBootstrapManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return gpmBootstrapManifest{}, false, nil, "", fmt.Errorf("invalid manifest json: %w", err)
	}
	if err := validateBootstrapManifest(manifest); err != nil {
		return gpmBootstrapManifest{}, false, nil, "", err
	}
	manifest = normalizeBootstrapManifest(manifest)
	signatureVerified := false
	hmacKey := strings.TrimSpace(s.gpmManifestHMACKey)
	ed25519PublicKey := strings.TrimSpace(s.gpmManifestEd25519PublicKey)
	requireSignature := s.gpmManifestRequireSignature

	if hmacKey != "" {
		receivedSignature := strings.TrimSpace(resp.Header.Get("X-GPM-Signature"))
		if receivedSignature == "" {
			return gpmBootstrapManifest{}, false, nil, "", errors.New("manifest signature header missing")
		}
		expected := computeManifestHMAC(body, hmacKey)
		if !subtleEqual(receivedSignature, expected) {
			return gpmBootstrapManifest{}, false, nil, "", errors.New("manifest signature verification failed")
		}
		signatureVerified = true
		return manifest, signatureVerified, body, receivedSignature, nil
	}
	if ed25519PublicKey != "" {
		receivedSignature := manifestEd25519SignatureFromHeaders(resp.Header)
		if receivedSignature == "" {
			return gpmBootstrapManifest{}, false, nil, "", errors.New("manifest ed25519 signature header missing (expected X-GPM-Signature-Ed25519 or X-GPM-Signature)")
		}
		if err := verifyManifestEd25519Signature(body, receivedSignature, ed25519PublicKey); err != nil {
			return gpmBootstrapManifest{}, false, nil, "", err
		}
		signatureVerified = true
		return manifest, signatureVerified, body, receivedSignature, nil
	}
	if requireSignature {
		return gpmBootstrapManifest{}, false, nil, "", manifestSignatureVerifierKeyRequiredError()
	}
	return manifest, signatureVerified, body, "", nil
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
	manifest.BootstrapDirectories = normalizeBootstrapDirectories(manifest.BootstrapDirectories)
	return manifest
}

func normalizeBootstrapDirectories(directories []string) []string {
	normalized := make([]string, 0, len(directories))
	seen := map[string]struct{}{}
	for _, dir := range directories {
		trimmed := strings.TrimSpace(dir)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func sessionTrustedBootstrapDirectories(session gpmSession) []string {
	directories := normalizeBootstrapDirectories(session.BootstrapDirectories)
	if len(directories) == 0 {
		if preferred := strings.TrimSpace(session.BootstrapDirectory); preferred != "" {
			return []string{preferred}
		}
	}
	return directories
}

func sessionConnectBootstrapDirectories(session gpmSession) []string {
	preferred := strings.TrimSpace(session.BootstrapDirectory)
	trusted := sessionTrustedBootstrapDirectories(session)
	ordered := make([]string, 0, len(trusted)+1)
	appendIfMissing := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		for _, existing := range ordered {
			if existing == candidate {
				return
			}
		}
		ordered = append(ordered, candidate)
	}
	appendIfMissing(preferred)
	for _, directory := range trusted {
		appendIfMissing(directory)
	}
	return ordered
}

func computeManifestHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) hasManifestHMACVerifierConfigured() bool {
	return strings.TrimSpace(s.gpmManifestHMACKey) != ""
}

func (s *Service) hasManifestEd25519VerifierConfigured() bool {
	return strings.TrimSpace(s.gpmManifestEd25519PublicKey) != ""
}

func (s *Service) hasManifestSignatureVerifierConfigured() bool {
	return s.hasManifestHMACVerifierConfigured() || s.hasManifestEd25519VerifierConfigured()
}

func (s *Service) manifestSignatureVerifierTelemetry() (string, string) {
	if s.hasManifestHMACVerifierConfigured() {
		return "hmac", normalizeManifestSignatureVerifierSource(s.gpmManifestHMACKeySource)
	}
	if s.hasManifestEd25519VerifierConfigured() {
		return "ed25519", normalizeManifestSignatureVerifierSource(s.gpmManifestEd25519PublicKeySource)
	}
	if s.gpmManifestRequireSignature {
		return "required_unconfigured", "none"
	}
	return "compatibility", "none"
}

func normalizeManifestSignatureVerifierSource(raw string) string {
	source := strings.TrimSpace(raw)
	if source == "" || source == "default" {
		return "configured"
	}
	return source
}

func manifestSignatureVerifierKeyRequiredError() error {
	return errors.New(
		"manifest signature verification key is required by policy (set GPM_BOOTSTRAP_MANIFEST_HMAC_KEY or GPM_BOOTSTRAP_MANIFEST_ED25519_PUBLIC_KEY; legacy aliases: TDPN_BOOTSTRAP_MANIFEST_HMAC_KEY, TDPN_BOOTSTRAP_MANIFEST_ED25519_PUBLIC_KEY)",
	)
}

func manifestEd25519SignatureFromHeaders(headers http.Header) string {
	if headers == nil {
		return ""
	}
	signature := strings.TrimSpace(headers.Get("X-GPM-Signature-Ed25519"))
	if signature != "" {
		return signature
	}
	return strings.TrimSpace(headers.Get("X-GPM-Signature"))
}

func decodeManifestProofMaterialStrict(raw string, expectedLen int, fieldName string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("%s is required", fieldName)
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return nil, fmt.Errorf("%s contains invalid whitespace/control characters", fieldName)
		}
	}
	return decodeGPMAuthProofMaterial(value, expectedLen, fieldName)
}

func decodeManifestEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	decoded, err := decodeManifestProofMaterialStrict(raw, ed25519.PublicKeySize, "manifest ed25519 public key")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(decoded), nil
}

func decodeManifestEd25519Signature(raw string) ([]byte, error) {
	return decodeManifestProofMaterialStrict(raw, ed25519.SignatureSize, "manifest signature")
}

func verifyManifestEd25519Signature(manifestBody []byte, signatureRaw string, publicKeyRaw string) error {
	publicKey, err := decodeManifestEd25519PublicKey(publicKeyRaw)
	if err != nil {
		return err
	}
	signature, err := decodeManifestEd25519Signature(signatureRaw)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, manifestBody, signature) {
		return errors.New("manifest ed25519 signature verification failed")
	}
	return nil
}

func decodeCachedManifestSignedPayloadEvidence(cache gpmBootstrapManifestCacheFile) ([]byte, string, error) {
	payloadBase64 := strings.TrimSpace(cache.ManifestPayloadBase64)
	signature := strings.TrimSpace(cache.ManifestSignature)
	if payloadBase64 == "" || signature == "" {
		return nil, "", errors.New("cached manifest is missing signed payload evidence")
	}
	payload, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, "", fmt.Errorf("cached manifest payload decode failed: %w", err)
	}
	return payload, signature, nil
}

func (s *Service) writeBootstrapManifestCache(manifest gpmBootstrapManifest, signatureVerified bool, manifestBody []byte, manifestSignature string) error {
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
		SignatureVerified: signatureVerified,
		Manifest:          manifest,
	}
	if !s.hasManifestSignatureVerifierConfigured() && !s.gpmManifestRequireSignature {
		cache.SignatureVerified = true
	}
	if s.hasManifestSignatureVerifierConfigured() && signatureVerified && len(manifestBody) > 0 && strings.TrimSpace(manifestSignature) != "" {
		cache.ManifestPayloadBase64 = base64.StdEncoding.EncodeToString(manifestBody)
		cache.ManifestSignature = strings.TrimSpace(manifestSignature)
	}
	body, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, body, 0o600)
}

func (s *Service) readBootstrapManifestCache() (gpmBootstrapManifest, bool, error) {
	cacheEntry, err := s.readTrustedBootstrapManifestCache()
	if err != nil {
		return gpmBootstrapManifest{}, false, err
	}
	return cacheEntry.Manifest, cacheEntry.SignatureVerified, nil
}

func (s *Service) readTrustedBootstrapManifestCache() (gpmTrustedBootstrapManifestCache, error) {
	cachePath := strings.TrimSpace(s.gpmManifestCache)
	if cachePath == "" {
		return gpmTrustedBootstrapManifestCache{}, errors.New("manifest cache path is empty")
	}
	body, err := readFileWithHardLimit(cachePath, gpmManifestCacheBodyLimit)
	if err != nil {
		return gpmTrustedBootstrapManifestCache{}, err
	}
	var cache gpmBootstrapManifestCacheFile
	if err := json.Unmarshal(body, &cache); err != nil {
		return gpmTrustedBootstrapManifestCache{}, err
	}
	if err := validateBootstrapManifest(cache.Manifest); err != nil {
		return gpmTrustedBootstrapManifestCache{}, err
	}
	fetchedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(cache.FetchedAtUTC))
	if err != nil {
		return gpmTrustedBootstrapManifestCache{}, err
	}
	now := time.Now().UTC()
	if fetchedAt.After(now.Add(gpmManifestCacheFutureSkew)) {
		return gpmTrustedBootstrapManifestCache{}, errors.New("cached manifest fetched_at_utc is in the future")
	}
	if sanitizedManifestCacheAge(fetchedAt, now) > s.gpmManifestMaxAge {
		return gpmTrustedBootstrapManifestCache{}, errors.New("cached manifest is stale")
	}
	pinnedHost, err := s.pinnedGPMMainDomainHost()
	if err != nil {
		return gpmTrustedBootstrapManifestCache{}, err
	}
	cacheSourceURL := strings.TrimSpace(cache.SourceURL)
	if cacheSourceURL == "" {
		cacheSourceURL = strings.TrimSpace(s.gpmManifestURL)
	}
	if err := s.validateManifestSourceURLPolicy(cacheSourceURL, pinnedHost, "cached manifest source url"); err != nil {
		return gpmTrustedBootstrapManifestCache{}, err
	}
	if pinnedHost != "" {
		cacheSourceHost, hostErr := normalizeHTTPHost(cacheSourceURL)
		if hostErr != nil {
			return gpmTrustedBootstrapManifestCache{}, fmt.Errorf("cached manifest source url is invalid for pinned gpm main domain host %q: %w", pinnedHost, hostErr)
		}
		if cacheSourceHost != pinnedHost {
			return gpmTrustedBootstrapManifestCache{}, fmt.Errorf("cached manifest source host mismatch: got %q, pinned gpm main domain host %q; clear the cache or refresh it from the pinned domain", cacheSourceHost, pinnedHost)
		}
	}
	signatureVerified, err := s.verifyCachedManifestSignature(cache)
	if err != nil {
		return gpmTrustedBootstrapManifestCache{}, err
	}
	return gpmTrustedBootstrapManifestCache{
		Manifest:          normalizeBootstrapManifest(cache.Manifest),
		SignatureVerified: signatureVerified,
		FetchedAtUTC:      fetchedAt,
		SourceURL:         cacheSourceURL,
	}, nil
}

func (s *Service) verifyCachedManifestSignature(cache gpmBootstrapManifestCacheFile) (bool, error) {
	hmacKey := strings.TrimSpace(s.gpmManifestHMACKey)
	ed25519PublicKey := strings.TrimSpace(s.gpmManifestEd25519PublicKey)
	if hmacKey == "" && ed25519PublicKey == "" {
		if s.gpmManifestRequireSignature {
			return false, manifestSignatureVerifierKeyRequiredError()
		}
		return cache.SignatureVerified, nil
	}

	payload, signature, err := decodeCachedManifestSignedPayloadEvidence(cache)
	if err != nil {
		return false, err
	}
	if hmacKey != "" {
		expected := computeManifestHMAC(payload, hmacKey)
		if !subtleEqual(signature, expected) {
			return false, errors.New("cached manifest signature verification failed")
		}
	} else {
		if err := verifyManifestEd25519Signature(payload, signature, ed25519PublicKey); err != nil {
			return false, fmt.Errorf("cached manifest signature verification failed: %w", err)
		}
	}

	var payloadManifest gpmBootstrapManifest
	if err := json.Unmarshal(payload, &payloadManifest); err != nil {
		return false, fmt.Errorf("cached manifest payload json invalid: %w", err)
	}
	if err := validateBootstrapManifest(payloadManifest); err != nil {
		return false, fmt.Errorf("cached manifest payload invalid: %w", err)
	}
	normalizedPayloadManifest := normalizeBootstrapManifest(payloadManifest)
	normalizedCachedManifest := normalizeBootstrapManifest(cache.Manifest)
	if !reflect.DeepEqual(normalizedPayloadManifest, normalizedCachedManifest) {
		return false, errors.New("cached manifest payload does not match cached manifest body")
	}
	return true, nil
}

func (s *Service) pinnedGPMMainDomainHost() (string, error) {
	mainDomain := strings.TrimSpace(s.gpmMainDomain)
	if mainDomain == "" {
		return "", nil
	}
	return normalizeHTTPHost(mainDomain)
}

func (s *Service) validateManifestSourceURLPolicy(rawURL string, pinnedHost string, sourceLabel string) error {
	parsed, err := parseManifestSourceURL(rawURL)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", sourceLabel, err)
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("%s host is empty", sourceLabel)
	}
	if strings.EqualFold(parsed.Scheme, "http") && s.gpmManifestRequireHTTPS {
		if pinnedHost != "" {
			return fmt.Errorf("%s must use https when pinned gpm main domain is configured", sourceLabel)
		}
		if !hostResolvesToLoopback(host) {
			return fmt.Errorf("%s must use https for non-loopback hosts", sourceLabel)
		}
	}
	return nil
}

func parseManifestSourceURL(raw string) (*urlpkg.URL, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, err := parseAbsoluteHTTPURL(trimmed)
	if err != nil {
		return nil, err
	}
	if parsed.User != nil {
		return nil, errors.New("url userinfo is not allowed")
	}
	if parsed.ForceQuery || strings.TrimSpace(parsed.RawQuery) != "" {
		return nil, errors.New("url query is not allowed")
	}
	if strings.Contains(trimmed, "#") || strings.TrimSpace(parsed.Fragment) != "" {
		return nil, errors.New("url fragment is not allowed")
	}
	return parsed, nil
}

func readFileWithHardLimit(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds max size %d bytes", path, maxBytes)
	}
	return body, nil
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
