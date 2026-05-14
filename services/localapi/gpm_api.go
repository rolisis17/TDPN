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
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
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

	"golang.org/x/crypto/ripemd160"

	"privacynode/pkg/settlement"
)

const (
	gpmChallengeTTL                  = 5 * time.Minute
	gpmSessionTTL                    = 12 * time.Hour
	gpmReservationPendingClaimTTL    = 15 * time.Minute
	gpmReservationLaunchClaimTTL     = 15 * time.Minute
	gpmChallengeMaxEntries           = 4096
	gpmChallengeMaxEntriesPerWallet  = 8
	gpmSessionMaxEntries             = 8192
	gpmSessionMaxEntriesPerWallet    = 16
	gpmOperatorApplicationMaxEntries = 16384
	gpmContributionMaxEntries        = 16384
	gpmReservationClaimMaxEntries    = 65536
	gpmManifestHTTPTimeout           = 6 * time.Second
	gpmManifestBodyLimit             = 1 << 20
	gpmManifestCacheBodyLimit        = 2 << 20
	gpmManifestCacheFutureSkew       = 2 * time.Minute
	gpmManifestMaxValidity           = 24 * time.Hour
	gpmManifestBootstrapDirectoryMax = 32
	gpmAuthSignatureMaxLen           = 8 * 1024
	gpmAuthSignatureEnvelopeMaxLen   = 16 * 1024
	gpmAuthVerifierOutputLimit       = 8 * 1024
	gpmGapScanSummaryBodyLimit       = 2 << 20
	gpmGapSummaryMaxAge              = 24 * time.Hour
	gpmBech32ChecksumLength          = 6
	gpmPublicVPNReservationMicros    = 200000
	gpmPublicVPNReservationCurrency  = "TDPNC"
)

var (
	errConnectSessionTokenEmpty            = errors.New("session token is empty")
	errConnectSessionTokenInvalidOrExpired = errors.New("session token is missing or expired")
	errConnectSessionWalletPolicyInvalid   = errors.New("session wallet policy is no longer valid")
	errConnectSessionWalletBindingRequired = errors.New("wallet-bound session is required for connect")
	errConnectSessionNotRegistered         = errors.New("session is not fully registered for connect")
	errConnectSessionBootstrapTrustError   = errors.New("session bootstrap trust revalidation failed")
	errConnectSessionBootstrapRevoked      = errors.New("session bootstrap directories are no longer trusted")
	errGPMGapSummaryArtifactMissing        = errors.New("gpm gap summary artifact missing")
	errGPMGapSummaryArtifactUnreadable     = errors.New("gpm gap summary artifact unreadable")
	errGPMGapSummaryArtifactMalformed      = errors.New("gpm gap summary artifact malformed")

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
	mu                sync.RWMutex
	challenges        map[string]gpmWalletChallenge
	sessions          map[string]gpmSession
	operators         map[string]gpmOperatorApplication
	contributions     map[string]gpmContributionState
	rewardHistory     map[string][]gpmWeeklyRewardSummary
	rewardHolds       map[string][]gpmRewardHold
	reservationClaims map[string]gpmReservationClaim
}

type gpmWalletChallenge struct {
	ChallengeID    string    `json:"challenge_id"`
	WalletAddress  string    `json:"wallet_address"`
	WalletProvider string    `json:"wallet_provider"`
	ChainID        string    `json:"chain_id,omitempty"`
	Message        string    `json:"message"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type gpmSession struct {
	Token                     string    `json:"token"`
	WalletAddress             string    `json:"wallet_address"`
	WalletProvider            string    `json:"wallet_provider"`
	ChainID                   string    `json:"chain_id,omitempty"`
	Role                      string    `json:"role"`
	WalletBindingVerified     bool      `json:"wallet_binding_verified,omitempty"`
	AuthVerificationSource    string    `json:"auth_verification_source,omitempty"`
	AuthPolicyFingerprint     string    `json:"auth_policy_fingerprint,omitempty"`
	EntitlementEvidenceSource string    `json:"entitlement_evidence_source,omitempty"`
	ClientTier                int       `json:"client_tier,omitempty"`
	StakeSatisfied            bool      `json:"stake_satisfied,omitempty"`
	PrepaidBalanceSatisfied   bool      `json:"prepaid_balance_satisfied,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
	ExpiresAt                 time.Time `json:"expires_at"`
	BootstrapDirectory        string    `json:"bootstrap_directory,omitempty"`
	BootstrapDirectories      []string  `json:"bootstrap_directories,omitempty"`
	InviteKey                 string    `json:"invite_key,omitempty"`
	PathProfile               string    `json:"path_profile,omitempty"`
	ChainOperatorID           string    `json:"chain_operator_id,omitempty"`
}

type gpmOperatorApplication struct {
	WalletAddress          string    `json:"wallet_address"`
	ChainOperatorID        string    `json:"chain_operator_id"`
	ServerLabel            string    `json:"server_label,omitempty"`
	Status                 string    `json:"status"`
	Reason                 string    `json:"reason,omitempty"`
	ApprovalEvidenceSource string    `json:"approval_evidence_source,omitempty"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type gpmContributionState struct {
	WalletAddress           string    `json:"wallet_address"`
	Enabled                 bool      `json:"enabled"`
	Role                    string    `json:"role"`
	RequestedRole           string    `json:"requested_role"`
	ClientTier              int       `json:"client_tier"`
	StakeSatisfied          bool      `json:"stake_satisfied"`
	PrepaidBalanceSatisfied bool      `json:"prepaid_balance_satisfied"`
	ExplicitOptIn           bool      `json:"explicit_opt_in"`
	MicroExitBetaAllowed    bool      `json:"micro_exit_beta_allowed"`
	CapacityScore           int       `json:"capacity_score"`
	HealthScore             int       `json:"health_score"`
	MaxForwardedSessions    int       `json:"max_forwarded_sessions"`
	MaxBandwidthMbps        int       `json:"max_bandwidth_mbps"`
	UptimeReliabilityPct    float64   `json:"uptime_reliability_pct"`
	DemotionState           string    `json:"demotion_state"`
	LockReason              string    `json:"lock_reason,omitempty"`
	MeteredWeekStartUTC     string    `json:"metered_week_start_utc"`
	MeteredSeconds          int64     `json:"metered_seconds"`
	ValidBytes              int64     `json:"valid_bytes"`
	PendingRewardUnits      float64   `json:"pending_reward_units"`
	LastMeteredAt           time.Time `json:"last_metered_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

type gpmReservationClaim struct {
	ReservationID        string    `json:"reservation_id"`
	ReservationSessionID string    `json:"reservation_session_id"`
	WalletAddress        string    `json:"wallet_address"`
	Status               string    `json:"status"`
	ClaimedAt            time.Time `json:"claimed_at"`
	LaunchStartedAt      time.Time `json:"launch_started_at,omitempty"`
	LaunchedAt           time.Time `json:"launched_at,omitempty"`
}

type gpmWeeklyRewardSummary struct {
	WalletAddress               string   `json:"wallet_address"`
	WeekStartUTC                string   `json:"week_start_utc"`
	WeekEndUTC                  string   `json:"week_end_utc"`
	Role                        string   `json:"role"`
	MeteredSeconds              int64    `json:"metered_seconds"`
	ValidBytes                  int64    `json:"valid_bytes"`
	CapacityScore               int      `json:"capacity_score"`
	HealthScore                 int      `json:"health_score"`
	RewardUnits                 float64  `json:"reward_units"`
	Status                      string   `json:"status"`
	HoldReason                  string   `json:"hold_reason,omitempty"`
	HoldSources                 []string `json:"hold_sources,omitempty"`
	PayoutAllowed               bool     `json:"payout_allowed"`
	SettlementFinalizationState string   `json:"settlement_finalization_state"`
	TrafficProofStatus          string   `json:"traffic_proof_status"`
	MeteringSource              string   `json:"metering_source"`
	TrafficProofRef             string   `json:"traffic_proof_ref,omitempty"`
	GeneratedAtUTC              string   `json:"generated_at_utc"`
	SettlementFrequency         string   `json:"settlement_frequency"`
	SettlementIssuedAtUTC       string   `json:"settlement_issued_at_utc,omitempty"`
	RewardIssueID               string   `json:"reward_issue_id,omitempty"`
	SettlementReferenceID       string   `json:"settlement_reference_id,omitempty"`
	SettlementChainStatus       string   `json:"settlement_chain_status,omitempty"`
	SettlementAdapterReference  string   `json:"settlement_adapter_reference_id,omitempty"`
	FinalizedAtUTC              string   `json:"finalized_at_utc,omitempty"`
}

type gpmRewardHold struct {
	HoldID        string    `json:"hold_id"`
	WalletAddress string    `json:"wallet_address"`
	WeekStartUTC  string    `json:"week_start_utc"`
	Source        string    `json:"source"`
	Reason        string    `json:"reason"`
	Status        string    `json:"status"`
	CreatedBy     string    `json:"created_by,omitempty"`
	ReleasedBy    string    `json:"released_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type gpmSlashEvidenceLister interface {
	ListSlashEvidence(context.Context, settlement.SlashEvidenceFilter) ([]settlement.SlashEvidence, error)
}

type gpmBootstrapManifest struct {
	Version              int                      `json:"version"`
	GeneratedAtUTC       string                   `json:"generated_at_utc"`
	ExpiresAtUTC         string                   `json:"expires_at_utc"`
	BootstrapDirectories []string                 `json:"bootstrap_directories"`
	GatewayMirrors       []gpmBootstrapURLHint    `json:"gateway_mirrors,omitempty"`
	BootstrapSources     []gpmBootstrapURLHint    `json:"bootstrap_sources,omitempty"`
	RelayHints           []gpmBootstrapRelayHint  `json:"relay_hints,omitempty"`
	BridgeHints          []gpmBootstrapBridgeHint `json:"bridge_hints,omitempty"`
	RelayPolicy          map[string]any           `json:"relay_policy,omitempty"`
}

type gpmBootstrapURLHint struct {
	URL          string `json:"url"`
	Kind         string `json:"kind"`
	OperatorID   string `json:"operator_id,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	ExpiresAtUTC string `json:"expires_at_utc,omitempty"`
}

type gpmBootstrapRelayHint struct {
	RelayID      string `json:"relay_id"`
	OperatorID   string `json:"operator_id"`
	DirectoryURL string `json:"directory_url,omitempty"`
	EntryURL     string `json:"entry_url,omitempty"`
	PublicHost   string `json:"public_host,omitempty"`
	Country      string `json:"country,omitempty"`
	Region       string `json:"region,omitempty"`
	HintSource   string `json:"hint_source"`
	ExpiresAtUTC string `json:"expires_at_utc,omitempty"`
}

type gpmBootstrapBridgeHint struct {
	BridgeID       string `json:"bridge_id"`
	OperatorID     string `json:"operator_id,omitempty"`
	Endpoint       string `json:"endpoint"`
	Transport      string `json:"transport"`
	TicketRequired bool   `json:"ticket_required"`
	RateLimitClass string `json:"rate_limit_class,omitempty"`
	ExpiresAtUTC   string `json:"expires_at_utc,omitempty"`
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

type gpmGapScanSummaryFile struct {
	Schema struct {
		ID string `json:"id"`
	} `json:"schema"`
	GeneratedAtUTC string                  `json:"generated_at_utc"`
	Status         string                  `json:"status"`
	Counts         gpmGapSummaryCounts     `json:"counts"`
	Items          []gpmGapScanSummaryItem `json:"items"`
}

type gpmGapSummaryCounts struct {
	InProgress  int `json:"in_progress"`
	MissingNext int `json:"missing_next"`
	Total       int `json:"total"`
}

type gpmGapScanSummaryItem struct {
	ID             string `json:"id"`
	Section        string `json:"section"`
	Ordinal        int    `json:"ordinal"`
	Text           string `json:"text"`
	NormalizedText string `json:"normalized_text,omitempty"`
}

type gpmGapSummarySnapshot struct {
	SchemaID       string
	GeneratedAtUTC string
	Counts         gpmGapSummaryCounts
	InProgress     []gpmGapScanSummaryItem
	MissingNext    []gpmGapScanSummaryItem
}

type gpmAuthChallengeRequest struct {
	WalletAddress  string `json:"wallet_address"`
	WalletProvider string `json:"wallet_provider"`
	ChainID        string `json:"chain_id,omitempty"`
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

type gpmContributionToggleRequest struct {
	SessionToken string `json:"session_token,omitempty"`
	Role         string `json:"role,omitempty"`
}

type gpmSettlementReserveFundsRequest struct {
	SessionToken   string `json:"session_token,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	UsageSessionID string `json:"usage_session_id,omitempty"`
	VPNSessionID   string `json:"vpn_session_id,omitempty"`
	ReservationID  string `json:"reservation_id,omitempty"`
	AmountMicros   int64  `json:"amount_micros"`
	Currency       string `json:"currency,omitempty"`
}

type gpmFundReservationFinalityResult struct {
	Allowed    bool
	Status     settlement.OperationStatus
	State      string
	Source     string
	Error      string
	HTTPStatus int
}

type gpmAdminContributionListRequest struct {
	SessionToken  string `json:"session_token"`
	WalletAddress string `json:"wallet_address,omitempty"`
	Role          string `json:"role,omitempty"`
	Status        string `json:"status,omitempty"`
	Limit         *int   `json:"limit,omitempty"`
}

type gpmAdminRewardReviewRequest struct {
	SessionToken  string `json:"session_token"`
	WalletAddress string `json:"wallet_address"`
	WeekStartUTC  string `json:"week_start_utc,omitempty"`
}

type gpmAdminRewardHoldRequest struct {
	SessionToken  string `json:"session_token"`
	WalletAddress string `json:"wallet_address"`
	WeekStartUTC  string `json:"week_start_utc,omitempty"`
	Action        string `json:"action,omitempty"`
	Source        string `json:"source,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type gpmAdminRewardFinalizeRequest struct {
	SessionToken  string `json:"session_token"`
	WalletAddress string `json:"wallet_address"`
	WeekStartUTC  string `json:"week_start_utc"`
}

func newGPMRuntimeState() *gpmRuntimeState {
	return &gpmRuntimeState{
		challenges:        map[string]gpmWalletChallenge{},
		sessions:          map[string]gpmSession{},
		operators:         map[string]gpmOperatorApplication{},
		contributions:     map[string]gpmContributionState{},
		rewardHistory:     map[string][]gpmWeeklyRewardSummary{},
		rewardHolds:       map[string][]gpmRewardHold{},
		reservationClaims: map[string]gpmReservationClaim{},
	}
}

func (st *gpmRuntimeState) putChallenge(challenge gpmWalletChallenge, now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.challenges == nil {
		st.challenges = map[string]gpmWalletChallenge{}
	}
	st.pruneExpiredChallengesLocked(now)
	if gpmChallengeMaxEntries > 0 && len(st.challenges) >= gpmChallengeMaxEntries {
		return false
	}
	wallet := normalizeWalletAddress(challenge.WalletAddress)
	if wallet != "" && gpmChallengeMaxEntriesPerWallet > 0 {
		walletChallenges := 0
		for _, existing := range st.challenges {
			if normalizeWalletAddress(existing.WalletAddress) == wallet {
				walletChallenges++
			}
		}
		if walletChallenges >= gpmChallengeMaxEntriesPerWallet {
			return false
		}
		challenge.WalletAddress = wallet
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

func (st *gpmRuntimeState) putSession(session gpmSession) bool {
	token := strings.TrimSpace(session.Token)
	if token == "" {
		return false
	}
	session.Token = token
	session.WalletAddress = normalizeWalletAddress(session.WalletAddress)
	now := time.Now().UTC()
	if !session.ExpiresAt.IsZero() && now.After(session.ExpiresAt) {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sessions == nil {
		st.sessions = map[string]gpmSession{}
	}
	st.pruneExpiredSessionsLocked(now)
	if _, exists := st.sessions[session.Token]; !exists {
		if gpmSessionMaxEntries > 0 && len(st.sessions) >= gpmSessionMaxEntries {
			return false
		}
		if session.WalletAddress != "" && gpmSessionMaxEntriesPerWallet > 0 && st.sessionCountForWalletLocked(session.WalletAddress) >= gpmSessionMaxEntriesPerWallet {
			return false
		}
	}
	st.sessions[session.Token] = session
	return true
}

func (st *gpmRuntimeState) pruneExpiredSessionsLocked(now time.Time) {
	for token, session := range st.sessions {
		if now.After(session.ExpiresAt) {
			delete(st.sessions, token)
		}
	}
}

func (st *gpmRuntimeState) sessionCountForWalletLocked(wallet string) int {
	count := 0
	for _, session := range st.sessions {
		if normalizeWalletAddress(session.WalletAddress) == wallet {
			count++
		}
	}
	return count
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
	if st.sessions == nil {
		st.sessions = map[string]gpmSession{}
	}
	delete(st.sessions, oldToken)
	session.Token = strings.TrimSpace(session.Token)
	session.WalletAddress = normalizeWalletAddress(session.WalletAddress)
	if session.Token == "" {
		return
	}
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

func (st *gpmRuntimeState) upsertOperator(app gpmOperatorApplication) bool {
	wallet := normalizeWalletAddress(app.WalletAddress)
	if wallet == "" {
		return false
	}
	app.WalletAddress = wallet
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.operators == nil {
		st.operators = map[string]gpmOperatorApplication{}
	}
	if _, exists := st.operators[wallet]; !exists && gpmOperatorApplicationMaxEntries > 0 && len(st.operators) >= gpmOperatorApplicationMaxEntries {
		return false
	}
	st.operators[wallet] = app
	return true
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

func (st *gpmRuntimeState) getContribution(walletAddress string) (gpmContributionState, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	state, ok := st.contributions[normalizeWalletAddress(walletAddress)]
	return state, ok
}

func (st *gpmRuntimeState) upsertContribution(state gpmContributionState) bool {
	wallet := normalizeWalletAddress(state.WalletAddress)
	if wallet == "" {
		return false
	}
	state.WalletAddress = wallet
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.contributions == nil {
		st.contributions = map[string]gpmContributionState{}
	}
	if _, exists := st.contributions[wallet]; !exists && gpmContributionMaxEntries > 0 && len(st.contributions) >= gpmContributionMaxEntries {
		return false
	}
	st.contributions[wallet] = state
	return true
}

func (st *gpmRuntimeState) listContributions() []gpmContributionState {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]gpmContributionState, 0, len(st.contributions))
	for _, state := range st.contributions {
		out = append(out, state)
	}
	return out
}

func (st *gpmRuntimeState) claimReservationForConnect(reservationID string, reservationSessionID string, walletAddress string, now time.Time) (gpmReservationClaim, bool, string) {
	reservationID = strings.TrimSpace(reservationID)
	reservationSessionID = strings.TrimSpace(reservationSessionID)
	wallet := normalizeWalletAddress(walletAddress)
	if reservationID == "" || reservationSessionID == "" || wallet == "" {
		return gpmReservationClaim{}, false, "reservation_id, reservation_session_id, and wallet_address are required"
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reservationClaims == nil {
		st.reservationClaims = map[string]gpmReservationClaim{}
	}
	st.pruneStaleReservationClaimsLocked(now)
	if existing, ok := st.reservationClaims[reservationID]; ok {
		existing.Status = strings.TrimSpace(existing.Status)
		if existing.Status == "" {
			existing.Status = "launched"
		}
		existingWalletMatches := normalizeWalletAddress(existing.WalletAddress) == wallet
		existingSessionMatches := strings.TrimSpace(existing.ReservationSessionID) == reservationSessionID
		if existing.Status == "pending_launch" && !existing.ClaimedAt.IsZero() && now.Sub(existing.ClaimedAt) > gpmReservationPendingClaimTTL {
			delete(st.reservationClaims, reservationID)
		} else if existing.Status == "launching" && existingWalletMatches && existingSessionMatches {
			return existing, false, "reservation connect launch has already started"
		} else if existing.Status == "pending_launch" && existing.ClaimedAt.IsZero() {
			existing.Status = "launched"
			st.reservationClaims[reservationID] = existing
			return existing, false, "reservation_id has already been used for production VPN connect"
		} else if !existingWalletMatches || !existingSessionMatches {
			return existing, false, "reservation_id is already claimed by another wallet or session"
		} else if existing.Status == "pending_launch" {
			return existing, false, "reservation connect launch is already in progress"
		} else {
			return existing, false, "reservation_id has already been used for production VPN connect"
		}
	}
	if gpmReservationClaimMaxEntries > 0 && len(st.reservationClaims) >= gpmReservationClaimMaxEntries {
		return gpmReservationClaim{}, false, "reservation claim store saturated; retry later"
	}
	claim := gpmReservationClaim{
		ReservationID:        reservationID,
		ReservationSessionID: reservationSessionID,
		WalletAddress:        wallet,
		Status:               "pending_launch",
		ClaimedAt:            now,
	}
	st.reservationClaims[reservationID] = claim
	return claim, true, ""
}

func (st *gpmRuntimeState) pruneStaleReservationClaimsLocked(now time.Time) {
	for reservationID, claim := range st.reservationClaims {
		status := strings.TrimSpace(claim.Status)
		switch {
		case status == "pending_launch" && !claim.ClaimedAt.IsZero() && now.Sub(claim.ClaimedAt) > gpmReservationPendingClaimTTL:
			delete(st.reservationClaims, reservationID)
		case status == "launching" && gpmReservationClaimIsStaleLaunching(claim, now):
			delete(st.reservationClaims, reservationID)
		}
	}
}

func gpmReservationClaimLaunchReferenceTime(claim gpmReservationClaim) time.Time {
	if !claim.LaunchStartedAt.IsZero() {
		return claim.LaunchStartedAt
	}
	return claim.ClaimedAt
}

func gpmReservationClaimIsStaleLaunching(claim gpmReservationClaim, now time.Time) bool {
	if strings.TrimSpace(claim.Status) != "launching" {
		return false
	}
	startedAt := gpmReservationClaimLaunchReferenceTime(claim)
	if startedAt.IsZero() {
		return false
	}
	return now.Sub(startedAt) > gpmReservationLaunchClaimTTL
}

func (st *gpmRuntimeState) staleLaunchingReservationClaim(reservationID string, reservationSessionID string, walletAddress string, now time.Time) (gpmReservationClaim, bool) {
	reservationID = strings.TrimSpace(reservationID)
	reservationSessionID = strings.TrimSpace(reservationSessionID)
	wallet := normalizeWalletAddress(walletAddress)
	if reservationID == "" || reservationSessionID == "" || wallet == "" {
		return gpmReservationClaim{}, false
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	claim, ok := st.reservationClaims[reservationID]
	if !ok {
		return gpmReservationClaim{}, false
	}
	if normalizeWalletAddress(claim.WalletAddress) != wallet || strings.TrimSpace(claim.ReservationSessionID) != reservationSessionID {
		return gpmReservationClaim{}, false
	}
	if !gpmReservationClaimIsStaleLaunching(claim, now) {
		return gpmReservationClaim{}, false
	}
	return claim, true
}

func (st *gpmRuntimeState) markReservationConnectLaunchStarted(reservationID string, reservationSessionID string, walletAddress string, now time.Time) bool {
	reservationID = strings.TrimSpace(reservationID)
	reservationSessionID = strings.TrimSpace(reservationSessionID)
	wallet := normalizeWalletAddress(walletAddress)
	st.mu.Lock()
	defer st.mu.Unlock()
	claim, ok := st.reservationClaims[reservationID]
	if !ok {
		return false
	}
	if normalizeWalletAddress(claim.WalletAddress) != wallet || strings.TrimSpace(claim.ReservationSessionID) != reservationSessionID {
		return false
	}
	status := strings.TrimSpace(claim.Status)
	if status != "pending_launch" && status != "launching" {
		return false
	}
	claim.WalletAddress = wallet
	claim.ReservationSessionID = reservationSessionID
	claim.Status = "launching"
	if claim.LaunchStartedAt.IsZero() {
		claim.LaunchStartedAt = now
	}
	st.reservationClaims[reservationID] = claim
	return true
}

func (st *gpmRuntimeState) markReservationConnectLaunched(reservationID string, reservationSessionID string, walletAddress string, now time.Time) bool {
	reservationID = strings.TrimSpace(reservationID)
	reservationSessionID = strings.TrimSpace(reservationSessionID)
	wallet := normalizeWalletAddress(walletAddress)
	st.mu.Lock()
	defer st.mu.Unlock()
	claim, ok := st.reservationClaims[reservationID]
	if !ok {
		return false
	}
	if normalizeWalletAddress(claim.WalletAddress) != wallet || strings.TrimSpace(claim.ReservationSessionID) != reservationSessionID {
		return false
	}
	status := strings.TrimSpace(claim.Status)
	if status != "pending_launch" && status != "launching" && status != "launched" {
		return false
	}
	claim.WalletAddress = wallet
	claim.ReservationSessionID = reservationSessionID
	claim.Status = "launched"
	claim.LaunchedAt = now
	st.reservationClaims[reservationID] = claim
	return true
}

func (st *gpmRuntimeState) launchedReservationClaimWalletAllowed(walletAddress string) (bool, bool) {
	wallet := normalizeWalletAddress(walletAddress)
	if wallet == "" {
		return false, false
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	hasLaunched := false
	for _, claim := range st.reservationClaims {
		if strings.TrimSpace(claim.Status) != "launched" {
			continue
		}
		hasLaunched = true
		if normalizeWalletAddress(claim.WalletAddress) == wallet {
			return true, true
		}
	}
	return !hasLaunched, hasLaunched
}

func (st *gpmRuntimeState) releasePendingReservationClaim(reservationID string, reservationSessionID string, walletAddress string) bool {
	reservationID = strings.TrimSpace(reservationID)
	reservationSessionID = strings.TrimSpace(reservationSessionID)
	wallet := normalizeWalletAddress(walletAddress)
	st.mu.Lock()
	defer st.mu.Unlock()
	claim, ok := st.reservationClaims[reservationID]
	status := strings.TrimSpace(claim.Status)
	if !ok || (status != "pending_launch" && status != "launching") {
		return false
	}
	if normalizeWalletAddress(claim.WalletAddress) != wallet || strings.TrimSpace(claim.ReservationSessionID) != reservationSessionID {
		return false
	}
	delete(st.reservationClaims, reservationID)
	return true
}

func (st *gpmRuntimeState) appendRewardHistory(walletAddress string, summary gpmWeeklyRewardSummary) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rewardHistory == nil {
		st.rewardHistory = map[string][]gpmWeeklyRewardSummary{}
	}
	wallet := normalizeWalletAddress(walletAddress)
	history := append(st.rewardHistory[wallet], summary)
	if len(history) > 52 {
		history = history[len(history)-52:]
	}
	st.rewardHistory[wallet] = history
}

func (st *gpmRuntimeState) upsertRewardHistory(walletAddress string, summary gpmWeeklyRewardSummary) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rewardHistory == nil {
		st.rewardHistory = map[string][]gpmWeeklyRewardSummary{}
	}
	wallet := normalizeWalletAddress(walletAddress)
	if wallet == "" {
		wallet = normalizeWalletAddress(summary.WalletAddress)
	}
	if wallet == "" {
		return
	}
	summary.WalletAddress = wallet
	weekStart := strings.TrimSpace(summary.WeekStartUTC)
	history := st.rewardHistory[wallet]
	for i := range history {
		if strings.TrimSpace(history[i].WeekStartUTC) == weekStart {
			history[i] = summary
			st.rewardHistory[wallet] = history
			return
		}
	}
	history = append(history, summary)
	if len(history) > 52 {
		history = history[len(history)-52:]
	}
	st.rewardHistory[wallet] = history
}

func (st *gpmRuntimeState) rewardHistoryFor(walletAddress string) []gpmWeeklyRewardSummary {
	st.mu.RLock()
	defer st.mu.RUnlock()
	wallet := normalizeWalletAddress(walletAddress)
	history := append([]gpmWeeklyRewardSummary{}, st.rewardHistory[wallet]...)
	slices.Reverse(history)
	return history
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
	if session.WalletBindingVerified && walletAddress != "" {
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
	approvedChainOperatorID := strings.TrimSpace(chainOperatorID)

	st.mu.Lock()
	defer st.mu.Unlock()
	changed := false
	for token, session := range st.sessions {
		if normalizeWalletAddress(session.WalletAddress) != normalizedWalletAddress {
			continue
		}
		nextRole := "client"
		nextChainOperatorID := ""
		if approved && session.WalletBindingVerified {
			nextRole = "operator"
			nextChainOperatorID = approvedChainOperatorID
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
	session, ok, _ := s.getGPMSessionWithWalletPolicy(token, now)
	return session, ok
}

func (s *Service) getGPMSessionWithWalletPolicy(token string, now time.Time) (gpmSession, bool, error) {
	if s == nil || s.gpmState == nil {
		return gpmSession{}, false, nil
	}
	session, ok := s.gpmState.getSession(token, now)
	if !ok {
		return gpmSession{}, false, nil
	}
	if err := s.validateGPMSessionWalletPolicy(session); err != nil {
		return gpmSession{}, false, err
	}
	return session, true, nil
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
	token := gpmSessionTokenFromRequest(r, in.SessionToken)
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
	session, ok, policyErr := s.getGPMSessionWithWalletPolicy(token, time.Now().UTC())
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return false
	}
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
	if !session.WalletBindingVerified {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "wallet-bound session is required for operator/admin lifecycle actions",
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
		if lockReason := s.gpmProductionOperatorApprovalEvidenceLock(app); lockReason != "" {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":    false,
				"error": lockReason,
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
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(sessionToken)
	if policyErr != nil {
		return nil, "", "", fmt.Errorf("%w: %v", errConnectSessionWalletPolicyInvalid, policyErr)
	}
	if !ok {
		return nil, "", "", errConnectSessionTokenInvalidOrExpired
	}
	if !session.WalletBindingVerified || normalizeWalletAddress(session.WalletAddress) == "" {
		return nil, "", "", errConnectSessionWalletBindingRequired
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
	in.ChainID = strings.TrimSpace(in.ChainID)
	if in.WalletAddress == "" || in.WalletProvider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "wallet_address and wallet_provider are required (wallet_provider: keplr|leap)",
		})
		return
	}
	chainID, err := s.gpmAuthChallengeChainID(in.ChainID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.validateGPMAuthWalletHRP(in.WalletAddress); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	challengeID, err := randomHex(24)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to create challenge"})
		return
	}
	now := time.Now().UTC()
	expires := now.Add(gpmChallengeTTL)
	message := "Global Private Mesh authentication challenge: " + challengeID
	if chainID != "" {
		message += "\nchain_id: " + chainID
	}
	challenge := gpmWalletChallenge{
		ChallengeID:    "gpm-chal-" + challengeID,
		WalletAddress:  in.WalletAddress,
		WalletProvider: in.WalletProvider,
		ChainID:        chainID,
		Message:        message,
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
		"chain_id":        challenge.ChainID,
		"challenge_id":    challenge.ChallengeID,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"challenge_id":    challenge.ChallengeID,
		"message":         challenge.Message,
		"chain_id":        challenge.ChainID,
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
		signatureMetadata.SignaturePublicKeyType = normalizeGPMAuthSignaturePublicKeyType(canonicalPublicKeyType)
		signatureMetadata.HasSignaturePublicKeyType = true
	case legacyPublicKeyType != "":
		signatureMetadata.SignaturePublicKeyType = normalizeGPMAuthSignaturePublicKeyType(legacyPublicKeyType)
		signatureMetadata.HasSignaturePublicKeyType = true
	case in.SignaturePublicKeyType != nil:
		signatureMetadata.SignaturePublicKeyType = normalizeGPMAuthSignaturePublicKeyType(canonicalPublicKeyType)
		signatureMetadata.HasSignaturePublicKeyType = true
	case in.PublicKeyType != nil:
		signatureMetadata.SignaturePublicKeyType = normalizeGPMAuthSignaturePublicKeyType(legacyPublicKeyType)
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
	if err := s.validateGPMAuthWalletHRP(in.WalletAddress); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	sessionChainID, err := s.validateGPMAuthVerifyChainID(challenge, in.ChainID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	signatureMetadata.ChainID = sessionChainID
	walletBindingVerified, err := s.verifyGPMAuthSignature(r.Context(), challenge, in.WalletAddress, in.WalletProvider, signature, signatureMetadata)
	if err != nil {
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
		Token:                   token,
		WalletAddress:           challenge.WalletAddress,
		WalletProvider:          challenge.WalletProvider,
		ChainID:                 sessionChainID,
		Role:                    "client",
		WalletBindingVerified:   walletBindingVerified,
		AuthVerificationSource:  gpmAuthVerificationSource(walletBindingVerified, s.gpmAuthVerifyCommand),
		AuthPolicyFingerprint:   s.gpmCurrentAuthPolicyFingerprint(),
		ClientTier:              1,
		StakeSatisfied:          false,
		PrepaidBalanceSatisfied: false,
		CreatedAt:               now,
		ExpiresAt:               now.Add(gpmSessionTTL),
	}
	if walletBindingVerified {
		session.Role = s.gpmRoleDefault
		session.EntitlementEvidenceSource = "local_env"
		session.ClientTier = envIntDefault([]string{"GPM_CLIENT_TIER", "GPM_DEFAULT_CLIENT_TIER", "TDPN_CLIENT_TIER", "TDPN_DEFAULT_CLIENT_TIER"}, 1)
		session.StakeSatisfied = envBoolDefault([]string{"GPM_STAKE_SATISFIED", "GPM_DEFAULT_STAKE_SATISFIED", "TDPN_STAKE_SATISFIED", "TDPN_DEFAULT_STAKE_SATISFIED"}, false)
		session.PrepaidBalanceSatisfied = envBoolDefault([]string{"GPM_PREPAID_BALANCE_SATISFIED", "GPM_DEFAULT_PREPAID_BALANCE_SATISFIED", "TDPN_PREPAID_BALANCE_SATISFIED", "TDPN_DEFAULT_PREPAID_BALANCE_SATISFIED"}, false)
		if s.gpmAdminWalletAllowed(challenge.WalletAddress) && s.gpmAdminSessionVerificationAllowed(session) {
			session.Role = "admin"
		} else if app, ok := s.gpmState.getOperator(challenge.WalletAddress); ok && app.Status == "approved" {
			session.Role = "operator"
			session.ChainOperatorID = app.ChainOperatorID
		}
	}
	if !s.gpmState.putSession(session) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "session store is temporarily saturated; revoke an existing session or retry later",
		})
		return
	}
	s.persistGPMStateBestEffort("auth_verify")
	s.appendGPMAudit("auth_verified", map[string]any{
		"wallet_address":           session.WalletAddress,
		"wallet_provider":          session.WalletProvider,
		"role":                     session.Role,
		"wallet_binding_verified":  session.WalletBindingVerified,
		"entitlements_fail_closed": !session.WalletBindingVerified,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                      true,
		"session_token":           session.Token,
		"wallet_binding_verified": session.WalletBindingVerified,
		"session":                 serializeGPMSession(session),
	})
}

func (s *Service) handleGPMSessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
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
	if action != "status" && !s.requireMutationAuth(w, r) {
		return
	}
	token := gpmSessionTokenFromRequest(r, in.SessionToken)
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token is required"})
		return
	}
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(token)
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return
	}
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
		if s.isGPMProductionMode() || strings.EqualFold(strings.TrimSpace(s.gpmConnectPolicyMode), "production") {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":     false,
				"action": "refresh",
				"error":  "production session refresh requires a fresh wallet challenge; sign in again",
			})
			return
		}
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
		refreshed.AuthPolicyFingerprint = s.gpmCurrentAuthPolicyFingerprint()
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
	adminSession, ok := s.gpmAdminSessionFromHeaderForResponse(w, r)
	if !ok {
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
		"ok":                        true,
		"admin_api_surface":         "gpm_admin_console",
		"admin_wallet_address":      adminSession.WalletAddress,
		"public_app_admin_controls": false,
		"total":                     result.Total,
		"count":                     count,
		"limit":                     limit,
		"offset":                    offset,
		"has_more":                  hasMore,
		"next_offset":               nextOffset,
		"filters": map[string]any{
			"event":          eventFilter,
			"wallet_address": walletFilter,
			"order":          orderFilter,
		},
		"entries": result.Entries,
	})
}

func (s *Service) handleGPMGapSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	if _, ok := s.gpmAdminSessionFromHeaderForResponse(w, r); !ok {
		return
	}

	summary, artifactPath, err := s.readGPMGapSummarySnapshot()
	if err != nil {
		statusCode := http.StatusInternalServerError
		status := "artifact_unreadable"
		switch {
		case errors.Is(err, errGPMGapSummaryArtifactMissing):
			statusCode = http.StatusServiceUnavailable
			status = "artifact_missing"
		case errors.Is(err, errGPMGapSummaryArtifactMalformed):
			status = "artifact_malformed"
		case errors.Is(err, errGPMGapSummaryArtifactUnreadable):
			status = "artifact_unreadable"
		}
		writeJSON(w, statusCode, map[string]any{
			"ok":            false,
			"status":        status,
			"artifact_path": strings.TrimSpace(artifactPath),
			"error":         err.Error(),
		})
		return
	}

	keyGaps := make([]string, 0, len(summary.MissingNext))
	nextActions := make([]string, 0, len(summary.MissingNext))
	for _, item := range summary.MissingNext {
		keyGaps = append(keyGaps, item.Text)
		nextActions = append(nextActions, item.Text)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"status":           "ok",
		"artifact_path":    strings.TrimSpace(artifactPath),
		"schema_id":        summary.SchemaID,
		"generated_at_utc": summary.GeneratedAtUTC,
		"counts": map[string]any{
			"in_progress":  summary.Counts.InProgress,
			"missing_next": summary.Counts.MissingNext,
			"total":        summary.Counts.Total,
		},
		"in_progress":  summary.InProgress,
		"missing_next": summary.MissingNext,
		"key_gaps":     keyGaps,
		"next_actions": nextActions,
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
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(in.SessionToken)
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	if !session.WalletBindingVerified || normalizeWalletAddress(session.WalletAddress) == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wallet-bound session is required for client registration"})
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
	canonicalBootstrapDirectory, err := canonicalizeBootstrapDirectoryURL(bootstrapDirectory)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	bootstrapDirectory = canonicalBootstrapDirectory
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
	if lockReason := gpmMicroRelayUseLock(session, pathProfile); lockReason != "" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":                       false,
			"error":                    lockReason,
			"path_profile":             pathProfile,
			"can_use_micro_relays":     false,
			"contribution_lock_reason": lockReason,
		})
		return
	}
	session.BootstrapDirectory = bootstrapDirectory
	session.BootstrapDirectories = normalizeBootstrapDirectories(manifest.BootstrapDirectories)
	session.InviteKey = inviteKey
	session.PathProfile = pathProfile
	if !s.gpmState.putSession(session) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "session store is temporarily saturated; sign in again or retry later",
		})
		return
	}
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
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(sessionToken)
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return
	}
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

func (s *Service) handleGPMContributionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	session, ok, policyErr := s.gpmSessionFromRequestOrBearer(r)
	if policyErr != nil {
		writeGPMSessionWalletPolicyError(w, policyErr)
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "valid session_token is required"})
		return
	}
	status := s.gpmContributionStatusForSession(session, time.Now().UTC())
	writeJSON(w, http.StatusOK, status)
}

func (s *Service) handleGPMContributionEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmContributionToggleRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	session, ok, policyErr := s.gpmSessionFromTokenOrBearer(r, in.SessionToken)
	if policyErr != nil {
		writeGPMSessionWalletPolicyError(w, policyErr)
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "valid session_token is required"})
		return
	}
	if !session.WalletBindingVerified || normalizeWalletAddress(session.WalletAddress) == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wallet-bound session is required for contribution enable"})
		return
	}
	role := normalizeGPMContributionRole(in.Role)
	if role == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "role must be one of: micro-relay, micro-exit"})
		return
	}
	status := s.gpmContributionStatusForSessionWithRequestedRole(session, role, time.Now().UTC())
	if eligible, _ := status["can_enable_requested_role"].(bool); !eligible {
		lockReason, _ := status["contribution_lock_reason"].(string)
		if strings.TrimSpace(lockReason) == "" {
			lockReason = "contribution role is not eligible for this session"
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":     false,
			"error":  lockReason,
			"status": status,
		})
		return
	}

	now := time.Now().UTC()
	existing, hadExisting := s.gpmState.getContribution(session.WalletAddress)
	state := gpmContributionStateFromStatus(status, session, role, now)
	state.Enabled = true
	state.Role = role
	state.RequestedRole = role
	state.ExplicitOptIn = true
	state.DemotionState = "none"
	state.LockReason = ""
	currentWeekStart := gpmWeekStartUTC(now).Format(time.RFC3339)
	if hadExisting && strings.TrimSpace(existing.MeteredWeekStartUTC) == currentWeekStart {
		existingRole := gpmContributionRoleForState(existing)
		preserveExistingMetering := existingRole == role &&
			!strings.EqualFold(strings.TrimSpace(existing.DemotionState), "auto_demoted") &&
			strings.TrimSpace(existing.LockReason) == ""
		if preserveExistingMetering {
			state.MeteredWeekStartUTC = existing.MeteredWeekStartUTC
			state.MeteredSeconds = existing.MeteredSeconds
			state.ValidBytes = existing.ValidBytes
			state.PendingRewardUnits = existing.PendingRewardUnits
		} else if existingRole != role {
			if gpmContributionHasMetering(existing) {
				writeJSON(w, http.StatusConflict, map[string]any{
					"ok":    false,
					"error": "contribution role switch is locked until the next weekly epoch after metered contribution exists",
				})
				return
			}
			state.MeteredWeekStartUTC = currentWeekStart
			state.MeteredSeconds = 0
			state.ValidBytes = 0
			state.PendingRewardUnits = 0
		} else {
			state.MeteredWeekStartUTC = currentWeekStart
			state.MeteredSeconds = 0
			state.ValidBytes = 0
			state.PendingRewardUnits = 0
		}
	} else if strings.TrimSpace(state.MeteredWeekStartUTC) == "" {
		state.MeteredWeekStartUTC = currentWeekStart
	} else if !hadExisting {
		state.MeteredWeekStartUTC = currentWeekStart
		state.MeteredSeconds = 0
		state.ValidBytes = 0
		state.PendingRewardUnits = 0
	}
	// Restart metering from opt-in time so disabled time is never counted.
	state.LastMeteredAt = now
	state.UpdatedAt = now
	if !s.gpmState.upsertContribution(state) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "contribution store is temporarily saturated; retry later",
		})
		return
	}
	s.persistGPMStateBestEffort("contribution_enable")
	s.appendGPMAudit("contribution_enabled", map[string]any{
		"wallet_address": session.WalletAddress,
		"role":           role,
		"client_tier":    state.ClientTier,
	})
	writeJSON(w, http.StatusOK, s.gpmContributionStatusForSessionWithRequestedRole(session, role, now))
}

func (s *Service) handleGPMContributionDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmContributionToggleRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	session, ok, policyErr := s.gpmSessionFromTokenOrBearer(r, in.SessionToken)
	if policyErr != nil {
		writeGPMSessionWalletPolicyError(w, policyErr)
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "valid session_token is required"})
		return
	}
	if !session.WalletBindingVerified || normalizeWalletAddress(session.WalletAddress) == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wallet-bound session is required for contribution disable"})
		return
	}
	now := time.Now().UTC()
	_ = s.gpmContributionStatusForSession(session, now)
	state, _ := s.refreshGPMContributionMeter(session.WalletAddress, now)
	if strings.TrimSpace(state.WalletAddress) == "" {
		state = gpmContributionStateFromStatus(s.gpmContributionStatusForSession(session, now), session, "micro-relay", now)
	}
	state.Enabled = false
	state.Role = firstNonEmpty(normalizeGPMContributionRole(state.Role), normalizeGPMContributionRole(state.RequestedRole), "micro-relay")
	state.ExplicitOptIn = false
	state.DemotionState = "disabled_by_user"
	state.UpdatedAt = now
	if !s.gpmState.upsertContribution(state) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "contribution store is temporarily saturated; retry later",
		})
		return
	}
	s.persistGPMStateBestEffort("contribution_disable")
	s.appendGPMAudit("contribution_disabled", map[string]any{
		"wallet_address": session.WalletAddress,
		"role":           state.RequestedRole,
	})
	writeJSON(w, http.StatusOK, s.gpmContributionStatusForSession(session, now))
}

func (s *Service) handleGPMSettlementReserveFunds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmSettlementReserveFundsRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	session, ok, policyErr := s.gpmSessionFromTokenOrBearer(r, in.SessionToken)
	if policyErr != nil {
		writeGPMSessionWalletPolicyError(w, policyErr)
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "valid session_token is required"})
		return
	}
	walletAddress := normalizeWalletAddress(session.WalletAddress)
	if !session.WalletBindingVerified || walletAddress == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wallet-bound session is required for settlement reservation"})
		return
	}
	if lockReason := s.gpmProductionEntitlementEvidenceLock(session); lockReason != "" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":                           false,
			"error":                        lockReason,
			"wallet_address":               walletAddress,
			"reservation_allowed":          false,
			"subject_source":               "wallet_session",
			"entitlement_evidence_source":  strings.TrimSpace(session.EntitlementEvidenceSource),
			"entitlement_evidence_trusted": false,
			"public_app_admin_controls":    false,
		})
		return
	}
	if !gpmEffectiveStakeSatisfied(session) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "stake is required before reserving VPN funds"})
		return
	}
	if !gpmEffectivePrepaidSatisfied(session) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "prepaid balance is required before reserving VPN funds"})
		return
	}
	sessionID := strings.TrimSpace(firstNonEmpty(in.SessionID, in.UsageSessionID, in.VPNSessionID))
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_id is required"})
		return
	}
	if len(sessionID) > 256 || strings.IndexFunc(sessionID, unicode.IsControl) >= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_id is invalid"})
		return
	}
	reservationID := strings.TrimSpace(in.ReservationID)
	if len(reservationID) > 256 || strings.IndexFunc(reservationID, unicode.IsControl) >= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "reservation_id is invalid"})
		return
	}
	if in.AmountMicros <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "amount_micros must be > 0"})
		return
	}
	if in.AmountMicros != gpmPublicVPNReservationMicros {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":                        false,
			"error":                     fmt.Sprintf("amount_micros must equal the public VPN reservation amount %d", gpmPublicVPNReservationMicros),
			"expected_amount_micros":    gpmPublicVPNReservationMicros,
			"requested_amount_micros":   in.AmountMicros,
			"public_app_admin_controls": false,
		})
		return
	}
	currency := strings.TrimSpace(in.Currency)
	if currency == "" {
		currency = gpmPublicVPNReservationCurrency
	}
	if !strings.EqualFold(currency, gpmPublicVPNReservationCurrency) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":                        false,
			"error":                     fmt.Sprintf("currency must be %s for public VPN reservations", gpmPublicVPNReservationCurrency),
			"expected_currency":         gpmPublicVPNReservationCurrency,
			"requested_currency":        in.Currency,
			"public_app_admin_controls": false,
		})
		return
	}
	in.Currency = gpmPublicVPNReservationCurrency
	settlementStatus := s.gpmSettlementStatusTelemetry()
	if s.gpmSettlementRequiresChainBackedAdapter() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":                         false,
			"error":                      s.gpmSettlementChainRequiredError(),
			"wallet_address":             walletAddress,
			"session_id":                 sessionID,
			"settlement_status":          settlementStatus,
			"reservation_allowed":        false,
			"subject_source":             "wallet_session",
			"public_app_admin_controls":  false,
			"settlement_frequency":       "per_session_reservation",
			"weekly_epoch_start_weekday": "monday",
			"weekly_epoch_timezone":      "UTC",
		})
		return
	}
	requested := settlement.FundReservation{
		ReservationID: reservationID,
		SessionID:     sessionID,
		SubjectID:     walletAddress,
		AmountMicros:  in.AmountMicros,
		Currency:      in.Currency,
		CreatedAt:     time.Now().UTC(),
	}
	reservation, err := s.gpmSettlementService().ReserveFunds(r.Context(), requested)
	if err != nil {
		status := http.StatusBadRequest
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "idempotency conflict"),
			strings.Contains(errMsg, "session already settled"),
			strings.Contains(errMsg, "session subject mismatch"):
			status = http.StatusConflict
		case strings.Contains(errMsg, "chain billing reservation submitter"),
			strings.Contains(errMsg, "chain reservation submit failed"),
			strings.Contains(errMsg, "chain adapter not configured"):
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]any{
			"ok":                        false,
			"error":                     errMsg,
			"wallet_address":            walletAddress,
			"session_id":                sessionID,
			"settlement_status":         settlementStatus,
			"reservation_allowed":       false,
			"subject_source":            "wallet_session",
			"public_app_admin_controls": false,
		})
		return
	}
	finality := s.gpmFundReservationFinality(r.Context(), reservation)
	if finality.Status != "" {
		reservation.Status = finality.Status
	}
	if !finality.Allowed {
		if finality.HTTPStatus == 0 {
			finality.HTTPStatus = http.StatusServiceUnavailable
		}
		s.appendGPMAudit("settlement_funds_reservation_held", map[string]any{
			"wallet_address":                  walletAddress,
			"session_id":                      reservation.SessionID,
			"reservation_id":                  reservation.ReservationID,
			"amount_micros":                   reservation.AmountMicros,
			"currency":                        reservation.Currency,
			"status":                          string(finality.Status),
			"reservation_finalization_state":  finality.State,
			"reservation_status_source":       finality.Source,
			"idempotent_replay":               reservation.IdempotentReplay,
			"reservation_allowed":             false,
			"subject_source":                  "wallet_session",
			"settlement_surface":              "public_app",
			"public_app_admin_controls":       false,
			"settlement_finality_fail_closed": true,
		})
		writeJSON(w, finality.HTTPStatus, map[string]any{
			"ok":                             false,
			"error":                          finality.Error,
			"reservation":                    serializeGPMFundReservation(reservation),
			"idempotent_replay":              reservation.IdempotentReplay,
			"wallet_address":                 walletAddress,
			"subject_source":                 "wallet_session",
			"settlement_status":              settlementStatus,
			"reservation_allowed":            false,
			"reservation_chain_status":       string(finality.Status),
			"reservation_status_source":      finality.Source,
			"reservation_finalization_state": finality.State,
			"public_app_admin_controls":      false,
		})
		return
	}
	s.appendGPMAudit("settlement_funds_reserved", map[string]any{
		"wallet_address":     walletAddress,
		"session_id":         reservation.SessionID,
		"reservation_id":     reservation.ReservationID,
		"amount_micros":      reservation.AmountMicros,
		"currency":           reservation.Currency,
		"status":             string(reservation.Status),
		"idempotent_replay":  reservation.IdempotentReplay,
		"subject_source":     "wallet_session",
		"settlement_surface": "public_app",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                             true,
		"reservation":                    serializeGPMFundReservation(reservation),
		"idempotent_replay":              reservation.IdempotentReplay,
		"wallet_address":                 walletAddress,
		"subject_source":                 "wallet_session",
		"settlement_status":              settlementStatus,
		"reservation_allowed":            true,
		"reservation_chain_status":       string(finality.Status),
		"reservation_status_source":      finality.Source,
		"reservation_finalization_state": finality.State,
		"public_app_admin_controls":      false,
	})
}

func (s *Service) gpmFundReservationFinality(ctx context.Context, reservation settlement.FundReservation) gpmFundReservationFinalityResult {
	status := reservation.Status
	source := "settlement_service"
	if !s.gpmSettlementChainRequiredEffective() && !s.gpmSettlementChainBacked {
		return gpmFundReservationFinalityResult{
			Allowed: true,
			Status:  status,
			State:   "compatibility_memory",
			Source:  source,
		}
	}

	if querier, ok := s.gpmSettlementService().(settlement.ChainFundReservationStatusQuerier); ok && querier != nil {
		source = "chain_status_query"
		reservationID := strings.TrimSpace(reservation.ReservationID)
		if reservationID == "" {
			return gpmFundReservationFinalityResult{
				Allowed:    false,
				Status:     "",
				State:      "unknown_chain_status",
				Source:     source,
				Error:      "fund reservation chain status is unknown: reservation_id is empty",
				HTTPStatus: http.StatusServiceUnavailable,
			}
		}
		chainStatus, found, err := querier.FundReservationStatus(ctx, reservationID)
		if err != nil {
			return gpmFundReservationFinalityResult{
				Allowed:    false,
				Status:     "",
				State:      "unknown_chain_status",
				Source:     source,
				Error:      fmt.Sprintf("fund reservation chain status query failed: %v", err),
				HTTPStatus: http.StatusServiceUnavailable,
			}
		}
		if !found {
			status, allowed, state, errMsg, httpStatus := gpmFundReservationFinalityDecision(status)
			if httpStatus == http.StatusAccepted {
				return gpmFundReservationFinalityResult{
					Allowed:    allowed,
					Status:     status,
					State:      state,
					Source:     "settlement_service_pending_chain_status_query_miss",
					Error:      errMsg,
					HTTPStatus: httpStatus,
				}
			}
			return gpmFundReservationFinalityResult{
				Allowed:    false,
				Status:     "",
				State:      "unknown_chain_status",
				Source:     source,
				Error:      "fund reservation chain status is unknown",
				HTTPStatus: http.StatusServiceUnavailable,
			}
		}
		status = chainStatus
	}

	status, allowed, state, errMsg, httpStatus := gpmFundReservationFinalityDecision(status)
	return gpmFundReservationFinalityResult{
		Allowed:    allowed,
		Status:     status,
		State:      state,
		Source:     source,
		Error:      errMsg,
		HTTPStatus: httpStatus,
	}
}

func gpmFundReservationFinalityDecision(status settlement.OperationStatus) (settlement.OperationStatus, bool, string, string, int) {
	switch strings.ToLower(strings.TrimSpace(string(status))) {
	case "":
		return "", false, "unknown_chain_status", "fund reservation chain status is unknown", http.StatusServiceUnavailable
	case string(settlement.OperationStatusConfirmed):
		return settlement.OperationStatusConfirmed, true, "chain_confirmed", "", http.StatusOK
	case string(settlement.OperationStatusPending):
		return settlement.OperationStatusPending, false, "pending_chain_submission", "fund reservation is pending chain submission", http.StatusAccepted
	case string(settlement.OperationStatusSubmitted):
		return settlement.OperationStatusSubmitted, false, "pending_chain_confirmation", "fund reservation is pending chain confirmation", http.StatusAccepted
	case string(settlement.OperationStatusFailed), "rejected", "reject", "failure", "fail":
		return settlement.OperationStatusFailed, false, "chain_rejected", "fund reservation was rejected by chain", http.StatusConflict
	default:
		return status, false, "unknown_chain_status", "fund reservation chain status is unknown", http.StatusServiceUnavailable
	}
}

func (s *Service) handleGPMRewardsCurrentWeek(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	session, ok, policyErr := s.gpmSessionFromRequestOrBearer(r)
	if policyErr != nil {
		writeGPMSessionWalletPolicyError(w, policyErr)
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "valid session_token is required"})
		return
	}
	now := time.Now().UTC()
	_ = s.gpmContributionStatusForSession(session, now)
	state, _ := s.refreshGPMContributionMeter(session.WalletAddress, now)
	if strings.TrimSpace(state.WalletAddress) == "" {
		state = gpmContributionStateFromStatus(s.gpmContributionStatusForSession(session, now), session, "micro-relay", now)
	}
	summary := s.gpmWeeklyRewardFromContributionWithContext(r.Context(), state, now, "pending")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                            true,
		"settlement_frequency":          "weekly",
		"weekly_epoch_start_weekday":    "monday",
		"timezone":                      "UTC",
		"reward":                        summary,
		"contribution_profile":          serializeGPMContributionProfile(state),
		"payout_allowed":                summary.PayoutAllowed,
		"settlement_finalization_state": summary.SettlementFinalizationState,
	})
}

func (s *Service) handleGPMRewardsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	session, ok, policyErr := s.gpmSessionFromRequestOrBearer(r)
	if policyErr != nil {
		writeGPMSessionWalletPolicyError(w, policyErr)
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "valid session_token is required"})
		return
	}
	now := time.Now().UTC()
	_ = s.gpmContributionStatusForSession(session, now)
	_, _ = s.refreshGPMContributionMeter(session.WalletAddress, now)
	history := s.applyGPMRewardHoldsToHistoryWithContext(r.Context(), session.WalletAddress, s.gpmState.rewardHistoryFor(session.WalletAddress))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                   true,
		"settlement_frequency": "weekly",
		"rewards":              history,
		"count":                len(history),
	})
}

func (s *Service) handleGPMAdminContributionList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	var in gpmAdminContributionListRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	adminSession, ok := s.gpmAdminSessionFromTokenForResponse(w, in.SessionToken)
	if !ok {
		return
	}

	roleFilter := ""
	if strings.TrimSpace(in.Role) != "" {
		roleFilter = normalizeGPMContributionRole(in.Role)
	}
	if strings.TrimSpace(in.Role) != "" && roleFilter == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "role must be one of: micro-relay, micro-exit"})
		return
	}
	statusFilter := strings.ToLower(strings.TrimSpace(in.Status))
	switch statusFilter {
	case "", "all", "enabled", "disabled":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "status must be one of: all, enabled, disabled"})
		return
	}
	walletFilter := normalizeWalletAddress(in.WalletAddress)
	limit := 100
	if in.Limit != nil {
		limit = clampInt(*in.Limit, 1, 500)
	}

	contributions := s.gpmState.listContributions()
	slices.SortFunc(contributions, func(a, b gpmContributionState) int {
		return strings.Compare(normalizeWalletAddress(a.WalletAddress), normalizeWalletAddress(b.WalletAddress))
	})
	items := make([]map[string]any, 0, minInt(limit, len(contributions)))
	totalMatched := 0
	now := time.Now().UTC()
	for _, contribution := range contributions {
		state := contribution
		wallet := normalizeWalletAddress(state.WalletAddress)
		if refreshed, ok := s.refreshGPMContributionMeter(wallet, now); ok {
			state = refreshed
		}
		if walletFilter != "" && wallet != walletFilter {
			continue
		}
		effectiveRole := normalizeGPMContributionRole(firstNonEmpty(state.RequestedRole, state.Role))
		if roleFilter != "" && effectiveRole != roleFilter {
			continue
		}
		switch statusFilter {
		case "enabled":
			if !state.Enabled {
				continue
			}
		case "disabled":
			if state.Enabled {
				continue
			}
		}
		totalMatched++
		if len(items) >= limit {
			continue
		}
		reward := s.gpmWeeklyRewardFromContributionWithContext(r.Context(), state, now, "pending")
		items = append(items, map[string]any{
			"wallet_address":            wallet,
			"enabled":                   state.Enabled,
			"role":                      normalizeGPMContributionRole(state.Role),
			"requested_role":            normalizeGPMContributionRole(state.RequestedRole),
			"client_tier":               state.ClientTier,
			"stake_satisfied":           state.StakeSatisfied,
			"prepaid_balance_satisfied": state.PrepaidBalanceSatisfied,
			"capacity_score":            state.CapacityScore,
			"health_score":              state.HealthScore,
			"max_forwarded_sessions":    state.MaxForwardedSessions,
			"max_bandwidth_mbps":        state.MaxBandwidthMbps,
			"demotion_state":            firstNonEmpty(state.DemotionState, "none"),
			"lock_reason":               strings.TrimSpace(state.LockReason),
			"current_week_reward":       reward,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                         true,
		"admin_api_surface":          "gpm_admin_console",
		"admin_wallet_address":       adminSession.WalletAddress,
		"public_app_admin_controls":  false,
		"settlement_frequency":       "weekly",
		"weekly_epoch_start_weekday": "monday",
		"weekly_epoch_timezone":      "UTC",
		"items":                      items,
		"count":                      len(items),
		"total_matched":              totalMatched,
		"limit":                      limit,
		"request": map[string]any{
			"wallet_address": walletFilter,
			"role":           roleFilter,
			"status":         firstNonEmpty(statusFilter, "all"),
		},
	})
}

func (s *Service) handleGPMAdminRewardReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	var in gpmAdminRewardReviewRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	adminSession, ok := s.gpmAdminSessionFromTokenForResponse(w, in.SessionToken)
	if !ok {
		return
	}
	walletAddress := normalizeWalletAddress(in.WalletAddress)
	if walletAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet_address is required"})
		return
	}
	state, ok := s.gpmState.getContribution(walletAddress)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "contribution state not found"})
		return
	}
	now := time.Now().UTC()
	if refreshed, ok := s.refreshGPMContributionMeter(walletAddress, now); ok {
		state = refreshed
	}
	currentReward := s.gpmWeeklyRewardFromContributionWithContext(r.Context(), state, now, "pending")
	rawHistory := s.gpmState.rewardHistoryFor(walletAddress)
	history := s.applyGPMRewardHoldsToHistoryWithContext(r.Context(), walletAddress, rawHistory)
	selectedWeekStart, err := resolveGPMRewardWeekStart(in.WeekStartUTC, now)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	selectedReward := s.gpmRewardForSelectedWeek(r.Context(), walletAddress, state, selectedWeekStart, now, rawHistory)
	activeHolds, slashingHoldIntegration, slashingHoldErr := s.gpmActiveRewardHoldsForWeek(r.Context(), walletAddress, selectedReward.WeekStartUTC)
	chainSlashingHoldCount := gpmRewardHoldSourceCount(activeHolds, "slashing_evidence")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                            true,
		"admin_api_surface":             "gpm_admin_console",
		"admin_wallet_address":          adminSession.WalletAddress,
		"wallet_address":                walletAddress,
		"contribution_profile":          serializeGPMContributionProfile(state),
		"current_week_reward":           currentReward,
		"selected_week_reward":          selectedReward,
		"selected_week_start_utc":       selectedReward.WeekStartUTC,
		"active_holds":                  activeHolds,
		"active_hold_count":             len(activeHolds),
		"reward_history":                history,
		"reward_history_count":          len(history),
		"settlement_frequency":          "weekly",
		"weekly_epoch_start_weekday":    "monday",
		"weekly_epoch_timezone":         "UTC",
		"slashing_hold_integration":     slashingHoldIntegration,
		"slashing_hold_error":           errorString(slashingHoldErr),
		"chain_slashing_hold_count":     chainSlashingHoldCount,
		"settlement_finalization_state": "pending_chain_bound_admin_console",
	})
}

func (s *Service) handleGPMAdminRewardHold(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmAdminRewardHoldRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	adminSession, ok := s.gpmAdminSessionFromTokenForResponse(w, in.SessionToken)
	if !ok {
		return
	}
	walletAddress := normalizeWalletAddress(in.WalletAddress)
	if walletAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet_address is required"})
		return
	}
	now := time.Now().UTC()
	weekStart, err := resolveGPMRewardWeekStart(in.WeekStartUTC, now)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action == "" {
		action = "hold"
	}
	switch action {
	case "hold", "release":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "action must be one of: hold, release"})
		return
	}
	if _, ok := s.gpmState.getContribution(walletAddress); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "contribution state not found"})
		return
	}
	var changed []gpmRewardHold
	if action == "release" {
		changed = s.gpmState.releaseActiveRewardHolds(walletAddress, weekStart.Format(time.RFC3339), adminSession.WalletAddress, now)
	} else {
		reason := strings.TrimSpace(in.Reason)
		if reason == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "reason is required when action is hold"})
			return
		}
		source := normalizeGPMRewardHoldSource(in.Source)
		if !gpmManualRewardHoldSourceAllowed(source) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("reward hold source %q is reserved for chain-derived evidence; use admin_reward_hold, abuse_flag, policy_violation, or traffic_proof for manual holds", source),
			})
			return
		}
		hold := gpmRewardHold{
			HoldID:        fmt.Sprintf("hold-%s-%d", walletAddress, now.UnixNano()),
			WalletAddress: walletAddress,
			WeekStartUTC:  weekStart.Format(time.RFC3339),
			Source:        source,
			Reason:        reason,
			Status:        "active",
			CreatedBy:     adminSession.WalletAddress,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		s.gpmState.upsertRewardHold(hold)
		changed = []gpmRewardHold{hold}
	}
	s.persistGPMStateBestEffort("reward_hold")
	s.appendGPMAudit("reward_hold_changed", map[string]any{
		"wallet_address": walletAddress,
		"week_start_utc": weekStart.Format(time.RFC3339),
		"action":         action,
		"admin_wallet":   adminSession.WalletAddress,
		"changed_count":  len(changed),
	})
	state, _ := s.gpmState.getContribution(walletAddress)
	summary := s.gpmRewardForSelectedWeek(r.Context(), walletAddress, state, weekStart, now, s.gpmState.rewardHistoryFor(walletAddress))
	activeHolds, slashingHoldIntegration, slashingHoldErr := s.gpmActiveRewardHoldsForWeek(r.Context(), walletAddress, weekStart.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                        true,
		"admin_api_surface":         "gpm_admin_console",
		"wallet_address":            walletAddress,
		"week_start_utc":            weekStart.Format(time.RFC3339),
		"action":                    action,
		"changed_holds":             changed,
		"active_holds":              activeHolds,
		"active_hold_count":         len(activeHolds),
		"selected_week_reward":      summary,
		"public_app_admin_controls": false,
		"slashing_hold_integration": slashingHoldIntegration,
		"slashing_hold_error":       errorString(slashingHoldErr),
		"chain_slashing_hold_count": gpmRewardHoldSourceCount(activeHolds, "slashing_evidence"),
	})
}

func (s *Service) handleGPMAdminRewardFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in gpmAdminRewardFinalizeRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	adminSession, ok := s.gpmAdminSessionFromTokenForResponse(w, in.SessionToken)
	if !ok {
		return
	}
	walletAddress := normalizeWalletAddress(in.WalletAddress)
	if walletAddress == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "wallet_address is required"})
		return
	}
	if strings.TrimSpace(in.WeekStartUTC) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "week_start_utc is required for reward finalization"})
		return
	}
	now := time.Now().UTC()
	weekStart, err := resolveGPMRewardWeekStart(in.WeekStartUTC, now)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if !weekStart.Before(gpmWeekStartUTC(now)) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":             false,
			"error":          "only closed weekly reward epochs can be finalized",
			"week_start_utc": weekStart.Format(time.RFC3339),
		})
		return
	}
	state, ok := s.gpmState.getContribution(walletAddress)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "contribution state not found"})
		return
	}
	rawHistory := s.gpmState.rewardHistoryFor(walletAddress)
	summary := s.gpmRewardForSelectedWeek(r.Context(), walletAddress, state, weekStart, now, rawHistory)
	if strings.EqualFold(strings.TrimSpace(summary.Status), "not_found") {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"ok":             false,
			"error":          "weekly reward summary not found for selected epoch",
			"week_start_utc": weekStart.Format(time.RFC3339),
		})
		return
	}
	activeHolds, slashingHoldIntegration, slashingHoldErr := s.gpmActiveRewardHoldsForWeek(r.Context(), walletAddress, summary.WeekStartUTC)
	if len(activeHolds) > 0 || strings.EqualFold(strings.TrimSpace(summary.Status), "hold") {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":                        false,
			"error":                     "weekly reward has active holds and cannot be finalized",
			"active_holds":              activeHolds,
			"active_hold_count":         len(activeHolds),
			"selected_week_reward":      summary,
			"slashing_hold_integration": slashingHoldIntegration,
			"slashing_hold_error":       errorString(slashingHoldErr),
			"chain_slashing_hold_count": gpmRewardHoldSourceCount(activeHolds, "slashing_evidence"),
		})
		return
	}
	summary.TrafficProofRef = gpmCanonicalObjectiveEvidenceRef(summary.TrafficProofRef)
	if proofErr := s.gpmWeeklyRewardFinalizeTrafficProofError(summary); proofErr != "" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":                   false,
			"error":                proofErr,
			"traffic_proof_status": summary.TrafficProofStatus,
			"traffic_proof_ref":    summary.TrafficProofRef,
			"metering_source":      summary.MeteringSource,
			"selected_week_reward": summary,
		})
		return
	}
	rewardMicros := gpmWeeklyRewardMicros(summary)
	if rewardMicros <= 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":                   false,
			"error":                "weekly reward has no positive payout amount",
			"selected_week_reward": summary,
		})
		return
	}
	settlementStatus := s.gpmSettlementStatusTelemetry()
	if s.gpmSettlementRequiresChainBackedAdapter() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":                         false,
			"error":                      s.gpmSettlementChainRequiredError(),
			"admin_api_surface":          "gpm_admin_console",
			"admin_wallet_address":       adminSession.WalletAddress,
			"wallet_address":             walletAddress,
			"week_start_utc":             summary.WeekStartUTC,
			"selected_week_reward":       summary,
			"settlement_status":          settlementStatus,
			"payout_allowed":             false,
			"public_app_admin_controls":  false,
			"settlement_frequency":       "weekly",
			"weekly_epoch_start_weekday": "monday",
			"weekly_epoch_timezone":      "UTC",
		})
		return
	}
	rewardIssueFromSummary := func(summary gpmWeeklyRewardSummary, issuedAt time.Time) settlement.RewardIssue {
		rewardID := strings.TrimSpace(summary.RewardIssueID)
		if rewardID == "" {
			rewardID = gpmWeeklyRewardIssueID(summary)
		}
		return settlement.RewardIssue{
			RewardID:              rewardID,
			ProviderSubjectID:     walletAddress,
			SessionID:             gpmWeeklyRewardSessionID(summary),
			SettlementReferenceID: strings.TrimSpace(summary.SettlementReferenceID),
			TrafficProofRef:       gpmWeeklyRewardTrafficProofRef(summary),
			PayoutPeriodStart:     weekStart,
			PayoutPeriodEnd:       weekStart.AddDate(0, 0, 7),
			RewardMicros:          gpmWeeklyRewardMicros(summary),
			Currency:              gpmWeeklyRewardCurrency(),
			IssuedAt:              issuedAt,
		}
	}
	if strings.TrimSpace(summary.RewardIssueID) != "" {
		reconcileReport, reconcileErr := s.gpmSettlementService().Reconcile(r.Context())
		reconcileResponseErr := reconcileErr
		issue, replayErr := s.gpmSettlementService().IssueReward(r.Context(), rewardIssueFromSummary(summary, gpmWeeklyRewardIssuedAt(summary, now)))
		if replayErr != nil {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok":                         false,
				"error":                      fmt.Sprintf("settlement reward replay failed: %v", replayErr),
				"admin_api_surface":          "gpm_admin_console",
				"admin_wallet_address":       adminSession.WalletAddress,
				"wallet_address":             walletAddress,
				"week_start_utc":             summary.WeekStartUTC,
				"selected_week_reward":       summary,
				"reward_issue":               map[string]any{"reward_id": summary.RewardIssueID, "status": summary.SettlementChainStatus, "adapter_reference_id": summary.SettlementAdapterReference},
				"reconcile_report":           reconcileReport,
				"reconcile_error":            errorString(reconcileResponseErr),
				"idempotent_replay":          false,
				"payout_allowed":             summary.PayoutAllowed,
				"public_app_admin_controls":  false,
				"settlement_frequency":       "weekly",
				"weekly_epoch_start_weekday": "monday",
				"weekly_epoch_timezone":      "UTC",
			})
			return
		}
		refreshed := applyGPMSettlementIssueToRewardSummary(summary, issue, now)
		if strings.TrimSpace(summary.FinalizedAtUTC) != "" {
			refreshed.FinalizedAtUTC = summary.FinalizedAtUTC
		}
		if strings.TrimSpace(summary.GeneratedAtUTC) != "" {
			refreshed.GeneratedAtUTC = summary.GeneratedAtUTC
		}
		summary = refreshed
		s.gpmState.upsertRewardHistory(walletAddress, summary)
		s.persistGPMStateBestEffort("reward_finalize_reconcile")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                         true,
			"admin_api_surface":          "gpm_admin_console",
			"admin_wallet_address":       adminSession.WalletAddress,
			"wallet_address":             walletAddress,
			"week_start_utc":             summary.WeekStartUTC,
			"selected_week_reward":       summary,
			"reward_issue":               map[string]any{"reward_id": summary.RewardIssueID, "status": summary.SettlementChainStatus, "adapter_reference_id": summary.SettlementAdapterReference},
			"reconcile_report":           reconcileReport,
			"reconcile_error":            errorString(reconcileResponseErr),
			"idempotent_replay":          true,
			"settlement_status":          settlementStatus,
			"payout_allowed":             summary.PayoutAllowed,
			"public_app_admin_controls":  false,
			"settlement_frequency":       "weekly",
			"weekly_epoch_start_weekday": "monday",
			"weekly_epoch_timezone":      "UTC",
		})
		return
	}
	rewardIssue := rewardIssueFromSummary(summary, gpmWeeklyRewardIssuedAt(summary, now))
	issue, err := s.gpmSettlementService().IssueReward(r.Context(), rewardIssue)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":                   false,
			"error":                fmt.Sprintf("settlement reward issue failed: %v", err),
			"selected_week_reward": summary,
		})
		return
	}
	reconcileReport, reconcileErr := s.gpmSettlementService().Reconcile(r.Context())
	if reconcileErr == nil {
		if replay, replayErr := s.gpmSettlementService().IssueReward(r.Context(), rewardIssue); replayErr == nil {
			issue = replay
		}
	}
	finalized := applyGPMSettlementIssueToRewardSummary(summary, issue, now)
	s.gpmState.upsertRewardHistory(walletAddress, finalized)
	s.persistGPMStateBestEffort("reward_finalize")
	s.appendGPMAudit("reward_finalized", map[string]any{
		"wallet_address":       walletAddress,
		"week_start_utc":       finalized.WeekStartUTC,
		"admin_wallet":         adminSession.WalletAddress,
		"reward_issue_id":      issue.RewardID,
		"settlement_status":    string(issue.Status),
		"payout_allowed":       finalized.PayoutAllowed,
		"adapter_reference_id": issue.AdapterReferenceID,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                         true,
		"admin_api_surface":          "gpm_admin_console",
		"admin_wallet_address":       adminSession.WalletAddress,
		"wallet_address":             walletAddress,
		"week_start_utc":             finalized.WeekStartUTC,
		"selected_week_reward":       finalized,
		"reward_issue":               issue,
		"reconcile_report":           reconcileReport,
		"reconcile_error":            errorString(reconcileErr),
		"settlement_status":          settlementStatus,
		"payout_allowed":             finalized.PayoutAllowed,
		"public_app_admin_controls":  false,
		"settlement_frequency":       "weekly",
		"weekly_epoch_start_weekday": "monday",
		"weekly_epoch_timezone":      "UTC",
	})
}

func (s *Service) gpmSettlementService() settlement.Service {
	if s.gpmSettlement != nil {
		return s.gpmSettlement
	}
	blockchainMode := s.gpmSettlementChainRequiredEffective()
	s.gpmSettlement = settlement.NewMemoryService(settlement.WithBlockchainMode(blockchainMode))
	if strings.TrimSpace(s.gpmSettlementBackend) == "" {
		s.gpmSettlementBackend = "memory"
	}
	if strings.TrimSpace(s.gpmSettlementBackendSource) == "" {
		s.gpmSettlementBackendSource = "default"
	}
	if blockchainMode && strings.TrimSpace(s.gpmSettlementChainRequiredSource) == "" {
		s.gpmSettlementChainRequired = true
		s.gpmSettlementChainRequiredSource = s.gpmSettlementChainRequiredSourceEffective()
	}
	return s.gpmSettlement
}

func gpmWeeklyRewardCurrency() string {
	currency := strings.TrimSpace(firstNonEmpty(os.Getenv("GPM_REWARD_CURRENCY"), os.Getenv("TDPN_REWARD_CURRENCY")))
	if currency == "" {
		return "TDPNC"
	}
	return currency
}

func gpmWeeklyRewardMicros(summary gpmWeeklyRewardSummary) int64 {
	if summary.RewardUnits <= 0 {
		return 0
	}
	return int64(math.Round(summary.RewardUnits * 1_000_000))
}

func gpmWeeklyRewardIssueID(summary gpmWeeklyRewardSummary) string {
	return "gpm-weekly-reward-" + gpmWeeklyRewardStableSuffix(summary)
}

func gpmWeeklyRewardSessionID(summary gpmWeeklyRewardSummary) string {
	return "gpm-weekly-session-" + gpmWeeklyRewardStableSuffix(summary)
}

func gpmWeeklyRewardStableSuffix(summary gpmWeeklyRewardSummary) string {
	weekStart := strings.TrimSpace(summary.WeekStartUTC)
	if parsed, err := time.Parse(time.RFC3339, weekStart); err == nil {
		weekStart = parsed.UTC().Format("20060102")
	}
	wallet := normalizeWalletAddress(summary.WalletAddress)
	if wallet == "" {
		wallet = "unknown"
	}
	return wallet + "-" + weekStart
}

func gpmWeeklyRewardTrafficProofRef(summary gpmWeeklyRewardSummary) string {
	if ref := gpmCanonicalObjectiveEvidenceRef(summary.TrafficProofRef); ref != "" {
		return ref
	}
	hashInput := strings.Join([]string{
		normalizeWalletAddress(summary.WalletAddress),
		strings.TrimSpace(summary.WeekStartUTC),
		strings.TrimSpace(summary.WeekEndUTC),
		strings.TrimSpace(summary.Role),
		strconv.FormatInt(summary.MeteredSeconds, 10),
		strconv.FormatInt(summary.ValidBytes, 10),
		strconv.FormatInt(gpmWeeklyRewardMicros(summary), 10),
		strings.TrimSpace(summary.MeteringSource),
	}, "|")
	sum := sha256.Sum256([]byte(hashInput))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func applyGPMSettlementIssueToRewardSummary(summary gpmWeeklyRewardSummary, issue settlement.RewardIssue, now time.Time) gpmWeeklyRewardSummary {
	summary.RewardIssueID = strings.TrimSpace(issue.RewardID)
	summary.SettlementReferenceID = strings.TrimSpace(issue.SettlementReferenceID)
	summary.SettlementChainStatus = string(issue.Status)
	summary.SettlementAdapterReference = strings.TrimSpace(issue.AdapterReferenceID)
	if ref := gpmCanonicalObjectiveEvidenceRef(issue.TrafficProofRef); ref != "" {
		summary.TrafficProofRef = ref
	}
	if !issue.IssuedAt.IsZero() {
		summary.SettlementIssuedAtUTC = issue.IssuedAt.UTC().Format(time.RFC3339)
	}
	summary.FinalizedAtUTC = now.UTC().Format(time.RFC3339)
	summary.GeneratedAtUTC = now.UTC().Format(time.RFC3339)
	summary.PayoutAllowed = issue.Status == settlement.OperationStatusConfirmed
	if summary.PayoutAllowed {
		summary.Status = "finalized_chain_confirmed"
		summary.SettlementFinalizationState = "chain_confirmed"
		summary.HoldReason = ""
		return summary
	}
	if issue.Status == settlement.OperationStatusFailed {
		summary.Status = "finalization_failed"
		summary.SettlementFinalizationState = "chain_failed"
		summary.HoldReason = appendHoldReason(summary.HoldReason, "settlement adapter failed weekly reward finalization")
		return summary
	}
	if issue.Status == settlement.OperationStatusPending || issue.AdapterDeferred {
		summary.Status = "finalized_pending_chain_submission"
		summary.SettlementFinalizationState = "pending_chain_submission"
		summary.PayoutAllowed = false
		return summary
	}
	summary.Status = "finalized_pending_chain_confirmation"
	summary.SettlementFinalizationState = "pending_chain_confirmation"
	summary.PayoutAllowed = false
	return summary
}

func (s *Service) gpmWeeklyRewardFinalizeTrafficProofError(summary gpmWeeklyRewardSummary) string {
	if strings.ToLower(strings.TrimSpace(summary.TrafficProofStatus)) != "trusted" {
		return "trusted traffic proof is required before weekly reward finalization"
	}
	if s == nil || !strings.EqualFold(strings.TrimSpace(s.gpmConnectPolicyMode), "production") {
		return ""
	}
	if !gpmIsStrongRewardTrafficProofRef(summary.TrafficProofRef) {
		return "production weekly reward finalization requires objective signed or chain-queryable traffic proof evidence (obj://...) before payout"
	}
	if !gpmWeeklyRewardProductionMeteringSource(summary.MeteringSource) {
		return "production weekly reward finalization requires chain or signed traffic proof metering source"
	}
	return ""
}

func gpmWeeklyRewardProductionMeteringSource(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	source = strings.ReplaceAll(source, "_", "-")
	switch source {
	case "chain-traffic-proof",
		"chain-counter",
		"chain-metered-counter",
		"signed-traffic-proof",
		"signed-counter",
		"signed-metered-counter",
		"objective-traffic-proof",
		"objective-counter",
		"objective-metered-counter",
		"verifiable-traffic-proof",
		"verifiable-metered-counter":
		return true
	default:
		return false
	}
}

func gpmCanonicalObjectiveEvidenceRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "sha256:") {
		sum := strings.TrimPrefix(ref, "sha256:")
		if len(sum) == 64 {
			return "sha256:" + strings.ToLower(sum)
		}
	}
	return ref
}

func gpmIsObjectiveEvidenceRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.HasPrefix(ref, "obj://") {
		path := strings.TrimSpace(strings.TrimPrefix(ref, "obj://"))
		return path != "" && !strings.ContainsAny(path, " \t\r\n")
	}
	if !strings.HasPrefix(ref, "sha256:") {
		return false
	}
	sum := strings.TrimPrefix(ref, "sha256:")
	if len(sum) != 64 {
		return false
	}
	for _, ch := range sum {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

func gpmIsStrongRewardTrafficProofRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "obj://") {
		return false
	}
	path := strings.TrimSpace(strings.TrimPrefix(ref, "obj://"))
	return path != "" && !strings.ContainsAny(path, " \t\r\n")
}

func gpmWeeklyRewardIssuedAt(summary gpmWeeklyRewardSummary, fallback time.Time) time.Time {
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(summary.SettlementIssuedAtUTC)); err == nil {
		return parsed.UTC()
	}
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(summary.FinalizedAtUTC)); err == nil {
		return parsed.UTC()
	}
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(summary.GeneratedAtUTC)); err == nil {
		return parsed.UTC()
	}
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(summary.WeekEndUTC)); err == nil {
		return parsed.UTC()
	}
	return fallback.UTC()
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
	if sessionToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token is required"})
		return
	}
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(sessionToken)
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	sessionPresent := true

	walletAddress := normalizeWalletAddress(in.WalletAddress)
	sessionWallet := normalizeWalletAddress(session.WalletAddress)
	if walletAddress == "" {
		walletAddress = sessionWallet
	} else if walletAddress != sessionWallet {
		if _, ok := s.gpmAdminSessionFromTokenForResponse(w, sessionToken); !ok {
			return
		}
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
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(sessionToken)
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return
	}
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
		"contribution": s.gpmContributionStatusForSession(session, time.Now().UTC()),
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

func (s *Service) gpmSessionFromQueryOrBearer(r *http.Request) (gpmSession, bool, error) {
	token := gpmSessionTokenFromRequest(r, r.URL.Query().Get("session_token"))
	return s.gpmSessionFromToken(token)
}

func (s *Service) gpmSessionFromRequestOrBearer(r *http.Request) (gpmSession, bool, error) {
	if r.Method == http.MethodGet {
		return s.gpmSessionFromQueryOrBearer(r)
	}
	var in struct {
		SessionToken string `json:"session_token"`
	}
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		return gpmSession{}, false, nil
	}
	return s.gpmSessionFromTokenOrBearer(r, in.SessionToken)
}

func (s *Service) gpmSessionFromTokenOrBearer(r *http.Request, token string) (gpmSession, bool, error) {
	return s.gpmSessionFromToken(gpmSessionTokenFromRequest(r, token))
}

func (s *Service) gpmAdminSessionFromHeaderForResponse(w http.ResponseWriter, r *http.Request) (gpmSession, bool) {
	if r != nil && strings.TrimSpace(r.URL.Query().Get("session_token")) != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token must be sent in X-GPM-Session-Token, not the URL query"})
		return gpmSession{}, false
	}
	token := strings.TrimSpace(r.Header.Get("X-GPM-Session-Token"))
	return s.gpmAdminSessionFromTokenForResponse(w, token)
}

func (s *Service) gpmSessionFromToken(token string) (gpmSession, bool, error) {
	return s.gpmSessionFromTokenWithWalletPolicy(token)
}

func writeGPMSessionWalletPolicyError(w http.ResponseWriter, policyErr error) {
	writeJSON(w, http.StatusForbidden, map[string]any{
		"ok":    false,
		"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
	})
}

func (s *Service) gpmSessionFromTokenWithWalletPolicy(token string) (gpmSession, bool, error) {
	if strings.TrimSpace(token) == "" || s == nil || s.gpmState == nil {
		return gpmSession{}, false, nil
	}
	session, ok := s.gpmState.getSession(strings.TrimSpace(token), time.Now().UTC())
	if !ok {
		return gpmSession{}, false, nil
	}
	if err := s.validateGPMSessionWalletPolicy(session); err != nil {
		return gpmSession{}, false, err
	}
	return session, true, nil
}

func (s *Service) gpmAdminSessionFromTokenForResponse(w http.ResponseWriter, token string) (gpmSession, bool) {
	sessionToken := strings.TrimSpace(token)
	if sessionToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token is required"})
		return gpmSession{}, false
	}
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(sessionToken)
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return gpmSession{}, false
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
		return gpmSession{}, false
	}
	if strings.ToLower(strings.TrimSpace(session.Role)) != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin session role is required"})
		return gpmSession{}, false
	}
	if !session.WalletBindingVerified {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wallet-bound admin session is required"})
		return gpmSession{}, false
	}
	if !s.gpmAdminWalletAllowed(session.WalletAddress) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "admin wallet is not currently allowlisted"})
		return gpmSession{}, false
	}
	if !s.gpmAdminSessionVerificationAllowed(session) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "command-backed wallet-bound admin session is required"})
		return gpmSession{}, false
	}
	return session, true
}

func normalizeGPMContributionRole(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "micro-relay", "micro_relay", "relay":
		return "micro-relay"
	case "micro-exit", "micro_exit", "exit":
		return "micro-exit"
	default:
		return ""
	}
}

func envIntDefault(names []string, fallback int) int {
	for _, name := range names {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			continue
		}
		parsed, err := strconv.Atoi(raw)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func envFloatDefault(names []string, fallback float64) float64 {
	for _, name := range names {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func envBoolDefault(names []string, fallback bool) bool {
	for _, name := range names {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			continue
		}
		return parseBoolWithDefault(raw, fallback)
	}
	return fallback
}

func gpmMicroExitBetaAllowed() bool {
	return envBoolDefault([]string{"GPM_MICRO_EXIT_BETA_ALLOWED", "TDPN_MICRO_EXIT_BETA_ALLOWED"}, false)
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func clampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func gpmEffectiveClientTier(session gpmSession) int {
	if !session.WalletBindingVerified {
		return 1
	}
	tier := session.ClientTier
	if tier <= 0 {
		tier = envIntDefault([]string{"GPM_CLIENT_TIER", "GPM_DEFAULT_CLIENT_TIER", "TDPN_CLIENT_TIER", "TDPN_DEFAULT_CLIENT_TIER"}, 1)
	}
	return clampInt(tier, 1, 3)
}

func gpmEffectiveStakeSatisfied(session gpmSession) bool {
	if !session.WalletBindingVerified {
		return false
	}
	return session.StakeSatisfied
}

func gpmEffectivePrepaidSatisfied(session gpmSession) bool {
	if !session.WalletBindingVerified {
		return false
	}
	return session.PrepaidBalanceSatisfied
}

func normalizeGPMEntitlementEvidenceSource(raw string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(raw, "_", "-")))
}

func gpmEntitlementEvidenceTrusted(session gpmSession) bool {
	switch normalizeGPMEntitlementEvidenceSource(session.EntitlementEvidenceSource) {
	case "chain", "chain-query", "chain-attestation", "signed-attestation", "signed-entitlement":
		return session.WalletBindingVerified
	default:
		return false
	}
}

func (s *Service) gpmProductionEntitlementEvidenceLock(session gpmSession) string {
	if s == nil || !s.isGPMProductionMode() {
		return ""
	}
	if gpmEntitlementEvidenceTrusted(session) {
		return ""
	}
	source := strings.TrimSpace(session.EntitlementEvidenceSource)
	if source == "" {
		source = "missing"
	}
	return fmt.Sprintf("production account eligibility requires trusted chain or signed entitlement evidence; current source=%s", source)
}

func normalizeGPMOperatorApprovalEvidenceSource(raw string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(raw, "_", "-")))
}

func gpmOperatorApprovalEvidenceTrusted(app gpmOperatorApplication) bool {
	switch normalizeGPMOperatorApprovalEvidenceSource(app.ApprovalEvidenceSource) {
	case "chain", "chain-governance", "chain-attestation", "signed-attestation":
		return true
	default:
		return false
	}
}

func (s *Service) gpmProductionOperatorApprovalEvidenceLock(app gpmOperatorApplication) string {
	if s == nil || !s.isGPMProductionMode() {
		return ""
	}
	if gpmOperatorApprovalEvidenceTrusted(app) {
		return ""
	}
	source := strings.TrimSpace(app.ApprovalEvidenceSource)
	if source == "" {
		source = "missing"
	}
	return fmt.Sprintf("production operator activation requires trusted chain-governance approval evidence; current source=%s", source)
}

func gpmAdaptiveContributionProfile(role string) gpmContributionState {
	role = normalizeGPMContributionRole(role)
	if role == "" {
		role = "micro-relay"
	}
	cpuCores := runtime.NumCPU()
	if cpuCores < 1 {
		cpuCores = 1
	}
	uplinkMbps := envIntDefault([]string{"GPM_AGENT_UPLINK_MBPS", "GPM_AGENT_UPLOAD_MBPS", "TDPN_AGENT_UPLINK_MBPS"}, 20)
	downlinkMbps := envIntDefault([]string{"GPM_AGENT_DOWNLINK_MBPS", "GPM_AGENT_DOWNLOAD_MBPS", "TDPN_AGENT_DOWNLINK_MBPS"}, 50)
	latencyMs := envIntDefault([]string{"GPM_AGENT_LATENCY_MS", "TDPN_AGENT_LATENCY_MS"}, 40)
	packetLossPct := envFloatDefault([]string{"GPM_AGENT_PACKET_LOSS_PCT", "TDPN_AGENT_PACKET_LOSS_PCT"}, 0.2)
	memoryGB := envFloatDefault([]string{"GPM_AGENT_MEMORY_GB", "TDPN_AGENT_MEMORY_GB"}, 8)
	reliabilityPct := envFloatDefault([]string{"GPM_AGENT_RELIABILITY_PCT", "TDPN_AGENT_RELIABILITY_PCT"}, 95)
	onBattery := envBoolDefault([]string{"GPM_AGENT_ON_BATTERY", "TDPN_AGENT_ON_BATTERY"}, false)

	capacityScore := clampInt((cpuCores*8)+(uplinkMbps*2)+(downlinkMbps/4)+int(memoryGB*3), 1, 100)
	healthPenalty := 0
	if latencyMs > 40 {
		healthPenalty += (latencyMs - 40) / 5
	}
	if packetLossPct > 0 {
		healthPenalty += int(packetLossPct * 18)
	}
	healthScore := clampInt(int(reliabilityPct)-healthPenalty, 1, 100)
	maxSessions := clampInt(minInt(cpuCores*2, maxInt(1, uplinkMbps/2)), 1, 64)
	maxBandwidth := clampInt(uplinkMbps/2, 1, 1000)
	if role == "micro-exit" {
		maxSessions = clampInt(minInt(maxSessions, maxInt(1, uplinkMbps/4)), 1, 32)
		maxBandwidth = clampInt(uplinkMbps/3, 1, 1000)
	}

	demotionState := "none"
	lockReason := ""
	if onBattery {
		demotionState = "disabled_power_policy"
		lockReason = "device is on battery power; contribution is disabled until external power is available"
	}
	if uplinkMbps < 5 {
		demotionState = "disabled_capacity"
		lockReason = "uplink capacity is below the minimum safe contribution threshold"
	}
	if healthScore < 45 {
		demotionState = "disabled_health"
		lockReason = "network health score is below the minimum safe contribution threshold"
	}

	return gpmContributionState{
		Role:                 role,
		RequestedRole:        role,
		CapacityScore:        capacityScore,
		HealthScore:          healthScore,
		MaxForwardedSessions: maxSessions,
		MaxBandwidthMbps:     maxBandwidth,
		UptimeReliabilityPct: clampFloat(reliabilityPct, 0, 100),
		DemotionState:        demotionState,
		LockReason:           lockReason,
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func gpmContributionEligibilityLock(session gpmSession, role string, profile gpmContributionState) string {
	role = normalizeGPMContributionRole(role)
	tier := gpmEffectiveClientTier(session)
	stakeSatisfied := gpmEffectiveStakeSatisfied(session)
	prepaidSatisfied := gpmEffectivePrepaidSatisfied(session)
	microExitBetaAllowed := gpmMicroExitBetaAllowed()
	switch {
	case tier < 2:
		return "Tier 2 or Tier 3 is required to use or provide micro-relay/micro-exit"
	case !stakeSatisfied:
		return "stake requirement is not satisfied"
	case !prepaidSatisfied:
		return "prepaid usage balance requirement is not satisfied"
	case role == "micro-exit" && !microExitBetaAllowed:
		return "micro-exit beta is disabled by policy"
	case strings.TrimSpace(profile.LockReason) != "":
		return profile.LockReason
	default:
		return ""
	}
}

func gpmMicroRelayUseLock(session gpmSession, pathProfile string) string {
	if !gpmPathProfileUsesMicroRelay(pathProfile) {
		return ""
	}
	tier := gpmEffectiveClientTier(session)
	switch {
	case tier < 2:
		return "Tier 2 or Tier 3 is required to use micro-relay paths"
	case !gpmEffectiveStakeSatisfied(session):
		return "stake requirement is not satisfied"
	case !gpmEffectivePrepaidSatisfied(session):
		return "prepaid usage balance requirement is not satisfied"
	default:
		return ""
	}
}

func gpmContributionRuntimeLock(state gpmContributionState) string {
	role := gpmContributionRoleForState(state)
	if role == "" {
		role = "micro-relay"
	}
	switch {
	case state.ClientTier < 2:
		return "Tier 2 or Tier 3 is required to use or provide micro-relay/micro-exit"
	case !state.StakeSatisfied:
		return "stake requirement is not satisfied"
	case !state.PrepaidBalanceSatisfied:
		return "prepaid usage balance requirement is not satisfied"
	case role == "micro-exit" && !gpmMicroExitBetaAllowed():
		return "micro-exit beta is disabled by policy"
	default:
		return strings.TrimSpace(gpmAdaptiveContributionProfile(role).LockReason)
	}
}

func gpmRewardFinalizeCurrentEligibilityLock(state gpmContributionState) string {
	switch {
	case state.ClientTier < 2:
		return "Tier 2 or Tier 3 is required to use or provide micro-relay/micro-exit"
	case !state.StakeSatisfied:
		return "stake requirement is not satisfied"
	case !state.PrepaidBalanceSatisfied:
		return "prepaid usage balance requirement is not satisfied"
	default:
		return ""
	}
}

func (s *Service) gpmContributionStatusForSession(session gpmSession, now time.Time) map[string]any {
	requestedRole := "micro-relay"
	if s != nil && s.gpmState != nil {
		if persisted, ok := s.gpmState.getContribution(session.WalletAddress); ok && normalizeGPMContributionRole(persisted.RequestedRole) != "" {
			requestedRole = normalizeGPMContributionRole(persisted.RequestedRole)
		}
	}
	return s.gpmContributionStatusForSessionWithRequestedRole(session, requestedRole, now)
}

func (s *Service) gpmContributionStatusForSessionWithRequestedRole(session gpmSession, requestedRole string, now time.Time) map[string]any {
	walletAddress := normalizeWalletAddress(session.WalletAddress)
	requestedRole = normalizeGPMContributionRole(requestedRole)
	if requestedRole == "" {
		requestedRole = "micro-relay"
	}
	var state gpmContributionState
	if s != nil && s.gpmState != nil {
		state, _ = s.gpmState.getContribution(walletAddress)
	}
	profile := gpmAdaptiveContributionProfile(requestedRole)
	tier := gpmEffectiveClientTier(session)
	stakeSatisfied := gpmEffectiveStakeSatisfied(session)
	prepaidSatisfied := gpmEffectivePrepaidSatisfied(session)
	microExitBetaAllowed := gpmMicroExitBetaAllowed()
	relayLock := gpmContributionEligibilityLock(session, "micro-relay", gpmAdaptiveContributionProfile("micro-relay"))
	exitLock := gpmContributionEligibilityLock(session, "micro-exit", gpmAdaptiveContributionProfile("micro-exit"))
	requestedLock := relayLock
	if requestedRole == "micro-exit" {
		requestedLock = exitLock
	}
	entitlementEvidenceLock := ""
	entitlementEvidenceTrusted := gpmEntitlementEvidenceTrusted(session)
	if s != nil {
		entitlementEvidenceLock = s.gpmProductionEntitlementEvidenceLock(session)
	}
	if entitlementEvidenceLock != "" {
		relayLock = entitlementEvidenceLock
		exitLock = entitlementEvidenceLock
		requestedLock = entitlementEvidenceLock
	}
	lockForRole := func(role string) string {
		if normalizeGPMContributionRole(role) == "micro-exit" {
			return exitLock
		}
		return relayLock
	}
	activeRoleForLock := gpmContributionRoleForState(state)
	if activeRoleForLock == "" {
		activeRoleForLock = requestedRole
	}
	activeLock := ""
	if state.Enabled {
		activeLock = lockForRole(activeRoleForLock)
	}
	if activeLock == "" {
		if refreshed, ok := s.refreshGPMContributionMeter(walletAddress, now); ok {
			state = refreshed
		}
	}
	if activeLock != "" && state.Enabled && strings.TrimSpace(state.WalletAddress) != "" {
		currentWeekStart := gpmWeekStartUTC(now)
		storedWeekStart, normalizedWeekStart, _ := normalizeGPMMeteredWeekStartUTC(state.MeteredWeekStartUTC, currentWeekStart)
		state.MeteredWeekStartUTC = normalizedWeekStart
		state.Enabled = false
		state.Role = firstNonEmpty(normalizeGPMContributionRole(state.Role), activeRoleForLock)
		state.ClientTier = tier
		state.StakeSatisfied = stakeSatisfied
		state.PrepaidBalanceSatisfied = prepaidSatisfied
		state.MicroExitBetaAllowed = microExitBetaAllowed
		state.ExplicitOptIn = false
		state.DemotionState = "auto_demoted"
		state.LockReason = activeLock
		state.PendingRewardUnits = 0
		state.LastMeteredAt = now
		state.UpdatedAt = now
		if currentWeekStart.After(storedWeekStart) {
			s.gpmState.upsertRewardHistory(walletAddress, s.gpmWeeklyRewardFromContributionWithContext(context.Background(), state, storedWeekStart, "week_closed_pending_admin_chain"))
			state.MeteredWeekStartUTC = currentWeekStart.Format(time.RFC3339)
			state.MeteredSeconds = 0
			state.ValidBytes = 0
			state.PendingRewardUnits = 0
		}
		s.gpmState.upsertContribution(state)
		s.persistGPMStateBestEffort("contribution_auto_demote")
		s.appendGPMAudit("contribution_auto_demoted", map[string]any{
			"wallet_address": session.WalletAddress,
			"requested_role": requestedRole,
			"active_role":    activeRoleForLock,
			"lock_reason":    activeLock,
		})
	}
	enabled := state.Enabled
	activeRole := strings.TrimSpace(state.Role)
	if activeRole == "" {
		activeRole = "disabled"
	}
	if state.CapacityScore > 0 && normalizeGPMContributionRole(state.RequestedRole) == requestedRole {
		profile.CapacityScore = state.CapacityScore
		profile.HealthScore = state.HealthScore
		profile.MaxForwardedSessions = state.MaxForwardedSessions
		profile.MaxBandwidthMbps = state.MaxBandwidthMbps
		profile.UptimeReliabilityPct = state.UptimeReliabilityPct
	}
	profile.WalletAddress = walletAddress
	profile.Enabled = enabled
	profile.Role = activeRole
	profile.RequestedRole = requestedRole
	profile.ClientTier = tier
	profile.StakeSatisfied = stakeSatisfied
	profile.PrepaidBalanceSatisfied = prepaidSatisfied
	profile.ExplicitOptIn = enabled
	profile.MicroExitBetaAllowed = microExitBetaAllowed
	if strings.TrimSpace(state.LockReason) != "" {
		profile.LockReason = state.LockReason
	}
	if strings.TrimSpace(state.DemotionState) != "" && state.DemotionState != "none" {
		profile.DemotionState = state.DemotionState
	}
	if strings.TrimSpace(profile.DemotionState) == "" {
		profile.DemotionState = "none"
	}
	profile.MeteredWeekStartUTC = state.MeteredWeekStartUTC
	profile.MeteredSeconds = state.MeteredSeconds
	profile.ValidBytes = state.ValidBytes
	profile.PendingRewardUnits = gpmPendingRewardUnits(profile)
	if profile.MeteredWeekStartUTC == "" {
		profile.MeteredWeekStartUTC = gpmWeekStartUTC(now).Format(time.RFC3339)
	}
	currentWeek := s.gpmWeeklyRewardFromContribution(profile, now, "pending")
	return map[string]any{
		"ok":                            true,
		"wallet_address":                walletAddress,
		"client_tier":                   tier,
		"stake_satisfied":               stakeSatisfied,
		"prepaid_balance_satisfied":     prepaidSatisfied,
		"entitlement_evidence_source":   strings.TrimSpace(session.EntitlementEvidenceSource),
		"entitlement_evidence_trusted":  entitlementEvidenceTrusted,
		"can_use_micro_relays":          tier >= 2 && stakeSatisfied && prepaidSatisfied && entitlementEvidenceLock == "",
		"can_enable_micro_relay":        relayLock == "",
		"can_enable_micro_exit":         exitLock == "",
		"requested_role":                requestedRole,
		"can_enable_requested_role":     requestedLock == "",
		"contribution_lock_reason":      requestedLock,
		"micro_exit_beta_allowed":       microExitBetaAllowed,
		"settlement_frequency":          "weekly",
		"weekly_epoch_start_weekday":    "monday",
		"weekly_epoch_timezone":         "UTC",
		"contribution_profile":          serializeGPMContributionProfile(profile),
		"current_week_reward":           currentWeek,
		"admin_controls_in_public_app":  false,
		"normal_app_has_admin_controls": false,
	}
}

func serializeGPMContributionProfile(state gpmContributionState) map[string]any {
	return map[string]any{
		"wallet_address":            normalizeWalletAddress(state.WalletAddress),
		"enabled":                   state.Enabled,
		"role":                      strings.TrimSpace(state.Role),
		"requested_role":            strings.TrimSpace(state.RequestedRole),
		"client_tier":               state.ClientTier,
		"stake_satisfied":           state.StakeSatisfied,
		"prepaid_balance_satisfied": state.PrepaidBalanceSatisfied,
		"explicit_opt_in":           state.ExplicitOptIn,
		"micro_exit_beta_allowed":   state.MicroExitBetaAllowed,
		"capacity_score":            state.CapacityScore,
		"health_score":              state.HealthScore,
		"max_forwarded_sessions":    state.MaxForwardedSessions,
		"max_bandwidth_mbps":        state.MaxBandwidthMbps,
		"uptime_reliability_pct":    state.UptimeReliabilityPct,
		"demotion_state":            firstNonEmpty(state.DemotionState, "none"),
		"lock_reason":               strings.TrimSpace(state.LockReason),
		"metered_week_start_utc":    strings.TrimSpace(state.MeteredWeekStartUTC),
		"metered_seconds":           state.MeteredSeconds,
		"valid_bytes":               state.ValidBytes,
		"pending_reward_units":      state.PendingRewardUnits,
		"user_vpn_traffic_priority": "always_first",
		"capacity_source":           "gpm_agent_local_heuristics",
		"measurement_inputs":        []string{"uplink_mbps", "downlink_mbps", "latency_ms", "packet_loss_pct", "cpu_cores", "memory_gb", "power_state", "reliability_pct"},
	}
}

func gpmContributionRoleForState(state gpmContributionState) string {
	return firstNonEmpty(normalizeGPMContributionRole(state.Role), normalizeGPMContributionRole(state.RequestedRole))
}

func gpmContributionHasMetering(state gpmContributionState) bool {
	return state.MeteredSeconds > 0 || state.ValidBytes > 0 || state.PendingRewardUnits > 0
}

func gpmContributionStateFromStatus(status map[string]any, session gpmSession, role string, now time.Time) gpmContributionState {
	profile, _ := status["contribution_profile"].(map[string]any)
	meteredWeekStart := stringFromAny(profile["metered_week_start_utc"])
	if meteredWeekStart == "" {
		meteredWeekStart = gpmWeekStartUTC(now).Format(time.RFC3339)
	}
	return gpmContributionState{
		WalletAddress:           normalizeWalletAddress(session.WalletAddress),
		Role:                    normalizeGPMContributionRole(role),
		RequestedRole:           normalizeGPMContributionRole(role),
		ClientTier:              gpmEffectiveClientTier(session),
		StakeSatisfied:          gpmEffectiveStakeSatisfied(session),
		PrepaidBalanceSatisfied: gpmEffectivePrepaidSatisfied(session),
		MicroExitBetaAllowed:    gpmMicroExitBetaAllowed(),
		CapacityScore:           intFromAny(profile["capacity_score"]),
		HealthScore:             intFromAny(profile["health_score"]),
		MaxForwardedSessions:    intFromAny(profile["max_forwarded_sessions"]),
		MaxBandwidthMbps:        intFromAny(profile["max_bandwidth_mbps"]),
		UptimeReliabilityPct:    floatFromAny(profile["uptime_reliability_pct"]),
		DemotionState:           firstNonEmpty(stringFromAny(profile["demotion_state"]), "none"),
		LockReason:              stringFromAny(status["contribution_lock_reason"]),
		MeteredWeekStartUTC:     meteredWeekStart,
		MeteredSeconds:          int64FromAny(profile["metered_seconds"]),
		ValidBytes:              int64FromAny(profile["valid_bytes"]),
		PendingRewardUnits:      floatFromAny(profile["pending_reward_units"]),
		LastMeteredAt:           now,
		UpdatedAt:               now,
	}
}

func int64FromAny(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	default:
		return 0
	}
}

func intFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func floatFromAny(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	default:
		return 0
	}
}

func stringFromAny(value any) string {
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func gpmPathProfileUsesMicroRelay(pathProfile string) bool {
	return normalizePathProfile(pathProfile) == "3hop"
}

func gpmWeekStartUTC(now time.Time) time.Time {
	utc := now.UTC()
	year, month, day := utc.Date()
	midnight := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	offset := (int(midnight.Weekday()) + 6) % 7
	return midnight.AddDate(0, 0, -offset)
}

func normalizeGPMMeteredWeekStartUTC(raw string, currentWeekStart time.Time) (time.Time, string, bool) {
	currentWeekStart = gpmWeekStartUTC(currentWeekStart)
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		formatted := currentWeekStart.Format(time.RFC3339)
		return currentWeekStart, formatted, strings.TrimSpace(raw) != formatted
	}
	canonical := gpmWeekStartUTC(parsed)
	if canonical.After(currentWeekStart) {
		canonical = currentWeekStart
	}
	formatted := canonical.Format(time.RFC3339)
	return canonical, formatted, strings.TrimSpace(raw) != formatted
}

func (s *Service) refreshGPMContributionMeter(walletAddress string, now time.Time) (gpmContributionState, bool) {
	walletAddress = normalizeWalletAddress(walletAddress)
	if walletAddress == "" || s == nil || s.gpmState == nil {
		return gpmContributionState{}, false
	}
	state, ok := s.gpmState.getContribution(walletAddress)
	if !ok {
		return gpmContributionState{}, false
	}
	now = now.UTC()
	currentWeekStart := gpmWeekStartUTC(now)
	dirty := false
	storedWeekStart, normalizedWeekStart, normalizedDirty := normalizeGPMMeteredWeekStartUTC(state.MeteredWeekStartUTC, currentWeekStart)
	if normalizedDirty {
		state.MeteredWeekStartUTC = normalizedWeekStart
		dirty = true
	}
	if currentWeekStart.After(storedWeekStart) {
		summary := s.gpmWeeklyRewardFromContributionWithContext(context.Background(), state, storedWeekStart, "week_closed_pending_admin_chain")
		s.gpmState.upsertRewardHistory(walletAddress, summary)
		state.MeteredWeekStartUTC = currentWeekStart.Format(time.RFC3339)
		state.MeteredSeconds = 0
		state.ValidBytes = 0
		state.PendingRewardUnits = 0
		state.LastMeteredAt = currentWeekStart
		dirty = true
	}
	if state.Enabled {
		if lockReason := gpmContributionRuntimeLock(state); lockReason != "" {
			state.Enabled = false
			state.Role = firstNonEmpty(normalizeGPMContributionRole(state.Role), gpmContributionRoleForState(state), "micro-relay")
			state.ExplicitOptIn = false
			state.DemotionState = "auto_demoted"
			state.LockReason = lockReason
			state.PendingRewardUnits = 0
			state.LastMeteredAt = now
			state.UpdatedAt = now
			dirty = true
		}
	}
	if state.Enabled {
		lastMetered := state.LastMeteredAt
		if lastMetered.IsZero() || lastMetered.Before(currentWeekStart) {
			lastMetered = currentWeekStart
		}
		if now.After(lastMetered) {
			delta := int64(now.Sub(lastMetered).Seconds())
			if delta > 0 {
				state.MeteredSeconds += delta
				utilizationNumerator := int64(15)
				if normalizeGPMContributionRole(state.Role) == "micro-exit" {
					utilizationNumerator = 25
				}
				bytesPerSecond := int64(maxInt(1, state.MaxBandwidthMbps)) * 125000 * utilizationNumerator / 100
				state.ValidBytes += delta * bytesPerSecond
				state.LastMeteredAt = now
				dirty = true
			}
		}
	}
	state.PendingRewardUnits = gpmPendingRewardUnits(state)
	s.gpmState.upsertContribution(state)
	if dirty {
		s.persistGPMStateBestEffort("contribution_meter_refresh")
	}
	return state, true
}

func gpmPendingRewardUnits(state gpmContributionState) float64 {
	if state.MeteredSeconds <= 0 {
		return 0
	}
	roleWeight := 1.0
	if normalizeGPMContributionRole(state.Role) == "micro-exit" {
		roleWeight = 1.4
	}
	quality := (float64(clampInt(state.CapacityScore, 1, 100)) + float64(clampInt(state.HealthScore, 1, 100))) / 200.0
	hours := float64(state.MeteredSeconds) / 3600.0
	return hours * quality * roleWeight
}

func appendUniqueString(values []string, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return values
	}
	for _, existing := range values {
		if strings.TrimSpace(existing) == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func appendHoldReason(existing string, reason string) string {
	existing = strings.TrimSpace(existing)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return existing
	}
	if existing == "" {
		return reason
	}
	if strings.Contains(existing, reason) {
		return existing
	}
	return existing + "; " + reason
}

func gpmContributionTrafficProofStatus(state gpmContributionState) (string, string) {
	mode := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		os.Getenv("GPM_CONTRIBUTION_TRAFFIC_PROOF_MODE"),
		os.Getenv("TDPN_CONTRIBUTION_TRAFFIC_PROOF_MODE"),
	)))
	mode = strings.ReplaceAll(mode, "_", "-")
	switch mode {
	case "trusted", "trusted-counter", "trusted-counter-test", "test-trusted", "verified", "verified-counter":
		return "trusted", "trusted_counter"
	}
	if state.MeteredSeconds <= 0 && state.ValidBytes <= 0 {
		return "not_required_yet", "none"
	}
	return "missing", "synthetic_wall_clock_estimate"
}

func gpmWeeklyRewardFromContribution(state gpmContributionState, now time.Time, status string) gpmWeeklyRewardSummary {
	weekStart := gpmWeekStartUTC(now)
	if strings.TrimSpace(state.MeteredWeekStartUTC) != "" {
		weekStart, _, _ = normalizeGPMMeteredWeekStartUTC(state.MeteredWeekStartUTC, weekStart)
	}
	rewardUnits := gpmPendingRewardUnits(state)
	holdReason := ""
	holdSources := []string{"pending_admin_console_review", "pending_chain_binding"}
	payoutAllowed := false
	settlementState := "pending_admin_chain_finalization"
	trafficProofStatus, meteringSource := gpmContributionTrafficProofStatus(state)
	if strings.TrimSpace(state.LockReason) != "" {
		status = "hold"
		holdReason = appendHoldReason(holdReason, state.LockReason)
		holdSources = appendUniqueString(holdSources, "contribution_lock")
		rewardUnits = 0
	}
	if trafficProofStatus == "missing" {
		holdReason = appendHoldReason(holdReason, "trusted traffic proof is required before weekly payout")
		holdSources = appendUniqueString(holdSources, "pending_traffic_proof")
		rewardUnits = 0
		status = "hold"
	}
	return gpmWeeklyRewardSummary{
		WalletAddress:               normalizeWalletAddress(state.WalletAddress),
		WeekStartUTC:                weekStart.Format(time.RFC3339),
		WeekEndUTC:                  weekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Role:                        normalizeGPMContributionRole(state.Role),
		MeteredSeconds:              state.MeteredSeconds,
		ValidBytes:                  state.ValidBytes,
		CapacityScore:               state.CapacityScore,
		HealthScore:                 state.HealthScore,
		RewardUnits:                 rewardUnits,
		Status:                      firstNonEmpty(status, "pending"),
		HoldReason:                  holdReason,
		HoldSources:                 holdSources,
		PayoutAllowed:               payoutAllowed,
		SettlementFinalizationState: settlementState,
		TrafficProofStatus:          trafficProofStatus,
		MeteringSource:              meteringSource,
		GeneratedAtUTC:              time.Now().UTC().Format(time.RFC3339),
		SettlementFrequency:         "weekly",
	}
}

func (s *Service) gpmWeeklyRewardFromContribution(state gpmContributionState, now time.Time, status string) gpmWeeklyRewardSummary {
	return s.gpmWeeklyRewardFromContributionWithContext(context.Background(), state, now, status)
}

func (s *Service) gpmWeeklyRewardFromContributionWithContext(ctx context.Context, state gpmContributionState, now time.Time, status string) gpmWeeklyRewardSummary {
	summary := gpmWeeklyRewardFromContribution(state, now, status)
	if s == nil || s.gpmState == nil {
		return summary
	}
	holds, _, _ := s.gpmActiveRewardHoldsForWeek(ctx, state.WalletAddress, summary.WeekStartUTC)
	return applyGPMRewardHolds(summary, holds)
}

func (s *Service) applyGPMRewardHoldsToHistory(walletAddress string, history []gpmWeeklyRewardSummary) []gpmWeeklyRewardSummary {
	return s.applyGPMRewardHoldsToHistoryWithContext(context.Background(), walletAddress, history)
}

func (s *Service) applyGPMRewardHoldsToHistoryWithContext(ctx context.Context, walletAddress string, history []gpmWeeklyRewardSummary) []gpmWeeklyRewardSummary {
	if s == nil || s.gpmState == nil {
		return history
	}
	out := make([]gpmWeeklyRewardSummary, 0, len(history))
	for _, summary := range history {
		holds, _, _ := s.gpmActiveRewardHoldsForWeek(ctx, walletAddress, summary.WeekStartUTC)
		out = append(out, applyGPMRewardHolds(summary, holds))
	}
	return out
}

func (s *Service) gpmRewardForSelectedWeek(ctx context.Context, walletAddress string, state gpmContributionState, selectedWeekStart time.Time, now time.Time, rawHistory []gpmWeeklyRewardSummary) gpmWeeklyRewardSummary {
	walletAddress = normalizeWalletAddress(walletAddress)
	selectedWeekStart = selectedWeekStart.UTC()
	if selectedWeekStart.Equal(gpmWeekStartUTC(now)) {
		return s.gpmWeeklyRewardFromContributionWithContext(ctx, state, now, "pending")
	}
	weekKey := selectedWeekStart.Format(time.RFC3339)
	for _, candidate := range rawHistory {
		if strings.TrimSpace(candidate.WeekStartUTC) == weekKey {
			holds, _, _ := s.gpmActiveRewardHoldsForWeek(ctx, walletAddress, weekKey)
			return applyGPMRewardHolds(candidate, holds)
		}
	}
	holds, _, _ := s.gpmActiveRewardHoldsForWeek(ctx, walletAddress, weekKey)
	return applyGPMRewardHolds(gpmWeeklyRewardSummary{
		WalletAddress:               walletAddress,
		WeekStartUTC:                weekKey,
		WeekEndUTC:                  selectedWeekStart.AddDate(0, 0, 7).Format(time.RFC3339),
		Status:                      "not_found",
		PayoutAllowed:               false,
		SettlementFinalizationState: "pending_admin_chain_finalization",
		GeneratedAtUTC:              now.UTC().Format(time.RFC3339),
		SettlementFrequency:         "weekly",
		TrafficProofStatus:          "not_required_yet",
		MeteringSource:              "none",
	}, holds)
}

func applyGPMRewardHolds(summary gpmWeeklyRewardSummary, holds []gpmRewardHold) gpmWeeklyRewardSummary {
	if len(holds) == 0 {
		return summary
	}
	summary.Status = "hold"
	summary.RewardUnits = 0
	summary.PayoutAllowed = false
	summary.SettlementFinalizationState = "held_pending_admin_chain_review"
	for _, hold := range holds {
		if strings.ToLower(strings.TrimSpace(hold.Status)) != "active" {
			continue
		}
		summary.HoldSources = appendUniqueString(summary.HoldSources, normalizeGPMRewardHoldSource(hold.Source))
		if reason := strings.TrimSpace(hold.Reason); reason != "" {
			summary.HoldReason = appendHoldReason(summary.HoldReason, reason)
		}
	}
	if strings.TrimSpace(summary.HoldReason) == "" {
		summary.HoldReason = "admin reward hold is active"
	}
	return summary
}

func (s *Service) gpmActiveRewardHoldsForWeek(ctx context.Context, walletAddress string, weekStartUTC string) ([]gpmRewardHold, string, error) {
	if s == nil || s.gpmState == nil {
		return nil, "unavailable", nil
	}
	manualHolds := s.gpmState.activeRewardHoldsFor(walletAddress, weekStartUTC)
	chainHolds, integration, err := s.gpmChainSlashRewardHoldsForWeek(ctx, walletAddress, weekStartUTC)
	out := make([]gpmRewardHold, 0, len(manualHolds)+len(chainHolds))
	out = append(out, manualHolds...)
	out = append(out, chainHolds...)
	return out, integration, err
}

func (s *Service) gpmChainSlashRewardHoldsForWeek(ctx context.Context, walletAddress string, weekStartUTC string) ([]gpmRewardHold, string, error) {
	walletAddress = normalizeWalletAddress(walletAddress)
	if walletAddress == "" {
		return nil, "local_settlement_slash_evidence", nil
	}
	weekStart, err := time.Parse(time.RFC3339, strings.TrimSpace(weekStartUTC))
	if err != nil {
		return []gpmRewardHold{gpmSyntheticChainRewardHold(walletAddress, weekStartUTC, "invalid_week", "slashing evidence reconciliation could not parse reward week")}, "local_settlement_slash_evidence_error", err
	}
	weekStart = weekStart.UTC()
	weekEnd := weekStart.AddDate(0, 0, 7)
	lister, ok := s.gpmSettlementService().(gpmSlashEvidenceLister)
	if !ok || lister == nil {
		if strings.EqualFold(strings.TrimSpace(s.gpmConnectPolicyMode), "production") {
			err := errors.New("slashing evidence reconciliation requires chain slash evidence lister in production mode")
			return []gpmRewardHold{
				gpmSyntheticChainRewardHold(walletAddress, weekStart.Format(time.RFC3339), "slash_lister_unavailable", err.Error()),
			}, "local_settlement_slash_evidence_error", err
		}
		return nil, "pending_chain_binding", nil
	}

	summaryKey := gpmWeeklyRewardSummary{
		WalletAddress: walletAddress,
		WeekStartUTC:  weekStart.Format(time.RFC3339),
	}
	sessionID := gpmWeeklyRewardSessionID(summaryKey)
	seen := map[string]struct{}{}
	holds := make([]gpmRewardHold, 0)
	addEvidence := func(evidence settlement.SlashEvidence) {
		id := strings.TrimSpace(evidence.EvidenceID)
		if id == "" {
			id = strings.TrimSpace(evidence.EvidenceRef)
		}
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		holds = append(holds, gpmSlashEvidenceRewardHold(walletAddress, weekStart, evidence))
	}

	bySession, err := lister.ListSlashEvidence(ctx, settlement.SlashEvidenceFilter{
		SubjectID:           walletAddress,
		SessionID:           sessionID,
		IncludeZeroObserved: true,
		IncludeFailed:       false,
		IncludeFailedSet:    true,
	})
	if err != nil {
		return []gpmRewardHold{gpmSyntheticChainRewardHold(walletAddress, weekStart.Format(time.RFC3339), "slash_list_error", "slashing evidence reconciliation failed: "+err.Error())}, "local_settlement_slash_evidence_error", err
	}
	for _, evidence := range bySession {
		addEvidence(evidence)
	}
	byWeek, err := lister.ListSlashEvidence(ctx, settlement.SlashEvidenceFilter{
		SubjectID:         walletAddress,
		ObservedAtOrAfter: weekStart,
		ObservedBefore:    weekEnd,
		IncludeFailed:     false,
		IncludeFailedSet:  true,
	})
	if err != nil {
		return []gpmRewardHold{gpmSyntheticChainRewardHold(walletAddress, weekStart.Format(time.RFC3339), "slash_list_error", "slashing evidence reconciliation failed: "+err.Error())}, "local_settlement_slash_evidence_error", err
	}
	for _, evidence := range byWeek {
		addEvidence(evidence)
	}
	return holds, "local_settlement_slash_evidence", nil
}

func gpmSlashEvidenceRewardHold(walletAddress string, weekStart time.Time, evidence settlement.SlashEvidence) gpmRewardHold {
	observedAt := evidence.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	reason := fmt.Sprintf("chain slashing evidence %s requires admin review before weekly payout", firstNonEmpty(evidence.EvidenceID, evidence.EvidenceRef))
	if violation := strings.TrimSpace(evidence.ViolationType); violation != "" {
		reason = fmt.Sprintf("%s (%s)", reason, violation)
	}
	if evidence.SlashMicros > 0 {
		reason = fmt.Sprintf("%s; slash_micros=%d %s", reason, evidence.SlashMicros, evidence.Currency)
	}
	return gpmRewardHold{
		HoldID:        "chain-slash-" + firstNonEmpty(evidence.EvidenceID, evidence.EvidenceRef),
		WalletAddress: normalizeWalletAddress(walletAddress),
		WeekStartUTC:  weekStart.UTC().Format(time.RFC3339),
		Source:        "slashing_evidence",
		Reason:        reason,
		Status:        "active",
		CreatedBy:     "chain",
		CreatedAt:     observedAt,
		UpdatedAt:     observedAt,
	}
}

func gpmSyntheticChainRewardHold(walletAddress string, weekStartUTC string, suffix string, reason string) gpmRewardHold {
	now := time.Now().UTC()
	return gpmRewardHold{
		HoldID:        "chain-binding-" + firstNonEmpty(strings.TrimSpace(suffix), "unknown"),
		WalletAddress: normalizeWalletAddress(walletAddress),
		WeekStartUTC:  strings.TrimSpace(weekStartUTC),
		Source:        "chain_binding",
		Reason:        strings.TrimSpace(reason),
		Status:        "active",
		CreatedBy:     "chain",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func gpmRewardHoldSourceCount(holds []gpmRewardHold, source string) int {
	source = normalizeGPMRewardHoldSource(source)
	count := 0
	for _, hold := range holds {
		if strings.ToLower(strings.TrimSpace(hold.Status)) != "active" {
			continue
		}
		if normalizeGPMRewardHoldSource(hold.Source) == source {
			count++
		}
	}
	return count
}

func resolveGPMRewardWeekStart(raw string, now time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return gpmWeekStartUTC(now), nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("week_start_utc must be RFC3339 Monday 00:00:00 UTC")
	}
	parsed = parsed.UTC()
	if !parsed.Equal(gpmWeekStartUTC(parsed)) {
		return time.Time{}, fmt.Errorf("week_start_utc must be Monday 00:00:00 UTC")
	}
	return parsed, nil
}

func normalizeGPMRewardHoldSource(raw string) string {
	source := strings.ToLower(strings.TrimSpace(raw))
	source = strings.ReplaceAll(source, " ", "_")
	source = strings.ReplaceAll(source, "-", "_")
	switch source {
	case "slashing", "slashing_evidence":
		return "slashing_evidence"
	case "abuse", "abuse_flag", "abuse_flags":
		return "abuse_flag"
	case "policy", "policy_violation":
		return "policy_violation"
	case "traffic", "traffic_proof", "pending_traffic_proof":
		return "traffic_proof"
	case "chain", "chain_binding", "governance":
		return "chain_binding"
	case "admin", "manual", "admin_review", "manual_admin_review", "admin_reward_hold":
		return "admin_reward_hold"
	default:
		return "admin_reward_hold"
	}
}

func gpmManualRewardHoldSourceAllowed(source string) bool {
	switch normalizeGPMRewardHoldSource(source) {
	case "slashing_evidence", "chain_binding":
		return false
	default:
		return true
	}
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
	operatorApprovalEvidenceSource := ""
	operatorApprovalEvidenceTrusted := false
	operatorApprovalEvidenceLock := ""
	if app, ok := s.gpmState.getOperator(walletAddress); ok {
		status := strings.ToLower(strings.TrimSpace(app.Status))
		switch status {
		case "approved", "pending", "rejected":
			operatorApplicationStatus = status
		default:
			operatorApplicationStatus = "pending"
		}
		chainOperatorID = strings.TrimSpace(app.ChainOperatorID)
		operatorApprovalEvidenceSource = strings.TrimSpace(app.ApprovalEvidenceSource)
		operatorApprovalEvidenceTrusted = gpmOperatorApprovalEvidenceTrusted(app)
		operatorApprovalEvidenceLock = s.gpmProductionOperatorApprovalEvidenceLock(app)
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
			operatorApprovalEvidenceLock == "" &&
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
				if operatorApprovalEvidenceLock != "" {
					lockReason = operatorApprovalEvidenceLock
					unlockActions = append(unlockActions,
						"Wait for chain-governance approval evidence to sync",
						"Refresh or rotate session after approval evidence is available",
					)
				} else {
					lockReason = "operator session is out of sync with approved application"
				}
				if strings.TrimSpace(strictChainBindingReason) != "" && operatorApprovalEvidenceLock == "" {
					lockReason = fmt.Sprintf("%s: %s", lockReason, strictChainBindingReason)
				}
				switch {
				case operatorApprovalEvidenceLock != "":
					// unlock actions were added above.
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
		"wallet_address":                     walletAddress,
		"role":                               role,
		"session_present":                    sessionPresent,
		"operator_application_status":        operatorApplicationStatus,
		"operator_approval_evidence_source":  operatorApprovalEvidenceSource,
		"operator_approval_evidence_trusted": operatorApprovalEvidenceTrusted,
		"chain_operator_id":                  chainOperatorID,
		"session_chain_operator_id":          sessionChainOperatorID,
		"tab_visible":                        tabVisible,
		"client_tab_visible":                 clientTabVisible,
		"client_registration_status":         clientRegistrationStatus,
		"client_registration_reason":         clientRegistrationReason,
		"lifecycle_actions_unlocked":         lifecycleActionsUnlocked,
		"chain_binding_status":               chainBindingStatus,
		"chain_binding_ok":                   chainBindingOK,
		"chain_binding_reason":               chainBindingReason,
		"service_mutations_configured":       serviceMutationsConfigured,
		"client_lock_reason":                 clientLockReason,
		"lock_reason":                        lockReason,
		"unlock_actions":                     unlockActions,
		"endpoint_posture":                   endpointPosture,
		"endpoint_warnings":                  endpointWarnings,
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

func (st *gpmRuntimeState) activeRewardHoldsFor(walletAddress string, weekStartUTC string) []gpmRewardHold {
	st.mu.RLock()
	defer st.mu.RUnlock()
	wallet := normalizeWalletAddress(walletAddress)
	week := strings.TrimSpace(weekStartUTC)
	if wallet == "" || week == "" {
		return nil
	}
	holds := st.rewardHolds[wallet]
	out := make([]gpmRewardHold, 0, len(holds))
	for _, hold := range holds {
		if strings.TrimSpace(hold.WeekStartUTC) != week {
			continue
		}
		if strings.ToLower(strings.TrimSpace(hold.Status)) != "active" {
			continue
		}
		out = append(out, hold)
	}
	return out
}

func (st *gpmRuntimeState) rewardHoldsFor(walletAddress string) []gpmRewardHold {
	st.mu.RLock()
	defer st.mu.RUnlock()
	wallet := normalizeWalletAddress(walletAddress)
	holds := st.rewardHolds[wallet]
	out := make([]gpmRewardHold, len(holds))
	copy(out, holds)
	return out
}

func (st *gpmRuntimeState) upsertRewardHold(hold gpmRewardHold) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rewardHolds == nil {
		st.rewardHolds = map[string][]gpmRewardHold{}
	}
	wallet := normalizeWalletAddress(hold.WalletAddress)
	if wallet == "" {
		return
	}
	hold.WalletAddress = wallet
	holds := st.rewardHolds[wallet]
	for i := range holds {
		if strings.TrimSpace(holds[i].HoldID) == strings.TrimSpace(hold.HoldID) {
			holds[i] = hold
			st.rewardHolds[wallet] = holds
			return
		}
	}
	st.rewardHolds[wallet] = append(holds, hold)
}

func (st *gpmRuntimeState) releaseActiveRewardHolds(walletAddress string, weekStartUTC string, releasedBy string, now time.Time) []gpmRewardHold {
	st.mu.Lock()
	defer st.mu.Unlock()
	wallet := normalizeWalletAddress(walletAddress)
	week := strings.TrimSpace(weekStartUTC)
	if wallet == "" || week == "" {
		return nil
	}
	holds := st.rewardHolds[wallet]
	released := make([]gpmRewardHold, 0)
	for i := range holds {
		if strings.TrimSpace(holds[i].WeekStartUTC) != week {
			continue
		}
		if strings.ToLower(strings.TrimSpace(holds[i].Status)) != "active" {
			continue
		}
		holds[i].Status = "released"
		holds[i].ReleasedBy = normalizeWalletAddress(releasedBy)
		holds[i].UpdatedAt = now
		released = append(released, holds[i])
	}
	st.rewardHolds[wallet] = holds
	return released
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
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(in.SessionToken)
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	walletAddress := normalizeWalletAddress(session.WalletAddress)
	if !session.WalletBindingVerified || walletAddress == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wallet-bound session is required for operator application"})
		return
	}
	chainOperatorID := strings.TrimSpace(in.ChainOperatorID)
	if chainOperatorID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "chain_operator_id is required"})
		return
	}
	app := gpmOperatorApplication{
		WalletAddress:   walletAddress,
		ChainOperatorID: chainOperatorID,
		ServerLabel:     strings.TrimSpace(in.ServerLabel),
		Status:          "pending",
		UpdatedAt:       time.Now().UTC(),
	}
	if !s.gpmState.upsertOperator(app) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "operator application store is temporarily saturated; retry later",
		})
		return
	}
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
	sessionToken := strings.TrimSpace(in.SessionToken)
	if sessionToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token is required"})
		return
	}
	session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(sessionToken)
	if policyErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
		})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "session not found"})
		return
	}
	walletAddress := normalizeWalletAddress(in.WalletAddress)
	sessionWallet := normalizeWalletAddress(session.WalletAddress)
	if walletAddress == "" {
		walletAddress = sessionWallet
	} else if walletAddress != sessionWallet {
		if _, ok := s.gpmAdminSessionFromTokenForResponse(w, sessionToken); !ok {
			return
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
	if _, ok := s.gpmAdminSessionFromTokenForResponse(w, sessionToken); !ok {
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
		if _, ok := s.gpmAdminSessionFromTokenForResponse(w, sessionToken); !ok {
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
		currentUpdatedAtUTC := gpmOperatorPreconditionTimestamp(app.UpdatedAt)
		if !gpmOperatorPreconditionTimestamp(ifUpdatedAtUTC).Equal(currentUpdatedAtUTC) {
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
	if s.isGPMProductionMode() {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "production operator approval requires trusted chain-governance approval evidence; local admin approval decisions are disabled",
		})
		return
	}
	app.Status = decision
	app.Reason = reason
	app.ApprovalEvidenceSource = decisionAuth
	app.UpdatedAt = gpmOperatorPreconditionTimestamp(time.Now().UTC())
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

func gpmOperatorPreconditionTimestamp(ts time.Time) time.Time {
	return ts.UTC().Truncate(time.Second)
}

func serializeGPMSession(session gpmSession) map[string]any {
	return map[string]any{
		"wallet_address":               session.WalletAddress,
		"wallet_provider":              session.WalletProvider,
		"chain_id":                     strings.TrimSpace(session.ChainID),
		"role":                         session.Role,
		"wallet_binding_verified":      session.WalletBindingVerified,
		"entitlement_evidence_source":  strings.TrimSpace(session.EntitlementEvidenceSource),
		"entitlement_evidence_trusted": gpmEntitlementEvidenceTrusted(session),
		"client_tier":                  gpmEffectiveClientTier(session),
		"stake_satisfied":              gpmEffectiveStakeSatisfied(session),
		"prepaid_balance_satisfied":    gpmEffectivePrepaidSatisfied(session),
		"created_at_utc":               session.CreatedAt.Format(time.RFC3339),
		"expires_at_utc":               session.ExpiresAt.Format(time.RFC3339),
		"bootstrap_directory":          strings.TrimSpace(session.BootstrapDirectory),
		"bootstrap_directories":        sessionTrustedBootstrapDirectories(session),
		"path_profile":                 strings.TrimSpace(session.PathProfile),
		"chain_operator_id":            strings.TrimSpace(session.ChainOperatorID),
	}
}

func serializeGPMFundReservation(reservation settlement.FundReservation) map[string]any {
	return map[string]any{
		"reservation_id":    reservation.ReservationID,
		"session_id":        reservation.SessionID,
		"subject_id":        reservation.SubjectID,
		"amount_micros":     reservation.AmountMicros,
		"currency":          reservation.Currency,
		"created_at_utc":    reservation.CreatedAt.UTC().Format(time.RFC3339),
		"idempotent_replay": reservation.IdempotentReplay,
		"status":            string(reservation.Status),
	}
}

func serializeGPMOperator(app gpmOperatorApplication) map[string]any {
	return map[string]any{
		"wallet_address":            app.WalletAddress,
		"chain_operator_id":         app.ChainOperatorID,
		"server_label":              app.ServerLabel,
		"status":                    app.Status,
		"reason":                    app.Reason,
		"approval_evidence_source":  strings.TrimSpace(app.ApprovalEvidenceSource),
		"approval_evidence_trusted": gpmOperatorApprovalEvidenceTrusted(app),
		"updated_at_utc":            app.UpdatedAt.Format(time.RFC3339),
	}
}

func normalizeGPMAdminWalletAllowlist(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		wallet := normalizeWalletAddress(part)
		if wallet == "" {
			continue
		}
		out[wallet] = struct{}{}
	}
	return out
}

func (s *Service) gpmAdminWalletAllowed(walletAddress string) bool {
	if s == nil || len(s.gpmAdminWalletAllowlist) == 0 {
		return false
	}
	_, ok := s.gpmAdminWalletAllowlist[normalizeWalletAddress(walletAddress)]
	return ok
}

func gpmAuthVerificationSource(walletBindingVerified bool, commandRaw string) string {
	if !walletBindingVerified {
		return ""
	}
	if strings.TrimSpace(commandRaw) != "" {
		return "command"
	}
	return "local_wallet"
}

func (s *Service) gpmAdminSessionVerificationAllowed(session gpmSession) bool {
	if !session.WalletBindingVerified {
		return false
	}
	if strings.ToLower(strings.TrimSpace(session.AuthVerificationSource)) != "command" {
		return false
	}
	return strings.TrimSpace(s.gpmAuthVerifyCommand) != ""
}

func (s *Service) gpmCurrentAuthPolicyFingerprint() string {
	if s == nil {
		return ""
	}
	policy := struct {
		Mode                       string `json:"mode"`
		RequireCommand             bool   `json:"require_command"`
		RequireMetadata            bool   `json:"require_metadata"`
		RequireWalletExtension     bool   `json:"require_wallet_extension"`
		RequireCryptoProof         bool   `json:"require_crypto_proof"`
		CommandConfigured          bool   `json:"command_configured"`
		ExpectedChainID            string `json:"expected_chain_id,omitempty"`
		ExpectedWalletHRP          string `json:"expected_wallet_hrp,omitempty"`
		ExpectedChainIDSource      string `json:"expected_chain_id_source,omitempty"`
		ExpectedWalletHRPSource    string `json:"expected_wallet_hrp_source,omitempty"`
		RequireCommandSource       string `json:"require_command_source,omitempty"`
		RequireMetadataSource      string `json:"require_metadata_source,omitempty"`
		RequireWalletExtSource     string `json:"require_wallet_extension_source,omitempty"`
		RequireCryptoProofSource   string `json:"require_crypto_proof_source,omitempty"`
		AuthVerificationPolicyMode string `json:"auth_verification_policy_mode,omitempty"`
	}{
		Mode:                       strings.TrimSpace(s.gpmAuthVerifyPolicyMode),
		RequireCommand:             s.gpmAuthVerifyRequireCommand,
		RequireMetadata:            s.gpmAuthVerifyRequireMetadata,
		RequireWalletExtension:     s.gpmAuthVerifyRequireWalletExt,
		RequireCryptoProof:         s.gpmAuthVerifyRequireCryptoProof,
		CommandConfigured:          strings.TrimSpace(s.gpmAuthVerifyCommand) != "",
		ExpectedChainID:            strings.TrimSpace(s.gpmAuthExpectedChainID),
		ExpectedWalletHRP:          strings.ToLower(strings.TrimSpace(s.gpmAuthExpectedWalletHRP)),
		ExpectedChainIDSource:      strings.TrimSpace(s.gpmAuthExpectedChainIDSource),
		ExpectedWalletHRPSource:    strings.TrimSpace(s.gpmAuthExpectedWalletHRPSource),
		RequireCommandSource:       strings.TrimSpace(s.gpmAuthVerifyRequireCmdSource),
		RequireMetadataSource:      strings.TrimSpace(s.gpmAuthVerifyMetadataSource),
		RequireWalletExtSource:     strings.TrimSpace(s.gpmAuthVerifyWalletExtSource),
		RequireCryptoProofSource:   strings.TrimSpace(s.gpmAuthVerifyCryptoSource),
		AuthVerificationPolicyMode: strings.TrimSpace(s.gpmAuthVerifyPolicyMode),
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
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

func normalizeGPMAuthSignaturePublicKeyType(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimPrefix(value, "type.googleapis.com/")
	switch value {
	case "secp256k1",
		"secp256k1pubkey",
		"pubkeysecp256k1",
		"tendermint/pubkeysecp256k1",
		"cosmos.crypto.secp256k1.pubkey",
		"/cosmos.crypto.secp256k1.pubkey",
		"ethermint.crypto.v1.ethsecp256k1.pubkey",
		"/ethermint.crypto.v1.ethsecp256k1.pubkey":
		return "secp256k1"
	case "ed25519",
		"ed25519pubkey",
		"pubkeyed25519",
		"tendermint/pubkeyed25519",
		"cosmos.crypto.ed25519.pubkey",
		"/cosmos.crypto.ed25519.pubkey":
		return "ed25519"
	default:
		return value
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

func (s *Service) gpmAuthChallengeChainID(requestedChainID string) (string, error) {
	requestedChainID = strings.TrimSpace(requestedChainID)
	expectedChainID := strings.TrimSpace(s.gpmAuthExpectedChainID)
	if expectedChainID == "" {
		return requestedChainID, nil
	}
	if requestedChainID != "" && !subtleEqual(requestedChainID, expectedChainID) {
		return "", fmt.Errorf("chain_id %q does not match expected wallet chain policy", requestedChainID)
	}
	return expectedChainID, nil
}

func (s *Service) validateGPMAuthVerifyChainID(challenge gpmWalletChallenge, providedChainID string) (string, error) {
	providedChainID = strings.TrimSpace(providedChainID)
	expectedChainID := strings.TrimSpace(s.gpmAuthExpectedChainID)
	challengeChainID := strings.TrimSpace(challenge.ChainID)
	if expectedChainID != "" {
		if challengeChainID == "" {
			return "", errors.New("issued challenge was not chain-bound by current wallet chain policy")
		}
		if !subtleEqual(challengeChainID, expectedChainID) {
			return "", errors.New("issued challenge chain_id does not match current wallet chain policy")
		}
		if providedChainID == "" {
			return "", errors.New("chain_id is required by wallet chain policy")
		}
		if !subtleEqual(providedChainID, expectedChainID) {
			return "", fmt.Errorf("chain_id %q does not match expected wallet chain policy", providedChainID)
		}
	}
	if challengeChainID != "" {
		if providedChainID == "" {
			return "", errors.New("chain_id is required because the issued challenge was chain-bound")
		}
		if !subtleEqual(providedChainID, challengeChainID) {
			return "", errors.New("chain_id does not match issued challenge")
		}
		return challengeChainID, nil
	}
	if providedChainID != "" {
		return "", errors.New("chain_id was not part of the issued challenge")
	}
	return providedChainID, nil
}

func (s *Service) validateGPMAuthWalletHRP(walletAddress string) error {
	expectedHRP := strings.ToLower(strings.TrimSpace(s.gpmAuthExpectedWalletHRP))
	if expectedHRP == "" {
		return nil
	}
	hrp, _, _, err := parseGPMBech32Address(walletAddress)
	if err != nil {
		return fmt.Errorf("wallet_address must be a valid bech32 address for wallet HRP policy: %w", err)
	}
	if !subtleEqual(hrp, expectedHRP) {
		return fmt.Errorf("wallet_address HRP %q does not match expected wallet HRP policy", hrp)
	}
	return nil
}

func (s *Service) validateGPMSessionWalletPolicy(session gpmSession) error {
	if s == nil || !session.WalletBindingVerified {
		return nil
	}
	if mintedPolicy := strings.TrimSpace(session.AuthPolicyFingerprint); mintedPolicy != "" {
		currentPolicy := s.gpmCurrentAuthPolicyFingerprint()
		if currentPolicy == "" {
			return errors.New("current wallet auth policy fingerprint is unavailable")
		}
		if !subtleEqual(mintedPolicy, currentPolicy) {
			return errors.New("session was minted under a different wallet auth policy")
		}
	}
	expectedChainID := strings.TrimSpace(s.gpmAuthExpectedChainID)
	sessionChainID := strings.TrimSpace(session.ChainID)
	if expectedChainID != "" {
		if sessionChainID == "" {
			return errors.New("session chain_id is missing")
		}
		if !subtleEqual(sessionChainID, expectedChainID) {
			return fmt.Errorf("session chain_id %q does not match expected wallet chain policy", sessionChainID)
		}
	}
	if err := s.validateGPMAuthWalletHRP(session.WalletAddress); err != nil {
		return err
	}
	return nil
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

const gpmBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var gpmBech32Generator = [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func gpmBech32CharsetIndex(r byte) int {
	return strings.IndexByte(gpmBech32Charset, r)
}

func gpmBech32HRPExpand(hrp string) []byte {
	expanded := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]>>5)
	}
	expanded = append(expanded, 0)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]&31)
	}
	return expanded
}

func gpmBech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, value := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(value)
		for i := 0; i < len(gpmBech32Generator); i++ {
			if ((top >> uint(i)) & 1) != 0 {
				chk ^= gpmBech32Generator[i]
			}
		}
	}
	return chk
}

func gpmBech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(gpmBech32HRPExpand(hrp), data...)
	values = append(values, make([]byte, gpmBech32ChecksumLength)...)
	polymod := gpmBech32Polymod(values) ^ 1
	checksum := make([]byte, gpmBech32ChecksumLength)
	for i := 0; i < gpmBech32ChecksumLength; i++ {
		checksum[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return checksum
}

func gpmBech32VerifyChecksum(hrp string, data []byte) bool {
	return gpmBech32Polymod(append(gpmBech32HRPExpand(hrp), data...)) == 1
}

func gpmBech32ConvertBits(data []byte, fromBits uint, toBits uint, pad bool) ([]byte, error) {
	acc := uint(0)
	bits := uint(0)
	maxv := uint((1 << toBits) - 1)
	maxAcc := uint((1 << (fromBits + toBits - 1)) - 1)
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits))
	for _, value := range data {
		v := uint(value)
		if v>>fromBits != 0 {
			return nil, errors.New("bech32 data value exceeds bit group size")
		}
		acc = ((acc << fromBits) | v) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("bech32 data has invalid padding")
	}
	return out, nil
}

func encodeGPMBech32Address(hrp string, payload []byte) (string, error) {
	hrp = strings.ToLower(strings.TrimSpace(hrp))
	if hrp == "" {
		return "", errors.New("bech32 hrp is required")
	}
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 || hrp[i] == '1' {
			return "", errors.New("bech32 hrp contains invalid characters")
		}
	}
	data, err := gpmBech32ConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	combined := append(append([]byte{}, data...), gpmBech32CreateChecksum(hrp, data)...)
	var b strings.Builder
	b.Grow(len(hrp) + 1 + len(combined))
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, value := range combined {
		if int(value) >= len(gpmBech32Charset) {
			return "", errors.New("bech32 data value out of range")
		}
		b.WriteByte(gpmBech32Charset[value])
	}
	return b.String(), nil
}

func parseGPMBech32Address(raw string) (string, []byte, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil, "", errors.New("bech32 address is required")
	}
	hasLower := false
	hasUpper := false
	for i := 0; i < len(value); i++ {
		if value[i] < 33 || value[i] > 126 {
			return "", nil, "", errors.New("bech32 address contains invalid characters")
		}
		if value[i] >= 'a' && value[i] <= 'z' {
			hasLower = true
		}
		if value[i] >= 'A' && value[i] <= 'Z' {
			hasUpper = true
		}
	}
	if hasLower && hasUpper {
		return "", nil, "", errors.New("bech32 address mixes upper and lower case")
	}
	canonical := strings.ToLower(value)
	separator := strings.LastIndexByte(canonical, '1')
	if separator <= 0 || separator+gpmBech32ChecksumLength >= len(canonical) {
		return "", nil, "", errors.New("bech32 address separator or checksum is invalid")
	}
	hrp := canonical[:separator]
	dataPart := canonical[separator+1:]
	data := make([]byte, len(dataPart))
	for i := range dataPart {
		idx := gpmBech32CharsetIndex(dataPart[i])
		if idx < 0 {
			return "", nil, "", errors.New("bech32 address contains invalid data character")
		}
		data[i] = byte(idx)
	}
	if !gpmBech32VerifyChecksum(hrp, data) {
		return "", nil, "", errors.New("bech32 address checksum is invalid")
	}
	payload, err := gpmBech32ConvertBits(data[:len(data)-gpmBech32ChecksumLength], 5, 8, false)
	if err != nil {
		return "", nil, "", err
	}
	if len(payload) != ripemd160.Size {
		return "", nil, "", fmt.Errorf("bech32 address payload must be %d bytes", ripemd160.Size)
	}
	return hrp, payload, canonical, nil
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

func encodeGPMAuthSecp256k1CompressedPublicKey(x *big.Int, y *big.Int) ([]byte, error) {
	if !secp256k1IsOnCurve(x, y) {
		return nil, errors.New("signature_public_key is not a valid secp256k1 point")
	}
	compressed := make([]byte, 33)
	compressed[0] = 0x02
	if y.Bit(0) == 1 {
		compressed[0] = 0x03
	}
	xBytes := x.Bytes()
	if len(xBytes) > 32 {
		return nil, errors.New("signature_public_key has invalid secp256k1 X coordinate")
	}
	copy(compressed[33-len(xBytes):], xBytes)
	return compressed, nil
}

func decodeGPMAuthSecp256k1CompressedPublicKey(publicKeyRaw string) ([]byte, error) {
	x, y, err := decodeGPMAuthSecp256k1PublicKey(publicKeyRaw)
	if err != nil {
		return nil, err
	}
	return encodeGPMAuthSecp256k1CompressedPublicKey(x, y)
}

func deriveGPMAuthCosmosBech32AddressFromSecp256k1PublicKey(hrp string, publicKeyRaw string) (string, error) {
	compressedPublicKey, err := decodeGPMAuthSecp256k1CompressedPublicKey(publicKeyRaw)
	if err != nil {
		return "", err
	}
	sha := sha256.Sum256(compressedPublicKey)
	ripemd := ripemd160.New()
	if _, err := ripemd.Write(sha[:]); err != nil {
		return "", err
	}
	return encodeGPMBech32Address(hrp, ripemd.Sum(nil))
}

func verifyGPMAuthSecp256k1WalletAddressBinding(walletAddress string, publicKeyRaw string) (bool, error) {
	hrp, _, canonicalWalletAddress, err := parseGPMBech32Address(walletAddress)
	if err != nil {
		return false, nil
	}
	derivedAddress, err := deriveGPMAuthCosmosBech32AddressFromSecp256k1PublicKey(hrp, publicKeyRaw)
	if err != nil {
		return false, err
	}
	return subtleEqual(canonicalWalletAddress, derivedAddress), nil
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

func (s *Service) verifyGPMAuthSignature(ctx context.Context, challenge gpmWalletChallenge, walletAddress string, walletProvider string, signature string, signatureMetadata gpmAuthSignatureMetadata) (bool, error) {
	if err := s.validateGPMAuthSignaturePolicy(signatureMetadata); err != nil {
		return false, err
	}
	if err := validateGPMAuthSignatureMetadata(challenge, signatureMetadata); err != nil {
		return false, err
	}
	verifier := s.gpmAuthSignatureVerifier
	if verifier == nil {
		verifier = defaultGPMAuthSignatureVerifier
	}
	if err := verifier(challenge, walletAddress, walletProvider, signature); err != nil {
		return false, err
	}
	if err := s.verifyGPMAuthSignatureCryptographicProof(signature, signatureMetadata); err != nil {
		return false, err
	}
	if s.gpmAuthVerifyRequireCommand && strings.TrimSpace(s.gpmAuthVerifyCommand) == "" {
		s.appendGPMAuthVerifyFailureAudit(challenge, walletAddress, walletProvider, "verifier_command_required", "policy")
		return false, errors.New("signature verifier command is required by policy")
	}
	walletBindingVerified := false
	if signatureMetadata.SignaturePublicKeyType == "secp256k1" && strings.TrimSpace(signatureMetadata.SignaturePublicKey) != "" {
		localWalletBindingVerified, err := verifyGPMAuthSecp256k1WalletAddressBinding(walletAddress, signatureMetadata.SignaturePublicKey)
		if err != nil {
			return false, err
		}
		walletBindingVerified = localWalletBindingVerified
	}
	if strings.TrimSpace(s.gpmAuthVerifyCommand) != "" {
		if err := s.runGPMAuthVerifierCommand(ctx, challenge, walletAddress, walletProvider, signature, signatureMetadata); err != nil {
			s.appendGPMAuthVerifyFailureAudit(challenge, walletAddress, walletProvider, "verifier_command_error", "external_verifier")
			return false, err
		}
	}
	if s.gpmAuthVerifyRequireCryptoProof && !walletBindingVerified {
		s.appendGPMAuthVerifyFailureAudit(challenge, walletAddress, walletProvider, "wallet_binding_verifier_required", "policy")
		return false, errors.New("wallet-bound signature verifier command is required by strict cryptographic proof policy unless local address binding matches")
	}
	return walletBindingVerified, nil
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
	release, err := s.acquireCommandSlot()
	if err != nil {
		return errors.New("signature verifier command concurrency limit reached")
	}
	defer release()
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
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("signature verifier command rejected signature (rc=%d)", exitErr.ExitCode())
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
	manifestURL := canonicalizeManifestSourceURLOrRaw(s.gpmManifestURL)
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
	manifestURL = canonicalizeManifestSourceURLOrRaw(manifestURL)
	if pinnedHost != "" {
		manifestHost, hostErr := normalizeHTTPHost(manifestURL)
		if hostErr != nil {
			return gpmBootstrapManifest{}, false, nil, "", fmt.Errorf("gpm manifest url is invalid for pinned gpm main domain host %q: %w", pinnedHost, hostErr)
		}
		if manifestHost != pinnedHost {
			return gpmBootstrapManifest{}, false, nil, "", fmt.Errorf("gpm manifest url host mismatch: got %q, pinned gpm main domain host %q; update GPM_MAIN_DOMAIN or GPM_BOOTSTRAP_MANIFEST_URL", manifestHost, pinnedHost)
		}
	}
	if s.isProductionManifestTrustPolicy() {
		if err := validateProductionManifestOutboundURL(ctx, manifestURL); err != nil {
			return gpmBootstrapManifest{}, false, nil, "", err
		}
	}
	return s.fetchRemoteManifest(ctx, manifestURL)
}

func (s *Service) fetchRemoteManifest(ctx context.Context, manifestURL string) (gpmBootstrapManifest, bool, []byte, string, error) {
	client := s.manifestHTTPClient()
	client.Timeout = gpmManifestHTTPTimeout
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return errors.New("manifest endpoint redirect is not allowed")
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

func (s *Service) manifestHTTPClient() *http.Client {
	client := &http.Client{}
	if !s.isProductionManifestTrustPolicy() {
		return client
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = productionManifestDialContext
	client.Transport = transport
	return client
}

func (s *Service) isProductionManifestTrustPolicy() bool {
	return strings.EqualFold(strings.TrimSpace(s.gpmManifestTrustPolicyMode), "production")
}

func productionManifestDialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("production manifest outbound policy rejected invalid target %q: %w", address, err)
	}
	addrs, err := resolveManifestOutboundIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("production manifest outbound policy failed to resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("production manifest outbound policy failed to resolve %q: no addresses", host)
	}
	for _, addr := range addrs {
		if err := validateProductionManifestOutboundIP(host, addr.IP); err != nil {
			return nil, err
		}
	}

	dialer := net.Dialer{Timeout: gpmManifestHTTPTimeout}
	var lastErr error
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("production manifest outbound policy failed to resolve %q: no usable addresses", host)
}

func validateProductionManifestOutboundURL(ctx context.Context, manifestURL string) error {
	parsed, err := parseManifestSourceURL(manifestURL)
	if err != nil {
		return fmt.Errorf("production manifest outbound policy rejected invalid manifest url: %w", err)
	}
	addrs, err := resolveManifestOutboundIPs(ctx, parsed.Hostname())
	if err != nil {
		return fmt.Errorf("production manifest outbound policy failed to resolve %q: %w", parsed.Hostname(), err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("production manifest outbound policy failed to resolve %q: no addresses", parsed.Hostname())
	}
	for _, addr := range addrs {
		if err := validateProductionManifestOutboundIP(parsed.Hostname(), addr.IP); err != nil {
			return err
		}
	}
	return nil
}

func resolveManifestOutboundIPs(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return nil, errors.New("host is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	resolveCtx, cancel := context.WithTimeout(ctx, hostResolveTimeout)
	defer cancel()
	return lookupIPAddr(resolveCtx, host)
}

func validateProductionManifestOutboundIP(host string, ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("production manifest outbound policy rejected %q: resolved address is empty", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("production manifest outbound policy rejected %q: resolved address %s is private, loopback, or link-local", host, ip.String())
	}
	if isSharedAddressSpaceCGNATIP(ip) {
		return fmt.Errorf("production manifest outbound policy rejected %q: resolved address %s is shared address space (100.64.0.0/10)", host, ip.String())
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("production manifest outbound policy rejected %q: resolved address %s is not a public unicast target", host, ip.String())
	}
	if isReservedOrTestOutboundIP(ip) {
		return fmt.Errorf("production manifest outbound policy rejected %q: resolved address %s is reserved or test-only", host, ip.String())
	}
	return nil
}

func isSharedAddressSpaceCGNATIP(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	return ipv4[0] == 100 && ipv4[1]&0xc0 == 0x40
}

func isReservedOrTestOutboundIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, prefix := range reservedOrTestOutboundIPPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

var reservedOrTestOutboundIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func validateBootstrapManifest(manifest gpmBootstrapManifest) error {
	if manifest.Version != 1 {
		return fmt.Errorf("manifest version must be 1, got %d", manifest.Version)
	}
	if len(manifest.BootstrapDirectories) == 0 {
		return errors.New("manifest bootstrap_directories is empty")
	}
	if len(manifest.BootstrapDirectories) > gpmManifestBootstrapDirectoryMax {
		return fmt.Errorf("manifest bootstrap_directories has %d items, max %d", len(manifest.BootstrapDirectories), gpmManifestBootstrapDirectoryMax)
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
	if expiresAt.Sub(generatedAt) > gpmManifestMaxValidity {
		return fmt.Errorf("manifest validity window exceeds maximum %s", gpmManifestMaxValidity)
	}
	now := time.Now().UTC()
	if generatedAt.After(now.Add(gpmManifestCacheFutureSkew)) {
		return errors.New("manifest generated_at_utc is in the future")
	}
	if !expiresAt.After(now) {
		return errors.New("manifest is expired")
	}
	for _, dir := range manifest.BootstrapDirectories {
		dir = strings.TrimSpace(dir)
		if err := validateBootstrapDirectoryURL(dir); err != nil {
			return fmt.Errorf("manifest bootstrap directory invalid: %w", err)
		}
	}
	if err := validateBootstrapURLHints("gateway_mirrors", manifest.GatewayMirrors, 32); err != nil {
		return err
	}
	if err := validateBootstrapURLHints("bootstrap_sources", manifest.BootstrapSources, 64); err != nil {
		return err
	}
	if err := validateBootstrapRelayHints(manifest.RelayHints); err != nil {
		return err
	}
	if err := validateBootstrapBridgeHints(manifest.BridgeHints); err != nil {
		return err
	}
	return nil
}

func normalizeBootstrapManifest(manifest gpmBootstrapManifest) gpmBootstrapManifest {
	manifest.BootstrapDirectories = normalizeBootstrapDirectories(manifest.BootstrapDirectories)
	manifest.GatewayMirrors = normalizeBootstrapURLHints(manifest.GatewayMirrors)
	manifest.BootstrapSources = normalizeBootstrapURLHints(manifest.BootstrapSources)
	manifest.RelayHints = normalizeBootstrapRelayHints(manifest.RelayHints)
	manifest.BridgeHints = normalizeBootstrapBridgeHints(manifest.BridgeHints)
	return manifest
}

func validateBootstrapURLHints(field string, hints []gpmBootstrapURLHint, maxItems int) error {
	if len(hints) > maxItems {
		return fmt.Errorf("manifest %s has %d items, max %d", field, len(hints), maxItems)
	}
	for i, hint := range hints {
		prefix := fmt.Sprintf("manifest %s[%d]", field, i)
		if err := validateManifestText(prefix+".url", hint.URL, 240, true); err != nil {
			return err
		}
		if err := validateBootstrapHintHTTPSURL(prefix+".url", hint.URL); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".kind", hint.Kind, 64, true); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".operator_id", hint.OperatorID, 128, false); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".key_id", hint.KeyID, 160, false); err != nil {
			return err
		}
		if err := validateOptionalManifestTime(prefix+".expires_at_utc", hint.ExpiresAtUTC); err != nil {
			return err
		}
	}
	return nil
}

func validateBootstrapRelayHints(hints []gpmBootstrapRelayHint) error {
	if len(hints) > 128 {
		return fmt.Errorf("manifest relay_hints has %d items, max 128", len(hints))
	}
	for i, hint := range hints {
		prefix := fmt.Sprintf("manifest relay_hints[%d]", i)
		if err := validateManifestText(prefix+".relay_id", hint.RelayID, 128, true); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".operator_id", hint.OperatorID, 128, true); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".directory_url", hint.DirectoryURL, 240, false); err != nil {
			return err
		}
		if strings.TrimSpace(hint.DirectoryURL) != "" {
			if err := validateBootstrapDirectoryURL(hint.DirectoryURL); err != nil {
				return fmt.Errorf("%s.directory_url invalid: %w", prefix, err)
			}
		}
		if err := validateManifestText(prefix+".entry_url", hint.EntryURL, 240, false); err != nil {
			return err
		}
		if strings.TrimSpace(hint.EntryURL) != "" {
			if err := validateBootstrapHintHTTPSURL(prefix+".entry_url", hint.EntryURL); err != nil {
				return err
			}
		}
		if err := validateManifestText(prefix+".public_host", hint.PublicHost, 180, false); err != nil {
			return err
		}
		if strings.TrimSpace(hint.PublicHost) != "" {
			if err := validateBootstrapHintPublicHost(prefix+".public_host", hint.PublicHost); err != nil {
				return err
			}
		}
		if err := validateManifestText(prefix+".country", hint.Country, 2, false); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".region", hint.Region, 80, false); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".hint_source", hint.HintSource, 64, true); err != nil {
			return err
		}
		if err := validateOptionalManifestTime(prefix+".expires_at_utc", hint.ExpiresAtUTC); err != nil {
			return err
		}
	}
	return nil
}

func validateBootstrapBridgeHints(hints []gpmBootstrapBridgeHint) error {
	if len(hints) > 64 {
		return fmt.Errorf("manifest bridge_hints has %d items, max 64", len(hints))
	}
	for i, hint := range hints {
		prefix := fmt.Sprintf("manifest bridge_hints[%d]", i)
		if err := validateManifestText(prefix+".bridge_id", hint.BridgeID, 128, true); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".operator_id", hint.OperatorID, 128, false); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".endpoint", hint.Endpoint, 240, true); err != nil {
			return err
		}
		if err := validateBootstrapHintHTTPSURL(prefix+".endpoint", hint.Endpoint); err != nil {
			return err
		}
		if err := validateManifestText(prefix+".transport", hint.Transport, 32, true); err != nil {
			return err
		}
		if !strings.EqualFold(strings.TrimSpace(hint.Transport), "https") {
			return fmt.Errorf("%s.transport unsupported: must be https", prefix)
		}
		if err := validateManifestText(prefix+".rate_limit_class", hint.RateLimitClass, 32, false); err != nil {
			return err
		}
		if err := validateOptionalManifestTime(prefix+".expires_at_utc", hint.ExpiresAtUTC); err != nil {
			return err
		}
	}
	return nil
}

func validateBootstrapHintHTTPSURL(field string, raw string) error {
	parsed, err := parseManifestSourceURL(raw)
	if err != nil {
		return fmt.Errorf("%s invalid: %w", field, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("%s must use https", field)
	}
	if err := validateBootstrapHintPublicHost(field+".host", parsed.Hostname()); err != nil {
		return err
	}
	return nil
}

func validateBootstrapHintPublicHost(field string, raw string) error {
	host, ip, err := parseBootstrapHintHost(raw)
	if err != nil {
		return fmt.Errorf("%s invalid: %w", field, err)
	}
	if ip != nil {
		return validateProductionManifestOutboundIP(host, ip)
	}
	if err := validatePublicBootstrapHintHostname(host); err != nil {
		return fmt.Errorf("%s invalid: %w", field, err)
	}
	addrs, err := resolveManifestOutboundIPs(context.Background(), host)
	if err != nil {
		return fmt.Errorf("%s failed to resolve %q: %w", field, host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%s failed to resolve %q: no addresses", field, host)
	}
	for _, addr := range addrs {
		if err := validateProductionManifestOutboundIP(host, addr.IP); err != nil {
			return err
		}
	}
	return nil
}

func parseBootstrapHintHost(raw string) (string, net.IP, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil, errors.New("host is required")
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "/?#@") {
		return "", nil, errors.New("host must not include scheme, path, query, fragment, or userinfo")
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), ip, nil
	}
	host := strings.Trim(value, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ip, nil
	}
	if strings.Contains(value, ":") {
		return "", nil, errors.New("host must not include a port")
	}
	return strings.ToLower(strings.TrimSuffix(value, ".")), nil, nil
}

func validatePublicBootstrapHintHostname(host string) error {
	if host == "" {
		return errors.New("host is required")
	}
	switch host {
	case "localhost", "localhost.localdomain", "example.com", "example.net", "example.org", "placeholder", "todo", "changeme":
		return errors.New("placeholder or local host is not allowed")
	}
	if !strings.Contains(host, ".") {
		return errors.New("single-label hosts are not allowed")
	}
	switch {
	case strings.HasSuffix(host, ".localhost"),
		strings.HasSuffix(host, ".local"),
		strings.HasSuffix(host, ".internal"),
		strings.HasSuffix(host, ".lan"),
		strings.HasSuffix(host, ".home"),
		strings.HasSuffix(host, ".test"),
		strings.HasSuffix(host, ".invalid"):
		return errors.New("internal or test host suffix is not allowed")
	}
	if len(host) > 253 {
		return errors.New("host exceeds max length 253")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return errors.New("host contains an empty label")
		}
		if len(label) > 63 {
			return errors.New("host label exceeds max length 63")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("host labels must not start or end with hyphen")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return errors.New("host contains invalid characters")
		}
	}
	return nil
}

func validateManifestText(field string, value string, maxLen int, required bool) error {
	trimmed := strings.TrimSpace(value)
	if required && trimmed == "" {
		return fmt.Errorf("%s is required", field)
	}
	if maxLen > 0 && len(trimmed) > maxLen {
		return fmt.Errorf("%s exceeds max length %d", field, maxLen)
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", field)
		}
	}
	return nil
}

func validateOptionalManifestTime(field string, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, trimmed); err != nil {
		return fmt.Errorf("%s invalid: %w", field, err)
	}
	return nil
}

func normalizeBootstrapURLHints(hints []gpmBootstrapURLHint) []gpmBootstrapURLHint {
	out := make([]gpmBootstrapURLHint, 0, len(hints))
	for _, hint := range hints {
		hint.URL = strings.TrimSpace(hint.URL)
		hint.Kind = strings.TrimSpace(hint.Kind)
		hint.OperatorID = strings.TrimSpace(hint.OperatorID)
		hint.KeyID = strings.TrimSpace(hint.KeyID)
		hint.ExpiresAtUTC = strings.TrimSpace(hint.ExpiresAtUTC)
		out = append(out, hint)
	}
	return out
}

func normalizeBootstrapRelayHints(hints []gpmBootstrapRelayHint) []gpmBootstrapRelayHint {
	out := make([]gpmBootstrapRelayHint, 0, len(hints))
	for _, hint := range hints {
		hint.RelayID = strings.TrimSpace(hint.RelayID)
		hint.OperatorID = strings.TrimSpace(hint.OperatorID)
		hint.DirectoryURL = strings.TrimSpace(hint.DirectoryURL)
		hint.EntryURL = strings.TrimSpace(hint.EntryURL)
		hint.PublicHost = strings.TrimSpace(hint.PublicHost)
		hint.Country = strings.ToUpper(strings.TrimSpace(hint.Country))
		hint.Region = strings.TrimSpace(hint.Region)
		hint.HintSource = strings.TrimSpace(hint.HintSource)
		hint.ExpiresAtUTC = strings.TrimSpace(hint.ExpiresAtUTC)
		out = append(out, hint)
	}
	return out
}

func normalizeBootstrapBridgeHints(hints []gpmBootstrapBridgeHint) []gpmBootstrapBridgeHint {
	out := make([]gpmBootstrapBridgeHint, 0, len(hints))
	for _, hint := range hints {
		hint.BridgeID = strings.TrimSpace(hint.BridgeID)
		hint.OperatorID = strings.TrimSpace(hint.OperatorID)
		hint.Endpoint = strings.TrimSpace(hint.Endpoint)
		hint.Transport = strings.TrimSpace(hint.Transport)
		hint.RateLimitClass = strings.TrimSpace(hint.RateLimitClass)
		hint.ExpiresAtUTC = strings.TrimSpace(hint.ExpiresAtUTC)
		out = append(out, hint)
	}
	return out
}

func normalizeBootstrapDirectories(directories []string) []string {
	normalized := make([]string, 0, len(directories))
	seen := map[string]struct{}{}
	for _, dir := range directories {
		candidate, err := canonicalizeBootstrapDirectoryURL(dir)
		if err != nil {
			candidate = strings.TrimSpace(dir)
		}
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		normalized = append(normalized, candidate)
	}
	return normalized
}

func sessionTrustedBootstrapDirectories(session gpmSession) []string {
	directories := normalizeBootstrapDirectories(session.BootstrapDirectories)
	if len(directories) == 0 {
		if preferred := strings.TrimSpace(session.BootstrapDirectory); preferred != "" {
			return normalizeBootstrapDirectories([]string{preferred})
		}
	}
	return directories
}

func sessionConnectBootstrapDirectories(session gpmSession) []string {
	preferred := strings.TrimSpace(session.BootstrapDirectory)
	trusted := sessionTrustedBootstrapDirectories(session)
	ordered := make([]string, 0, len(trusted)+1)
	appendIfMissing := func(candidate string) {
		normalized := normalizeBootstrapDirectories([]string{candidate})
		if len(normalized) == 0 {
			return
		}
		candidate = normalized[0]
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
		SourceURL:         canonicalizeManifestSourceURLOrRaw(s.gpmManifestURL),
		SignatureVerified: signatureVerified,
		Manifest:          manifest,
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
		cacheSourceURL = canonicalizeManifestSourceURLOrRaw(s.gpmManifestURL)
	}
	if err := s.validateManifestSourceURLPolicy(cacheSourceURL, pinnedHost, "cached manifest source url"); err != nil {
		return gpmTrustedBootstrapManifestCache{}, err
	}
	cacheSourceURL = canonicalizeManifestSourceURLOrRaw(cacheSourceURL)
	if s.isProductionManifestTrustPolicy() {
		if err := validateProductionManifestOutboundURL(context.Background(), cacheSourceURL); err != nil {
			return gpmTrustedBootstrapManifestCache{}, fmt.Errorf("cached manifest source url %w", err)
		}
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

func canonicalizeManifestSourceURL(raw string) (string, error) {
	parsed, err := parseManifestSourceURL(raw)
	if err != nil {
		return "", err
	}
	return canonicalizeParsedHTTPURL(parsed, false), nil
}

func canonicalizeManifestSourceURLOrRaw(raw string) string {
	canonical, err := canonicalizeManifestSourceURL(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return canonical
}

func (s *Service) readGPMGapSummarySnapshot() (gpmGapSummarySnapshot, string, error) {
	artifactPath := strings.TrimSpace(s.gpmGapScanSummaryPath)
	if artifactPath == "" {
		return gpmGapSummarySnapshot{}, "", fmt.Errorf("%w: path is empty", errGPMGapSummaryArtifactMissing)
	}

	body, err := readFileWithHardLimit(artifactPath, gpmGapScanSummaryBodyLimit)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return gpmGapSummarySnapshot{}, artifactPath, fmt.Errorf("%w: %s", errGPMGapSummaryArtifactMissing, artifactPath)
		}
		return gpmGapSummarySnapshot{}, artifactPath, fmt.Errorf("%w: %v", errGPMGapSummaryArtifactUnreadable, err)
	}

	var parsed gpmGapScanSummaryFile
	if err := json.Unmarshal(body, &parsed); err != nil {
		return gpmGapSummarySnapshot{}, artifactPath, fmt.Errorf("%w: invalid json: %v", errGPMGapSummaryArtifactMalformed, err)
	}

	summary, err := normalizeGPMGapSummary(parsed)
	if err != nil {
		return gpmGapSummarySnapshot{}, artifactPath, fmt.Errorf("%w: %v", errGPMGapSummaryArtifactMalformed, err)
	}
	return summary, artifactPath, nil
}

func normalizeGPMGapSummary(in gpmGapScanSummaryFile) (gpmGapSummarySnapshot, error) {
	schemaID := strings.TrimSpace(in.Schema.ID)
	if schemaID != "gpm_gap_scan_summary" {
		return gpmGapSummarySnapshot{}, fmt.Errorf("unsupported schema id %q", schemaID)
	}

	status := strings.TrimSpace(strings.ToLower(in.Status))
	if status != "ok" {
		return gpmGapSummarySnapshot{}, fmt.Errorf("artifact status must be ok, got %q", strings.TrimSpace(in.Status))
	}

	generatedAtUTC := strings.TrimSpace(in.GeneratedAtUTC)
	if generatedAtUTC == "" {
		return gpmGapSummarySnapshot{}, errors.New("generated_at_utc is required")
	}
	generatedAt, err := time.Parse(time.RFC3339, generatedAtUTC)
	if err != nil {
		return gpmGapSummarySnapshot{}, fmt.Errorf("generated_at_utc invalid: %w", err)
	}
	now := time.Now().UTC()
	if generatedAt.After(now.Add(gpmManifestCacheFutureSkew)) {
		return gpmGapSummarySnapshot{}, errors.New("generated_at_utc is in the future")
	}
	if now.Sub(generatedAt) > gpmGapSummaryMaxAge {
		return gpmGapSummarySnapshot{}, errors.New("artifact summary is stale")
	}

	if in.Counts.InProgress < 0 || in.Counts.MissingNext < 0 || in.Counts.Total < 0 {
		return gpmGapSummarySnapshot{}, errors.New("counts must be non-negative")
	}

	inProgress := make([]gpmGapScanSummaryItem, 0, len(in.Items))
	missingNext := make([]gpmGapScanSummaryItem, 0, len(in.Items))
	for idx, item := range in.Items {
		section := strings.TrimSpace(strings.ToLower(item.Section))
		text := strings.TrimSpace(item.Text)
		if text == "" {
			return gpmGapSummarySnapshot{}, fmt.Errorf("item[%d] text is required", idx)
		}
		if item.Ordinal <= 0 {
			return gpmGapSummarySnapshot{}, fmt.Errorf("item[%d] ordinal must be > 0", idx)
		}

		normalized := gpmGapScanSummaryItem{
			ID:             strings.TrimSpace(item.ID),
			Section:        section,
			Ordinal:        item.Ordinal,
			Text:           text,
			NormalizedText: strings.TrimSpace(item.NormalizedText),
		}
		switch section {
		case "in_progress":
			inProgress = append(inProgress, normalized)
		case "missing_next":
			missingNext = append(missingNext, normalized)
		default:
			return gpmGapSummarySnapshot{}, fmt.Errorf("item[%d] section %q is unsupported", idx, item.Section)
		}
	}

	if in.Counts.InProgress != len(inProgress) {
		return gpmGapSummarySnapshot{}, fmt.Errorf("counts.in_progress=%d does not match parsed items=%d", in.Counts.InProgress, len(inProgress))
	}
	if in.Counts.MissingNext != len(missingNext) {
		return gpmGapSummarySnapshot{}, fmt.Errorf("counts.missing_next=%d does not match parsed items=%d", in.Counts.MissingNext, len(missingNext))
	}
	expectedTotal := len(inProgress) + len(missingNext)
	if in.Counts.Total != expectedTotal {
		return gpmGapSummarySnapshot{}, fmt.Errorf("counts.total=%d does not match parsed items=%d", in.Counts.Total, expectedTotal)
	}

	return gpmGapSummarySnapshot{
		SchemaID:       schemaID,
		GeneratedAtUTC: generatedAtUTC,
		Counts: gpmGapSummaryCounts{
			InProgress:  len(inProgress),
			MissingNext: len(missingNext),
			Total:       expectedTotal,
		},
		InProgress:  inProgress,
		MissingNext: missingNext,
	}, nil
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

func canonicalizeParsedHTTPURL(parsed *urlpkg.URL, trimPathTrailingSlash bool) string {
	canonical := *parsed
	canonical.Scheme = strings.ToLower(strings.TrimSpace(canonical.Scheme))
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	port := strings.TrimSpace(parsed.Port())
	if isDefaultHTTPPort(canonical.Scheme, port) {
		port = ""
	}
	canonical.Host = canonicalURLHost(host, port)
	canonical.User = nil
	canonical.ForceQuery = false
	canonical.RawQuery = ""
	canonical.Fragment = ""
	if trimPathTrailingSlash && canonical.RawPath == "" {
		canonical.Path = strings.TrimRight(canonical.Path, "/")
	}
	return canonical.String()
}

func canonicalURLHost(host string, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func isDefaultHTTPPort(scheme string, port string) bool {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return port == "80"
	case "https":
		return port == "443"
	default:
		return false
	}
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
