package settlement

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"privacynode/internal/fileperm"
)

const (
	CosmosSubmitModeHTTP                          = "http"
	CosmosSubmitModeSignedTx                      = "signed-tx"
	cosmosSignedTxSecretFileMaxBytes              = int64(8 * 1024)
	cosmosAllowProxyFromEnvConfigName             = "COSMOS_ADAPTER_ALLOW_PROXY_FROM_ENV"
	cosmosAllowDangerousPrivateEndpointConfigName = "COSMOS_ADAPTER_ALLOW_DANGEROUS_PRIVATE_ENDPOINT"
	cosmosDeferredOperationDefaultMax             = 4096
	cosmosRewardProofAuthorizationHeader          = "X-GPM-Reward-Proof-Authorization"
	cosmosFinalityAuthorizationHeader             = "X-GPM-Finality-Authorization"
)

var cosmosLookupIPAddrs = net.DefaultResolver.LookupIPAddr

type CosmosAdapterConfig struct {
	Endpoint    string
	APIKey      string
	QueueSize   int
	MaxRetries  int
	BaseBackoff time.Duration
	HTTPTimeout time.Duration
	// AllowInsecureHTTP permits non-loopback plain HTTP endpoints.
	// Keep disabled outside controlled local development.
	AllowInsecureHTTP bool

	SubmitMode            string
	TrustedBridgeFinality bool
	RewardProofAuthToken  string
	FinalityAuthToken     string
	RewardProofVerifierID string
	SignedTxBroadcastPath string
	SignedTxChainID       string
	SignedTxSigner        string
	SignedTxSecret        string
	SignedTxSecretFile    string
	SignedTxKeyID         string
}

type CosmosAdapter struct {
	endpoint              string
	apiKey                string
	client                *http.Client
	maxRetries            int
	baseBackoff           time.Duration
	submitMode            string
	trustedBridgeFinality bool
	rewardProofAuthToken  string
	finalityAuthToken     string
	rewardProofVerifierID string

	queue chan cosmosQueuedOperation

	signedTxSubmitter cosmosSignedTxSubmitter

	stateMu                         sync.Mutex
	closed                          bool
	deferredOp                      map[string]cosmosDeferredOperation
	deferredOpMax                   int
	backlogFull                     bool
	deferredPersistenceFailureCount int
	deferredPersistenceFailureLast  string
	acceptedOp                      map[string]cosmosQueuedOperation

	workerCtx    context.Context
	workerCancel context.CancelFunc
	workerWG     sync.WaitGroup
	closeOnce    sync.Once
}

var _ ChainAdapter = (*CosmosAdapter)(nil)
var _ ChainBillingReservationSubmitter = (*CosmosAdapter)(nil)
var _ ChainConfirmationQuerier = (*CosmosAdapter)(nil)
var _ ChainConfirmationStatusQuerier = (*CosmosAdapter)(nil)
var _ ChainFundReservationStatusQuerier = (*CosmosAdapter)(nil)
var _ ChainReservationConfirmationStatusQuerier = (*CosmosAdapter)(nil)
var _ ChainSlashEvidenceLister = (*CosmosAdapter)(nil)
var _ FundReservationQuerier = (*CosmosAdapter)(nil)
var _ SessionSettlementQuerier = (*CosmosAdapter)(nil)
var _ RewardIssueQuerier = (*CosmosAdapter)(nil)
var _ SlashEvidenceQuerier = (*CosmosAdapter)(nil)
var _ RewardProofVerifier = (*CosmosAdapter)(nil)
var _ ChainRewardProofRegistrar = (*CosmosAdapter)(nil)

type cosmosQueuedOperation struct {
	path           string
	payload        any
	idempotencyKey string
}

type cosmosFundReservationPayload struct {
	ReservationID string    `json:"ReservationID"`
	SessionID     string    `json:"SessionID"`
	SubjectID     string    `json:"SubjectID"`
	AmountMicros  int64     `json:"AmountMicros"`
	Currency      string    `json:"Currency"`
	CreatedAt     time.Time `json:"CreatedAt"`
	Status        string    `json:"Status"`
}

type cosmosSessionSettlementPayload struct {
	SettlementID  string    `json:"SettlementID"`
	ReservationID string    `json:"ReservationID"`
	SessionID     string    `json:"SessionID"`
	SubjectID     string    `json:"SubjectID"`
	ChargedMicros int64     `json:"ChargedMicros"`
	Currency      string    `json:"Currency"`
	SettledAt     time.Time `json:"SettledAt"`
	Status        string    `json:"Status"`
}

type cosmosRewardIssuePayload struct {
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

type cosmosRewardProofPayload struct {
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

type cosmosSponsorReservationPayload struct {
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

type cosmosSlashEvidencePayload struct {
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

type cosmosSlashEvidenceQueryRecord struct {
	EvidenceID      string `json:"EvidenceID"`
	SubjectID       string `json:"SubjectID"`
	ProviderID      string `json:"ProviderID"`
	SessionID       string `json:"SessionID"`
	ViolationType   string `json:"ViolationType"`
	EvidenceRef     string `json:"EvidenceRef"`
	ProofHash       string `json:"ProofHash"`
	SlashMicros     int64  `json:"SlashMicros"`
	SlashAmount     int64  `json:"SlashAmount"`
	Currency        string `json:"Currency"`
	SlashDenom      string `json:"SlashDenom"`
	ObservedAt      string `json:"ObservedAt"`
	SubmittedAtUnix int64  `json:"SubmittedAtUnix"`
	Status          string `json:"Status"`
}

func (r cosmosSlashEvidenceQueryRecord) toSlashEvidence() SlashEvidence {
	observedAt := time.Time{}
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(r.ObservedAt)); err == nil {
		observedAt = parsed.UTC()
	} else if r.SubmittedAtUnix > 0 {
		observedAt = time.Unix(r.SubmittedAtUnix, 0).UTC()
	}
	amount := r.SlashMicros
	if amount == 0 {
		amount = r.SlashAmount
	}
	return SlashEvidence{
		EvidenceID:    strings.TrimSpace(r.EvidenceID),
		SubjectID:     cosmosFirstNonEmpty(strings.TrimSpace(r.SubjectID), strings.TrimSpace(r.ProviderID)),
		SessionID:     strings.TrimSpace(r.SessionID),
		ViolationType: strings.TrimSpace(r.ViolationType),
		EvidenceRef:   cosmosFirstNonEmpty(strings.TrimSpace(r.EvidenceRef), strings.TrimSpace(r.ProofHash)),
		SlashMicros:   amount,
		Currency:      normalizeCurrencyCode(cosmosFirstNonEmpty(strings.TrimSpace(r.Currency), strings.TrimSpace(r.SlashDenom))),
		ObservedAt:    observedAt,
		Status:        cosmosOperationStatus(r.Status),
	}
}

type cosmosDeferredOperation struct {
	operation     cosmosQueuedOperation
	deferredAt    time.Time
	lastAttemptAt time.Time
	attempts      int
	lastError     string
	replayable    bool
}

type cosmosSignedTxSubmitter interface {
	Submit(ctx context.Context, op cosmosQueuedOperation) error
}

type cosmosHTTPSignedTxSubmitter struct {
	endpoint      string
	broadcastPath string
	apiKey        string
	signer        string
	chainID       string
	secret        string
	keyID         string
	client        *http.Client
}

type cosmosSignedTx struct {
	ChainID        string          `json:"chain_id,omitempty"`
	KeyID          string          `json:"key_id,omitempty"`
	Signer         string          `json:"signer"`
	MessageType    string          `json:"message_type"`
	Message        json.RawMessage `json:"message"`
	IdempotencyKey string          `json:"idempotency_key"`
	Nonce          int64           `json:"nonce"`
	Signature      string          `json:"signature"`
}

type cosmosBroadcastRequest struct {
	Mode string         `json:"mode"`
	Tx   cosmosSignedTx `json:"tx"`
}

type cosmosBroadcastResponse struct {
	TxResponse *cosmosBroadcastTxResponse `json:"tx_response"`
}

type cosmosBroadcastTxResponse struct {
	Code   uint32 `json:"code"`
	RawLog string `json:"raw_log"`
}

type cosmosHTTPStatusError struct {
	message    string
	statusCode int
}

type cosmosEndpointPolicyRoundTripper struct {
	inner                         http.RoundTripper
	resolver                      cosmosOutboundIPResolver
	allowDangerousPrivateEndpoint bool
}

func (e *cosmosHTTPStatusError) Error() string {
	return e.message
}

func (rt *cosmosEndpointPolicyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("cosmos request URL is required")
	}
	host := strings.TrimSpace(req.URL.Hostname())
	if host == "" {
		return nil, fmt.Errorf("cosmos request host is required")
	}
	port := strings.TrimSpace(req.URL.Port())
	if port == "" {
		if strings.EqualFold(req.URL.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(host, port)
	if _, err := resolveCosmosSafeDialAddress(req.Context(), rt.resolver, address, rt.allowDangerousPrivateEndpoint); err != nil {
		return nil, err
	}
	inner := rt.inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	return inner.RoundTrip(req)
}

type cosmosRetryableError struct {
	cause error
}

func (e *cosmosRetryableError) Error() string {
	return e.cause.Error()
}

func (e *cosmosRetryableError) Unwrap() error {
	return e.cause
}

var errCosmosAdapterClosedWithBacklog = errors.New("cosmos adapter closed with backlog")
var errCosmosAdapterDeferredBacklogLimitReached = errors.New("cosmos adapter deferred backlog limit reached")

func NewCosmosAdapter(cfg CosmosAdapterConfig) (*CosmosAdapter, error) {
	endpoint, err := normalizeCosmosAdapterEndpoint(cfg.Endpoint, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = 256
	}
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	baseBackoff := cfg.BaseBackoff
	if baseBackoff <= 0 {
		baseBackoff = 250 * time.Millisecond
	}
	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = 4 * time.Second
	}
	submitMode := strings.TrimSpace(cfg.SubmitMode)
	if submitMode == "" {
		submitMode = CosmosSubmitModeHTTP
	}
	submitMode = strings.ToLower(submitMode)
	switch submitMode {
	case CosmosSubmitModeHTTP, CosmosSubmitModeSignedTx:
	default:
		return nil, fmt.Errorf("invalid cosmos submit mode %q", cfg.SubmitMode)
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	rewardProofAuthToken := strings.TrimSpace(cfg.RewardProofAuthToken)
	finalityAuthToken := strings.TrimSpace(cfg.FinalityAuthToken)
	if submitMode == CosmosSubmitModeHTTP {
		if rewardProofAuthToken != "" && apiKey == "" {
			return nil, fmt.Errorf("cosmos reward proof auth token requires APIKey")
		}
		if finalityAuthToken != "" && apiKey == "" {
			return nil, fmt.Errorf("cosmos finality auth token requires APIKey")
		}
		if cfg.TrustedBridgeFinality && finalityAuthToken == "" {
			return nil, fmt.Errorf("cosmos trusted bridge finality requires FinalityAuthToken")
		}
	}

	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if strings.TrimSpace(os.Getenv(cosmosAllowProxyFromEnvConfigName)) == "1" {
		transport.Proxy = http.ProxyFromEnvironment
	}
	allowDangerousPrivateEndpoint := strings.TrimSpace(os.Getenv(cosmosAllowDangerousPrivateEndpointConfigName)) == "1"
	resolver := cosmosDefaultResolver{}
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		safeAddress, resolveErr := resolveCosmosSafeDialAddress(
			ctx,
			resolver,
			address,
			allowDangerousPrivateEndpoint,
		)
		if resolveErr != nil {
			return nil, resolveErr
		}
		return dialer.DialContext(ctx, network, safeAddress)
	}
	client := &http.Client{
		Timeout: httpTimeout,
		Transport: &cosmosEndpointPolicyRoundTripper{
			inner:                         transport,
			resolver:                      resolver,
			allowDangerousPrivateEndpoint: allowDangerousPrivateEndpoint,
		},
		// Never follow redirects for settlement transport/auth requests.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var signedTxSubmitter cosmosSignedTxSubmitter
	if submitMode == CosmosSubmitModeSignedTx {
		broadcastPath := strings.TrimSpace(cfg.SignedTxBroadcastPath)
		if broadcastPath == "" {
			broadcastPath = "/cosmos/tx/v1beta1/txs"
		}
		if !strings.HasPrefix(broadcastPath, "/") {
			broadcastPath = "/" + broadcastPath
		}
		signer := strings.TrimSpace(cfg.SignedTxSigner)
		if signer == "" {
			return nil, fmt.Errorf("cosmos signed-tx signer required")
		}
		chainID := strings.TrimSpace(cfg.SignedTxChainID)
		if chainID == "" {
			return nil, fmt.Errorf("cosmos signed-tx chain_id required")
		}
		secret := strings.TrimSpace(cfg.SignedTxSecret)
		if secret == "" {
			secretFile := strings.TrimSpace(cfg.SignedTxSecretFile)
			if secretFile != "" {
				var readErr error
				secret, readErr = readCosmosSignedTxSecretFile(secretFile)
				if readErr != nil {
					return nil, readErr
				}
			}
		}
		if secret == "" {
			return nil, fmt.Errorf("cosmos signed-tx secret required")
		}
		signedTxSubmitter = &cosmosHTTPSignedTxSubmitter{
			endpoint:      endpoint,
			broadcastPath: broadcastPath,
			apiKey:        apiKey,
			signer:        signer,
			chainID:       chainID,
			secret:        secret,
			keyID:         strings.TrimSpace(cfg.SignedTxKeyID),
			client:        client,
		}
	}

	workerCtx, workerCancel := context.WithCancel(context.Background())
	a := &CosmosAdapter{
		endpoint:              endpoint,
		apiKey:                apiKey,
		client:                client,
		maxRetries:            maxRetries,
		baseBackoff:           baseBackoff,
		submitMode:            submitMode,
		trustedBridgeFinality: cfg.TrustedBridgeFinality,
		rewardProofAuthToken:  rewardProofAuthToken,
		finalityAuthToken:     finalityAuthToken,
		rewardProofVerifierID: strings.TrimSpace(cfg.RewardProofVerifierID),
		queue:                 make(chan cosmosQueuedOperation, queueSize),
		signedTxSubmitter:     signedTxSubmitter,
		deferredOp:            map[string]cosmosDeferredOperation{},
		acceptedOp:            map[string]cosmosQueuedOperation{},
		deferredOpMax:         cosmosDeferredOperationDefaultMax,
		workerCtx:             workerCtx,
		workerCancel:          workerCancel,
	}
	a.workerWG.Add(1)
	go a.runWorker()
	return a, nil
}

func normalizeCosmosAdapterEndpoint(raw string, allowInsecureHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("cosmos adapter endpoint required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid cosmos adapter endpoint %q: %w", raw, err)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("cosmos adapter endpoint must not include user info")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("cosmos adapter endpoint must include host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("cosmos adapter endpoint must not include query or fragment")
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("cosmos adapter endpoint scheme must be http or https")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if cosmosHostHasZoneIdentifier(host) {
		return "", fmt.Errorf("cosmos adapter endpoint host must not include a zone identifier")
	}
	if scheme == "http" && !allowInsecureHTTP && !isLoopbackHost(host) {
		return "", fmt.Errorf("cosmos adapter endpoint must use https for non-loopback hosts")
	}
	normalized := strings.TrimRight(raw, "/")
	return normalized, nil
}

type cosmosOutboundIPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type cosmosDefaultResolver struct{}

func (cosmosDefaultResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	lookup := cosmosLookupIPAddrs
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	return lookup(ctx, host)
}

func resolveCosmosSafeDialAddress(
	ctx context.Context,
	resolver cosmosOutboundIPResolver,
	address string,
	allowDangerousPrivateEndpoint bool,
) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", fmt.Errorf("invalid cosmos endpoint address %q: %w", address, err)
	}
	if cosmosHostHasZoneIdentifier(host) {
		return "", fmt.Errorf("cosmos endpoint host %q includes unsupported zone identifier", host)
	}
	host = normalizeCosmosDialHost(host)
	if host == "" {
		return "", fmt.Errorf("cosmos endpoint host is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedCosmosEndpointIP(ip) && !allowDangerousPrivateEndpoint && !ip.IsLoopback() {
			return "", fmt.Errorf("cosmos endpoint host %q is blocked by outbound dial policy", ip.String())
		}
		return net.JoinHostPort(ip.String(), port), nil
	}

	if resolver == nil {
		resolver = cosmosDefaultResolver{}
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve cosmos endpoint host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve cosmos endpoint host %q returned no addresses", host)
	}

	loopbackHostname := host == "localhost"
	loopbackDialAddress := ""
	for _, candidate := range ips {
		ip := candidate.IP
		if ip == nil {
			continue
		}
		if loopbackHostname {
			if !ip.IsLoopback() {
				return "", fmt.Errorf("cosmos localhost host %q resolved to non-loopback address %q", host, ip.String())
			}
			if loopbackDialAddress == "" {
				loopbackDialAddress = net.JoinHostPort(ip.String(), port)
			}
			continue
		}
		if ip.IsLoopback() && !allowDangerousPrivateEndpoint {
			continue
		}
		if isDisallowedCosmosEndpointIP(ip) && !allowDangerousPrivateEndpoint {
			continue
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	if loopbackHostname && loopbackDialAddress != "" {
		return loopbackDialAddress, nil
	}
	return "", fmt.Errorf("cosmos endpoint host %q resolved only to blocked address classes", host)
}

func normalizeCosmosDialHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	return strings.ToLower(host)
}

func cosmosHostHasZoneIdentifier(host string) bool {
	return strings.Contains(strings.TrimSpace(host), "%")
}

func isDisallowedCosmosEndpointIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	return ip.IsPrivate() || isCosmosSharedAddressSpaceCGNATIP(ip)
}

func isCosmosSharedAddressSpaceCGNATIP(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	return ipv4[0] == 100 && ipv4[1]&0xc0 == 0x40
}

func readCosmosSignedTxSecretFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("cosmos signed-tx secret file path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open cosmos signed-tx secret file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat cosmos signed-tx secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("cosmos signed-tx secret file %q must be a regular file", path)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("lstat cosmos signed-tx secret file: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("cosmos signed-tx secret file %q must not be a symlink", path)
	}
	if !os.SameFile(info, pathInfo) {
		return "", fmt.Errorf("cosmos signed-tx secret file %q changed while opening", path)
	}
	if err := fileperm.ValidateOwnerOnly(path, info); err != nil {
		return "", err
	}
	if info.Size() > cosmosSignedTxSecretFileMaxBytes {
		return "", fmt.Errorf("cosmos signed-tx secret file %q exceeds max size %d bytes", path, cosmosSignedTxSecretFileMaxBytes)
	}
	secretBytes, err := io.ReadAll(io.LimitReader(f, cosmosSignedTxSecretFileMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read cosmos signed-tx secret file: %w", err)
	}
	if int64(len(secretBytes)) > cosmosSignedTxSecretFileMaxBytes {
		return "", fmt.Errorf("cosmos signed-tx secret file %q exceeds max size %d bytes", path, cosmosSignedTxSecretFileMaxBytes)
	}
	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return "", fmt.Errorf("cosmos signed-tx secret file %q is empty", path)
	}
	return secret, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	// Treat localhost as loopback-safe only when all resolver answers are loopback.
	if !strings.EqualFold(host, "localhost") {
		return false
	}
	lookup := cosmosLookupIPAddrs
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	addrs, err := lookup(context.Background(), host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		if addr.IP == nil || !addr.IP.IsLoopback() {
			return false
		}
	}
	return true
}

func (a *CosmosAdapter) SubmitFundReservation(_ context.Context, reservation FundReservation) (string, error) {
	id := cosmosID("reservation", reservation.ReservationID, reservation.SessionID)
	status, err := a.cosmosTrustedHTTPWriteStatus(reservation.Status, OperationStatusPending)
	if err != nil {
		return id, err
	}
	if !a.trustedBridgeFinality || status != string(OperationStatusConfirmed) {
		return id, a.enqueue(cosmosQueuedOperation{
			path: "/x/vpnbilling/reservations",
			payload: cosmosFundReservationPayload{
				ReservationID: reservation.ReservationID,
				SessionID:     reservation.SessionID,
				SubjectID:     reservation.SubjectID,
				AmountMicros:  reservation.AmountMicros,
				Currency:      reservation.Currency,
				CreatedAt:     reservation.CreatedAt,
				Status:        status,
			},
			idempotencyKey: id,
		})
	}
	if err := a.enqueue(cosmosQueuedOperation{
		path: "/x/vpnbilling/reservations",
		payload: cosmosFundReservationPayload{
			ReservationID: reservation.ReservationID,
			SessionID:     reservation.SessionID,
			SubjectID:     reservation.SubjectID,
			AmountMicros:  reservation.AmountMicros,
			Currency:      reservation.Currency,
			CreatedAt:     reservation.CreatedAt,
			Status:        string(OperationStatusSubmitted),
		},
		idempotencyKey: id,
	}); err != nil {
		return id, err
	}
	return id, a.enqueue(cosmosQueuedOperation{
		path: "/x/vpnbilling/reservations",
		payload: cosmosFundReservationPayload{
			ReservationID: reservation.ReservationID,
			SessionID:     reservation.SessionID,
			SubjectID:     reservation.SubjectID,
			AmountMicros:  reservation.AmountMicros,
			Currency:      reservation.Currency,
			CreatedAt:     reservation.CreatedAt,
			Status:        string(OperationStatusConfirmed),
		},
		idempotencyKey: id + ":confirmed",
	})
}

func (a *CosmosAdapter) RequiresRewardProofReference() bool {
	return true
}

func (a *CosmosAdapter) TrustedBridgeFinalityEnabled() bool {
	return a.httpBridgeFinalityDerivationEnabled()
}

func (a *CosmosAdapter) VerifyRewardProof(ctx context.Context, request RewardProofVerificationRequest) (RewardProofVerification, error) {
	if request.TrustContract != RewardProofTrustContractObjectiveTrafficV1 {
		return RewardProofVerification{}, fmt.Errorf("unsupported reward proof trust contract: %s", request.TrustContract)
	}
	proofPath, ok := cosmosObjectiveProofPath(request.TrafficProofRef)
	if !ok {
		return RewardProofVerification{}, fmt.Errorf("reward proof verifier requires obj:// traffic_proof_ref")
	}
	var payload map[string]json.RawMessage
	if err := a.queryJSON(ctx, "/x/vpnrewards/proofs/"+url.PathEscape(proofPath), &payload); err != nil {
		return RewardProofVerification{}, err
	}
	proof := cosmosProofObject(payload)
	if !cosmosProofStringEqual(proof, "traffic_proof_ref", "TrafficProofRef", request.TrafficProofRef) {
		return RewardProofVerification{}, fmt.Errorf("reward proof traffic_proof_ref mismatch")
	}
	if !cosmosProofStringEqual(proof, "trust_contract", "TrustContract", string(request.TrustContract)) {
		return RewardProofVerification{}, fmt.Errorf("reward proof trust contract mismatch")
	}
	if !cosmosProofStringEqual(proof, "reward_id", "RewardID", request.RewardID) {
		return RewardProofVerification{}, fmt.Errorf("reward proof reward_id mismatch")
	}
	if !cosmosProofStringEqual(proof, "provider_subject_id", "ProviderSubjectID", request.ProviderSubjectID) {
		return RewardProofVerification{}, fmt.Errorf("reward proof provider_subject_id mismatch")
	}
	if !cosmosProofStringEqual(proof, "session_id", "SessionID", request.SessionID) {
		return RewardProofVerification{}, fmt.Errorf("reward proof session_id mismatch")
	}
	if !cosmosProofStringEqual(proof, "currency", "Currency", request.Currency) {
		return RewardProofVerification{}, fmt.Errorf("reward proof currency mismatch")
	}
	if !cosmosProofInt64Equal(proof, "reward_micros", "RewardMicros", request.RewardMicros) {
		return RewardProofVerification{}, fmt.Errorf("reward proof reward_micros mismatch")
	}
	if !cosmosProofTimeEqual(proof, "payout_period_start", "PayoutPeriodStart", request.PayoutPeriodStart) {
		return RewardProofVerification{}, fmt.Errorf("reward proof payout_period_start mismatch")
	}
	if !cosmosProofTimeEqual(proof, "payout_period_end", "PayoutPeriodEnd", request.PayoutPeriodEnd) {
		return RewardProofVerification{}, fmt.Errorf("reward proof payout_period_end mismatch")
	}
	if !cosmosProofTimeEqual(proof, "issued_at", "IssuedAt", request.IssuedAt) {
		return RewardProofVerification{}, fmt.Errorf("reward proof issued_at mismatch")
	}
	verified, ok := cosmosProofBool(proof, "verified", "Verified")
	if !ok || !verified {
		return RewardProofVerification{}, fmt.Errorf("reward proof is not verified")
	}
	verifierID := cosmosProofString(proof, "verifier_id", "VerifierID")
	if verifierID == "" {
		return RewardProofVerification{}, fmt.Errorf("reward proof verifier_id required")
	}
	expected := strings.TrimSpace(a.rewardProofVerifierID)
	if expected == "" {
		return RewardProofVerification{}, fmt.Errorf("cosmos adapter reward proof verifier id is required")
	}
	if !hmac.Equal([]byte(verifierID), []byte(expected)) {
		return RewardProofVerification{}, fmt.Errorf("reward proof verifier_id %q is not authorized", verifierID)
	}
	verifiedAt := cosmosProofTime(proof, "verified_at_utc", "VerifiedAtUTC", "verified_at", "VerifiedAt")
	return RewardProofVerification{
		Verified:   true,
		VerifierID: verifierID,
		VerifiedAt: verifiedAt,
	}, nil
}

func cosmosObjectiveProofPath(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "obj://") {
		return "", false
	}
	path := strings.TrimSpace(strings.TrimPrefix(ref, "obj://"))
	if path == "" || strings.ContainsAny(path, " \t\r\n") {
		return "", false
	}
	return path, true
}

func cosmosProofObject(payload map[string]json.RawMessage) map[string]json.RawMessage {
	for _, key := range []string{"proof", "traffic_proof", "trafficProof", "reward_proof", "rewardProof"} {
		if raw, ok := cosmosProofRaw(payload, key); ok {
			var nested map[string]json.RawMessage
			if err := json.Unmarshal(raw, &nested); err == nil && nested != nil {
				return nested
			}
		}
	}
	return payload
}

func cosmosProofRaw(payload map[string]json.RawMessage, keys ...string) (json.RawMessage, bool) {
	for _, want := range keys {
		want = strings.ToLower(strings.TrimSpace(want))
		for key, raw := range payload {
			if strings.ToLower(strings.TrimSpace(key)) == want {
				return raw, true
			}
		}
	}
	return nil, false
}

func cosmosProofString(payload map[string]json.RawMessage, keys ...string) string {
	raw, ok := cosmosProofRaw(payload, keys...)
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return strings.TrimSpace(value)
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return strings.TrimSpace(number.String())
	}
	return ""
}

func cosmosProofStringEqual(payload map[string]json.RawMessage, snakeKey string, camelKey string, expected string) bool {
	return strings.TrimSpace(expected) == cosmosProofString(payload, snakeKey, camelKey)
}

func cosmosProofInt64Equal(payload map[string]json.RawMessage, snakeKey string, camelKey string, expected int64) bool {
	raw, ok := cosmosProofRaw(payload, snakeKey, camelKey)
	if !ok {
		return false
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err == nil {
		return value == expected
	}
	var valueString string
	if err := json.Unmarshal(raw, &valueString); err == nil {
		parsed, err := strconv.ParseInt(strings.TrimSpace(valueString), 10, 64)
		return err == nil && parsed == expected
	}
	var valueFloat float64
	if err := json.Unmarshal(raw, &valueFloat); err == nil {
		return int64(valueFloat) == expected && valueFloat == float64(expected)
	}
	return false
}

func cosmosProofBool(payload map[string]json.RawMessage, keys ...string) (bool, bool) {
	raw, ok := cosmosProofRaw(payload, keys...)
	if !ok {
		return false, false
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, true
	}
	var valueString string
	if err := json.Unmarshal(raw, &valueString); err == nil {
		switch strings.ToLower(strings.TrimSpace(valueString)) {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		}
	}
	return false, false
}

func cosmosProofTimeEqual(payload map[string]json.RawMessage, snakeKey string, camelKey string, expected time.Time) bool {
	if expected.IsZero() {
		raw, ok := cosmosProofRaw(payload, snakeKey, camelKey)
		if !ok {
			return true
		}
		var value *string
		if err := json.Unmarshal(raw, &value); err == nil {
			if value == nil || strings.TrimSpace(*value) == "" {
				return true
			}
			parsed, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(*value))
			return parseErr == nil && parsed.UTC().Round(0).IsZero()
		}
		return false
	}
	got := cosmosProofTime(payload, snakeKey, camelKey)
	return chainTimeUnixSecondEqual(expected, got)
}

func cosmosProofTime(payload map[string]json.RawMessage, keys ...string) time.Time {
	value := cosmosProofString(payload, keys...)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC().Round(0)
}

func (a *CosmosAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	id := cosmosID("settlement", settlement.SettlementID, settlement.SessionID)
	status, err := a.cosmosTrustedHTTPWriteStatus(settlement.Status, OperationStatusSubmitted)
	if err != nil {
		return id, err
	}
	return id, a.enqueue(cosmosQueuedOperation{
		path: "/x/vpnbilling/settlements",
		payload: cosmosSessionSettlementPayload{
			SettlementID:  settlement.SettlementID,
			ReservationID: settlement.ReservationID,
			SessionID:     settlement.SessionID,
			SubjectID:     settlement.SubjectID,
			ChargedMicros: settlement.ChargedMicros,
			Currency:      settlement.Currency,
			SettledAt:     settlement.SettledAt,
			Status:        status,
		},
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) SubmitRewardIssue(_ context.Context, reward RewardIssue) (string, error) {
	if _, ok := cosmosObjectiveProofPath(reward.TrafficProofRef); !ok {
		return "", fmt.Errorf("cosmos adapter reward issue requires obj:// traffic_proof_ref")
	}
	id := cosmosID("reward", reward.RewardID, reward.SessionID)
	status, err := a.cosmosTrustedHTTPWriteStatus(reward.Status, OperationStatusSubmitted)
	if err != nil {
		return id, err
	}
	return id, a.enqueue(cosmosQueuedOperation{
		path: "/x/vpnrewards/issues",
		payload: cosmosRewardIssuePayload{
			RewardID:              reward.RewardID,
			ProviderSubjectID:     reward.ProviderSubjectID,
			SessionID:             reward.SessionID,
			SettlementReferenceID: reward.SettlementReferenceID,
			TrafficProofRef:       reward.TrafficProofRef,
			PayoutPeriodStart:     reward.PayoutPeriodStart,
			PayoutPeriodEnd:       reward.PayoutPeriodEnd,
			RewardMicros:          reward.RewardMicros,
			Currency:              reward.Currency,
			IssuedAt:              reward.IssuedAt.UTC().Truncate(time.Second),
			Status:                status,
		},
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) SubmitRewardProof(ctx context.Context, proof RewardProofRecord) (string, error) {
	id := cosmosID("reward-proof", proof.ProofPath, proof.RewardID)
	a.stateMu.Lock()
	if a.deferredPersistenceFailureCount > 0 {
		err := a.deferredPersistenceFailureErrorLocked()
		a.stateMu.Unlock()
		return "", err
	}
	if a.closed {
		a.stateMu.Unlock()
		return "", fmt.Errorf("cosmos adapter closed")
	}
	a.stateMu.Unlock()
	op := cosmosQueuedOperation{
		path: "/x/vpnrewards/proofs",
		payload: cosmosRewardProofPayload{
			ProofPath:         proof.ProofPath,
			TrafficProofRef:   proof.TrafficProofRef,
			TrustContract:     string(proof.TrustContract),
			RewardID:          proof.RewardID,
			ProviderSubjectID: proof.ProviderSubjectID,
			SessionID:         proof.SessionID,
			PayoutPeriodStart: proof.PayoutPeriodStart,
			PayoutPeriodEnd:   proof.PayoutPeriodEnd,
			RewardMicros:      proof.RewardMicros,
			Currency:          proof.Currency,
			IssuedAt:          proof.IssuedAt.UTC().Truncate(time.Second),
			Verified:          proof.Verified,
			VerifierID:        proof.VerifierID,
			VerifiedAt:        proof.VerifiedAt.UTC().Truncate(time.Second),
		},
		idempotencyKey: id,
	}
	if err := a.submitWithRetry(ctx, op); err != nil {
		return "", err
	}
	return id, nil
}

func (a *CosmosAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	id := cosmosID("sponsor-reservation", reservation.ReservationID, reservation.SessionID)
	status, err := cosmosValidatedStatusValue(reservation.Status, OperationStatusPending)
	if err != nil {
		return id, err
	}
	return id, a.enqueue(cosmosQueuedOperation{
		path: "/x/vpnsponsor/reservations",
		payload: cosmosSponsorReservationPayload{
			ReservationID: reservation.ReservationID,
			SponsorID:     reservation.SponsorID,
			SubjectID:     reservation.SubjectID,
			SessionID:     reservation.SessionID,
			AmountMicros:  reservation.AmountMicros,
			Currency:      reservation.Currency,
			CreatedAt:     reservation.CreatedAt,
			ExpiresAt:     reservation.ExpiresAt,
			Status:        status,
		},
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) SubmitSlashEvidence(_ context.Context, evidence SlashEvidence) (string, error) {
	evidence.ViolationType = strings.ToLower(strings.TrimSpace(evidence.ViolationType))
	evidence.EvidenceRef = strings.TrimSpace(evidence.EvidenceRef)
	if !isObjectiveViolationType(evidence.ViolationType) {
		return "", fmt.Errorf("submit slash evidence requires objective violation_type")
	}
	if !isObjectiveEvidenceRef(evidence.EvidenceRef) {
		return "", fmt.Errorf("submit slash evidence requires objective evidence_ref (obj://... or sha256:...)")
	}

	id := cosmosID("slash", evidence.EvidenceID, evidence.SubjectID)
	return id, a.enqueue(cosmosQueuedOperation{
		path: "/x/vpnslashing/evidence",
		payload: cosmosSlashEvidencePayload{
			EvidenceID:    evidence.EvidenceID,
			SubjectID:     evidence.SubjectID,
			SessionID:     evidence.SessionID,
			ViolationType: evidence.ViolationType,
			EvidenceRef:   evidence.EvidenceRef,
			SlashMicros:   evidence.SlashMicros,
			Currency:      evidence.Currency,
			ObservedAt:    evidence.ObservedAt,
			// Slash evidence creation is not a finality-authorized path.
			Status: string(OperationStatusSubmitted),
		},
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) Health(ctx context.Context) error {
	a.stateMu.Lock()
	if a.deferredPersistenceFailureCount > 0 {
		a.stateMu.Unlock()
		return a.deferredPersistenceFailureError()
	}
	if a.backlogFull || a.deferredBacklogLimitReachedLocked() {
		a.backlogFull = true
		err := a.deferredBacklogLimitErrorLocked()
		a.stateMu.Unlock()
		return err
	}
	a.stateMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return err
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cosmos adapter health status %d", resp.StatusCode)
	}
	return nil
}

func (a *CosmosAdapter) HasSessionSettlement(ctx context.Context, settlementID string) (bool, error) {
	settlementID = strings.TrimSpace(settlementID)
	if settlementID == "" {
		return false, fmt.Errorf("settlement id required")
	}
	return a.queryByID(ctx, "/x/vpnbilling/settlements/"+url.PathEscape(settlementID))
}

func (a *CosmosAdapter) SessionSettlementStatus(ctx context.Context, settlementID string) (OperationStatus, bool, error) {
	settlementID = strings.TrimSpace(settlementID)
	if settlementID == "" {
		return "", false, fmt.Errorf("settlement id required")
	}
	return a.queryStatusByID(ctx, "/x/vpnbilling/settlements/"+url.PathEscape(settlementID), "settlement")
}

func (a *CosmosAdapter) SessionSettlement(ctx context.Context, settlementID string) (SessionSettlement, bool, error) {
	settlementID = strings.TrimSpace(settlementID)
	if settlementID == "" {
		return SessionSettlement{}, false, fmt.Errorf("settlement id required")
	}
	_, found, body, err := a.queryStatusBodyByID(ctx, "/x/vpnbilling/settlements/"+url.PathEscape(settlementID), "settlement")
	if err != nil || !found {
		return SessionSettlement{}, found, err
	}
	settlement, ok, err := cosmosSessionSettlementFromQueryBody(body)
	if err != nil {
		return SessionSettlement{}, false, err
	}
	if !ok {
		return SessionSettlement{}, false, nil
	}
	if strings.TrimSpace(settlement.SettlementID) == "" {
		settlement.SettlementID = settlementID
	}
	return settlement, true, nil
}

func (a *CosmosAdapter) FundReservationStatus(ctx context.Context, reservationID string) (OperationStatus, bool, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return "", false, fmt.Errorf("reservation id required")
	}
	status, found, err := a.queryStatusByID(ctx, "/x/vpnbilling/reservations/"+url.PathEscape(reservationID), "reservation")
	if err != nil || !found || !a.httpBridgeFinalityDerivationEnabled() {
		return status, found, err
	}
	return cosmosHTTPBridgePersistedFinalStatus(status), found, nil
}

func (a *CosmosAdapter) FundReservation(ctx context.Context, reservationID string) (FundReservation, bool, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return FundReservation{}, false, fmt.Errorf("reservation id required")
	}
	_, found, body, err := a.queryStatusBodyByID(ctx, "/x/vpnbilling/reservations/"+url.PathEscape(reservationID), "reservation")
	if err != nil || !found {
		return FundReservation{}, found, err
	}
	reservation, ok, err := cosmosFundReservationFromQueryBody(body)
	if err != nil {
		return FundReservation{}, false, err
	}
	if !ok {
		return FundReservation{}, false, nil
	}
	if strings.TrimSpace(reservation.ReservationID) == "" {
		reservation.ReservationID = reservationID
	}
	return reservation, true, nil
}

func (a *CosmosAdapter) HasRewardIssue(ctx context.Context, rewardID string) (bool, error) {
	rewardID = strings.TrimSpace(rewardID)
	if rewardID == "" {
		return false, fmt.Errorf("reward id required")
	}
	// Bridge materializes reward submissions as distribution records with "dist:<reward_id>".
	distributionID := "dist:" + rewardID
	return a.queryByID(ctx, "/x/vpnrewards/distributions/"+url.PathEscape(distributionID))
}

func (a *CosmosAdapter) RewardIssueStatus(ctx context.Context, rewardID string) (OperationStatus, bool, error) {
	rewardID = strings.TrimSpace(rewardID)
	if rewardID == "" {
		return "", false, fmt.Errorf("reward id required")
	}
	// Bridge materializes reward submissions as distribution records with "dist:<reward_id>".
	distributionID := "dist:" + rewardID
	return a.queryStatusByID(ctx, "/x/vpnrewards/distributions/"+url.PathEscape(distributionID), "distribution")
}

func (a *CosmosAdapter) RewardIssue(ctx context.Context, rewardID string) (RewardIssue, bool, error) {
	rewardID = strings.TrimSpace(rewardID)
	if rewardID == "" {
		return RewardIssue{}, false, fmt.Errorf("reward id required")
	}
	distributionID := "dist:" + rewardID
	_, found, distributionBody, err := a.queryStatusBodyByID(ctx, "/x/vpnrewards/distributions/"+url.PathEscape(distributionID), "distribution")
	if err != nil || !found {
		return RewardIssue{}, found, err
	}
	distribution, ok, err := cosmosRewardDistributionFromQueryBody(distributionBody)
	if err != nil {
		return RewardIssue{}, false, err
	}
	if !ok {
		return RewardIssue{}, false, nil
	}
	accrualID := strings.TrimSpace(distribution.AccrualID)
	if accrualID == "" {
		accrualID = rewardID
	}
	_, accrualFound, accrualBody, err := a.queryStatusBodyByID(ctx, "/x/vpnrewards/accruals/"+url.PathEscape(accrualID), "accrual")
	if err != nil || !accrualFound {
		return RewardIssue{}, accrualFound, err
	}
	accrual, ok, err := cosmosRewardAccrualFromQueryBody(accrualBody)
	if err != nil {
		return RewardIssue{}, false, err
	}
	if !ok {
		return RewardIssue{}, false, nil
	}
	payout := cosmosRewardPayoutRefFromString(distribution.PayoutRef)
	issuedAt := time.Time{}
	if distribution.DistributedAt > 0 {
		issuedAt = time.Unix(distribution.DistributedAt, 0).UTC()
	} else if accrual.AccruedAtUnix > 0 {
		issuedAt = time.Unix(accrual.AccruedAtUnix, 0).UTC()
	}
	payoutStart := payout.PayoutPeriodStart
	if payoutStart.IsZero() && accrual.PayoutStartUnix > 0 {
		payoutStart = time.Unix(accrual.PayoutStartUnix, 0).UTC()
	}
	payoutEnd := payout.PayoutPeriodEnd
	if payoutEnd.IsZero() && accrual.PayoutEndUnix > 0 {
		payoutEnd = time.Unix(accrual.PayoutEndUnix, 0).UTC()
	}
	materialRewardID := cosmosFirstNonEmpty(payout.RewardID, accrual.AccrualID, rewardID)
	return RewardIssue{
		RewardID:              materialRewardID,
		ProviderSubjectID:     strings.TrimSpace(accrual.ProviderID),
		SessionID:             strings.TrimSpace(accrual.SessionID),
		SettlementReferenceID: strings.TrimSpace(payout.SettlementReferenceID),
		TrafficProofRef:       canonicalObjectiveEvidenceRef(payout.TrafficProofRef),
		PayoutPeriodStart:     payoutStart,
		PayoutPeriodEnd:       payoutEnd,
		RewardMicros:          accrual.Amount,
		Currency:              normalizeCurrencyCode(accrual.AssetDenom),
		IssuedAt:              issuedAt,
		Status:                distribution.Status,
	}, true, nil
}

func (a *CosmosAdapter) HasSponsorReservation(ctx context.Context, reservationID string) (bool, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return false, fmt.Errorf("reservation id required")
	}
	return a.queryByID(ctx, "/x/vpnsponsor/delegations/"+url.PathEscape(reservationID))
}

func (a *CosmosAdapter) SponsorReservationStatus(ctx context.Context, reservationID string) (OperationStatus, bool, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return "", false, fmt.Errorf("reservation id required")
	}
	status, found, err := a.queryStatusByID(ctx, "/x/vpnsponsor/delegations/"+url.PathEscape(reservationID), "delegation")
	if err != nil || !found || !a.httpBridgeFinalityDerivationEnabled() {
		return status, found, err
	}
	return cosmosHTTPBridgePersistedFinalStatus(status), found, nil
}

func (a *CosmosAdapter) HasSlashEvidence(ctx context.Context, evidenceID string) (bool, error) {
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return false, fmt.Errorf("evidence id required")
	}
	return a.queryByID(ctx, "/x/vpnslashing/evidence/"+url.PathEscape(evidenceID))
}

func (a *CosmosAdapter) SlashEvidenceStatus(ctx context.Context, evidenceID string) (OperationStatus, bool, error) {
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return "", false, fmt.Errorf("evidence id required")
	}
	status, found, err := a.queryStatusByID(ctx, "/x/vpnslashing/evidence/"+url.PathEscape(evidenceID), "evidence")
	if err != nil || !found || !a.httpBridgeFinalityDerivationEnabled() {
		return status, found, err
	}
	return cosmosHTTPBridgePersistedFinalStatus(status), found, nil
}

func (a *CosmosAdapter) SlashEvidence(ctx context.Context, evidenceID string) (SlashEvidence, bool, error) {
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return SlashEvidence{}, false, fmt.Errorf("evidence id required")
	}
	status, found, body, err := a.queryStatusBodyByID(ctx, "/x/vpnslashing/evidence/"+url.PathEscape(evidenceID), "evidence")
	if err != nil || !found {
		return SlashEvidence{}, found, err
	}
	evidence, ok, err := cosmosSlashEvidenceFromQueryBody(body)
	if err != nil {
		return SlashEvidence{}, false, err
	}
	if !ok {
		return SlashEvidence{}, false, nil
	}
	if strings.TrimSpace(evidence.EvidenceID) == "" {
		evidence.EvidenceID = evidenceID
	}
	if evidence.Status == "" {
		evidence.Status = status
	}
	if a.httpBridgeFinalityDerivationEnabled() {
		evidence.Status = cosmosHTTPBridgePersistedFinalStatus(evidence.Status)
	}
	return evidence, true, nil
}

func (a *CosmosAdapter) ListSlashEvidence(ctx context.Context, filter SlashEvidenceFilter) ([]SlashEvidence, error) {
	values := url.Values{}
	if subjectID := strings.TrimSpace(filter.SubjectID); subjectID != "" {
		values.Set("subject_id", subjectID)
	}
	if sessionID := strings.TrimSpace(filter.SessionID); sessionID != "" {
		values.Set("session_id", sessionID)
	}
	if violationType := strings.TrimSpace(filter.ViolationType); violationType != "" {
		values.Set("violation_type", violationType)
	}
	if !filter.ObservedAtOrAfter.IsZero() {
		values.Set("observed_at_or_after", filter.ObservedAtOrAfter.UTC().Format(time.RFC3339))
	}
	if !filter.ObservedBefore.IsZero() {
		values.Set("observed_before", filter.ObservedBefore.UTC().Format(time.RFC3339))
	}
	if filter.IncludeFailedSet {
		if filter.IncludeFailed {
			values.Set("include_failed", "1")
		} else {
			values.Set("include_failed", "0")
		}
	}
	if filter.IncludeZeroObserved {
		values.Set("include_zero_observed", "1")
	}
	path := "/x/vpnslashing/evidence"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var payload struct {
		Evidence []cosmosSlashEvidenceQueryRecord `json:"evidence"`
	}
	if err := a.queryJSON(ctx, path, &payload); err != nil {
		return nil, err
	}
	out := make([]SlashEvidence, 0, len(payload.Evidence))
	for _, record := range payload.Evidence {
		out = append(out, record.toSlashEvidence())
	}
	return out, nil
}

func (a *CosmosAdapter) Close() {
	a.closeOnce.Do(func() {
		a.stateMu.Lock()
		a.closed = true
		a.stateMu.Unlock()
		a.workerCancel()
		a.workerWG.Wait()
		a.drainAcceptedOperationsToDeferred(errCosmosAdapterClosedWithBacklog)
	})
}

func (a *CosmosAdapter) deferredOperationLimit() int {
	limit := a.deferredOpMax
	if limit <= 0 {
		limit = cosmosDeferredOperationDefaultMax
	}
	return limit
}

func (a *CosmosAdapter) deferredBacklogLimitReachedLocked() bool {
	limit := a.deferredOperationLimit()
	return limit > 0 && len(a.deferredOp) >= limit
}

func (a *CosmosAdapter) deferredBacklogLimitErrorLocked() error {
	return fmt.Errorf("%w: limit=%d current=%d", errCosmosAdapterDeferredBacklogLimitReached, a.deferredOperationLimit(), len(a.deferredOp))
}

func (a *CosmosAdapter) updateBacklogHealthLocked() {
	a.backlogFull = a.deferredBacklogLimitReachedLocked()
}

func (a *CosmosAdapter) enqueue(op cosmosQueuedOperation) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.deferredPersistenceFailureCount > 0 {
		return a.deferredPersistenceFailureErrorLocked()
	}
	if a.closed {
		return fmt.Errorf("cosmos adapter closed")
	}
	if a.backlogFull || a.deferredBacklogLimitReachedLocked() {
		a.backlogFull = true
		return a.deferredBacklogLimitErrorLocked()
	}
	select {
	case a.queue <- op:
		a.trackAcceptedOperationLocked(op)
		return nil
	default:
		return fmt.Errorf("cosmos adapter queue full")
	}
}

func (a *CosmosAdapter) trackAcceptedOperationLocked(op cosmosQueuedOperation) {
	if a.acceptedOp == nil {
		a.acceptedOp = map[string]cosmosQueuedOperation{}
	}
	a.acceptedOp[op.idempotencyKey] = op
}

func (a *CosmosAdapter) runWorker() {
	defer a.workerWG.Done()
	replayTicker := time.NewTicker(a.replayInterval())
	defer replayTicker.Stop()
	for {
		select {
		case <-a.workerCtx.Done():
			a.drainQueuedOperationsToDeferred(errCosmosAdapterClosedWithBacklog)
			return
		case op := <-a.queue:
			a.processQueuedOperation(a.workerCtx, op)
		case <-replayTicker.C:
			a.replayDeferredOperations(a.workerCtx)
		}
	}
}

func (a *CosmosAdapter) processQueuedOperation(ctx context.Context, op cosmosQueuedOperation) {
	attempts, err := a.submitWithRetryCount(ctx, op)
	if err != nil {
		if markErr := a.markDeferredOperation(op, attempts, err, cosmosSubmitErrorRetryable(err)); markErr != nil {
			a.recordDeferredPersistenceFailure(op, markErr)
		}
		a.clearAcceptedOperation(op.idempotencyKey)
		return
	}
	a.clearCompletedOperation(op.idempotencyKey)
}

func (a *CosmosAdapter) replayDeferredOperations(ctx context.Context) {
	ops := a.snapshotReplayableDeferredOperations()
	for _, op := range ops {
		if ctx.Err() != nil {
			return
		}
		a.processQueuedOperation(ctx, op)
	}
}

func (a *CosmosAdapter) drainQueuedOperationsToDeferred(err error) {
	for {
		select {
		case op := <-a.queue:
			if markErr := a.markDeferredOperation(op, 0, err, false); markErr != nil {
				a.recordDeferredPersistenceFailure(op, markErr)
			}
			a.clearAcceptedOperation(op.idempotencyKey)
		default:
			return
		}
	}
}

func (a *CosmosAdapter) drainAcceptedOperationsToDeferred(err error) {
	ops := a.snapshotAcceptedOperations()
	for _, op := range ops {
		if markErr := a.markDeferredOperation(op, 0, err, false); markErr != nil {
			a.recordDeferredPersistenceFailure(op, markErr)
		}
		a.clearAcceptedOperation(op.idempotencyKey)
	}
}

func (a *CosmosAdapter) recordDeferredPersistenceFailure(op cosmosQueuedOperation, markErr error) {
	detail := "unknown"
	if markErr != nil {
		detail = markErr.Error()
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.backlogFull = true
	a.deferredPersistenceFailureCount++
	a.deferredPersistenceFailureLast = fmt.Sprintf(
		"idempotency_key=%s defer_error=%s",
		strings.TrimSpace(op.idempotencyKey),
		detail,
	)
}

func (a *CosmosAdapter) deferredPersistenceFailureErrorLocked() error {
	last := strings.TrimSpace(a.deferredPersistenceFailureLast)
	if last == "" {
		last = "unknown"
	}
	return fmt.Errorf(
		"%w: accepted operation persistence failures=%d last=%s",
		errCosmosAdapterDeferredBacklogLimitReached,
		a.deferredPersistenceFailureCount,
		last,
	)
}

func (a *CosmosAdapter) deferredPersistenceFailureError() error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.deferredPersistenceFailureErrorLocked()
}

func (a *CosmosAdapter) replayInterval() time.Duration {
	if a.baseBackoff <= 0 {
		return 250 * time.Millisecond
	}
	if a.baseBackoff < 25*time.Millisecond {
		return 25 * time.Millisecond
	}
	return a.baseBackoff
}

func (a *CosmosAdapter) markDeferredOperation(op cosmosQueuedOperation, attempts int, submitErr error, replayable bool) error {
	now := time.Now().UTC()
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	entry, ok := a.deferredOp[op.idempotencyKey]
	if !ok {
		if a.deferredBacklogLimitReachedLocked() {
			a.backlogFull = true
			return a.deferredBacklogLimitErrorLocked()
		}
		entry = cosmosDeferredOperation{
			operation:  op,
			deferredAt: now,
		}
	}
	if attempts <= 0 {
		attempts = 1
	}
	entry.operation = op
	entry.lastAttemptAt = now
	entry.attempts += attempts
	entry.replayable = replayable
	if submitErr != nil {
		entry.lastError = submitErr.Error()
	}
	a.deferredOp[op.idempotencyKey] = entry
	a.updateBacklogHealthLocked()
	return nil
}

func (a *CosmosAdapter) clearDeferredOperation(idempotencyKey string) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	delete(a.deferredOp, idempotencyKey)
	a.updateBacklogHealthLocked()
}

func (a *CosmosAdapter) clearAcceptedOperation(idempotencyKey string) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	delete(a.acceptedOp, idempotencyKey)
}

func (a *CosmosAdapter) clearCompletedOperation(idempotencyKey string) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	delete(a.deferredOp, idempotencyKey)
	delete(a.acceptedOp, idempotencyKey)
	a.updateBacklogHealthLocked()
}

func (a *CosmosAdapter) snapshotAcceptedOperations() []cosmosQueuedOperation {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	ops := make([]cosmosQueuedOperation, 0, len(a.acceptedOp))
	for _, op := range a.acceptedOp {
		ops = append(ops, op)
	}
	return ops
}

func (a *CosmosAdapter) snapshotReplayableDeferredOperations() []cosmosQueuedOperation {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	ops := make([]cosmosQueuedOperation, 0, len(a.deferredOp))
	for _, entry := range a.deferredOp {
		if !entry.replayable {
			continue
		}
		ops = append(ops, entry.operation)
	}
	return ops
}

func (a *CosmosAdapter) deferredOperationCount() int {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return len(a.deferredOp)
}

func (a *CosmosAdapter) deferredPersistenceFailureSnapshot() (int, string) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.deferredPersistenceFailureCount, a.deferredPersistenceFailureLast
}

// DeferredOperationCount exposes adapter-internal deferred backlog size through
// the optional ChainDeferredReporter interface.
func (a *CosmosAdapter) DeferredOperationCount() int {
	return a.deferredOperationCount()
}

func (a *CosmosAdapter) deferredOperationByID(id string) (cosmosDeferredOperation, bool) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	entry, ok := a.deferredOp[id]
	return entry, ok
}

func (a *CosmosAdapter) submitWithRetry(ctx context.Context, op cosmosQueuedOperation) error {
	_, err := a.submitWithRetryCount(ctx, op)
	return err
}

func (a *CosmosAdapter) submitWithRetryCount(ctx context.Context, op cosmosQueuedOperation) (int, error) {
	backoff := a.baseBackoff
	var lastErr error
	attempts := 0
	for i := 0; i <= a.maxRetries; i++ {
		attempts++
		if err := a.submit(ctx, op); err == nil {
			return attempts, nil
		} else {
			lastErr = err
		}
		if i == a.maxRetries || !cosmosSubmitErrorRetryable(lastErr) {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return attempts, ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}
	return attempts, lastErr
}

func (a *CosmosAdapter) submit(ctx context.Context, op cosmosQueuedOperation) error {
	if a.submitMode == CosmosSubmitModeSignedTx {
		return a.signedTxSubmitter.Submit(ctx, op)
	}
	body, err := json.Marshal(op.payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+op.path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", op.idempotencyKey)
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	if err := a.applyScopedBridgeHeaders(req, op); err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &cosmosRetryableError{cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &cosmosHTTPStatusError{
			message:    fmt.Sprintf("cosmos submit %s status %d", op.path, resp.StatusCode),
			statusCode: resp.StatusCode,
		}
	}
	return nil
}

func (a *CosmosAdapter) applyScopedBridgeHeaders(req *http.Request, op cosmosQueuedOperation) error {
	if req == nil || a == nil {
		return nil
	}
	if op.path == "/x/vpnrewards/proofs" {
		if strings.TrimSpace(a.rewardProofAuthToken) == "" {
			return fmt.Errorf("cosmos reward proof submit requires RewardProofAuthToken")
		}
		req.Header.Set(cosmosRewardProofAuthorizationHeader, "Bearer "+a.rewardProofAuthToken)
	}
	if cosmosOperationRequiresFinalityToken(op) {
		if strings.TrimSpace(a.finalityAuthToken) == "" {
			return fmt.Errorf("cosmos trusted finality submit requires FinalityAuthToken")
		}
		req.Header.Set(cosmosFinalityAuthorizationHeader, "Bearer "+a.finalityAuthToken)
	}
	return nil
}

func cosmosOperationRequiresFinalityToken(op cosmosQueuedOperation) bool {
	switch payload := op.payload.(type) {
	case cosmosFundReservationPayload:
		return op.path == "/x/vpnbilling/reservations" && cosmosReconciliationStatusIsFinal(payload.Status)
	case cosmosSessionSettlementPayload:
		return op.path == "/x/vpnbilling/settlements" && cosmosReconciliationStatusIsFinal(payload.Status)
	case cosmosRewardIssuePayload:
		return op.path == "/x/vpnrewards/issues" && cosmosReconciliationStatusIsFinal(payload.Status)
	default:
		return false
	}
}

func cosmosReconciliationStatusIsFinal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case string(OperationStatusConfirmed), string(OperationStatusFailed):
		return true
	default:
		return false
	}
}

func (a *CosmosAdapter) queryByID(ctx context.Context, path string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+path, nil)
	if err != nil {
		return false, err
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("cosmos query %s status %d", path, resp.StatusCode)
}

func (a *CosmosAdapter) queryStatusByID(ctx context.Context, path string, objectKey string) (OperationStatus, bool, error) {
	status, found, _, err := a.queryStatusBodyByID(ctx, path, objectKey)
	return status, found, err
}

func (a *CosmosAdapter) queryStatusBodyByID(ctx context.Context, path string, objectKey string) (OperationStatus, bool, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+path, nil)
	if err != nil {
		return "", false, nil, err
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", false, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, nil, fmt.Errorf("cosmos query %s status %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false, nil, fmt.Errorf("read cosmos query %s: %w", path, err)
	}
	status, err := cosmosStatusFromQueryBody(body, objectKey)
	if err != nil {
		return "", false, nil, fmt.Errorf("decode cosmos query %s status: %w", path, err)
	}
	return status, true, body, nil
}

func (a *CosmosAdapter) queryJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+path, nil)
	if err != nil {
		return err
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cosmos query %s status %d", path, resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode cosmos query %s: %w", path, err)
	}
	return nil
}

func (s *cosmosHTTPSignedTxSubmitter) Submit(ctx context.Context, op cosmosQueuedOperation) error {
	payload, err := json.Marshal(op.payload)
	if err != nil {
		return fmt.Errorf("marshal signed-tx payload: %w", err)
	}
	tx := cosmosSignedTx{
		ChainID:        s.chainID,
		KeyID:          s.keyID,
		Signer:         s.signer,
		MessageType:    op.path,
		Message:        payload,
		IdempotencyKey: op.idempotencyKey,
		Nonce:          time.Now().UnixNano(),
	}
	tx.Signature = s.sign(tx)
	reqPayload := cosmosBroadcastRequest{
		Mode: "BROADCAST_MODE_SYNC",
		Tx:   tx,
	}
	body, err := json.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("marshal signed-tx broadcast request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+s.broadcastPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", op.idempotencyKey)
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &cosmosRetryableError{cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		const maxBody = 512
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		trimmed := strings.TrimSpace(string(b))
		if trimmed == "" {
			return &cosmosHTTPStatusError{
				message:    fmt.Sprintf("cosmos signed-tx submit %s status %d", s.broadcastPath, resp.StatusCode),
				statusCode: resp.StatusCode,
			}
		}
		return &cosmosHTTPStatusError{
			message:    fmt.Sprintf("cosmos signed-tx submit %s status %d: %s", s.broadcastPath, resp.StatusCode, trimmed),
			statusCode: resp.StatusCode,
		}
	}

	const maxBody = 4096
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("read cosmos signed-tx submit %s response: %w", s.broadcastPath, err)
	}
	if len(bodyBytes) > maxBody {
		return fmt.Errorf("cosmos signed-tx submit %s response exceeded %d bytes", s.broadcastPath, maxBody)
	}
	var broadcastResp cosmosBroadcastResponse
	if err := json.Unmarshal(bodyBytes, &broadcastResp); err != nil {
		trimmed := strings.TrimSpace(string(bodyBytes))
		if trimmed == "" {
			trimmed = "<empty>"
		}
		return fmt.Errorf(
			"cosmos signed-tx submit %s returned invalid JSON response: %s",
			s.broadcastPath,
			trimmed,
		)
	}
	if broadcastResp.TxResponse == nil {
		return fmt.Errorf("cosmos signed-tx submit %s missing tx_response", s.broadcastPath)
	}
	if broadcastResp.TxResponse.Code != 0 {
		rawLog := strings.TrimSpace(broadcastResp.TxResponse.RawLog)
		if rawLog == "" {
			rawLog = "no raw_log"
		}
		return &cosmosHTTPStatusError{
			message: fmt.Sprintf(
				"cosmos signed-tx submit %s tx failed code %d: %s",
				s.broadcastPath,
				broadcastResp.TxResponse.Code,
				rawLog,
			),
			statusCode: http.StatusUnprocessableEntity,
		}
	}
	return nil
}

func cosmosSubmitErrorRetryable(err error) bool {
	if err == nil {
		return false
	}
	var retryableErr *cosmosRetryableError
	if errors.As(err, &retryableErr) {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var statusErr *cosmosHTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.statusCode == http.StatusRequestTimeout ||
			statusErr.statusCode == http.StatusTooEarly ||
			statusErr.statusCode == http.StatusTooManyRequests ||
			statusErr.statusCode >= http.StatusInternalServerError
	}
	return false
}

func (s *cosmosHTTPSignedTxSubmitter) sign(tx cosmosSignedTx) string {
	payload := strings.Join([]string{
		tx.ChainID,
		tx.KeyID,
		tx.Signer,
		tx.MessageType,
		base64.StdEncoding.EncodeToString(tx.Message),
		tx.IdempotencyKey,
		fmt.Sprintf("%d", tx.Nonce),
	}, "\n")
	mac := hmac.New(sha256.New, []byte(s.secret))
	_, _ = mac.Write([]byte(payload))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func cosmosID(prefix string, id string, fallback string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		id = strings.TrimSpace(fallback)
	}
	if id == "" {
		id = fmt.Sprintf("t-%d", time.Now().UnixNano())
	}
	return prefix + ":" + id
}

func cosmosStatusValue(status OperationStatus, fallback OperationStatus) string {
	value := strings.TrimSpace(string(status))
	if value == "" {
		value = strings.TrimSpace(string(fallback))
	}
	if value == "" {
		value = strings.TrimSpace(string(OperationStatusSubmitted))
	}
	return value
}

func cosmosValidatedStatusValue(status OperationStatus, fallback OperationStatus) (string, error) {
	value := cosmosStatusValue(status, fallback)
	normalized, ok := cosmosKnownOperationStatus(value)
	if !ok {
		return "", fmt.Errorf("invalid cosmos operation status %q", value)
	}
	return string(normalized), nil
}

func cosmosOperationStatus(raw string) OperationStatus {
	status, ok := cosmosKnownOperationStatus(raw)
	if ok {
		return status
	}
	return OperationStatusSubmitted
}

func cosmosKnownOperationStatus(raw string) (OperationStatus, bool) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.TrimPrefix(normalized, "reconciliation_status_")
	switch normalized {
	case string(OperationStatusPending):
		return OperationStatusPending, true
	case string(OperationStatusSubmitted):
		return OperationStatusSubmitted, true
	case string(OperationStatusConfirmed):
		return OperationStatusConfirmed, true
	case string(OperationStatusFailed), "fail", "failure", "rejected", "reject":
		return OperationStatusFailed, true
	default:
		return "", false
	}
}

func cosmosStatusFromQueryBody(body []byte, objectKey string) (OperationStatus, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return "", fmt.Errorf("status missing")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if status, ok := cosmosStatusFromRawObject(payload); ok {
		return status, nil
	}
	if nested, ok := cosmosNestedRawObject(payload, objectKey); ok {
		if status, ok := cosmosStatusFromRawObject(nested); ok {
			return status, nil
		}
	}
	return "", fmt.Errorf("status missing")
}

func cosmosNestedRawObject(payload map[string]json.RawMessage, objectKey string) (map[string]json.RawMessage, bool) {
	objectKey = strings.ToLower(strings.TrimSpace(objectKey))
	if objectKey == "" {
		return nil, false
	}
	for key, raw := range payload {
		if strings.ToLower(strings.TrimSpace(key)) != objectKey {
			continue
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(raw, &nested); err != nil {
			return nil, false
		}
		return nested, true
	}
	return nil, false
}

func cosmosStatusFromRawObject(payload map[string]json.RawMessage) (OperationStatus, bool) {
	for key, raw := range payload {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "status", "operationstate", "operation_state":
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				continue
			}
			if strings.TrimSpace(value) == "" {
				continue
			}
			return cosmosKnownOperationStatus(value)
		}
	}
	return "", false
}

func (a *CosmosAdapter) httpBridgeFinalityDerivationEnabled() bool {
	return a != nil && a.submitMode == CosmosSubmitModeHTTP && a.trustedBridgeFinality
}

func (a *CosmosAdapter) cosmosTrustedHTTPWriteStatus(status OperationStatus, fallback OperationStatus) (string, error) {
	value, err := cosmosValidatedStatusValue(status, fallback)
	if err != nil {
		return "", err
	}
	if cosmosReconciliationStatusIsFinal(value) && !a.httpBridgeFinalityDerivationEnabled() {
		return "", fmt.Errorf("cosmos final status %q requires trusted bridge finality", value)
	}
	return value, nil
}

func cosmosHTTPBridgePersistedFinalStatus(status OperationStatus) OperationStatus {
	switch status {
	case OperationStatusFailed, OperationStatusConfirmed:
		return status
	default:
		return status
	}
}

func cosmosStringFromQueryBody(body []byte, objectKey string, fieldNames ...string) string {
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	if value := cosmosStringFromRawObject(payload, fieldNames...); value != "" {
		return value
	}
	if nested, ok := cosmosNestedRawObject(payload, objectKey); ok {
		return cosmosStringFromRawObject(nested, fieldNames...)
	}
	return ""
}

func cosmosFundReservationFromQueryBody(body []byte) (FundReservation, bool, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return FundReservation{}, false, nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return FundReservation{}, false, fmt.Errorf("decode fund reservation body: %w", err)
	}
	raw := payload
	if nested, ok := cosmosNestedRawObject(payload, "reservation"); ok {
		raw = nested
	}
	reservationID := cosmosStringFromRawObject(raw, "reservation_id", "ReservationID")
	sessionID := cosmosStringFromRawObject(raw, "session_id", "SessionID")
	subjectID := cosmosStringFromRawObject(raw, "subject_id", "SubjectID", "sponsor_id", "SponsorID")
	currency := cosmosStringFromRawObject(raw, "currency", "Currency", "asset_denom", "AssetDenom")
	status, _ := cosmosStatusFromRawObject(raw)
	amountMicros, err := cosmosInt64FromRawObject(raw, "amount_micros", "AmountMicros", "amount", "Amount")
	if err != nil {
		return FundReservation{}, false, err
	}
	createdAt, err := cosmosTimeFromRawObject(raw, "created_at", "CreatedAt", "created_at_unix", "CreatedAtUnix")
	if err != nil {
		return FundReservation{}, false, err
	}
	if strings.TrimSpace(reservationID) == "" && strings.TrimSpace(sessionID) == "" && strings.TrimSpace(subjectID) == "" {
		return FundReservation{}, false, nil
	}
	return FundReservation{
		ReservationID: strings.TrimSpace(reservationID),
		SessionID:     strings.TrimSpace(sessionID),
		SubjectID:     strings.TrimSpace(subjectID),
		AmountMicros:  amountMicros,
		Currency:      strings.TrimSpace(currency),
		CreatedAt:     createdAt,
		Status:        status,
	}, true, nil
}

func cosmosSessionSettlementFromQueryBody(body []byte) (SessionSettlement, bool, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return SessionSettlement{}, false, nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return SessionSettlement{}, false, fmt.Errorf("decode session settlement body: %w", err)
	}
	raw := payload
	if nested, ok := cosmosNestedRawObject(payload, "settlement"); ok {
		raw = nested
	}
	settlementID := cosmosStringFromRawObject(raw, "settlement_id", "SettlementID")
	reservationID := cosmosStringFromRawObject(raw, "reservation_id", "ReservationID")
	sessionID := cosmosStringFromRawObject(raw, "session_id", "SessionID")
	subjectID := cosmosStringFromRawObject(raw, "subject_id", "SubjectID")
	currency := cosmosStringFromRawObject(raw, "currency", "Currency", "asset_denom", "AssetDenom")
	status, _ := cosmosStatusFromRawObject(raw)
	chargedMicros, err := cosmosInt64FromRawObject(raw, "charged_micros", "ChargedMicros", "billed_amount", "BilledAmount", "amount", "Amount")
	if err != nil {
		return SessionSettlement{}, false, err
	}
	settledAt, err := cosmosTimeFromRawObject(raw, "settled_at", "SettledAt", "settled_at_unix", "SettledAtUnix")
	if err != nil {
		return SessionSettlement{}, false, err
	}
	if strings.TrimSpace(settlementID) == "" && strings.TrimSpace(sessionID) == "" && strings.TrimSpace(reservationID) == "" {
		return SessionSettlement{}, false, nil
	}
	return SessionSettlement{
		SettlementID:  strings.TrimSpace(settlementID),
		ReservationID: strings.TrimSpace(reservationID),
		SessionID:     strings.TrimSpace(sessionID),
		SubjectID:     strings.TrimSpace(subjectID),
		ChargedMicros: chargedMicros,
		Currency:      strings.TrimSpace(currency),
		SettledAt:     settledAt,
		Status:        status,
	}, true, nil
}

type cosmosRewardDistributionMaterial struct {
	DistributionID string
	AccrualID      string
	PayoutRef      string
	DistributedAt  int64
	Status         OperationStatus
}

type cosmosRewardAccrualMaterial struct {
	AccrualID       string
	SessionID       string
	ProviderID      string
	AssetDenom      string
	Amount          int64
	AccruedAtUnix   int64
	PayoutStartUnix int64
	PayoutEndUnix   int64
	Status          OperationStatus
}

type cosmosRewardPayoutRefMaterial struct {
	RewardID              string
	SettlementReferenceID string
	TrafficProofRef       string
	PayoutPeriodStart     time.Time
	PayoutPeriodEnd       time.Time
}

func cosmosRewardDistributionFromQueryBody(body []byte) (cosmosRewardDistributionMaterial, bool, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return cosmosRewardDistributionMaterial{}, false, nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return cosmosRewardDistributionMaterial{}, false, fmt.Errorf("decode reward distribution body: %w", err)
	}
	raw := payload
	if nested, ok := cosmosNestedRawObject(payload, "distribution"); ok {
		raw = nested
	}
	distributionID := cosmosStringFromRawObject(raw, "distribution_id", "DistributionID")
	accrualID := cosmosStringFromRawObject(raw, "accrual_id", "AccrualID")
	payoutRef := cosmosStringFromRawObject(raw, "payout_ref", "PayoutRef")
	status, _ := cosmosStatusFromRawObject(raw)
	distributedAt, err := cosmosInt64FromRawObject(raw, "distributed_at", "DistributedAt", "distributed_at_unix", "DistributedAtUnix")
	if err != nil {
		return cosmosRewardDistributionMaterial{}, false, err
	}
	if strings.TrimSpace(distributionID) == "" && strings.TrimSpace(accrualID) == "" {
		return cosmosRewardDistributionMaterial{}, false, nil
	}
	return cosmosRewardDistributionMaterial{
		DistributionID: strings.TrimSpace(distributionID),
		AccrualID:      strings.TrimSpace(accrualID),
		PayoutRef:      strings.TrimSpace(payoutRef),
		DistributedAt:  distributedAt,
		Status:         status,
	}, true, nil
}

func cosmosRewardAccrualFromQueryBody(body []byte) (cosmosRewardAccrualMaterial, bool, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return cosmosRewardAccrualMaterial{}, false, nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return cosmosRewardAccrualMaterial{}, false, fmt.Errorf("decode reward accrual body: %w", err)
	}
	raw := payload
	if nested, ok := cosmosNestedRawObject(payload, "accrual"); ok {
		raw = nested
	}
	accrualID := cosmosStringFromRawObject(raw, "accrual_id", "AccrualID")
	sessionID := cosmosStringFromRawObject(raw, "session_id", "SessionID")
	providerID := cosmosStringFromRawObject(raw, "provider_id", "ProviderID", "provider_subject_id", "ProviderSubjectID")
	assetDenom := cosmosStringFromRawObject(raw, "asset_denom", "AssetDenom", "currency", "Currency")
	status, _ := cosmosStatusFromRawObject(raw)
	amount, err := cosmosInt64FromRawObject(raw, "amount", "Amount", "reward_micros", "RewardMicros")
	if err != nil {
		return cosmosRewardAccrualMaterial{}, false, err
	}
	accruedAtUnix, err := cosmosInt64FromRawObject(raw, "accrued_at_unix", "AccruedAtUnix", "issued_at_unix", "IssuedAtUnix")
	if err != nil {
		return cosmosRewardAccrualMaterial{}, false, err
	}
	payoutStartUnix, err := cosmosInt64FromRawObject(raw, "payout_start_unix", "PayoutStartUnix")
	if err != nil {
		return cosmosRewardAccrualMaterial{}, false, err
	}
	payoutEndUnix, err := cosmosInt64FromRawObject(raw, "payout_end_unix", "PayoutEndUnix")
	if err != nil {
		return cosmosRewardAccrualMaterial{}, false, err
	}
	if strings.TrimSpace(accrualID) == "" && strings.TrimSpace(sessionID) == "" && strings.TrimSpace(providerID) == "" {
		return cosmosRewardAccrualMaterial{}, false, nil
	}
	return cosmosRewardAccrualMaterial{
		AccrualID:       strings.TrimSpace(accrualID),
		SessionID:       strings.TrimSpace(sessionID),
		ProviderID:      strings.TrimSpace(providerID),
		AssetDenom:      strings.TrimSpace(assetDenom),
		Amount:          amount,
		AccruedAtUnix:   accruedAtUnix,
		PayoutStartUnix: payoutStartUnix,
		PayoutEndUnix:   payoutEndUnix,
		Status:          status,
	}, true, nil
}

func cosmosRewardPayoutRefFromString(raw string) cosmosRewardPayoutRefMaterial {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cosmosRewardPayoutRefMaterial{}
	}
	var payload struct {
		RewardID              string `json:"RewardID"`
		SettlementReferenceID string `json:"SettlementReferenceID"`
		TrafficProofRef       string `json:"TrafficProofRef"`
		PayoutPeriodStart     string `json:"PayoutPeriodStart"`
		PayoutPeriodEnd       string `json:"PayoutPeriodEnd"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return cosmosRewardPayoutRefMaterial{RewardID: raw}
	}
	return cosmosRewardPayoutRefMaterial{
		RewardID:              strings.TrimSpace(payload.RewardID),
		SettlementReferenceID: strings.TrimSpace(payload.SettlementReferenceID),
		TrafficProofRef:       strings.TrimSpace(payload.TrafficProofRef),
		PayoutPeriodStart:     cosmosParseOptionalRFC3339(payload.PayoutPeriodStart),
		PayoutPeriodEnd:       cosmosParseOptionalRFC3339(payload.PayoutPeriodEnd),
	}
}

func cosmosParseOptionalRFC3339(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func cosmosSlashEvidenceFromQueryBody(body []byte) (SlashEvidence, bool, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return SlashEvidence{}, false, nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return SlashEvidence{}, false, fmt.Errorf("decode slash evidence body: %w", err)
	}
	raw := payload
	if nested, ok := cosmosNestedRawObject(payload, "evidence"); ok {
		raw = nested
	}
	evidenceID := cosmosStringFromRawObject(raw, "evidence_id", "EvidenceID")
	subjectID := cosmosStringFromRawObject(raw, "subject_id", "SubjectID", "provider_id", "ProviderID")
	sessionID := cosmosStringFromRawObject(raw, "session_id", "SessionID")
	violationType := cosmosStringFromRawObject(raw, "violation_type", "ViolationType")
	evidenceRef := cosmosFirstNonEmpty(
		cosmosStringFromRawObject(raw, "evidence_ref", "EvidenceRef"),
		cosmosStringFromRawObject(raw, "proof_hash", "ProofHash"),
	)
	currency := cosmosFirstNonEmpty(
		cosmosStringFromRawObject(raw, "currency", "Currency"),
		cosmosStringFromRawObject(raw, "slash_denom", "SlashDenom"),
	)
	status, _ := cosmosStatusFromRawObject(raw)
	slashMicros, err := cosmosInt64FromRawObject(raw, "slash_micros", "SlashMicros", "slash_amount", "SlashAmount")
	if err != nil {
		return SlashEvidence{}, false, err
	}
	observedAt, err := cosmosTimeFromRawObject(raw, "observed_at", "ObservedAt", "submitted_at", "SubmittedAt", "submitted_at_unix", "SubmittedAtUnix")
	if err != nil {
		return SlashEvidence{}, false, err
	}
	if strings.TrimSpace(evidenceID) == "" && strings.TrimSpace(subjectID) == "" && strings.TrimSpace(evidenceRef) == "" {
		return SlashEvidence{}, false, nil
	}
	return SlashEvidence{
		EvidenceID:    strings.TrimSpace(evidenceID),
		SubjectID:     strings.TrimSpace(subjectID),
		SessionID:     strings.TrimSpace(sessionID),
		ViolationType: strings.TrimSpace(violationType),
		EvidenceRef:   canonicalObjectiveEvidenceRef(evidenceRef),
		SlashMicros:   slashMicros,
		Currency:      normalizeCurrencyCode(currency),
		ObservedAt:    observedAt,
		Status:        status,
	}, true, nil
}

func cosmosInt64FromRawObject(payload map[string]json.RawMessage, fieldNames ...string) (int64, error) {
	raw, fieldName, ok := cosmosRawFromObject(payload, fieldNames...)
	if !ok {
		return 0, nil
	}
	{
		var number json.Number
		if err := json.Unmarshal(raw, &number); err == nil {
			if value, parseErr := number.Int64(); parseErr == nil {
				return value, nil
			}
			return 0, fmt.Errorf("decode fund reservation %s: expected integer value", fieldName)
		}
		var stringValue string
		if err := json.Unmarshal(raw, &stringValue); err == nil {
			if strings.TrimSpace(stringValue) == "" {
				return 0, nil
			}
			value, parseErr := strconv.ParseInt(strings.TrimSpace(stringValue), 10, 64)
			if parseErr != nil {
				return 0, fmt.Errorf("decode fund reservation %s: %w", fieldName, parseErr)
			}
			return value, nil
		}
		return 0, fmt.Errorf("decode fund reservation %s: unsupported number encoding", fieldName)
	}
}

func cosmosTimeFromRawObject(payload map[string]json.RawMessage, fieldNames ...string) (time.Time, error) {
	raw, fieldName, ok := cosmosRawFromObject(payload, fieldNames...)
	if !ok {
		return time.Time{}, nil
	}
	{
		var stringValue string
		if err := json.Unmarshal(raw, &stringValue); err == nil {
			if strings.TrimSpace(stringValue) == "" {
				return time.Time{}, nil
			}
			parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(stringValue))
			if err == nil {
				return parsed, nil
			}
			unixValue, parseErr := strconv.ParseInt(strings.TrimSpace(stringValue), 10, 64)
			if parseErr != nil {
				return time.Time{}, fmt.Errorf("decode fund reservation %s: %w", fieldName, err)
			}
			if unixValue <= 0 {
				return time.Time{}, nil
			}
			return time.Unix(unixValue, 0).UTC(), nil
		}
		var number json.Number
		if err := json.Unmarshal(raw, &number); err == nil {
			unixValue, parseErr := number.Int64()
			if parseErr != nil {
				return time.Time{}, fmt.Errorf("decode fund reservation %s: expected unix integer value", fieldName)
			}
			if unixValue <= 0 {
				return time.Time{}, nil
			}
			return time.Unix(unixValue, 0).UTC(), nil
		}
		return time.Time{}, fmt.Errorf("decode fund reservation %s: unsupported time encoding", fieldName)
	}
}

func cosmosStringFromRawObject(payload map[string]json.RawMessage, fieldNames ...string) string {
	raw, _, ok := cosmosRawFromObject(payload, fieldNames...)
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func cosmosRawFromObject(payload map[string]json.RawMessage, fieldNames ...string) (json.RawMessage, string, bool) {
	if len(payload) == 0 || len(fieldNames) == 0 {
		return nil, "", false
	}
	wanted := make(map[string]struct{}, len(fieldNames))
	for _, name := range fieldNames {
		name = strings.ToLower(strings.TrimSpace(name))
		name = strings.ReplaceAll(name, "_", "")
		if name != "" {
			wanted[name] = struct{}{}
		}
	}
	for key, raw := range payload {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		normalizedKey = strings.ReplaceAll(normalizedKey, "_", "")
		if _, ok := wanted[normalizedKey]; !ok {
			continue
		}
		return raw, key, true
	}
	return nil, "", false
}

func cosmosFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
