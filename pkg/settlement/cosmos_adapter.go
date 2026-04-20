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
	SignedTxBroadcastPath string
	SignedTxChainID       string
	SignedTxSigner        string
	SignedTxSecret        string
	SignedTxSecretFile    string
	SignedTxKeyID         string
}

type CosmosAdapter struct {
	endpoint    string
	apiKey      string
	client      *http.Client
	maxRetries  int
	baseBackoff time.Duration
	submitMode  string

	queue chan cosmosQueuedOperation

	signedTxSubmitter cosmosSignedTxSubmitter

	stateMu       sync.Mutex
	closed        bool
	deferredOp    map[string]cosmosDeferredOperation
	deferredOpMax int

	workerCtx    context.Context
	workerCancel context.CancelFunc
	workerWG     sync.WaitGroup
	closeOnce    sync.Once
}

var _ ChainAdapter = (*CosmosAdapter)(nil)
var _ ChainConfirmationQuerier = (*CosmosAdapter)(nil)

type cosmosQueuedOperation struct {
	path           string
	payload        any
	idempotencyKey string
}

type cosmosSessionSettlementPayload struct {
	SettlementID  string    `json:"SettlementID"`
	SessionID     string    `json:"SessionID"`
	SubjectID     string    `json:"SubjectID"`
	ChargedMicros int64     `json:"ChargedMicros"`
	Currency      string    `json:"Currency"`
	SettledAt     time.Time `json:"SettledAt"`
	Status        string    `json:"Status"`
}

type cosmosRewardIssuePayload struct {
	RewardID          string    `json:"RewardID"`
	ProviderSubjectID string    `json:"ProviderSubjectID"`
	SessionID         string    `json:"SessionID"`
	RewardMicros      int64     `json:"RewardMicros"`
	Currency          string    `json:"Currency"`
	IssuedAt          time.Time `json:"IssuedAt"`
	Status            string    `json:"Status"`
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
	ObservedAt    time.Time `json:"ObservedAt"`
	Status        string    `json:"Status"`
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
			apiKey:        strings.TrimSpace(cfg.APIKey),
			signer:        signer,
			chainID:       strings.TrimSpace(cfg.SignedTxChainID),
			secret:        secret,
			keyID:         strings.TrimSpace(cfg.SignedTxKeyID),
			client:        client,
		}
	}

	workerCtx, workerCancel := context.WithCancel(context.Background())
	a := &CosmosAdapter{
		endpoint:          endpoint,
		apiKey:            strings.TrimSpace(cfg.APIKey),
		client:            client,
		maxRetries:        maxRetries,
		baseBackoff:       baseBackoff,
		submitMode:        submitMode,
		queue:             make(chan cosmosQueuedOperation, queueSize),
		signedTxSubmitter: signedTxSubmitter,
		deferredOp:        map[string]cosmosDeferredOperation{},
		deferredOpMax:     cosmosDeferredOperationDefaultMax,
		workerCtx:         workerCtx,
		workerCancel:      workerCancel,
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
	return ip.IsPrivate()
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

func (a *CosmosAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	id := cosmosID("settlement", settlement.SettlementID, settlement.SessionID)
	return id, a.enqueue(cosmosQueuedOperation{
		path: "/x/vpnbilling/settlements",
		payload: cosmosSessionSettlementPayload{
			SettlementID:  settlement.SettlementID,
			SessionID:     settlement.SessionID,
			SubjectID:     settlement.SubjectID,
			ChargedMicros: settlement.ChargedMicros,
			Currency:      settlement.Currency,
			SettledAt:     settlement.SettledAt,
			Status:        cosmosStatusValue(settlement.Status, OperationStatusSubmitted),
		},
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) SubmitRewardIssue(_ context.Context, reward RewardIssue) (string, error) {
	id := cosmosID("reward", reward.RewardID, reward.SessionID)
	return id, a.enqueue(cosmosQueuedOperation{
		path: "/x/vpnrewards/issues",
		payload: cosmosRewardIssuePayload{
			RewardID:          reward.RewardID,
			ProviderSubjectID: reward.ProviderSubjectID,
			SessionID:         reward.SessionID,
			RewardMicros:      reward.RewardMicros,
			Currency:          reward.Currency,
			IssuedAt:          reward.IssuedAt,
			Status:            cosmosStatusValue(reward.Status, OperationStatusSubmitted),
		},
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	id := cosmosID("sponsor-reservation", reservation.ReservationID, reservation.SessionID)
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
			Status:        cosmosStatusValue(reservation.Status, OperationStatusPending),
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
			ObservedAt:    evidence.ObservedAt,
			Status:        cosmosStatusValue(evidence.Status, OperationStatusSubmitted),
		},
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) Health(ctx context.Context) error {
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

func (a *CosmosAdapter) HasRewardIssue(ctx context.Context, rewardID string) (bool, error) {
	rewardID = strings.TrimSpace(rewardID)
	if rewardID == "" {
		return false, fmt.Errorf("reward id required")
	}
	// Bridge materializes reward submissions as distribution records with "dist:<reward_id>".
	distributionID := "dist:" + rewardID
	return a.queryByID(ctx, "/x/vpnrewards/distributions/"+url.PathEscape(distributionID))
}

func (a *CosmosAdapter) HasSponsorReservation(ctx context.Context, reservationID string) (bool, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return false, fmt.Errorf("reservation id required")
	}
	return a.queryByID(ctx, "/x/vpnsponsor/delegations/"+url.PathEscape(reservationID))
}

func (a *CosmosAdapter) HasSlashEvidence(ctx context.Context, evidenceID string) (bool, error) {
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return false, fmt.Errorf("evidence id required")
	}
	return a.queryByID(ctx, "/x/vpnslashing/evidence/"+url.PathEscape(evidenceID))
}

func (a *CosmosAdapter) Close() {
	a.closeOnce.Do(func() {
		a.stateMu.Lock()
		a.closed = true
		a.stateMu.Unlock()
		a.workerCancel()
		a.workerWG.Wait()
	})
}

func (a *CosmosAdapter) enqueue(op cosmosQueuedOperation) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.closed {
		return fmt.Errorf("cosmos adapter closed")
	}
	select {
	case a.queue <- op:
		return nil
	default:
		return fmt.Errorf("cosmos adapter queue full")
	}
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
		a.markDeferredOperation(op, attempts, err, cosmosSubmitErrorRetryable(err))
		return
	}
	a.clearDeferredOperation(op.idempotencyKey)
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
			a.markDeferredOperation(op, 0, err, false)
		default:
			return
		}
	}
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

func (a *CosmosAdapter) markDeferredOperation(op cosmosQueuedOperation, attempts int, submitErr error, replayable bool) {
	now := time.Now().UTC()
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	entry, ok := a.deferredOp[op.idempotencyKey]
	if !ok {
		a.enforceDeferredOperationLimitLocked()
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
}

func (a *CosmosAdapter) enforceDeferredOperationLimitLocked() {
	limit := a.deferredOpMax
	if limit <= 0 {
		limit = cosmosDeferredOperationDefaultMax
	}
	if limit <= 0 {
		return
	}
	for len(a.deferredOp) >= limit {
		oldestKey := ""
		var oldestAt time.Time
		for key, entry := range a.deferredOp {
			if oldestKey == "" || entry.deferredAt.Before(oldestAt) ||
				(entry.deferredAt.Equal(oldestAt) && key < oldestKey) {
				oldestKey = key
				oldestAt = entry.deferredAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(a.deferredOp, oldestKey)
	}
}

func (a *CosmosAdapter) clearDeferredOperation(idempotencyKey string) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	delete(a.deferredOp, idempotencyKey)
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
