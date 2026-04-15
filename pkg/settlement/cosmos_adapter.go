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
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	CosmosSubmitModeHTTP     = "http"
	CosmosSubmitModeSignedTx = "signed-tx"
)

type CosmosAdapterConfig struct {
	Endpoint    string
	APIKey      string
	QueueSize   int
	MaxRetries  int
	BaseBackoff time.Duration
	HTTPTimeout time.Duration

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

	workerCtx    context.Context
	workerCancel context.CancelFunc
	workerWG     sync.WaitGroup
}

var _ ChainAdapter = (*CosmosAdapter)(nil)
var _ ChainConfirmationQuerier = (*CosmosAdapter)(nil)

type cosmosQueuedOperation struct {
	path           string
	payload        any
	idempotencyKey string
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

type cosmosHTTPStatusError struct {
	message    string
	statusCode int
}

func (e *cosmosHTTPStatusError) Error() string {
	return e.message
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

func NewCosmosAdapter(cfg CosmosAdapterConfig) (*CosmosAdapter, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		return nil, fmt.Errorf("cosmos adapter endpoint required")
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

	client := &http.Client{Timeout: httpTimeout}

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
				secretBytes, err := os.ReadFile(secretFile)
				if err != nil {
					return nil, fmt.Errorf("read cosmos signed-tx secret file: %w", err)
				}
				secret = strings.TrimSpace(string(secretBytes))
				if secret == "" {
					return nil, fmt.Errorf("cosmos signed-tx secret file %q is empty", secretFile)
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
		workerCtx:         workerCtx,
		workerCancel:      workerCancel,
	}
	a.workerWG.Add(1)
	go a.runWorker()
	return a, nil
}

func (a *CosmosAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	id := cosmosID("settlement", settlement.SettlementID, settlement.SessionID)
	return id, a.enqueue(cosmosQueuedOperation{
		path:           "/x/vpnbilling/settlements",
		payload:        settlement,
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) SubmitRewardIssue(_ context.Context, reward RewardIssue) (string, error) {
	id := cosmosID("reward", reward.RewardID, reward.SessionID)
	return id, a.enqueue(cosmosQueuedOperation{
		path:           "/x/vpnrewards/issues",
		payload:        reward,
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	id := cosmosID("sponsor-reservation", reservation.ReservationID, reservation.SessionID)
	return id, a.enqueue(cosmosQueuedOperation{
		path:           "/x/vpnsponsor/reservations",
		payload:        reservation,
		idempotencyKey: id,
	})
}

func (a *CosmosAdapter) SubmitSlashEvidence(_ context.Context, evidence SlashEvidence) (string, error) {
	id := cosmosID("slash", evidence.EvidenceID, evidence.SubjectID)
	return id, a.enqueue(cosmosQueuedOperation{
		path:           "/x/vpnslashing/evidence",
		payload:        evidence,
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
	a.workerCancel()
	a.workerWG.Wait()
}

func (a *CosmosAdapter) enqueue(op cosmosQueuedOperation) error {
	select {
	case <-a.workerCtx.Done():
		return fmt.Errorf("cosmos adapter closed")
	case a.queue <- op:
		return nil
	default:
		return fmt.Errorf("cosmos adapter queue full")
	}
}

func (a *CosmosAdapter) runWorker() {
	defer a.workerWG.Done()
	for {
		select {
		case <-a.workerCtx.Done():
			return
		case op := <-a.queue:
			_ = a.submitWithRetry(a.workerCtx, op)
		}
	}
}

func (a *CosmosAdapter) submitWithRetry(ctx context.Context, op cosmosQueuedOperation) error {
	backoff := a.baseBackoff
	var lastErr error
	for i := 0; i <= a.maxRetries; i++ {
		if err := a.submit(ctx, op); err == nil {
			return nil
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
			return ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}
	return lastErr
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
