package settlement

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCosmosAdapterSubmitsSettlementWithIdempotencyKey(t *testing.T) {
	type seenRequest struct {
		path string
		key  string
	}
	seenCh := make(chan seenRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCh <- seenRequest{
			path: r.URL.Path,
			key:  r.Header.Get("Idempotency-Key"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	ref, err := adapter.SubmitSessionSettlement(context.Background(), SessionSettlement{
		SettlementID: "set-123",
		SessionID:    "sess-123",
	})
	if err != nil {
		t.Fatalf("SubmitSessionSettlement: %v", err)
	}
	if ref != "settlement:set-123" {
		t.Fatalf("unexpected ref id %q", ref)
	}

	select {
	case got := <-seenCh:
		if got.path != "/x/vpnbilling/settlements" {
			t.Fatalf("unexpected path %q", got.path)
		}
		if got.key != "settlement:set-123" {
			t.Fatalf("unexpected idempotency key %q", got.key)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for queued submit")
	}
}

func TestCosmosAdapterRetriesTransientFailure(t *testing.T) {
	var attempts int32
	doneCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		select {
		case doneCh <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  2,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-1",
		RewardMicros:      100,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for retry success")
	}
	if atomic.LoadInt32(&attempts) < 2 {
		t.Fatalf("expected at least two attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestCosmosAdapterDoesNotRetryNonRetryable4xx(t *testing.T) {
	var attempts int32
	firstAttemptCh := make(chan struct{}, 1)
	secondAttemptCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			select {
			case firstAttemptCh <- struct{}{}:
			default:
			}
		}
		if n == 2 {
			select {
			case secondAttemptCh <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  3,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-4xx-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-1",
		RewardMicros:      100,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}

	select {
	case <-firstAttemptCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first attempt")
	}

	select {
	case <-secondAttemptCh:
		t.Fatalf("unexpected retry for non-retryable 4xx response")
	case <-time.After(200 * time.Millisecond):
	}

	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected exactly one attempt, got %d", got)
	}
}

func TestCosmosAdapterRetries429And503(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statusCode int
	}{
		{name: "too_many_requests", statusCode: http.StatusTooManyRequests},
		{name: "service_unavailable", statusCode: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts int32
			doneCh := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := atomic.AddInt32(&attempts, 1)
				if n == 1 {
					w.WriteHeader(tc.statusCode)
					return
				}
				w.WriteHeader(http.StatusOK)
				select {
				case doneCh <- struct{}{}:
				default:
				}
			}))
			defer srv.Close()

			adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
				Endpoint:    srv.URL,
				QueueSize:   8,
				MaxRetries:  2,
				BaseBackoff: 5 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			if _, err := adapter.SubmitSponsorReservation(context.Background(), SponsorCreditReservation{
				ReservationID: "res-1",
				SponsorID:     "sp-1",
				SessionID:     "sess-1",
				AmountMicros:  100,
				Currency:      "USD",
			}); err != nil {
				t.Fatalf("SubmitSponsorReservation: %v", err)
			}

			select {
			case <-doneCh:
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out waiting for retry success")
			}
			if got := atomic.LoadInt32(&attempts); got < 2 {
				t.Fatalf("expected at least two attempts, got %d", got)
			}
		})
	}
}

func TestCosmosAdapterConfirmationQueryPathMappings(t *testing.T) {
	seenPathCh := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPathCh <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if ok, err := adapter.HasSessionSettlement(context.Background(), "set-1"); err != nil || !ok {
		t.Fatalf("HasSessionSettlement expected true,nil got ok=%v err=%v", ok, err)
	}
	if got := <-seenPathCh; got != "/x/vpnbilling/settlements/set-1" {
		t.Fatalf("unexpected settlement query path %q", got)
	}

	if ok, err := adapter.HasRewardIssue(context.Background(), "rew-1"); err != nil || !ok {
		t.Fatalf("HasRewardIssue expected true,nil got ok=%v err=%v", ok, err)
	}
	if got := <-seenPathCh; got != "/x/vpnrewards/distributions/dist:rew-1" {
		t.Fatalf("unexpected reward query path %q", got)
	}

	if ok, err := adapter.HasSponsorReservation(context.Background(), "sres-1"); err != nil || !ok {
		t.Fatalf("HasSponsorReservation expected true,nil got ok=%v err=%v", ok, err)
	}
	if got := <-seenPathCh; got != "/x/vpnsponsor/delegations/sres-1" {
		t.Fatalf("unexpected sponsor query path %q", got)
	}

	if ok, err := adapter.HasSlashEvidence(context.Background(), "ev-1"); err != nil || !ok {
		t.Fatalf("HasSlashEvidence expected true,nil got ok=%v err=%v", ok, err)
	}
	if got := <-seenPathCh; got != "/x/vpnslashing/evidence/ev-1" {
		t.Fatalf("unexpected slash query path %q", got)
	}
}

func TestCosmosAdapterConfirmationQueriesReturnFalseOnNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  1,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	ok, err := adapter.HasSessionSettlement(context.Background(), "missing-settlement")
	if err != nil {
		t.Fatalf("HasSessionSettlement unexpected err: %v", err)
	}
	if ok {
		t.Fatalf("expected HasSessionSettlement=false for 404 query")
	}
}

func TestCosmosAdapterSignedTxModeSubmitsBroadcast(t *testing.T) {
	type seenRequest struct {
		path string
		key  string
		body []byte
	}
	seenCh := make(chan seenRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- seenRequest{
			path: r.URL.Path,
			key:  r.Header.Get("Idempotency-Key"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:        srv.URL,
		QueueSize:       8,
		MaxRetries:      1,
		BaseBackoff:     5 * time.Millisecond,
		SubmitMode:      CosmosSubmitModeSignedTx,
		SignedTxChainID: "tdpn-1",
		SignedTxSigner:  "signer1",
		SignedTxSecret:  "test-secret",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	ref, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-signed-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-1",
		RewardMicros:      100,
		Currency:          "USD",
	})
	if err != nil {
		t.Fatalf("SubmitRewardIssue: %v", err)
	}
	if ref != "reward:rew-signed-1" {
		t.Fatalf("unexpected ref id %q", ref)
	}

	select {
	case got := <-seenCh:
		if got.path != "/cosmos/tx/v1beta1/txs" {
			t.Fatalf("unexpected path %q", got.path)
		}
		if got.key != "reward:rew-signed-1" {
			t.Fatalf("unexpected idempotency key %q", got.key)
		}
		var req cosmosBroadcastRequest
		if err := json.Unmarshal(got.body, &req); err != nil {
			t.Fatalf("unmarshal broadcast request: %v", err)
		}
		if req.Mode != "BROADCAST_MODE_SYNC" {
			t.Fatalf("unexpected broadcast mode %q", req.Mode)
		}
		if req.Tx.ChainID != "tdpn-1" {
			t.Fatalf("unexpected chain id %q", req.Tx.ChainID)
		}
		if req.Tx.Signer != "signer1" {
			t.Fatalf("unexpected signer %q", req.Tx.Signer)
		}
		if req.Tx.MessageType != "/x/vpnrewards/issues" {
			t.Fatalf("unexpected message type %q", req.Tx.MessageType)
		}
		if req.Tx.IdempotencyKey != "reward:rew-signed-1" {
			t.Fatalf("unexpected tx idempotency key %q", req.Tx.IdempotencyKey)
		}
		if req.Tx.Signature == "" {
			t.Fatalf("expected non-empty signature")
		}
		var msg RewardIssue
		if err := json.Unmarshal(req.Tx.Message, &msg); err != nil {
			t.Fatalf("unmarshal tx message: %v", err)
		}
		if msg.RewardID != "rew-signed-1" {
			t.Fatalf("unexpected reward id %q", msg.RewardID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for signed-tx submit")
	}
}

func TestCosmosAdapterSignedTxModeRetriesFailures(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:       srv.URL,
		QueueSize:      8,
		MaxRetries:     2,
		BaseBackoff:    5 * time.Millisecond,
		SubmitMode:     CosmosSubmitModeSignedTx,
		SignedTxSigner: "signer1",
		SignedTxSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
		EvidenceID:    "ev-1",
		SubjectID:     "subject-1",
		SessionID:     "sess-1",
		ViolationType: "double-sign",
		EvidenceRef:   "ref-1",
		SlashMicros:   1000,
		Currency:      "USD",
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&attempts) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected exactly 3 attempts (1 + 2 retries), got %d", got)
	}
}

func TestCosmosAdapterSignedTxModeDoesNotRetryNonRetryable4xx(t *testing.T) {
	var attempts int32
	firstAttemptCh := make(chan struct{}, 1)
	secondAttemptCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			select {
			case firstAttemptCh <- struct{}{}:
			default:
			}
		}
		if n == 2 {
			select {
			case secondAttemptCh <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:       srv.URL,
		QueueSize:      8,
		MaxRetries:     3,
		BaseBackoff:    5 * time.Millisecond,
		SubmitMode:     CosmosSubmitModeSignedTx,
		SignedTxSigner: "signer-4xx",
		SignedTxSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
		EvidenceID:    "ev-4xx-signed-1",
		SubjectID:     "subject-1",
		SessionID:     "sess-1",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:abc123",
		SlashMicros:   500,
		Currency:      "USD",
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}

	select {
	case <-firstAttemptCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first signed-tx attempt")
	}

	select {
	case <-secondAttemptCh:
		t.Fatalf("unexpected retry for non-retryable signed-tx 4xx response")
	case <-time.After(200 * time.Millisecond):
	}

	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected exactly one signed-tx attempt, got %d", got)
	}
}

func TestCosmosAdapterSignedTxModeRetries429And503(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statusCode int
	}{
		{name: "too_many_requests", statusCode: http.StatusTooManyRequests},
		{name: "service_unavailable", statusCode: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts int32
			doneCh := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := atomic.AddInt32(&attempts, 1)
				if n == 1 {
					w.WriteHeader(tc.statusCode)
					return
				}
				w.WriteHeader(http.StatusOK)
				select {
				case doneCh <- struct{}{}:
				default:
				}
			}))
			defer srv.Close()

			adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
				Endpoint:       srv.URL,
				QueueSize:      8,
				MaxRetries:     2,
				BaseBackoff:    5 * time.Millisecond,
				SubmitMode:     CosmosSubmitModeSignedTx,
				SignedTxSigner: "signer-retry",
				SignedTxSecret: "test-secret",
			})
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
				RewardID:          "rew-signed-retry-1",
				ProviderSubjectID: "provider-1",
				SessionID:         "sess-1",
				RewardMicros:      100,
				Currency:          "USD",
			}); err != nil {
				t.Fatalf("SubmitRewardIssue: %v", err)
			}

			select {
			case <-doneCh:
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out waiting for signed-tx retry success")
			}
			if got := atomic.LoadInt32(&attempts); got < 2 {
				t.Fatalf("expected at least two signed-tx attempts, got %d", got)
			}
		})
	}
}

func TestCosmosAdapterSignedTxModeReadsSecretFromFileAndIncludesKeyID(t *testing.T) {
	type seenRequest struct {
		path string
		body []byte
	}
	seenCh := make(chan seenRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- seenRequest{
			path: r.URL.Path,
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secretFile := filepath.Join(t.TempDir(), "signed_tx_secret.txt")
	if err := os.WriteFile(secretFile, []byte("  file-secret-value \n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           srv.URL,
		QueueSize:          8,
		MaxRetries:         1,
		BaseBackoff:        5 * time.Millisecond,
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxChainID:    "tdpn-file-secret-1",
		SignedTxSigner:     "file-secret-signer",
		SignedTxSecretFile: secretFile,
		SignedTxKeyID:      "kms-key-1",
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitSessionSettlement(context.Background(), SessionSettlement{
		SettlementID: "set-file-secret-1",
		SessionID:    "sess-file-secret-1",
	}); err != nil {
		t.Fatalf("SubmitSessionSettlement: %v", err)
	}

	select {
	case got := <-seenCh:
		if got.path != "/cosmos/tx/v1beta1/txs" {
			t.Fatalf("unexpected path %q", got.path)
		}
		var req cosmosBroadcastRequest
		if err := json.Unmarshal(got.body, &req); err != nil {
			t.Fatalf("unmarshal signed-tx request: %v", err)
		}
		if req.Tx.KeyID != "kms-key-1" {
			t.Fatalf("unexpected key id %q", req.Tx.KeyID)
		}
		if req.Tx.Signature == "" {
			t.Fatalf("expected non-empty signature")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for signed-tx submit")
	}
}

func TestCosmosAdapterSignedTxModeRejectsEmptySecretFile(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "empty_signed_tx_secret.txt")
	if err := os.WriteFile(secretFile, []byte("   \n\t"), 0o600); err != nil {
		t.Fatalf("write empty secret file: %v", err)
	}

	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           "http://127.0.0.1:9999",
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxSigner:     "signer-empty-secret-file",
		SignedTxSecretFile: secretFile,
	})
	if err == nil {
		t.Fatalf("expected empty secret file validation error")
	}
}

func TestCosmosAdapterSignedTxModeRejectsUnreadableSecretFile(t *testing.T) {
	_, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:           "http://127.0.0.1:9999",
		SubmitMode:         CosmosSubmitModeSignedTx,
		SignedTxSigner:     "signer-missing-secret-file",
		SignedTxSecretFile: filepath.Join(t.TempDir(), "missing_secret.txt"),
	})
	if err == nil {
		t.Fatalf("expected unreadable secret file validation error")
	}
}
