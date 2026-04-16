package settlement

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestCosmosAdapterHealthPaths(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				w.WriteHeader(http.StatusNotFound)
				return
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

		if err := adapter.Health(context.Background()); err != nil {
			t.Fatalf("Health expected nil error, got %v", err)
		}
	})

	t.Run("failure_non_200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
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

		err = adapter.Health(context.Background())
		if err == nil {
			t.Fatalf("Health expected non-200 error")
		}
		if !strings.Contains(err.Error(), "status 503") {
			t.Fatalf("expected status 503 health error, got %v", err)
		}
	})

	t.Run("failure_client_unavailable", func(t *testing.T) {
		adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
			Endpoint:    "http://127.0.0.1:1",
			QueueSize:   8,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		adapter.client = &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("transport unavailable")
			}),
		}

		err = adapter.Health(context.Background())
		if err == nil {
			t.Fatalf("Health expected client transport error")
		}
		if !strings.Contains(err.Error(), "transport unavailable") {
			t.Fatalf("unexpected health transport error: %v", err)
		}
	})
}

func TestCosmosAdapterSubmitWithRetryTransientEventuallySucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  5,
		BaseBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	err = adapter.submitWithRetry(context.Background(), cosmosQueuedOperation{
		path: "/x/vpnrewards/issues",
		payload: RewardIssue{
			RewardID:          "rew-retry-direct-1",
			ProviderSubjectID: "provider-1",
			SessionID:         "sess-1",
			RewardMicros:      100,
			Currency:          "USD",
		},
		idempotencyKey: "reward:rew-retry-direct-1",
	})
	if err != nil {
		t.Fatalf("submitWithRetry expected success, got %v", err)
	}

	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected exactly 3 attempts (2 transient failures + success), got %d", got)
	}
}

func TestCosmosAdapterSubmitWithRetryRespectsContextDeadline(t *testing.T) {
	var attempts int32

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    "http://127.0.0.1:1",
		QueueSize:   8,
		MaxRetries:  100,
		BaseBackoff: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	adapter.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			atomic.AddInt32(&attempts, 1)
			return nil, errors.New("transient dial error")
		}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = adapter.submitWithRetry(ctx, cosmosQueuedOperation{
		path: "/x/vpnbilling/settlements",
		payload: SessionSettlement{
			SettlementID: "set-ctx-deadline-1",
			SessionID:    "sess-ctx-deadline-1",
		},
		idempotencyKey: "settlement:set-ctx-deadline-1",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("submitWithRetry expected context deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("submitWithRetry took too long after context deadline: %s", elapsed)
	}
	if got := atomic.LoadInt32(&attempts); got < 2 || got > 4 {
		t.Fatalf("unexpected retry attempts under deadline; got %d", got)
	}
}

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

func TestCosmosAdapterConfirmationQueriesRejectEmptyIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	testCases := []struct {
		name string
		call func(context.Context, string) (bool, error)
	}{
		{name: "session_settlement", call: adapter.HasSessionSettlement},
		{name: "reward_issue", call: adapter.HasRewardIssue},
		{name: "sponsor_reservation", call: adapter.HasSponsorReservation},
		{name: "slash_evidence", call: adapter.HasSlashEvidence},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := tc.call(context.Background(), " \t\n")
			if err == nil {
				t.Fatalf("expected validation error for empty id")
			}
			if ok {
				t.Fatalf("expected false when validation fails")
			}
			if !strings.Contains(err.Error(), "required") {
				t.Fatalf("expected required-id validation error, got %v", err)
			}
		})
	}
}

func TestCosmosAdapterConfirmationQueriesReturnErrorOnNon404Status(t *testing.T) {
	for _, statusCode := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
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

			testCases := []struct {
				name string
				call func(context.Context) (bool, error)
			}{
				{
					name: "session_settlement",
					call: func(ctx context.Context) (bool, error) {
						return adapter.HasSessionSettlement(ctx, "set-1")
					},
				},
				{
					name: "reward_issue",
					call: func(ctx context.Context) (bool, error) {
						return adapter.HasRewardIssue(ctx, "rew-1")
					},
				},
				{
					name: "sponsor_reservation",
					call: func(ctx context.Context) (bool, error) {
						return adapter.HasSponsorReservation(ctx, "sres-1")
					},
				},
				{
					name: "slash_evidence",
					call: func(ctx context.Context) (bool, error) {
						return adapter.HasSlashEvidence(ctx, "ev-1")
					},
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ok, err := tc.call(context.Background())
					if err == nil {
						t.Fatalf("expected error for non-404 status %d", statusCode)
					}
					if ok {
						t.Fatalf("expected false when query fails")
					}
				})
			}
		})
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
		EvidenceRef:   "sha256:7f39f8317fbdb1988ef4c628eba02591d8cc0f0f67d330f140edca76163ffbee",
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

func TestCosmosAdapterSubmitSlashEvidenceNormalizesObjectiveFieldsBeforeEnqueue(t *testing.T) {
	t.Run("trims_obj_ref", func(t *testing.T) {
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
			Endpoint:    srv.URL,
			QueueSize:   4,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		ref, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
			EvidenceID:    "ev-normalize-obj-1",
			SubjectID:     "subject-1",
			SessionID:     "sess-1",
			ViolationType: "  DOUBLE-SIGN  ",
			EvidenceRef:   "  obj://validator/double-sign/block-12 \t",
			SlashMicros:   1000,
			Currency:      "USD",
		})
		if err != nil {
			t.Fatalf("SubmitSlashEvidence: %v", err)
		}
		if ref != "slash:ev-normalize-obj-1" {
			t.Fatalf("unexpected ref id %q", ref)
		}

		select {
		case got := <-seenCh:
			if got.path != "/x/vpnslashing/evidence" {
				t.Fatalf("unexpected path %q", got.path)
			}
			if got.key != "slash:ev-normalize-obj-1" {
				t.Fatalf("unexpected idempotency key %q", got.key)
			}
			var payload SlashEvidence
			if err := json.Unmarshal(got.body, &payload); err != nil {
				t.Fatalf("unmarshal slash evidence payload: %v", err)
			}
			if payload.ViolationType != "double-sign" {
				t.Fatalf("expected normalized violation type, got %q", payload.ViolationType)
			}
			if payload.EvidenceRef != "obj://validator/double-sign/block-12" {
				t.Fatalf("expected trimmed evidence ref, got %q", payload.EvidenceRef)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for slash evidence submit")
		}
	})

	t.Run("accepts_mixed_case_sha256_hex", func(t *testing.T) {
		type seenRequest struct {
			body []byte
		}
		seenCh := make(chan seenRequest, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			seenCh <- seenRequest{body: body}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
			Endpoint:    srv.URL,
			QueueSize:   4,
			MaxRetries:  1,
			BaseBackoff: 5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewCosmosAdapter: %v", err)
		}
		defer adapter.Close()

		const mixedCaseDigest = "6Ca13D52CA70c883E0f0Bb101E425a89E8624dE51dB2d2392593aF6A84118090"
		_, err = adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
			EvidenceID:    "ev-normalize-sha-1",
			SubjectID:     "subject-1",
			SessionID:     "sess-1",
			ViolationType: "double-sign",
			EvidenceRef:   "  sha256:" + mixedCaseDigest + "\n",
			SlashMicros:   1000,
			Currency:      "USD",
		})
		if err != nil {
			t.Fatalf("SubmitSlashEvidence: %v", err)
		}

		select {
		case got := <-seenCh:
			var payload SlashEvidence
			if err := json.Unmarshal(got.body, &payload); err != nil {
				t.Fatalf("unmarshal slash evidence payload: %v", err)
			}
			if payload.EvidenceRef != "sha256:"+mixedCaseDigest {
				t.Fatalf("expected mixed-case digest to remain intact after trim, got %q", payload.EvidenceRef)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for slash evidence submit")
		}
	})
}

func TestCosmosAdapterRejectsInvalidObjectiveSlashEvidenceBeforeEnqueue(t *testing.T) {
	for _, mode := range []struct {
		name string
		cfg  CosmosAdapterConfig
	}{
		{
			name: "http_mode",
			cfg: CosmosAdapterConfig{
				QueueSize:   4,
				MaxRetries:  1,
				BaseBackoff: 5 * time.Millisecond,
			},
		},
		{
			name: "signed_tx_mode",
			cfg: CosmosAdapterConfig{
				QueueSize:      4,
				MaxRetries:     1,
				BaseBackoff:    5 * time.Millisecond,
				SubmitMode:     CosmosSubmitModeSignedTx,
				SignedTxSigner: "signer-invalid-evidence",
				SignedTxSecret: "test-secret",
			},
		},
	} {
		mode := mode
		t.Run(mode.name, func(t *testing.T) {
			var attempts int32
			attemptCh := make(chan struct{}, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&attempts, 1)
				select {
				case attemptCh <- struct{}{}:
				default:
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			cfg := mode.cfg
			cfg.Endpoint = srv.URL
			adapter, err := NewCosmosAdapter(cfg)
			if err != nil {
				t.Fatalf("NewCosmosAdapter: %v", err)
			}
			defer adapter.Close()

			for _, tc := range []struct {
				name          string
				violationType string
				evidenceRef   string
				errContains   string
			}{
				{
					name:          "invalid_violation_type",
					violationType: "subjective-abuse",
					evidenceRef:   "sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
					errContains:   "requires objective violation_type",
				},
				{
					name:          "invalid_sha_ref",
					violationType: "double-sign",
					evidenceRef:   "sha256:abc123",
					errContains:   "requires objective evidence_ref",
				},
				{
					name:          "empty_ref_after_trim",
					violationType: "double-sign",
					evidenceRef:   " \t\n",
					errContains:   "requires objective evidence_ref",
				},
				{
					name:          "obj_ref_contains_internal_whitespace",
					violationType: "double-sign",
					evidenceRef:   "obj://validator/double-sign/block 12",
					errContains:   "requires objective evidence_ref",
				},
			} {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					_, err := adapter.SubmitSlashEvidence(context.Background(), SlashEvidence{
						EvidenceID:    "ev-invalid-1",
						SubjectID:     "subject-1",
						SessionID:     "sess-1",
						ViolationType: tc.violationType,
						EvidenceRef:   tc.evidenceRef,
						SlashMicros:   1000,
						Currency:      "USD",
					})
					if err == nil {
						t.Fatalf("expected error for %s", tc.name)
					}
					if !strings.Contains(err.Error(), tc.errContains) {
						t.Fatalf("expected error to contain %q, got %v", tc.errContains, err)
					}
				})
			}

			select {
			case <-attemptCh:
				t.Fatalf("expected no network attempts for invalid slash evidence")
			case <-time.After(200 * time.Millisecond):
			}
			if got := atomic.LoadInt32(&attempts); got != 0 {
				t.Fatalf("expected no network attempts for invalid slash evidence, got %d", got)
			}
		})
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
		EvidenceRef:   "sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
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

func TestCosmosAdapterFailureAfterEnqueueTransitionsToDeferredReplayable(t *testing.T) {
	var failWrites atomic.Bool
	failWrites.Store(true)
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/x/vpnbilling/settlements" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&attempts, 1)
		if failWrites.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  0,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := adapter.SubmitSessionSettlement(context.Background(), SessionSettlement{
		SettlementID: "set-deferred-1",
		SessionID:    "sess-deferred-1",
	}); err != nil {
		t.Fatalf("SubmitSessionSettlement: %v", err)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 1
	}, "operation to be marked deferred")

	entry, ok := adapter.deferredOperationByID("settlement:set-deferred-1")
	if !ok {
		t.Fatalf("expected deferred entry for settlement:set-deferred-1")
	}
	if !entry.replayable {
		t.Fatalf("expected deferred entry to be replayable")
	}
	if entry.attempts < 1 {
		t.Fatalf("expected deferred entry attempts >= 1, got %d", entry.attempts)
	}
	if !strings.Contains(entry.lastError, "status 503") {
		t.Fatalf("expected deferred entry error to include status 503, got %q", entry.lastError)
	}

	failWrites.Store(false)
	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 0
	}, "deferred replay to clear")

	if got := atomic.LoadInt32(&attempts); got < 2 {
		t.Fatalf("expected at least two submit attempts, got %d", got)
	}
}

func TestCosmosAdapterCloseDrainsBacklogToDeferred(t *testing.T) {
	startedCh := make(chan string, 2)
	releaseCh := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/x/vpnrewards/issues" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		select {
		case startedCh <- r.Header.Get("Idempotency-Key"):
		default:
		}
		select {
		case <-releaseCh:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
			return
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  0,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-close-1",
		ProviderSubjectID: "provider-close-1",
		SessionID:         "sess-close-1",
		RewardMicros:      100,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue first: %v", err)
	}
	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-close-2",
		ProviderSubjectID: "provider-close-2",
		SessionID:         "sess-close-2",
		RewardMicros:      200,
	}); err != nil {
		t.Fatalf("SubmitRewardIssue second: %v", err)
	}

	select {
	case <-startedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first queued submit to start")
	}

	adapter.Close()
	close(releaseCh)

	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 2
	}, "close backlog to deferred transition")

	first, ok := adapter.deferredOperationByID("reward:rew-close-1")
	if !ok {
		t.Fatalf("expected deferred entry for reward:rew-close-1")
	}
	if first.replayable {
		t.Fatalf("expected closed in-flight deferred entry to be non-replayable")
	}
	if first.lastError == "" {
		t.Fatalf("expected closed in-flight deferred entry to include a last error")
	}

	second, ok := adapter.deferredOperationByID("reward:rew-close-2")
	if !ok {
		t.Fatalf("expected deferred entry for reward:rew-close-2")
	}
	if second.replayable {
		t.Fatalf("expected closed queued deferred entry to be non-replayable")
	}
	if !strings.Contains(second.lastError, "closed with backlog") && !strings.Contains(second.lastError, "context canceled") {
		t.Fatalf("expected close-path deferred error marker, got %q", second.lastError)
	}

	if _, err := adapter.SubmitRewardIssue(context.Background(), RewardIssue{
		RewardID:          "rew-after-close",
		ProviderSubjectID: "provider-close-3",
		SessionID:         "sess-close-3",
		RewardMicros:      300,
	}); err == nil {
		t.Fatalf("expected submit after close to fail")
	}
}
