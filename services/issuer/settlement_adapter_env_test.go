package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/settlement"
)

type observedCosmosRequest struct {
	path    string
	auth    string
	payload []byte
}

func reserveSponsorCreditsForAdapterTest(t *testing.T, svc settlement.Service, reservationID string) settlement.SponsorCreditReservation {
	t.Helper()
	res, err := svc.ReserveSponsorCredits(context.Background(), settlement.SponsorCreditReservation{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "client-a",
		SessionID:     "sess-a",
		AmountMicros:  1000,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	return res
}

func waitObservedCosmosRequest(t *testing.T, ch <-chan observedCosmosRequest) observedCosmosRequest {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cosmos adapter request")
		return observedCosmosRequest{}
	}
}

func assertNoObservedCosmosRequest(t *testing.T, ch <-chan observedCosmosRequest, wait time.Duration) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("expected no cosmos adapter request, got path=%s", got.path)
	case <-time.After(wait):
	}
}

func assertPanicContains(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		got := recover()
		if got == nil {
			t.Fatalf("expected panic containing %q", want)
		}
		if want != "" && !strings.Contains(fmt.Sprint(got), want) {
			t.Fatalf("expected panic containing %q, got %v", want, got)
		}
	}()
	fn()
}

func TestNewSettlementServiceFromEnvCosmosDefaultSubmitModeHTTP(t *testing.T) {
	reqCh := make(chan observedCosmosRequest, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		reqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", ts.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "api-http")
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "")

	svc := newSettlementServiceFromEnv()
	reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-http")
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation with cosmos adapter, got %s", reservation.Status)
	}

	got := waitObservedCosmosRequest(t, reqCh)
	if got.path != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected default http submit path, got %s", got.path)
	}
	if got.auth != "Bearer api-http" {
		t.Fatalf("expected auth header to propagate, got %q", got.auth)
	}
}

func TestNewSettlementServiceFromEnvCosmosSignedTxModeForwardsEnv(t *testing.T) {
	reqCh := make(chan observedCosmosRequest, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		reqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", ts.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "api-signed")
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "signed-tx")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH", "/custom/txs")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "tdpn-1")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "issuer-signer")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "issuer-secret")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID", "issuer-kms-key-1")

	svc := newSettlementServiceFromEnv()
	reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-signed")
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation with signed-tx adapter, got %s", reservation.Status)
	}

	got := waitObservedCosmosRequest(t, reqCh)
	if got.path != "/custom/txs" {
		t.Fatalf("expected signed-tx broadcast path /custom/txs, got %s", got.path)
	}
	if got.auth != "Bearer api-signed" {
		t.Fatalf("expected auth header to propagate, got %q", got.auth)
	}

	var payload struct {
		Mode string `json:"mode"`
		Tx   struct {
			ChainID     string `json:"chain_id"`
			KeyID       string `json:"key_id"`
			Signer      string `json:"signer"`
			MessageType string `json:"message_type"`
		} `json:"tx"`
	}
	if err := json.Unmarshal(got.payload, &payload); err != nil {
		t.Fatalf("decode signed-tx payload: %v", err)
	}
	if payload.Mode != "BROADCAST_MODE_SYNC" {
		t.Fatalf("expected broadcast mode BROADCAST_MODE_SYNC, got %s", payload.Mode)
	}
	if payload.Tx.ChainID != "tdpn-1" {
		t.Fatalf("expected chain id tdpn-1, got %s", payload.Tx.ChainID)
	}
	if payload.Tx.KeyID != "issuer-kms-key-1" {
		t.Fatalf("expected key id issuer-kms-key-1, got %s", payload.Tx.KeyID)
	}
	if payload.Tx.Signer != "issuer-signer" {
		t.Fatalf("expected signer issuer-signer, got %s", payload.Tx.Signer)
	}
	if payload.Tx.MessageType != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected message type /x/vpnsponsor/reservations, got %s", payload.Tx.MessageType)
	}
}

func TestNewSettlementServiceFromEnvCosmosSignedTxSecretFileInvalidOrEmptyPanicsByDefault(t *testing.T) {
	cases := []struct {
		name       string
		secretFile string
	}{
		{
			name:       "missing file",
			secretFile: filepath.Join(t.TempDir(), "missing_secret_file.txt"),
		},
		{
			name: "empty file",
			secretFile: func() string {
				p := filepath.Join(t.TempDir(), "empty_secret_file.txt")
				if err := os.WriteFile(p, []byte(" \n\t"), 0o600); err != nil {
					t.Fatalf("write empty secret file: %v", err)
				}
				return p
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer ts.Close()

			t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
			t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", ts.URL)
			t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "signed-tx")
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "tdpn-1")
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "issuer-signer")
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE", tc.secretFile)
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID", "issuer-kms-key-1")
			assertPanicContains(t, "refusing startup", func() {
				_ = newSettlementServiceFromEnv()
			})
		})
	}
}

func TestNewSettlementServiceFromEnvCosmosSignedTxMissingCredentialsPanicsByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", ts.URL)
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "signed-tx")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "tdpn-1")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")

	assertPanicContains(t, "refusing startup", func() {
		_ = newSettlementServiceFromEnv()
	})
}

func TestNewSettlementServiceFromEnvCosmosSignedTxMissingCredentialsFallsBackWithDangerousOverride(t *testing.T) {
	reqCh := make(chan observedCosmosRequest, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		reqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", ts.URL)
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "signed-tx")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "tdpn-1")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")
	t.Setenv(allowDangerousCosmosAdapterFallback, "1")

	svc := newSettlementServiceFromEnv()
	reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-fallback-dangerous")
	if reservation.Status != settlement.OperationStatusConfirmed {
		t.Fatalf("expected confirmed reservation in dangerous memory-only fallback mode, got %s", reservation.Status)
	}
	if reservation.AdapterSubmitted {
		t.Fatalf("expected no adapter submission in dangerous fallback mode")
	}
	assertNoObservedCosmosRequest(t, reqCh, 200*time.Millisecond)
}

func TestNewSettlementServiceFromEnvCosmosQueueFullDefersWithoutBlocking(t *testing.T) {
	reqCh := make(chan observedCosmosRequest, 4)
	releaseCh := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		reqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		<-releaseCh
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	defer close(releaseCh)

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", ts.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "primary-api")
	t.Setenv("COSMOS_SETTLEMENT_QUEUE_SIZE", "1")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "0")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "1000")

	svc := newSettlementServiceFromEnv()
	first := reserveSponsorCreditsForAdapterTest(t, svc, "sres-queue-full-1")
	second := reserveSponsorCreditsForAdapterTest(t, svc, "sres-queue-full-2")
	third := reserveSponsorCreditsForAdapterTest(t, svc, "sres-queue-full-3")

	records := []settlement.SponsorCreditReservation{first, second, third}
	submittedCount := 0
	deferredPendingCount := 0
	for _, rec := range records {
		if rec.Status == settlement.OperationStatusSubmitted && rec.AdapterSubmitted && !rec.AdapterDeferred {
			submittedCount++
		}
		if rec.Status == settlement.OperationStatusPending && rec.AdapterDeferred && !rec.AdapterSubmitted {
			deferredPendingCount++
		}
	}
	if submittedCount < 1 {
		t.Fatalf("expected at least one submitted reservation under queue pressure, got submitted_count=%d", submittedCount)
	}
	if deferredPendingCount < 1 {
		t.Fatalf("expected at least one deferred/pending reservation under queue pressure, got deferred_pending_count=%d", deferredPendingCount)
	}

	got := waitObservedCosmosRequest(t, reqCh)
	if got.path != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected queue-full request path /x/vpnsponsor/reservations, got %s", got.path)
	}
	if got.auth != "Bearer primary-api" {
		t.Fatalf("expected queue-full auth header to propagate, got %q", got.auth)
	}
}

func TestNewSettlementServiceFromEnvCosmosPrimary5xxStillReturnsSubmittedAsync(t *testing.T) {
	reqCh := make(chan observedCosmosRequest, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		reqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", ts.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "primary-api")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "0")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "500")

	svc := newSettlementServiceFromEnv()
	reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-primary-5xx")
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation on async 5xx fail-soft path, got %s", reservation.Status)
	}
	if !reservation.AdapterSubmitted {
		t.Fatalf("expected adapter submitted marker on async 5xx fail-soft path")
	}
	if reservation.AdapterDeferred {
		t.Fatalf("expected no immediate adapter deferred marker on async 5xx fail-soft path")
	}

	got := waitObservedCosmosRequest(t, reqCh)
	if got.path != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected 5xx request path /x/vpnsponsor/reservations, got %s", got.path)
	}
	if got.auth != "Bearer primary-api" {
		t.Fatalf("expected 5xx auth header to propagate, got %q", got.auth)
	}
}

func TestNewSettlementServiceFromEnvCosmosShadowMirrorsSponsorReservationToPrimaryAndShadow(t *testing.T) {
	primaryReqCh := make(chan observedCosmosRequest, 1)
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		primaryReqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	shadowReqCh := make(chan observedCosmosRequest, 1)
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		shadowReqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", primaryServer.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "primary-api")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_ENDPOINT", shadowServer.URL)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_API_KEY", "shadow-api")

	svc := newSettlementServiceFromEnv()
	reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-shadow-mirror")
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation with primary cosmos adapter, got %s", reservation.Status)
	}
	if !reservation.AdapterSubmitted {
		t.Fatalf("expected primary adapter submitted marker")
	}
	if !reservation.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submitted marker")
	}

	primaryReq := waitObservedCosmosRequest(t, primaryReqCh)
	if primaryReq.path != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected primary path /x/vpnsponsor/reservations, got %s", primaryReq.path)
	}
	if primaryReq.auth != "Bearer primary-api" {
		t.Fatalf("expected primary auth header to propagate, got %q", primaryReq.auth)
	}
	if !strings.Contains(string(primaryReq.payload), "\"ReservationID\":\"sres-shadow-mirror\"") {
		t.Fatalf("expected primary payload to include reservation id, got %s", string(primaryReq.payload))
	}

	shadowReq := waitObservedCosmosRequest(t, shadowReqCh)
	if shadowReq.path != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected shadow path /x/vpnsponsor/reservations, got %s", shadowReq.path)
	}
	if shadowReq.auth != "Bearer shadow-api" {
		t.Fatalf("expected shadow auth header to propagate, got %q", shadowReq.auth)
	}
	if !strings.Contains(string(shadowReq.payload), "\"ReservationID\":\"sres-shadow-mirror\"") {
		t.Fatalf("expected shadow payload to include reservation id, got %s", string(shadowReq.payload))
	}

	report, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !report.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter configured report marker")
	}
	if report.ShadowAttemptedOperations < 1 || report.ShadowSubmittedOperations < 1 {
		t.Fatalf("expected shadow attempted/submitted counts >=1, got attempted=%d submitted=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations)
	}
}

func TestNewSettlementServiceFromEnvCosmosShadowInitFailurePanicsByDefault(t *testing.T) {
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", primaryServer.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "primary-api")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_ENDPOINT", shadowServer.URL)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE", "signed-tx")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET", "")

	assertPanicContains(t, "refusing startup", func() {
		_ = newSettlementServiceFromEnv()
	})
}

func TestNewSettlementServiceFromEnvCosmosShadowInitFailureWithDangerousOverrideDoesNotBreakPrimary(t *testing.T) {
	primaryReqCh := make(chan observedCosmosRequest, 1)
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		primaryReqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	shadowReqCh := make(chan observedCosmosRequest, 1)
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		shadowReqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", primaryServer.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "primary-api")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_ENDPOINT", shadowServer.URL)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE", "signed-tx")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET", "")
	t.Setenv(allowDangerousCosmosAdapterFallback, "1")

	svc := newSettlementServiceFromEnv()
	reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-shadow-fail-open")
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation with healthy primary adapter, got %s", reservation.Status)
	}
	if !reservation.AdapterSubmitted {
		t.Fatalf("expected primary adapter submitted marker")
	}
	if reservation.ShadowAdapterSubmitted {
		t.Fatalf("expected no shadow adapter submission marker when shadow init fails")
	}

	primaryReq := waitObservedCosmosRequest(t, primaryReqCh)
	if primaryReq.path != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected primary path /x/vpnsponsor/reservations, got %s", primaryReq.path)
	}
	if primaryReq.auth != "Bearer primary-api" {
		t.Fatalf("expected primary auth header to propagate, got %q", primaryReq.auth)
	}
	if !strings.Contains(string(primaryReq.payload), "\"ReservationID\":\"sres-shadow-fail-open\"") {
		t.Fatalf("expected primary payload to include reservation id, got %s", string(primaryReq.payload))
	}
	assertNoObservedCosmosRequest(t, shadowReqCh, 200*time.Millisecond)

	report, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter to remain disabled when shadow init fails")
	}
}

func TestNewSettlementServiceFromEnvCosmosShadowSignedTxModeUsesShadowEnv(t *testing.T) {
	primaryReqCh := make(chan observedCosmosRequest, 1)
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		primaryReqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer primaryServer.Close()

	shadowReqCh := make(chan observedCosmosRequest, 1)
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		shadowReqCh <- observedCosmosRequest{
			path:    r.URL.Path,
			auth:    r.Header.Get("Authorization"),
			payload: b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", primaryServer.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "primary-api")
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "")

	t.Setenv("COSMOS_SETTLEMENT_SHADOW_ENDPOINT", shadowServer.URL)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_API_KEY", "shadow-api")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE", "signed-tx")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_BROADCAST_PATH", "/shadow/custom/txs")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_CHAIN_ID", "tdpn-shadow-1")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SIGNER", "shadow-signer-1")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET", "shadow-secret")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET_FILE", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_KEY_ID", "shadow-kms-key-1")

	svc := newSettlementServiceFromEnv()
	reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-shadow-signed-tx")
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation with primary cosmos adapter, got %s", reservation.Status)
	}
	if !reservation.AdapterSubmitted {
		t.Fatalf("expected primary adapter submitted marker")
	}
	if !reservation.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submitted marker")
	}

	primaryReq := waitObservedCosmosRequest(t, primaryReqCh)
	if primaryReq.path != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected primary http submit path /x/vpnsponsor/reservations, got %s", primaryReq.path)
	}
	if primaryReq.auth != "Bearer primary-api" {
		t.Fatalf("expected primary auth header to propagate, got %q", primaryReq.auth)
	}

	shadowReq := waitObservedCosmosRequest(t, shadowReqCh)
	if shadowReq.path != "/shadow/custom/txs" {
		t.Fatalf("expected shadow signed-tx broadcast path /shadow/custom/txs, got %s", shadowReq.path)
	}
	if shadowReq.auth != "Bearer shadow-api" {
		t.Fatalf("expected shadow auth header to propagate, got %q", shadowReq.auth)
	}

	var payload struct {
		Mode string `json:"mode"`
		Tx   struct {
			ChainID     string `json:"chain_id"`
			KeyID       string `json:"key_id"`
			Signer      string `json:"signer"`
			MessageType string `json:"message_type"`
		} `json:"tx"`
	}
	if err := json.Unmarshal(shadowReq.payload, &payload); err != nil {
		t.Fatalf("decode shadow signed-tx payload: %v", err)
	}
	if payload.Mode != "BROADCAST_MODE_SYNC" {
		t.Fatalf("expected broadcast mode BROADCAST_MODE_SYNC, got %s", payload.Mode)
	}
	if payload.Tx.ChainID != "tdpn-shadow-1" {
		t.Fatalf("expected shadow chain id tdpn-shadow-1, got %s", payload.Tx.ChainID)
	}
	if payload.Tx.KeyID != "shadow-kms-key-1" {
		t.Fatalf("expected shadow key id shadow-kms-key-1, got %s", payload.Tx.KeyID)
	}
	if payload.Tx.Signer != "shadow-signer-1" {
		t.Fatalf("expected shadow signer shadow-signer-1, got %s", payload.Tx.Signer)
	}
	if payload.Tx.MessageType != "/x/vpnsponsor/reservations" {
		t.Fatalf("expected shadow message type /x/vpnsponsor/reservations, got %s", payload.Tx.MessageType)
	}
}

func TestNewSettlementServiceFromEnvCurrencyBaseFromEnv(t *testing.T) {
	t.Setenv("SETTLEMENT_CURRENCY", "usdc")
	t.Setenv("SETTLEMENT_NATIVE_CURRENCY", "")
	t.Setenv("SETTLEMENT_NATIVE_RATE_NUMERATOR", "")
	t.Setenv("SETTLEMENT_NATIVE_RATE_DENOMINATOR", "")
	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "")

	svc := newSettlementServiceFromEnv()

	quoteDefault, err := svc.QuotePrice(context.Background(), "client-currency", "")
	if err != nil {
		t.Fatalf("QuotePrice default currency: %v", err)
	}
	if quoteDefault.Currency != "USDC" {
		t.Fatalf("expected base quote currency USDC, got %s", quoteDefault.Currency)
	}
	if quoteDefault.PricePerMiBMicros != 1000 {
		t.Fatalf("expected base quote price 1000, got %d", quoteDefault.PricePerMiBMicros)
	}

	quoteExplicit, err := svc.QuotePrice(context.Background(), "client-currency", "USDC")
	if err != nil {
		t.Fatalf("QuotePrice explicit USDC currency: %v", err)
	}
	if quoteExplicit.Currency != "USDC" {
		t.Fatalf("expected explicit quote currency USDC, got %s", quoteExplicit.Currency)
	}
	if quoteExplicit.PricePerMiBMicros != 1000 {
		t.Fatalf("expected explicit USDC quote price 1000, got %d", quoteExplicit.PricePerMiBMicros)
	}
}

func TestNewSettlementServiceFromEnvDualNativeCurrencyConversion(t *testing.T) {
	t.Setenv("SETTLEMENT_CURRENCY", "USDC")
	t.Setenv("SETTLEMENT_NATIVE_CURRENCY", "tdpn")
	t.Setenv("SETTLEMENT_NATIVE_RATE_NUMERATOR", "3")
	t.Setenv("SETTLEMENT_NATIVE_RATE_DENOMINATOR", "2")
	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "")

	svc := newSettlementServiceFromEnv()

	baseQuote, err := svc.QuotePrice(context.Background(), "client-dual", "")
	if err != nil {
		t.Fatalf("QuotePrice base currency: %v", err)
	}
	if baseQuote.Currency != "USDC" {
		t.Fatalf("expected base quote currency USDC, got %s", baseQuote.Currency)
	}
	if baseQuote.PricePerMiBMicros != 1000 {
		t.Fatalf("expected base quote price 1000, got %d", baseQuote.PricePerMiBMicros)
	}

	nativeQuote, err := svc.QuotePrice(context.Background(), "client-dual", "TDPN")
	if err != nil {
		t.Fatalf("QuotePrice native currency: %v", err)
	}
	if nativeQuote.Currency != "TDPN" {
		t.Fatalf("expected native quote currency TDPN, got %s", nativeQuote.Currency)
	}
	if nativeQuote.PricePerMiBMicros != 1500 {
		t.Fatalf("expected native quote price 1500, got %d", nativeQuote.PricePerMiBMicros)
	}
}
