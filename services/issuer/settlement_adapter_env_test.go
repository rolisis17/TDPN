package issuer

import (
	"context"
	"encoding/json"
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
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")
	secretFile := filepath.Join(t.TempDir(), "issuer_signed_tx_secret.txt")
	if err := os.WriteFile(secretFile, []byte(" issuer-secret \n"), 0o600); err != nil {
		t.Fatalf("write signed-tx secret file: %v", err)
	}
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE", secretFile)
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

func TestNewSettlementServiceFromEnvCosmosSignedTxSecretFileInvalidOrEmptyFallsBack(t *testing.T) {
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
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "issuer-signer")
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE", tc.secretFile)
			t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID", "issuer-kms-key-1")

			svc := newSettlementServiceFromEnv()
			reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-fallback-"+strings.ReplaceAll(tc.name, " ", "-"))
			if reservation.Status != settlement.OperationStatusConfirmed {
				t.Fatalf("expected confirmed reservation in memory-only fallback mode, got %s", reservation.Status)
			}
			if reservation.AdapterSubmitted {
				t.Fatalf("expected no adapter submission in fallback mode")
			}

			select {
			case got := <-reqCh:
				t.Fatalf("expected no cosmos request in fallback mode, got path=%s", got.path)
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}

func TestNewSettlementServiceFromEnvCosmosSignedTxMissingCredentialsFallsBack(t *testing.T) {
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

	svc := newSettlementServiceFromEnv()
	reservation := reserveSponsorCreditsForAdapterTest(t, svc, "sres-fallback")
	if reservation.Status != settlement.OperationStatusConfirmed {
		t.Fatalf("expected confirmed reservation in memory-only fallback mode, got %s", reservation.Status)
	}
	if reservation.AdapterSubmitted {
		t.Fatalf("expected no adapter submission in fallback mode")
	}

	select {
	case got := <-reqCh:
		t.Fatalf("expected no cosmos request in fallback mode, got path=%s", got.path)
	case <-time.After(200 * time.Millisecond):
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
