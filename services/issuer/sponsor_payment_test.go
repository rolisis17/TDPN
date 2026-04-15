package issuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
	"privacynode/pkg/settlement"
)

func TestHandleIssueTokenRequiresPaymentProofWhenEnabled(t *testing.T) {
	s := newSponsorTestService(t)
	s.requirePaymentProof = true

	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	popPubB64 := crypto.EncodeEd25519PublicKey(popPub)
	reqBody, _ := json.Marshal(proto.IssueTokenRequest{
		Tier:      1,
		Subject:   "client-1",
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: popPubB64,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()

	s.handleIssueToken(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusPaymentRequired, rr.Code, rr.Body.String())
	}
}

func TestSponsorReserveAndIssueTokenFlow(t *testing.T) {
	s := newSponsorTestService(t)

	reserveReqBody, _ := json.Marshal(proto.SponsorReserveRequest{
		ReservationID: "sres-test-1",
		SponsorID:     "sponsor-1",
		Subject:       "client-1",
		SessionID:     "sess-1",
		AmountMicros:  1000,
	})
	reserveReq := httptest.NewRequest(http.MethodPost, "/v1/sponsor/reserve", bytes.NewReader(reserveReqBody))
	reserveReq.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
	reserveRR := httptest.NewRecorder()
	s.handleSponsorReserve(reserveRR, reserveReq)
	if reserveRR.Code != http.StatusOK {
		t.Fatalf("reserve status=%d body=%s", reserveRR.Code, reserveRR.Body.String())
	}

	var reserveResp proto.SponsorReserveResponse
	if err := json.Unmarshal(reserveRR.Body.Bytes(), &reserveResp); err != nil {
		t.Fatalf("decode reserve response: %v", err)
	}
	if !reserveResp.Accepted || reserveResp.ReservationID != "sres-test-1" {
		t.Fatalf("unexpected reserve response: %+v", reserveResp)
	}

	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	popPubB64 := crypto.EncodeEd25519PublicKey(popPub)

	tokenReqBody, _ := json.Marshal(proto.IssueTokenRequest{
		Tier:      1,
		Subject:   "client-1",
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: popPubB64,
		PaymentProof: &proto.SponsorPaymentProof{
			ReservationID: "sres-test-1",
			SponsorID:     "sponsor-1",
			Subject:       "client-1",
			SessionID:     "sess-1",
		},
	})
	tokenReq := httptest.NewRequest(http.MethodPost, "/v1/sponsor/token", bytes.NewReader(tokenReqBody))
	tokenReq.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
	tokenRR := httptest.NewRecorder()
	s.handleSponsorIssueToken(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("sponsor token status=%d body=%s", tokenRR.Code, tokenRR.Body.String())
	}

	var tokenResp proto.IssueTokenResponse
	if err := json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResp.Token == "" || tokenResp.JTI == "" {
		t.Fatalf("unexpected empty token response: %+v", tokenResp)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/v1/sponsor/status?reservation_id=sres-test-1", nil)
	statusReq.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
	statusRR := httptest.NewRecorder()
	s.handleSponsorStatus(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("sponsor status status=%d body=%s", statusRR.Code, statusRR.Body.String())
	}
	var statusResp proto.SponsorReserveResponse
	if err := json.Unmarshal(statusRR.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if statusResp.ConsumedAt <= 0 {
		t.Fatalf("expected consumed reservation after token issuance: %+v", statusResp)
	}
}

func TestSponsorEndpointsRequireSponsorToken(t *testing.T) {
	s := newSponsorTestService(t)
	reqBody, _ := json.Marshal(proto.SponsorQuoteRequest{Subject: "client-1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/quote", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	s.handleSponsorQuote(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized sponsor request, got %d", rr.Code)
	}
}

func TestSponsorQuoteValidation(t *testing.T) {
	s := newSponsorTestService(t)
	s.sponsorMaxSubjectLen = 8
	s.sponsorMaxCurrencyLen = 3

	tests := []struct {
		name        string
		req         proto.SponsorQuoteRequest
		wantMessage string
	}{
		{
			name:        "missing subject",
			req:         proto.SponsorQuoteRequest{Subject: " "},
			wantMessage: "subject required",
		},
		{
			name:        "subject too long",
			req:         proto.SponsorQuoteRequest{Subject: "client-too-long"},
			wantMessage: "subject too long",
		},
		{
			name:        "currency too long",
			req:         proto.SponsorQuoteRequest{Subject: "client-1", Currency: "USDT"},
			wantMessage: "currency too long",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(tc.req)
			req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/quote", bytes.NewReader(reqBody))
			req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			rr := httptest.NewRecorder()
			s.handleSponsorQuote(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusBadRequest, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantMessage) {
				t.Fatalf("expected response to contain %q, body=%s", tc.wantMessage, rr.Body.String())
			}
		})
	}
}

func TestSponsorReserveValidation(t *testing.T) {
	s := newSponsorTestService(t)
	s.sponsorMaxSubjectLen = 8
	s.sponsorMaxIDLen = 8
	s.sponsorMaxCurrencyLen = 3
	s.sponsorMaxReservationMicros = 100

	baseReq := proto.SponsorReserveRequest{
		ReservationID: "sres-1",
		SponsorID:     "sp-1",
		Subject:       "client1",
		SessionID:     "sess-1",
		AmountMicros:  10,
		Currency:      "USD",
	}

	tests := []struct {
		name        string
		mutate      func(*proto.SponsorReserveRequest)
		wantMessage string
	}{
		{
			name: "missing sponsor_id",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.SponsorID = " "
			},
			wantMessage: "sponsor_id required",
		},
		{
			name: "missing subject",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.Subject = ""
			},
			wantMessage: "subject required",
		},
		{
			name: "missing session_id",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.SessionID = ""
			},
			wantMessage: "session_id required",
		},
		{
			name: "amount must be positive",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.AmountMicros = 0
			},
			wantMessage: "amount_micros must be > 0",
		},
		{
			name: "amount exceeds max",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.AmountMicros = 101
			},
			wantMessage: "amount_micros exceeds max",
		},
		{
			name: "reservation id too long",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.ReservationID = "id-too-long"
			},
			wantMessage: "reservation_id too long",
		},
		{
			name: "sponsor id too long",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.SponsorID = "sponsor-too-long"
			},
			wantMessage: "sponsor_id too long",
		},
		{
			name: "subject too long",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.Subject = "subject-too-long"
			},
			wantMessage: "subject too long",
		},
		{
			name: "session id too long",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.SessionID = "session-too-long"
			},
			wantMessage: "session_id too long",
		},
		{
			name: "currency too long",
			mutate: func(req *proto.SponsorReserveRequest) {
				req.Currency = "USDT"
			},
			wantMessage: "currency too long",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqPayload := baseReq
			tc.mutate(&reqPayload)
			reqBody, _ := json.Marshal(reqPayload)
			req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/reserve", bytes.NewReader(reqBody))
			req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			rr := httptest.NewRecorder()
			s.handleSponsorReserve(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusBadRequest, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantMessage) {
				t.Fatalf("expected response to contain %q, body=%s", tc.wantMessage, rr.Body.String())
			}
		})
	}
}

func TestSponsorStatusValidation(t *testing.T) {
	s := newSponsorTestService(t)
	s.sponsorMaxIDLen = 8

	tests := []struct {
		name        string
		url         string
		wantMessage string
	}{
		{
			name:        "missing reservation id",
			url:         "/v1/sponsor/status",
			wantMessage: "reservation_id required",
		},
		{
			name:        "reservation id too long",
			url:         "/v1/sponsor/status?reservation_id=reservation-too-long",
			wantMessage: "reservation_id too long",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			rr := httptest.NewRecorder()
			s.handleSponsorStatus(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusBadRequest, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantMessage) {
				t.Fatalf("expected response to contain %q, body=%s", tc.wantMessage, rr.Body.String())
			}
		})
	}
}

func TestNewSponsorValidationLimitsDefaults(t *testing.T) {
	t.Setenv("ISSUER_SPONSOR_MAX_SUBJECT_LEN", "")
	t.Setenv("ISSUER_SPONSOR_MAX_ID_LEN", "")
	t.Setenv("ISSUER_SPONSOR_MAX_CURRENCY_LEN", "")
	t.Setenv("ISSUER_SPONSOR_MAX_RESERVATION_MICROS", "")

	s := New()
	if s.sponsorMaxSubjectLen != defaultSponsorMaxSubjectLen {
		t.Fatalf("expected default sponsorMaxSubjectLen=%d got=%d", defaultSponsorMaxSubjectLen, s.sponsorMaxSubjectLen)
	}
	if s.sponsorMaxIDLen != defaultSponsorMaxIDLen {
		t.Fatalf("expected default sponsorMaxIDLen=%d got=%d", defaultSponsorMaxIDLen, s.sponsorMaxIDLen)
	}
	if s.sponsorMaxCurrencyLen != defaultSponsorMaxCurrencyLen {
		t.Fatalf("expected default sponsorMaxCurrencyLen=%d got=%d", defaultSponsorMaxCurrencyLen, s.sponsorMaxCurrencyLen)
	}
	if s.sponsorMaxReservationMicros != defaultSponsorMaxReservationMicros {
		t.Fatalf("expected default sponsorMaxReservationMicros=%d got=%d", defaultSponsorMaxReservationMicros, s.sponsorMaxReservationMicros)
	}
}

func TestNewSponsorValidationLimitsFromEnv(t *testing.T) {
	t.Setenv("ISSUER_SPONSOR_MAX_SUBJECT_LEN", "222")
	t.Setenv("ISSUER_SPONSOR_MAX_ID_LEN", "200")
	t.Setenv("ISSUER_SPONSOR_MAX_CURRENCY_LEN", "12")
	t.Setenv("ISSUER_SPONSOR_MAX_RESERVATION_MICROS", "1234567")

	s := New()
	if s.sponsorMaxSubjectLen != 222 {
		t.Fatalf("expected sponsorMaxSubjectLen=222 got=%d", s.sponsorMaxSubjectLen)
	}
	if s.sponsorMaxIDLen != 200 {
		t.Fatalf("expected sponsorMaxIDLen=200 got=%d", s.sponsorMaxIDLen)
	}
	if s.sponsorMaxCurrencyLen != 12 {
		t.Fatalf("expected sponsorMaxCurrencyLen=12 got=%d", s.sponsorMaxCurrencyLen)
	}
	if s.sponsorMaxReservationMicros != 1234567 {
		t.Fatalf("expected sponsorMaxReservationMicros=1234567 got=%d", s.sponsorMaxReservationMicros)
	}
}

func newSponsorTestService(t *testing.T) *Service {
	t.Helper()
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	return &Service{
		issuerID:                    "issuer-test",
		pubKey:                      pub,
		privKey:                     priv,
		tokenTTL:                    2 * time.Minute,
		settlement:                  settlement.NewMemoryService(),
		sponsorAPIToken:             "sponsor-secret-token",
		sponsorMaxSubjectLen:        defaultSponsorMaxSubjectLen,
		sponsorMaxIDLen:             defaultSponsorMaxIDLen,
		sponsorMaxCurrencyLen:       defaultSponsorMaxCurrencyLen,
		sponsorMaxReservationMicros: defaultSponsorMaxReservationMicros,
		keyEpoch:                    1,
		minTokenEpoch:               1,
		subjects:                    map[string]proto.SubjectProfile{},
	}
}
