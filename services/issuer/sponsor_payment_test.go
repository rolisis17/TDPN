package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestIssueEndpointsValidateProvidedPaymentProofWhenGloballyOptional(t *testing.T) {
	tests := []struct {
		name string
		path string
		call func(*Service, *httptest.ResponseRecorder, *http.Request)
	}{
		{
			name: "client token endpoint",
			path: "/v1/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleIssueToken(rr, req)
			},
		},
		{
			name: "sponsor token endpoint",
			path: "/v1/sponsor/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleSponsorIssueToken(rr, req)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSponsorTestService(t)
			s.requirePaymentProof = false
			reqBody, _ := json.Marshal(proto.IssueTokenRequest{
				Tier:      1,
				Subject:   "client-1",
				TokenType: crypto.TokenTypeClientAccess,
				PopPubKey: sponsorTestPopPubKey(t),
				PaymentProof: &proto.SponsorPaymentProof{
					ReservationID: "unknown-" + strings.ReplaceAll(tc.path, "/", "-"),
					SponsorID:     "sponsor-1",
					Subject:       "client-1",
					SessionID:     "sess-1",
				},
			})
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(reqBody))
			if tc.path == "/v1/sponsor/token" {
				req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			}
			rr := httptest.NewRecorder()
			tc.call(s, rr, req)

			if rr.Code != http.StatusPaymentRequired {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusPaymentRequired, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "payment proof invalid") {
				t.Fatalf("expected payment proof invalid error, body=%s", rr.Body.String())
			}
		})
	}
}

func TestHandleSponsorIssueTokenRejectsMalformedJSONShapes(t *testing.T) {
	s := newSponsorTestService(t)
	popPubKey := sponsorTestPopPubKey(t)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `{"tier":1,"subject":"client-1","token_type":"client_access","pop_pub_key":"` + popPubKey + `","unexpected":"value"}`,
		},
		{
			name: "trailing json",
			body: `{"tier":1,"subject":"client-1","token_type":"client_access","pop_pub_key":"` + popPubKey + `"} {"jti":"other"}`,
		},
		{
			name: "oversized body",
			body: `{"tier":1,"subject":"` + strings.Repeat("a", 70*1024) + `","token_type":"client_access","pop_pub_key":"` + popPubKey + `"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/token", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			rr := httptest.NewRecorder()

			s.handleSponsorIssueToken(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusBadRequest, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "invalid json") {
				t.Fatalf("expected invalid json error, got body=%s", rr.Body.String())
			}
		})
	}
}

func TestIssueEndpointsPaymentProofWithExplicitBindingsSucceeds(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		reservationID string
		sessionID     string
		call          func(*Service, *httptest.ResponseRecorder, *http.Request)
	}{
		{
			name:          "client token endpoint",
			path:          "/v1/token",
			reservationID: "sres-empty-subject-token",
			sessionID:     "sess-empty-subject-token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleIssueToken(rr, req)
			},
		},
		{
			name:          "sponsor token endpoint",
			path:          "/v1/sponsor/token",
			reservationID: "sres-empty-subject-sponsor",
			sessionID:     "sess-empty-subject-sponsor",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleSponsorIssueToken(rr, req)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSponsorTestService(t)
			s.requirePaymentProof = false

			const subjectID = "client-1"
			_, err := s.settlementService().ReserveSponsorCredits(context.Background(), settlement.SponsorCreditReservation{
				ReservationID: tc.reservationID,
				SponsorID:     "sponsor-1",
				SubjectID:     subjectID,
				SessionID:     tc.sessionID,
				AmountMicros:  1000,
				ExpiresAt:     time.Now().UTC().Add(2 * time.Minute),
			})
			if err != nil {
				t.Fatalf("ReserveSponsorCredits: %v", err)
			}

			reqBody, _ := json.Marshal(proto.IssueTokenRequest{
				Tier:      1,
				Subject:   subjectID,
				TokenType: crypto.TokenTypeClientAccess,
				PopPubKey: sponsorTestPopPubKey(t),
				PaymentProof: &proto.SponsorPaymentProof{
					ReservationID: tc.reservationID,
					SponsorID:     "sponsor-1",
					Subject:       subjectID,
					SessionID:     tc.sessionID,
				},
			})
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(reqBody))
			if tc.path == "/v1/sponsor/token" {
				req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			}
			rr := httptest.NewRecorder()
			tc.call(s, rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, rr.Code, rr.Body.String())
			}
			var resp proto.IssueTokenResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode token response: %v", err)
			}
			if resp.Token == "" || resp.JTI == "" {
				t.Fatalf("unexpected empty token response: %+v", resp)
			}
		})
	}
}

func TestIssueEndpointsRejectPaymentProofMissingRequiredBindings(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		call        func(*Service, *httptest.ResponseRecorder, *http.Request)
		mutateProof func(*proto.SponsorPaymentProof)
		requestSub  string
		wantMessage string
	}{
		{
			name: "client token endpoint missing sponsor_id",
			path: "/v1/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleIssueToken(rr, req)
			},
			mutateProof: func(proof *proto.SponsorPaymentProof) {
				proof.SponsorID = " "
			},
			requestSub:  "client-1",
			wantMessage: "payment proof invalid: authorize payment requires sponsor_id",
		},
		{
			name: "client token endpoint missing subject binding",
			path: "/v1/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleIssueToken(rr, req)
			},
			mutateProof: func(proof *proto.SponsorPaymentProof) {
				proof.Subject = " "
			},
			requestSub:  "",
			wantMessage: "payment proof invalid: authorize payment requires subject_id",
		},
		{
			name: "sponsor token endpoint missing session_id",
			path: "/v1/sponsor/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleSponsorIssueToken(rr, req)
			},
			mutateProof: func(proof *proto.SponsorPaymentProof) {
				proof.SessionID = " "
			},
			requestSub:  "client-1",
			wantMessage: "payment proof invalid: authorize payment requires session_id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSponsorTestService(t)
			s.requirePaymentProof = false
			const reservationID = "sres-missing-binding-1"
			const sessionID = "sess-missing-binding-1"
			const subjectID = "client-1"
			_, err := s.settlementService().ReserveSponsorCredits(context.Background(), settlement.SponsorCreditReservation{
				ReservationID: reservationID,
				SponsorID:     "sponsor-1",
				SubjectID:     subjectID,
				SessionID:     sessionID,
				AmountMicros:  1000,
				ExpiresAt:     time.Now().UTC().Add(2 * time.Minute),
			})
			if err != nil {
				t.Fatalf("ReserveSponsorCredits: %v", err)
			}

			proof := &proto.SponsorPaymentProof{
				ReservationID: reservationID,
				SponsorID:     "sponsor-1",
				Subject:       subjectID,
				SessionID:     sessionID,
			}
			tc.mutateProof(proof)

			reqBody, _ := json.Marshal(proto.IssueTokenRequest{
				Tier:         1,
				Subject:      tc.requestSub,
				TokenType:    crypto.TokenTypeClientAccess,
				PopPubKey:    sponsorTestPopPubKey(t),
				PaymentProof: proof,
			})
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(reqBody))
			if tc.path == "/v1/sponsor/token" {
				req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			}
			rr := httptest.NewRecorder()
			tc.call(s, rr, req)

			if rr.Code != http.StatusPaymentRequired {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusPaymentRequired, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantMessage) {
				t.Fatalf("expected response to contain %q, body=%s", tc.wantMessage, rr.Body.String())
			}
		})
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

func TestSponsorReserveDeferredSubmissionStillAllowsPaymentProofTokenIssue(t *testing.T) {
	s := newSponsorTestService(t)
	s.settlement = settlement.NewMemoryService(settlement.WithChainAdapter(sponsorReservationFailingChainAdapter{}))

	const reservationID = "sres-deferred-submit-1"
	const sessionID = "sess-deferred-submit-1"
	reserveReqBody, _ := json.Marshal(proto.SponsorReserveRequest{
		ReservationID: reservationID,
		SponsorID:     "sponsor-1",
		Subject:       "client-1",
		SessionID:     sessionID,
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
	if !reserveResp.Accepted || reserveResp.ReservationID != reservationID {
		t.Fatalf("unexpected reserve response: %+v", reserveResp)
	}
	if reserveResp.Status != string(settlement.OperationStatusPending) {
		t.Fatalf("expected pending reserve status under deferred adapter submission, got %q", reserveResp.Status)
	}

	tokenReqBody, _ := json.Marshal(proto.IssueTokenRequest{
		Tier:      1,
		Subject:   "client-1",
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: sponsorTestPopPubKey(t),
		PaymentProof: &proto.SponsorPaymentProof{
			ReservationID: reservationID,
			SponsorID:     "sponsor-1",
			Subject:       "client-1",
			SessionID:     sessionID,
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

	statusReq := httptest.NewRequest(http.MethodGet, "/v1/sponsor/status?reservation_id="+reservationID, nil)
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
		t.Fatalf("expected consumed reservation after payment-proof token issuance: %+v", statusResp)
	}

	report, err := s.settlementService().Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations < 1 {
		t.Fatalf("expected deferred adapter backlog to remain observable, got pending_adapter_operations=%d", report.PendingAdapterOperations)
	}
}

func TestSponsorIssueTokenRequiresPaymentProof(t *testing.T) {
	s := newSponsorTestService(t)
	popPubB64 := sponsorTestPopPubKey(t)
	reqBody, _ := json.Marshal(proto.IssueTokenRequest{
		Tier:      1,
		Subject:   "client-1",
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: popPubB64,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/token", bytes.NewReader(reqBody))
	req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
	rr := httptest.NewRecorder()

	s.handleSponsorIssueToken(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusPaymentRequired, rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "payment proof required") {
		t.Fatalf("expected missing payment proof error, body=%s", rr.Body.String())
	}
}

func TestSponsorIssueTokenRejectsPaymentProofMismatches(t *testing.T) {
	tests := []struct {
		name        string
		mutateProof func(*proto.SponsorPaymentProof)
		wantMessage string
	}{
		{
			name: "sponsor mismatch",
			mutateProof: func(proof *proto.SponsorPaymentProof) {
				proof.SponsorID = "sponsor-2"
			},
			wantMessage: "payment proof invalid: reservation sponsor mismatch",
		},
		{
			name: "subject mismatch",
			mutateProof: func(proof *proto.SponsorPaymentProof) {
				proof.Subject = "client-2"
			},
			wantMessage: "payment proof invalid: request subject mismatch",
		},
		{
			name: "session mismatch",
			mutateProof: func(proof *proto.SponsorPaymentProof) {
				proof.SessionID = "sess-2"
			},
			wantMessage: "payment proof invalid: reservation session mismatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSponsorTestService(t)
			const reservationID = "sres-mismatch-1"
			reserveReqBody, _ := json.Marshal(proto.SponsorReserveRequest{
				ReservationID: reservationID,
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

			proof := &proto.SponsorPaymentProof{
				ReservationID: reservationID,
				SponsorID:     "sponsor-1",
				Subject:       "client-1",
				SessionID:     "sess-1",
			}
			tc.mutateProof(proof)

			tokenReqBody, _ := json.Marshal(proto.IssueTokenRequest{
				Tier:         1,
				Subject:      "client-1",
				TokenType:    crypto.TokenTypeClientAccess,
				PopPubKey:    sponsorTestPopPubKey(t),
				PaymentProof: proof,
			})
			tokenReq := httptest.NewRequest(http.MethodPost, "/v1/sponsor/token", bytes.NewReader(tokenReqBody))
			tokenReq.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			tokenRR := httptest.NewRecorder()
			s.handleSponsorIssueToken(tokenRR, tokenReq)

			if tokenRR.Code != http.StatusPaymentRequired {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusPaymentRequired, tokenRR.Code, tokenRR.Body.String())
			}
			if !strings.Contains(tokenRR.Body.String(), tc.wantMessage) {
				t.Fatalf("expected response to contain %q, body=%s", tc.wantMessage, tokenRR.Body.String())
			}
		})
	}
}

func TestIssueEndpointsRejectRequestAndPaymentProofSubjectMismatch(t *testing.T) {
	tests := []struct {
		name string
		path string
		call func(*Service, *httptest.ResponseRecorder, *http.Request)
	}{
		{
			name: "client token endpoint",
			path: "/v1/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleIssueToken(rr, req)
			},
		},
		{
			name: "sponsor token endpoint",
			path: "/v1/sponsor/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleSponsorIssueToken(rr, req)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSponsorTestService(t)
			s.requirePaymentProof = false
			const reservationID = "sres-request-proof-subject-mismatch"
			const sessionID = "sess-request-proof-subject-mismatch"
			_, err := s.settlementService().ReserveSponsorCredits(context.Background(), settlement.SponsorCreditReservation{
				ReservationID: reservationID,
				SponsorID:     "sponsor-1",
				SubjectID:     "client-2",
				SessionID:     sessionID,
				AmountMicros:  1000,
				ExpiresAt:     time.Now().UTC().Add(2 * time.Minute),
			})
			if err != nil {
				t.Fatalf("ReserveSponsorCredits: %v", err)
			}

			reqBody, _ := json.Marshal(proto.IssueTokenRequest{
				Tier:      1,
				Subject:   "client-1",
				TokenType: crypto.TokenTypeClientAccess,
				PopPubKey: sponsorTestPopPubKey(t),
				PaymentProof: &proto.SponsorPaymentProof{
					ReservationID: reservationID,
					SponsorID:     "sponsor-1",
					Subject:       "client-2",
					SessionID:     sessionID,
				},
			})
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(reqBody))
			if tc.path == "/v1/sponsor/token" {
				req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			}
			rr := httptest.NewRecorder()
			tc.call(s, rr, req)

			if rr.Code != http.StatusPaymentRequired {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusPaymentRequired, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "payment proof invalid: request subject mismatch") {
				t.Fatalf("expected request/proof subject mismatch error, body=%s", rr.Body.String())
			}
		})
	}
}

func TestIssueEndpointsPropagateCanceledRequestContextToAuthorizePayment(t *testing.T) {
	tests := []struct {
		name string
		path string
		call func(*Service, *httptest.ResponseRecorder, *http.Request)
	}{
		{
			name: "client token endpoint",
			path: "/v1/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleIssueToken(rr, req)
			},
		},
		{
			name: "sponsor token endpoint",
			path: "/v1/sponsor/token",
			call: func(s *Service, rr *httptest.ResponseRecorder, req *http.Request) {
				s.handleSponsorIssueToken(rr, req)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSponsorTestService(t)
			baseSettlement := settlement.NewMemoryService()
			probe := &authorizePaymentContextProbe{Service: baseSettlement}
			s.settlement = probe
			const reservationID = "sres-context-cancelled"
			const subjectID = "client-ctx"
			const sessionID = "sess-ctx"
			_, err := s.settlementService().ReserveSponsorCredits(context.Background(), settlement.SponsorCreditReservation{
				ReservationID: reservationID,
				SponsorID:     "sponsor-1",
				SubjectID:     subjectID,
				SessionID:     sessionID,
				AmountMicros:  1000,
				ExpiresAt:     time.Now().UTC().Add(2 * time.Minute),
			})
			if err != nil {
				t.Fatalf("ReserveSponsorCredits: %v", err)
			}

			reqBody, _ := json.Marshal(proto.IssueTokenRequest{
				Tier:      1,
				Subject:   subjectID,
				TokenType: crypto.TokenTypeClientAccess,
				PopPubKey: sponsorTestPopPubKey(t),
				PaymentProof: &proto.SponsorPaymentProof{
					ReservationID: reservationID,
					SponsorID:     "sponsor-1",
					Subject:       subjectID,
					SessionID:     sessionID,
				},
			})
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(reqBody))
			if tc.path == "/v1/sponsor/token" {
				req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
			}
			canceledCtx, cancel := context.WithCancel(req.Context())
			cancel()
			req = req.WithContext(canceledCtx)

			rr := httptest.NewRecorder()
			tc.call(s, rr, req)

			if rr.Code != http.StatusPaymentRequired {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusPaymentRequired, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "payment proof invalid: context canceled") {
				t.Fatalf("expected canceled context error, body=%s", rr.Body.String())
			}
			if !probe.sawCanceledContext {
				t.Fatalf("expected AuthorizePayment to observe canceled request context")
			}
		})
	}
}

func TestSponsorIssueTokenRejectsExpiredPaymentReservation(t *testing.T) {
	s := newSponsorTestService(t)
	const reservationID = "sres-expired-1"
	_, err := s.settlementService().ReserveSponsorCredits(context.Background(), settlement.SponsorCreditReservation{
		ReservationID: reservationID,
		SponsorID:     "sponsor-1",
		SubjectID:     "client-1",
		SessionID:     "sess-expired-1",
		AmountMicros:  1000,
		ExpiresAt:     time.Now().UTC().Add(-1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	reqBody, _ := json.Marshal(proto.IssueTokenRequest{
		Tier:      1,
		Subject:   "client-1",
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: sponsorTestPopPubKey(t),
		PaymentProof: &proto.SponsorPaymentProof{
			ReservationID: reservationID,
			SponsorID:     "sponsor-1",
			Subject:       "client-1",
			SessionID:     "sess-expired-1",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/token", bytes.NewReader(reqBody))
	req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
	rr := httptest.NewRecorder()
	s.handleSponsorIssueToken(rr, req)

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusPaymentRequired, rr.Code, rr.Body.String())
	}
	wantMessage := "payment proof invalid: reservation expired: " + reservationID
	if !strings.Contains(rr.Body.String(), wantMessage) {
		t.Fatalf("expected response to contain %q, body=%s", wantMessage, rr.Body.String())
	}
}

func TestSponsorIssueTokenRejectsDuplicatePaymentProofReplay(t *testing.T) {
	s := newSponsorTestService(t)
	const reservationID = "sres-replay-1"
	reserveReqBody, _ := json.Marshal(proto.SponsorReserveRequest{
		ReservationID: reservationID,
		SponsorID:     "sponsor-1",
		Subject:       "client-1",
		SessionID:     "sess-replay-1",
		AmountMicros:  1000,
	})
	reserveReq := httptest.NewRequest(http.MethodPost, "/v1/sponsor/reserve", bytes.NewReader(reserveReqBody))
	reserveReq.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
	reserveRR := httptest.NewRecorder()
	s.handleSponsorReserve(reserveRR, reserveReq)
	if reserveRR.Code != http.StatusOK {
		t.Fatalf("reserve status=%d body=%s", reserveRR.Code, reserveRR.Body.String())
	}

	tokenReqBody, _ := json.Marshal(proto.IssueTokenRequest{
		Tier:      1,
		Subject:   "client-1",
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: sponsorTestPopPubKey(t),
		PaymentProof: &proto.SponsorPaymentProof{
			ReservationID: reservationID,
			SponsorID:     "sponsor-1",
			Subject:       "client-1",
			SessionID:     "sess-replay-1",
		},
	})

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/sponsor/token", bytes.NewReader(tokenReqBody))
	firstReq.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
	firstRR := httptest.NewRecorder()
	s.handleSponsorIssueToken(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first sponsor token status=%d body=%s", firstRR.Code, firstRR.Body.String())
	}
	var firstResp proto.IssueTokenResponse
	if err := json.Unmarshal(firstRR.Body.Bytes(), &firstResp); err != nil {
		t.Fatalf("decode first token response: %v", err)
	}
	if firstResp.Token == "" || firstResp.JTI == "" {
		t.Fatalf("unexpected first token response: %+v", firstResp)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/sponsor/token", bytes.NewReader(tokenReqBody))
	secondReq.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
	secondRR := httptest.NewRecorder()
	s.handleSponsorIssueToken(secondRR, secondReq)
	if secondRR.Code != http.StatusConflict {
		t.Fatalf("expected replay rejection status=%d got=%d body=%s", http.StatusConflict, secondRR.Code, secondRR.Body.String())
	}
	if !strings.Contains(secondRR.Body.String(), "payment proof already used") {
		t.Fatalf("expected replay rejection message, body=%s", secondRR.Body.String())
	}

	reservation, err := s.settlementService().GetSponsorReservation(context.Background(), reservationID)
	if err != nil {
		t.Fatalf("GetSponsorReservation: %v", err)
	}
	if reservation.ConsumedAt.IsZero() {
		t.Fatalf("expected consumed reservation after replay issuance")
	}
}

func TestSponsorIssueTokenFailsClosedWhenPaymentReplayCacheSaturated(t *testing.T) {
	s := newSponsorTestService(t)
	s.issuedPaymentReplayMaxEntries = 1
	s.issuedPaymentReplayTTL = 24 * time.Hour

	reserve := func(reservationID, sessionID string) {
		t.Helper()
		_, err := s.settlementService().ReserveSponsorCredits(context.Background(), settlement.SponsorCreditReservation{
			ReservationID: reservationID,
			SponsorID:     "sponsor-1",
			SubjectID:     "client-1",
			SessionID:     sessionID,
			AmountMicros:  1000,
			ExpiresAt:     time.Now().UTC().Add(2 * time.Minute),
		})
		if err != nil {
			t.Fatalf("ReserveSponsorCredits(%s): %v", reservationID, err)
		}
	}
	issue := func(reservationID, sessionID string) *httptest.ResponseRecorder {
		t.Helper()
		reqBody, _ := json.Marshal(proto.IssueTokenRequest{
			Tier:      1,
			Subject:   "client-1",
			TokenType: crypto.TokenTypeClientAccess,
			PopPubKey: sponsorTestPopPubKey(t),
			PaymentProof: &proto.SponsorPaymentProof{
				ReservationID: reservationID,
				SponsorID:     "sponsor-1",
				Subject:       "client-1",
				SessionID:     sessionID,
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/token", bytes.NewReader(reqBody))
		req.Header.Set("X-Sponsor-Token", "sponsor-secret-token")
		rr := httptest.NewRecorder()
		s.handleSponsorIssueToken(rr, req)
		return rr
	}

	reserve("sres-cache-1", "sess-cache-1")
	reserve("sres-cache-2", "sess-cache-2")

	first := issue("sres-cache-1", "sess-cache-1")
	if first.Code != http.StatusOK {
		t.Fatalf("first sponsor token status=%d body=%s", first.Code, first.Body.String())
	}
	second := issue("sres-cache-2", "sess-cache-2")
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected cache saturation status=%d got=%d body=%s", http.StatusServiceUnavailable, second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "payment replay cache saturated") {
		t.Fatalf("expected saturation error message, body=%s", second.Body.String())
	}
}

func TestMarkIssuedPaymentReservationPrunesExpiredEntriesBeforeCapacityCheck(t *testing.T) {
	s := &Service{
		issuedPaymentReplayMaxEntries: 1,
		issuedPaymentReplayTTL:        time.Second,
		issuedPaymentReservations: map[string]int64{
			"expired": time.Now().Add(-5 * time.Second).Unix(),
		},
	}
	marked, saturated := s.markIssuedPaymentReservation("fresh")
	if !marked {
		t.Fatalf("expected fresh reservation to be marked after prune; saturated=%t", saturated)
	}
	if _, exists := s.issuedPaymentReservations["expired"]; exists {
		t.Fatal("expected expired reservation to be pruned")
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

func TestSponsorEndpointsAcceptBearerTokenWhenXSponsorTokenMissing(t *testing.T) {
	s := newSponsorTestService(t)
	reqBody, _ := json.Marshal(proto.SponsorQuoteRequest{Subject: "client-1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/quote", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer sponsor-secret-token")
	rr := httptest.NewRecorder()
	s.handleSponsorQuote(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected bearer-backed sponsor request to pass, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSponsorEndpointsRejectMalformedOrConflictingBearerToken(t *testing.T) {
	s := newSponsorTestService(t)
	reqBody, _ := json.Marshal(proto.SponsorQuoteRequest{Subject: "client-1"})

	tests := []struct {
		name             string
		xSponsorToken    string
		authorization    string
		expectedHTTPCode int
	}{
		{
			name:             "malformed bearer token",
			authorization:    "Bearer",
			expectedHTTPCode: http.StatusUnauthorized,
		},
		{
			name:             "wrong bearer token",
			authorization:    "Bearer wrong-token",
			expectedHTTPCode: http.StatusUnauthorized,
		},
		{
			name:             "x sponsor token takes precedence over bearer fallback",
			xSponsorToken:    "wrong-x-token",
			authorization:    "Bearer sponsor-secret-token",
			expectedHTTPCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/sponsor/quote", bytes.NewReader(reqBody))
			if tc.xSponsorToken != "" {
				req.Header.Set("X-Sponsor-Token", tc.xSponsorToken)
			}
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			rr := httptest.NewRecorder()
			s.handleSponsorQuote(rr, req)
			if rr.Code != tc.expectedHTTPCode {
				t.Fatalf("expected status %d, got %d body=%s", tc.expectedHTTPCode, rr.Code, rr.Body.String())
			}
		})
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

func sponsorTestPopPubKey(t *testing.T) string {
	t.Helper()
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	return crypto.EncodeEd25519PublicKey(popPub)
}

type authorizePaymentContextProbe struct {
	settlement.Service
	sawCanceledContext bool
}

func (p *authorizePaymentContextProbe) AuthorizePayment(ctx context.Context, proof settlement.PaymentProof) (settlement.PaymentAuthorization, error) {
	if err := ctx.Err(); err != nil {
		p.sawCanceledContext = true
		return settlement.PaymentAuthorization{}, err
	}
	return p.Service.AuthorizePayment(ctx, proof)
}

type sponsorReservationFailingChainAdapter struct{}

func (sponsorReservationFailingChainAdapter) SubmitSessionSettlement(context.Context, settlement.SessionSettlement) (string, error) {
	return "ok-settlement", nil
}

func (sponsorReservationFailingChainAdapter) SubmitRewardIssue(context.Context, settlement.RewardIssue) (string, error) {
	return "ok-reward", nil
}

func (sponsorReservationFailingChainAdapter) SubmitSponsorReservation(context.Context, settlement.SponsorCreditReservation) (string, error) {
	return "", errors.New("adapter sponsor reservation submission failed")
}

func (sponsorReservationFailingChainAdapter) SubmitSlashEvidence(context.Context, settlement.SlashEvidence) (string, error) {
	return "ok-slash", nil
}

func (sponsorReservationFailingChainAdapter) Health(context.Context) error {
	return nil
}
