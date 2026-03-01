package issuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestHandleIssueTokenWithAnonymousCredential(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := &Service{
		issuerID:            "issuer-local",
		pubKey:              pub,
		privKey:             priv,
		tokenTTL:            5 * time.Minute,
		keyEpoch:            3,
		minTokenEpoch:       3,
		anonRevocations:     map[string]int64{},
		revocations:         map[string]int64{},
		subjects:            map[string]proto.SubjectProfile{},
		previousPubKeysFile: "",
	}
	anonCred, err := signAnonymousCredential(anonymousCredentialClaims{
		Issuer:       "issuer-local",
		CredentialID: "cred-1",
		Tier:         2,
		ExpiryUnix:   time.Now().Add(20 * time.Minute).Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("sign anonymous credential: %v", err)
	}
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}
	reqBody, err := json.Marshal(proto.IssueTokenRequest{
		Tier:      3,
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: crypto.EncodeEd25519PublicKey(popPub),
		AnonCred:  anonCred,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	s.handleIssueToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.IssueTokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims, err := crypto.VerifyClaims(out.Token, pub)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.Tier != 2 {
		t.Fatalf("expected tier capped by anon credential to 2, got %d", claims.Tier)
	}
	if claims.AnonCredID != "cred-1" {
		t.Fatalf("expected anon credential id in token claims, got %q", claims.AnonCredID)
	}
	if claims.Subject == "" || claims.Subject[:5] != "anon:" {
		t.Fatalf("expected anonymous subject alias, got %q", claims.Subject)
	}
}

func TestHandleIssueTokenWithRevokedAnonymousCredential(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	credID := "cred-revoked"
	s := &Service{
		issuerID:            "issuer-local",
		pubKey:              pub,
		privKey:             priv,
		tokenTTL:            5 * time.Minute,
		keyEpoch:            3,
		minTokenEpoch:       3,
		anonRevocations:     map[string]int64{credID: time.Now().Add(30 * time.Minute).Unix()},
		revocations:         map[string]int64{},
		subjects:            map[string]proto.SubjectProfile{},
		previousPubKeysFile: "",
	}
	anonCred, err := signAnonymousCredential(anonymousCredentialClaims{
		Issuer:       "issuer-local",
		CredentialID: credID,
		Tier:         2,
		ExpiryUnix:   time.Now().Add(20 * time.Minute).Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("sign anonymous credential: %v", err)
	}
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}
	reqBody, err := json.Marshal(proto.IssueTokenRequest{
		Tier:      2,
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: crypto.EncodeEd25519PublicKey(popPub),
		AnonCred:  anonCred,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	s.handleIssueToken(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked anonymous credential, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleIssueTokenWithDisputedAnonymousCredentialTierCap(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	dir := t.TempDir()
	credID := "cred-disputed"
	s := &Service{
		issuerID:            "issuer-local",
		adminToken:          "test-admin",
		pubKey:              pub,
		privKey:             priv,
		tokenTTL:            5 * time.Minute,
		keyEpoch:            3,
		minTokenEpoch:       3,
		disputeDefaultTTL:   time.Hour,
		anonRevocations:     map[string]int64{},
		anonDisputes:        map[string]anonymousCredentialDispute{},
		anonDisputesFile:    filepath.Join(dir, "anon_disputes.json"),
		revocations:         map[string]int64{},
		subjects:            map[string]proto.SubjectProfile{},
		previousPubKeysFile: "",
	}
	anonCred, err := signAnonymousCredential(anonymousCredentialClaims{
		Issuer:       "issuer-local",
		CredentialID: credID,
		Tier:         3,
		ExpiryUnix:   time.Now().Add(20 * time.Minute).Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("sign anonymous credential: %v", err)
	}
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}
	applyBody, err := json.Marshal(proto.ApplyAnonymousCredentialDisputeRequest{
		CredentialID: credID,
		TierCap:      1,
		Until:        time.Now().Add(2 * time.Hour).Unix(),
		CaseID:       "case-anon-1",
		EvidenceRef:  "evidence://anon-1",
		Reason:       "test",
	})
	if err != nil {
		t.Fatalf("marshal dispute request: %v", err)
	}
	applyReq := httptest.NewRequest(http.MethodPost, "/v1/admin/anon-credential/dispute", bytes.NewReader(applyBody))
	applyReq.Header.Set("X-Admin-Token", "test-admin")
	applyRR := httptest.NewRecorder()
	s.handleApplyAnonymousCredentialDispute(applyRR, applyReq)
	if applyRR.Code != http.StatusOK {
		t.Fatalf("expected 200 on dispute apply, got %d body=%s", applyRR.Code, applyRR.Body.String())
	}

	reqBody, err := json.Marshal(proto.IssueTokenRequest{
		Tier:      3,
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: crypto.EncodeEd25519PublicKey(popPub),
		AnonCred:  anonCred,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	s.handleIssueToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.IssueTokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims, err := crypto.VerifyClaims(out.Token, pub)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.Tier != 1 {
		t.Fatalf("expected tier capped by anon dispute to 1, got %d", claims.Tier)
	}

	clearBody, err := json.Marshal(proto.ClearAnonymousCredentialDisputeRequest{
		CredentialID: credID,
		Reason:       "resolved",
	})
	if err != nil {
		t.Fatalf("marshal clear request: %v", err)
	}
	clearReq := httptest.NewRequest(http.MethodPost, "/v1/admin/anon-credential/dispute/clear", bytes.NewReader(clearBody))
	clearReq.Header.Set("X-Admin-Token", "test-admin")
	clearRR := httptest.NewRecorder()
	s.handleClearAnonymousCredentialDispute(clearRR, clearReq)
	if clearRR.Code != http.StatusOK {
		t.Fatalf("expected 200 on dispute clear, got %d body=%s", clearRR.Code, clearRR.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewReader(reqBody))
	rr2 := httptest.NewRecorder()
	s.handleIssueToken(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 after dispute clear, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	var out2 proto.IssueTokenResponse
	if err := json.NewDecoder(rr2.Body).Decode(&out2); err != nil {
		t.Fatalf("decode response after clear: %v", err)
	}
	claims2, err := crypto.VerifyClaims(out2.Token, pub)
	if err != nil {
		t.Fatalf("verify token after clear: %v", err)
	}
	if claims2.Tier != 3 {
		t.Fatalf("expected tier restored to credential tier 3 after dispute clear, got %d", claims2.Tier)
	}
}

func TestHandleGetAnonymousCredentialStatus(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	s := &Service{
		adminToken:      "test-admin",
		issuerID:        "issuer-local",
		pubKey:          pub,
		privKey:         priv,
		anonRevocations: map[string]int64{"cred-a": now + 120},
		anonDisputes: map[string]anonymousCredentialDispute{
			"cred-a": {
				TierCap:      1,
				DisputeUntil: now + 180,
				CaseID:       "case-anon-99",
				EvidenceRef:  "evidence://anon-99",
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/anon-credential/get?credential_id=cred-a", nil)
	req.Header.Set("X-Admin-Token", "test-admin")
	rr := httptest.NewRecorder()
	s.handleGetAnonymousCredentialStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.AnonymousCredentialStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if !out.Revoked || out.RevokedUntil <= now {
		t.Fatalf("expected active revoke status, got %+v", out)
	}
	if !out.Disputed || out.DisputeTier != 1 || out.DisputeUntil <= now {
		t.Fatalf("expected active dispute status, got %+v", out)
	}
	if out.CaseID != "case-anon-99" || out.EvidenceRef != "evidence://anon-99" {
		t.Fatalf("expected dispute metadata in status, got %+v", out)
	}
}

func TestHandleGetAnonymousCredentialStatusPrunesExpiredState(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	dir := t.TempDir()
	now := time.Now().Unix()
	s := &Service{
		adminToken:          "test-admin",
		issuerID:            "issuer-local",
		pubKey:              pub,
		privKey:             priv,
		anonRevocations:     map[string]int64{"cred-expired": now - 1},
		anonRevocationsFile: filepath.Join(dir, "anon_revocations.json"),
		anonDisputes: map[string]anonymousCredentialDispute{
			"cred-expired": {TierCap: 1, DisputeUntil: now - 1},
		},
		anonDisputesFile: filepath.Join(dir, "anon_disputes.json"),
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/anon-credential/get?credential_id=cred-expired", nil)
	req.Header.Set("X-Admin-Token", "test-admin")
	rr := httptest.NewRecorder()
	s.handleGetAnonymousCredentialStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.AnonymousCredentialStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if out.Revoked || out.Disputed {
		t.Fatalf("expected expired status to be pruned, got %+v", out)
	}
	if _, ok := s.anonRevocations["cred-expired"]; ok {
		t.Fatalf("expected expired revoke to be removed from memory")
	}
	if _, ok := s.anonDisputes["cred-expired"]; ok {
		t.Fatalf("expected expired dispute to be removed from memory")
	}
}
