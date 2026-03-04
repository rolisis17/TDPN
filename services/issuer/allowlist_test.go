package issuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func newTokenRequestBody(t *testing.T, req proto.IssueTokenRequest) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return bytes.NewReader(b)
}

func TestHandleIssueTokenClientAllowlistRejectsUnknownSubject(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}
	s := &Service{
		issuerID:            "issuer-local",
		pubKey:              pub,
		privKey:             priv,
		tokenTTL:            5 * time.Minute,
		keyEpoch:            1,
		minTokenEpoch:       1,
		clientAllowlistOnly: true,
		disableAnonCred:     false,
		subjects:            map[string]proto.SubjectProfile{},
		revocations:         map[string]int64{},
		anonRevocations:     map[string]int64{},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/token", newTokenRequestBody(t, proto.IssueTokenRequest{
		Tier:      1,
		Subject:   "client-not-allowed",
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: crypto.EncodeEd25519PublicKey(popPub),
	}))
	rr := httptest.NewRecorder()
	s.handleIssueToken(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleIssueTokenClientAllowlistAllowsKnownClientSubject(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}
	s := &Service{
		issuerID:            "issuer-local",
		pubKey:              pub,
		privKey:             priv,
		tokenTTL:            5 * time.Minute,
		keyEpoch:            1,
		minTokenEpoch:       1,
		clientAllowlistOnly: true,
		disableAnonCred:     false,
		subjects: map[string]proto.SubjectProfile{
			"client-allowed": {
				Subject: "client-allowed",
				Kind:    proto.SubjectKindClient,
				Tier:    2,
			},
		},
		revocations:     map[string]int64{},
		anonRevocations: map[string]int64{},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/token", newTokenRequestBody(t, proto.IssueTokenRequest{
		Tier:      2,
		Subject:   "client-allowed",
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: crypto.EncodeEd25519PublicKey(popPub),
	}))
	rr := httptest.NewRecorder()
	s.handleIssueToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleIssueTokenRejectsAnonCredentialWhenDisabled(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}
	anonCred, err := signAnonymousCredential(anonymousCredentialClaims{
		Issuer:       "issuer-local",
		CredentialID: "cred-allowlist-test",
		Tier:         2,
		ExpiryUnix:   time.Now().Add(20 * time.Minute).Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("sign anonymous credential: %v", err)
	}
	s := &Service{
		issuerID:            "issuer-local",
		pubKey:              pub,
		privKey:             priv,
		tokenTTL:            5 * time.Minute,
		keyEpoch:            1,
		minTokenEpoch:       1,
		clientAllowlistOnly: false,
		disableAnonCred:     true,
		subjects:            map[string]proto.SubjectProfile{},
		revocations:         map[string]int64{},
		anonRevocations:     map[string]int64{},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/token", newTokenRequestBody(t, proto.IssueTokenRequest{
		Tier:      2,
		TokenType: crypto.TokenTypeClientAccess,
		PopPubKey: crypto.EncodeEd25519PublicKey(popPub),
		AnonCred:  anonCred,
	}))
	rr := httptest.NewRecorder()
	s.handleIssueToken(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}
