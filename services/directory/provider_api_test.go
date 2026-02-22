package directory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestHandleProviderRelayUpsertAcceptsProviderToken(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-1",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-1",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:       "exit-provider-1",
		Role:          "exit",
		PubKey:        base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:      "127.0.0.1:52821",
		ControlURL:    "http://127.0.0.1:9284",
		CountryCode:   "US",
		GeoConfidence: 0.9,
		Region:        "us-east",
		Capabilities:  []string{"wg", "tiered-policy"},
		Reputation:    0.8,
		Uptime:        0.9,
		Capacity:      0.7,
		AbusePenalty:  0.1,
		ValidForSec:   120,
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.ProviderRelayUpsertResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected accepted response")
	}
	if out.Relay.OperatorID != "provider-op-1" {
		t.Fatalf("expected operator from token subject, got %s", out.Relay.OperatorID)
	}

	relaysReq := httptest.NewRequest(http.MethodGet, "/v1/relays", nil)
	relaysRR := httptest.NewRecorder()
	s.handleRelays(relaysRR, relaysReq)
	if relaysRR.Code != http.StatusOK {
		t.Fatalf("relays expected 200, got %d", relaysRR.Code)
	}
	var relaysOut proto.RelayListResponse
	if err := json.NewDecoder(relaysRR.Body).Decode(&relaysOut); err != nil {
		t.Fatalf("decode relays response: %v", err)
	}
	found := false
	for _, desc := range relaysOut.Relays {
		if desc.RelayID == "exit-provider-1" && desc.Role == "exit" {
			found = true
			if desc.OperatorID != "provider-op-1" {
				t.Fatalf("expected relays operator from provider token subject, got %s", desc.OperatorID)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected provider relay in directory relays list")
	}
}

func TestHandleProviderRelayUpsertRejectsClientAccessToken(t *testing.T) {
	_, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	s := &Service{
		httpClient:        &http.Client{Transport: mockRoundTripper{handlers: map[string]func(*http.Request) (*http.Response, error){}}},
		entryEndpoints:    []string{"127.0.0.1:51820"},
		endpointRotateSec: 30,
		providerIssuerURLs: []string{
			"http://issuer.local",
		},
	}

	// no fetch path here; short-circuit by providing invalid token class after successful key fetch
	issuerPub := issuerPriv.Public().(ed25519.PublicKey)
	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://issuer.local/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s.httpClient = &http.Client{Transport: mockRoundTripper{handlers: handlers}}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		Subject:    "client-user-1",
		TokenType:  crypto.TokenTypeClientAccess,
		Tier:       1,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "client-token-1",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-1",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(issuerPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for client_access token, got %d", rr.Code)
	}
}

func signProviderTestToken(t *testing.T, priv ed25519.PrivateKey, claims crypto.CapabilityClaims) string {
	t.Helper()
	tok, err := crypto.SignClaims(claims, priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}
