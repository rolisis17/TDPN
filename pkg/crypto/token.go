package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	TokenTypeClientAccess = "client_access"
	TokenTypeProviderRole = "provider_role"

	pathOpenProofContext = "path_open_v1"
)

type CapabilityClaims struct {
	Issuer     string   `json:"iss"`
	Audience   string   `json:"aud"`
	Subject    string   `json:"sub,omitempty"`
	AnonCredID string   `json:"anon_cred_id,omitempty"`
	KeyEpoch   int64    `json:"key_epoch,omitempty"`
	TokenType  string   `json:"token_type,omitempty"`
	CNFEd25519 string   `json:"cnf_ed25519,omitempty"`
	Tier       int      `json:"tier"`
	ExpiryUnix int64    `json:"exp"`
	TokenID    string   `json:"jti"`
	AllowPorts []int    `json:"allow_ports,omitempty"`
	DenyPorts  []int    `json:"deny_ports,omitempty"`
	BWKbps     int      `json:"bw_kbps"`
	ConnRate   int      `json:"conn_rate"`
	MaxConns   int      `json:"max_conns"`
	ExitScope  []string `json:"exit_scope,omitempty"`
}

type PathOpenProofInput struct {
	Token           string
	ExitID          string
	MiddleRelayID   string
	TokenProofNonce string
	ClientInnerPub  string
	Transport       string
	RequestedMTU    int
	RequestedRegion string
}

func NormalizeTokenType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", TokenTypeClientAccess:
		return TokenTypeClientAccess
	case TokenTypeProviderRole:
		return TokenTypeProviderRole
	default:
		return ""
	}
}

func EncodeEd25519PublicKey(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

func ParseEd25519PublicKey(pubB64 string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return nil, fmt.Errorf("invalid public key encoding: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}
	return ed25519.PublicKey(raw), nil
}

func NormalizeEd25519PublicKey(pubB64 string) (string, error) {
	pub, err := ParseEd25519PublicKey(pubB64)
	if err != nil {
		return "", err
	}
	return EncodeEd25519PublicKey(pub), nil
}

func GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func SignClaims(claims CapabilityClaims, priv ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyClaims(token string, pub ed25519.PublicKey) (CapabilityClaims, error) {
	var claims CapabilityClaims

	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok || payloadB64 == "" || sigB64 == "" {
		return claims, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return claims, fmt.Errorf("invalid payload encoding: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return claims, fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !ed25519.Verify(pub, payload, sig) {
		return claims, fmt.Errorf("signature verification failed")
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("invalid claims json: %w", err)
	}
	return claims, nil
}

func SignPathOpenProof(priv ed25519.PrivateKey, input PathOpenProofInput) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}
	msg, err := pathOpenProofMessage(input)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyPathOpenProof(proof string, pub ed25519.PublicKey, input PathOpenProofInput) error {
	if strings.TrimSpace(proof) == "" {
		return fmt.Errorf("missing token proof")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(proof))
	if err != nil {
		return fmt.Errorf("invalid token proof encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid token proof size")
	}
	msgs, err := pathOpenProofMessagesForVerification(input)
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		if ed25519.Verify(pub, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("invalid token proof signature")
}

func pathOpenProofMessage(input PathOpenProofInput) ([]byte, error) {
	return pathOpenProofMessageVariant(input, true, true, true, true)
}

func pathOpenProofMessagesForVerification(input PathOpenProofInput) ([][]byte, error) {
	variants := []struct {
		includeMiddleRelayID   bool
		includeTransport       bool
		includeRequestedMTU    bool
		includeRequestedRegion bool
	}{
		{includeMiddleRelayID: true, includeTransport: true, includeRequestedMTU: true, includeRequestedRegion: true},
		{includeMiddleRelayID: true, includeTransport: true, includeRequestedMTU: true, includeRequestedRegion: false},
		{includeMiddleRelayID: false, includeTransport: true, includeRequestedMTU: true, includeRequestedRegion: false},
		{includeMiddleRelayID: true, includeTransport: true, includeRequestedMTU: false, includeRequestedRegion: false},
		{includeMiddleRelayID: false, includeTransport: true, includeRequestedMTU: false, includeRequestedRegion: false},
		{includeMiddleRelayID: true, includeTransport: false, includeRequestedMTU: false, includeRequestedRegion: false},
		{includeMiddleRelayID: false, includeTransport: false, includeRequestedMTU: false, includeRequestedRegion: false},
	}
	out := make([][]byte, 0, len(variants))
	seen := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		msg, err := pathOpenProofMessageVariant(
			input,
			variant.includeMiddleRelayID,
			variant.includeTransport,
			variant.includeRequestedMTU,
			variant.includeRequestedRegion,
		)
		if err != nil {
			return nil, err
		}
		key := string(msg)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, msg)
	}
	return out, nil
}

func pathOpenProofMessageVariant(input PathOpenProofInput, includeMiddleRelayID bool, includeTransport bool, includeRequestedMTU bool, includeRequestedRegion bool) ([]byte, error) {
	normalized := normalizePathOpenProofInput(input)
	middleRelayID := normalized.MiddleRelayID
	transport := normalized.Transport
	requestedMTU := normalized.RequestedMTU
	requestedRegion := normalized.RequestedRegion

	payload := struct {
		Context         string  `json:"ctx"`
		Token           string  `json:"token"`
		ExitID          string  `json:"exit_id"`
		MiddleRelayID   *string `json:"middle_relay_id,omitempty"`
		TokenProofNonce string  `json:"token_proof_nonce"`
		ClientInnerPub  string  `json:"client_inner_pub"`
		Transport       *string `json:"transport,omitempty"`
		RequestedMTU    *int    `json:"requested_mtu,omitempty"`
		RequestedRegion *string `json:"requested_region,omitempty"`
	}{
		Context:         pathOpenProofContext,
		Token:           normalized.Token,
		ExitID:          normalized.ExitID,
		TokenProofNonce: normalized.TokenProofNonce,
		ClientInnerPub:  normalized.ClientInnerPub,
	}
	if includeMiddleRelayID {
		payload.MiddleRelayID = &middleRelayID
	}
	if includeTransport {
		payload.Transport = &transport
	}
	if includeRequestedMTU {
		payload.RequestedMTU = &requestedMTU
	}
	if includeRequestedRegion {
		payload.RequestedRegion = &requestedRegion
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal path-open proof payload: %w", err)
	}
	return msg, nil
}

func normalizePathOpenProofInput(input PathOpenProofInput) PathOpenProofInput {
	input.Token = strings.TrimSpace(input.Token)
	input.ExitID = strings.TrimSpace(input.ExitID)
	input.MiddleRelayID = strings.TrimSpace(input.MiddleRelayID)
	input.TokenProofNonce = strings.TrimSpace(input.TokenProofNonce)
	input.ClientInnerPub = strings.TrimSpace(input.ClientInnerPub)
	input.Transport = strings.TrimSpace(input.Transport)
	input.RequestedRegion = strings.TrimSpace(input.RequestedRegion)
	return input
}
