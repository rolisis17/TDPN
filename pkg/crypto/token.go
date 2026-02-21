package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type CapabilityClaims struct {
	Issuer     string   `json:"iss"`
	Audience   string   `json:"aud"`
	Subject    string   `json:"sub,omitempty"`
	KeyEpoch   int64    `json:"key_epoch,omitempty"`
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
