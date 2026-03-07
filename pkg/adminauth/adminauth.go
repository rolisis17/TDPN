package adminauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"strconv"
	"strings"
)

const (
	HeaderKeyID     = "X-Admin-Key-Id"
	HeaderTimestamp = "X-Admin-Timestamp"
	HeaderNonce     = "X-Admin-Nonce"
	HeaderSignature = "X-Admin-Signature"
)

func PathWithQuery(u *urlpkg.URL) string {
	if u == nil {
		return "/"
	}
	p := u.EscapedPath()
	if strings.TrimSpace(p) == "" {
		p = "/"
	}
	if strings.TrimSpace(u.RawQuery) != "" {
		p += "?" + u.RawQuery
	}
	return p
}

func BodySHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func CanonicalMessage(method string, pathWithQuery string, bodySHA256Hex string, timestamp int64, nonce string) ([]byte, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	pathWithQuery = strings.TrimSpace(pathWithQuery)
	bodySHA256Hex = strings.ToLower(strings.TrimSpace(bodySHA256Hex))
	nonce = strings.TrimSpace(nonce)
	if method == "" {
		return nil, fmt.Errorf("missing method")
	}
	if pathWithQuery == "" {
		pathWithQuery = "/"
	}
	if bodySHA256Hex == "" {
		return nil, fmt.Errorf("missing body hash")
	}
	if nonce == "" {
		return nil, fmt.Errorf("missing nonce")
	}
	msg := strings.Join([]string{
		method,
		pathWithQuery,
		bodySHA256Hex,
		strconv.FormatInt(timestamp, 10),
		nonce,
	}, "\n")
	return []byte(msg), nil
}

func Sign(priv ed25519.PrivateKey, method string, pathWithQuery string, body []byte, timestamp int64, nonce string) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}
	msg, err := CanonicalMessage(method, pathWithQuery, BodySHA256Hex(body), timestamp, nonce)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func Verify(pub ed25519.PublicKey, signature string, method string, pathWithQuery string, body []byte, timestamp int64, nonce string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}
	rawSig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(rawSig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size")
	}
	msg, err := CanonicalMessage(method, pathWithQuery, BodySHA256Hex(body), timestamp, nonce)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, rawSig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func ReadBodyPreserve(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func ParseAdminHeaders(r *http.Request) (keyID string, ts int64, nonce string, signature string, err error) {
	if r == nil {
		return "", 0, "", "", fmt.Errorf("nil request")
	}
	keyID = strings.TrimSpace(r.Header.Get(HeaderKeyID))
	tsRaw := strings.TrimSpace(r.Header.Get(HeaderTimestamp))
	nonce = strings.TrimSpace(r.Header.Get(HeaderNonce))
	signature = strings.TrimSpace(r.Header.Get(HeaderSignature))
	if keyID == "" || tsRaw == "" || nonce == "" || signature == "" {
		return "", 0, "", "", fmt.Errorf("missing admin signature headers")
	}
	ts, err = strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return "", 0, "", "", fmt.Errorf("invalid admin timestamp header")
	}
	return keyID, ts, nonce, signature, nil
}

func EncodePublicKey(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

func ParsePublicKey(pubB64 string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return nil, fmt.Errorf("invalid public key encoding: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}
	return ed25519.PublicKey(raw), nil
}

func KeyIDFromPublicKey(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
