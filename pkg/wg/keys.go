package wg

import (
	"encoding/base64"
	"errors"
)

var ErrInvalidKey = errors.New("invalid wireguard key")

func DecodeKeyBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrInvalidKey
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, ErrInvalidKey
}

func IsValidPublicKey(s string) bool {
	_, err := DecodeKeyBase64(s)
	return err == nil
}

func EncodeKeyBase64(b []byte) (string, error) {
	if len(b) != 32 {
		return "", ErrInvalidKey
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
