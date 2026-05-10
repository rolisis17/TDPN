package accesspack

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	TextEnvelopePrefix = "GPMREC1"
	EnvelopeKindPack   = "access-pack"
	EnvelopeKindStore  = "trust-store"
	EnvelopeKindKey    = "trusted-key"
)

type TextEnvelope struct {
	Version int             `json:"v"`
	Kind    string          `json:"k"`
	Payload json.RawMessage `json:"p"`
}

func EncodeTextEnvelope(kind string, payload []byte) (string, error) {
	kind = strings.TrimSpace(kind)
	if err := ValidateEnvelopeKind(kind); err != nil {
		return "", err
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return "", errors.New("envelope payload is required")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, payload); err != nil {
		return "", fmt.Errorf("envelope payload must be json: %w", err)
	}
	envelope := TextEnvelope{
		Version: 1,
		Kind:    kind,
		Payload: append(json.RawMessage(nil), compact.Bytes()...),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return TextEnvelopePrefix + "." + base64.RawURLEncoding.EncodeToString(body), nil
}

func DecodeTextEnvelope(text string) (TextEnvelope, []byte, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return TextEnvelope{}, nil, errors.New("envelope text is required")
	}
	prefix := TextEnvelopePrefix + "."
	if !strings.HasPrefix(text, prefix) {
		return TextEnvelope{}, nil, fmt.Errorf("envelope must start with %s.", TextEnvelopePrefix)
	}
	encoded := strings.TrimSpace(strings.TrimPrefix(text, prefix))
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return TextEnvelope{}, nil, fmt.Errorf("invalid envelope encoding: %w", err)
	}
	var envelope TextEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return TextEnvelope{}, nil, fmt.Errorf("invalid envelope json: %w", err)
	}
	if envelope.Version != 1 {
		return TextEnvelope{}, nil, fmt.Errorf("unsupported envelope version %d", envelope.Version)
	}
	if err := ValidateEnvelopeKind(envelope.Kind); err != nil {
		return TextEnvelope{}, nil, err
	}
	if len(bytes.TrimSpace(envelope.Payload)) == 0 {
		return TextEnvelope{}, nil, errors.New("envelope payload is empty")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, envelope.Payload); err != nil {
		return TextEnvelope{}, nil, fmt.Errorf("envelope payload must be json: %w", err)
	}
	return envelope, compact.Bytes(), nil
}

func ValidateEnvelopeKind(kind string) error {
	switch strings.TrimSpace(kind) {
	case EnvelopeKindPack, EnvelopeKindStore, EnvelopeKindKey:
		return nil
	default:
		return fmt.Errorf("unsupported envelope kind %q", kind)
	}
}
