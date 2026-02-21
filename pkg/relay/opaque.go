package relay

import (
	"encoding/binary"
	"errors"
)

var ErrOpaquePayload = errors.New("invalid opaque payload")

func BuildOpaquePayload(nonce uint64, payload []byte) []byte {
	buf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint64(buf[:8], nonce)
	copy(buf[8:], payload)
	return buf
}

func ParseOpaquePayload(payload []byte) (uint64, []byte, error) {
	if len(payload) < 9 {
		return 0, nil, ErrOpaquePayload
	}
	return binary.BigEndian.Uint64(payload[:8]), payload[8:], nil
}
