package relay

import (
	"bytes"
	"errors"
)

var ErrInvalidFrame = errors.New("invalid frame")

func BuildDatagram(sessionID string, payload []byte) []byte {
	frame := make([]byte, 0, len(sessionID)+1+len(payload))
	frame = append(frame, []byte(sessionID)...)
	frame = append(frame, '\n')
	frame = append(frame, payload...)
	return frame
}

func ParseDatagram(frame []byte) (string, []byte, error) {
	idx := bytes.IndexByte(frame, '\n')
	if idx <= 0 || idx == len(frame)-1 {
		return "", nil, ErrInvalidFrame
	}
	return string(frame[:idx]), frame[idx+1:], nil
}
