package relay

const (
	wgTypeHandshakeInitiation = byte(1)
	wgTypeHandshakeResponse   = byte(2)
	wgTypeCookieReply         = byte(3)
	wgTypeTransportData       = byte(4)
)

// Minimum plausible message lengths from WireGuard message framing.
const (
	wgMinHandshakeInitiation = 148
	wgMinHandshakeResponse   = 92
	wgMinCookieReply         = 64
	wgMinTransportData       = 32
)

// LooksLikeWireGuardMessage checks for WG message type framing:
// byte[0] in {1,2,3,4} and bytes[1..3] are zero.
func LooksLikeWireGuardMessage(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	if packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
		return false
	}
	switch packet[0] {
	case wgTypeHandshakeInitiation, wgTypeHandshakeResponse, wgTypeCookieReply, wgTypeTransportData:
		return true
	default:
		return false
	}
}

// LooksLikePlausibleWireGuardMessage checks framing and type-specific minimum
// packet lengths for live-mode packet acceptance.
func LooksLikePlausibleWireGuardMessage(packet []byte) bool {
	if !LooksLikeWireGuardMessage(packet) {
		return false
	}
	switch packet[0] {
	case wgTypeHandshakeInitiation:
		return len(packet) >= wgMinHandshakeInitiation
	case wgTypeHandshakeResponse:
		return len(packet) >= wgMinHandshakeResponse
	case wgTypeCookieReply:
		return len(packet) >= wgMinCookieReply
	case wgTypeTransportData:
		return len(packet) >= wgMinTransportData
	default:
		return false
	}
}
