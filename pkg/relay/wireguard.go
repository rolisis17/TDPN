package relay

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
	case 1, 2, 3, 4:
		return true
	default:
		return false
	}
}
