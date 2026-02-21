package relay

import "net/netip"

type Packet struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Payload     []byte
}

type ForwardTarget struct {
	ExitID   string
	Endpoint string
}
