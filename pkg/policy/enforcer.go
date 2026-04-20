package policy

import (
	"errors"
	"time"

	"privacynode/pkg/crypto"
)

var ErrDenied = errors.New("policy denied")

type FlowContext struct {
	DestinationPort int
	Now             time.Time
}

type Enforcer struct{}

func NewEnforcer() *Enforcer {
	return &Enforcer{}
}

func (e *Enforcer) Allow(claims crypto.CapabilityClaims, flow FlowContext) error {
	if !isValidPort(flow.DestinationPort) {
		return ErrDenied
	}
	if flow.Now.Unix() >= claims.ExpiryUnix {
		return ErrDenied
	}
	for _, p := range claims.DenyPorts {
		if !isValidPort(p) {
			return ErrDenied
		}
		if flow.DestinationPort == p {
			return ErrDenied
		}
	}

	if claims.Tier == 1 && flow.DestinationPort == 25 {
		return ErrDenied
	}

	if len(claims.AllowPorts) > 0 {
		allowed := false
		for _, p := range claims.AllowPorts {
			if !isValidPort(p) {
				return ErrDenied
			}
			if flow.DestinationPort == p {
				allowed = true
			}
		}
		if !allowed {
			return ErrDenied
		}
	}
	return nil
}

func isValidPort(port int) bool {
	return port >= 1 && port <= 65535
}
