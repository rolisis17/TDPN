package policy

import (
	"testing"
	"time"

	"privacynode/pkg/crypto"
)

func TestTier1BlocksSMTP(t *testing.T) {
	e := NewEnforcer()
	claims := crypto.CapabilityClaims{Tier: 1, ExpiryUnix: time.Now().Add(5 * time.Minute).Unix()}
	flow := FlowContext{DestinationPort: 25, Now: time.Now()}

	if err := e.Allow(claims, flow); err == nil {
		t.Fatalf("expected smtp to be blocked for tier 1")
	}
}

func TestAllowHTTPS(t *testing.T) {
	e := NewEnforcer()
	claims := crypto.CapabilityClaims{Tier: 1, ExpiryUnix: time.Now().Add(5 * time.Minute).Unix()}
	flow := FlowContext{DestinationPort: 443, Now: time.Now()}

	if err := e.Allow(claims, flow); err != nil {
		t.Fatalf("expected https to be allowed, got error: %v", err)
	}
}

func TestAllowRejectsInvalidDestinationPort(t *testing.T) {
	e := NewEnforcer()
	claims := crypto.CapabilityClaims{Tier: 2, ExpiryUnix: time.Now().Add(5 * time.Minute).Unix()}
	flow := FlowContext{DestinationPort: 0, Now: time.Now()}
	if err := e.Allow(claims, flow); err == nil {
		t.Fatalf("expected invalid destination port to be denied")
	}
}

func TestAllowRejectsInvalidAllowPortsClaim(t *testing.T) {
	e := NewEnforcer()
	claims := crypto.CapabilityClaims{
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		AllowPorts: []int{443, 70000},
	}
	flow := FlowContext{DestinationPort: 443, Now: time.Now()}
	if err := e.Allow(claims, flow); err == nil {
		t.Fatalf("expected invalid allow_ports claim to be denied")
	}
}

func TestAllowRejectsInvalidDenyPortsClaim(t *testing.T) {
	e := NewEnforcer()
	claims := crypto.CapabilityClaims{
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		DenyPorts:  []int{-1},
	}
	flow := FlowContext{DestinationPort: 443, Now: time.Now()}
	if err := e.Allow(claims, flow); err == nil {
		t.Fatalf("expected invalid deny_ports claim to be denied")
	}
}
