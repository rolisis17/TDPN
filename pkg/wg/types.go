package wg

import "context"

type SessionConfig struct {
	SessionID      string
	SessionKeyID   string
	Interface      string
	ExitPrivateKey string
	ClientPubKey   string
	ClientInnerIP  string
	ExitInnerIP    string
	ListenPort     int
	MTU            int
	KeepaliveSec   int
}

type Manager interface {
	ConfigureSession(ctx context.Context, cfg SessionConfig) error
	RemoveSession(ctx context.Context, cfg SessionConfig) error
}
