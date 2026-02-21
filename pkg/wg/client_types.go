package wg

import "context"

type ClientSessionConfig struct {
	SessionID        string
	SessionKeyID     string
	Interface        string
	ClientPrivateKey string
	ExitPublicKey    string
	ClientInnerIP    string
	Endpoint         string
	AllowedIPs       string
	MTU              int
	KeepaliveSec     int
}

type ClientManager interface {
	ConfigureClientSession(ctx context.Context, cfg ClientSessionConfig) error
	RemoveClientSession(ctx context.Context, cfg ClientSessionConfig) error
}
