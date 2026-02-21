package wg

import "context"

type NoopClientManager struct{}

func NewNoopClientManager() *NoopClientManager {
	return &NoopClientManager{}
}

func (m *NoopClientManager) ConfigureClientSession(_ context.Context, _ ClientSessionConfig) error {
	return nil
}

func (m *NoopClientManager) RemoveClientSession(_ context.Context, _ ClientSessionConfig) error {
	return nil
}
