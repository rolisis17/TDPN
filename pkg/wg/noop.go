package wg

import "context"

type NoopManager struct{}

func NewNoopManager() *NoopManager {
	return &NoopManager{}
}

func (m *NoopManager) ConfigureSession(_ context.Context, _ SessionConfig) error {
	return nil
}

func (m *NoopManager) RemoveSession(_ context.Context, _ SessionConfig) error {
	return nil
}
