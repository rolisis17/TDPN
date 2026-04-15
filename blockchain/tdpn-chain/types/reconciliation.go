package types

// ReconciliationStatus tracks an operation across async chain submission flow.
type ReconciliationStatus string

const (
	ReconciliationPending   ReconciliationStatus = "pending"
	ReconciliationSubmitted ReconciliationStatus = "submitted"
	ReconciliationConfirmed ReconciliationStatus = "confirmed"
	ReconciliationFailed    ReconciliationStatus = "failed"
)

// OperationRef identifies app-initiated operations mirrored to chain records.
type OperationRef struct {
	ID     string
	Status ReconciliationStatus
}
