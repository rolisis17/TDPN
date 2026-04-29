package keeper

import "github.com/tdpn/tdpn-chain/x/vpnrewards/types"

// KeeperStore is the internal persistence seam for vpnrewards keeper state.
// A Cosmos KV-backed implementation can be plugged later without changing keeper callers.
type KeeperStore interface {
	UpsertAccrual(record types.RewardAccrual)
	GetAccrual(accrualID string) (types.RewardAccrual, bool)
	ListAccruals() []types.RewardAccrual
	UpsertDistribution(record types.DistributionRecord)
	GetDistribution(distributionID string) (types.DistributionRecord, bool)
	ListDistributions() []types.DistributionRecord
}

// KeeperStoreWithWriteErrors allows callers to observe persistence failures.
// Implementations should leave in-memory state unchanged when returning an error.
type KeeperStoreWithWriteErrors interface {
	UpsertAccrualWithError(record types.RewardAccrual) error
	UpsertDistributionWithError(record types.DistributionRecord) error
}

// KeeperStoreWithReadErrors allows callers to fail closed when decoding persisted records.
type KeeperStoreWithReadErrors interface {
	ListAccrualsWithError() ([]types.RewardAccrual, error)
	ListDistributionsWithError() ([]types.DistributionRecord, error)
}

// KeeperProofStore is optional storage for explicit reward proof records.
type KeeperProofStore interface {
	UpsertProof(record types.RewardProofRecord)
	GetProof(proofPath string) (types.RewardProofRecord, bool)
	ListProofs() []types.RewardProofRecord
}

// KeeperProofStoreWithWriteErrors allows proof callers to observe persistence failures.
type KeeperProofStoreWithWriteErrors interface {
	UpsertProofWithError(record types.RewardProofRecord) error
}

// KeeperProofStoreWithReadErrors allows proof callers to fail closed on corrupt persisted records.
type KeeperProofStoreWithReadErrors interface {
	ListProofsWithError() ([]types.RewardProofRecord, error)
}

// InMemoryStore is the default keeper store implementation.
type InMemoryStore struct {
	accruals      map[string]types.RewardAccrual
	distributions map[string]types.DistributionRecord
	proofs        map[string]types.RewardProofRecord
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		accruals:      make(map[string]types.RewardAccrual),
		distributions: make(map[string]types.DistributionRecord),
		proofs:        make(map[string]types.RewardProofRecord),
	}
}

func (s *InMemoryStore) UpsertAccrual(record types.RewardAccrual) {
	s.accruals[record.AccrualID] = record
}

func (s *InMemoryStore) UpsertAccrualWithError(record types.RewardAccrual) error {
	s.UpsertAccrual(record)
	return nil
}

func (s *InMemoryStore) GetAccrual(accrualID string) (types.RewardAccrual, bool) {
	record, ok := s.accruals[accrualID]
	return record, ok
}

func (s *InMemoryStore) ListAccruals() []types.RewardAccrual {
	records := make([]types.RewardAccrual, 0, len(s.accruals))
	for _, record := range s.accruals {
		records = append(records, record)
	}
	return records
}

func (s *InMemoryStore) ListAccrualsWithError() ([]types.RewardAccrual, error) {
	return s.ListAccruals(), nil
}

func (s *InMemoryStore) UpsertDistribution(record types.DistributionRecord) {
	s.distributions[record.DistributionID] = record
}

func (s *InMemoryStore) UpsertDistributionWithError(record types.DistributionRecord) error {
	s.UpsertDistribution(record)
	return nil
}

func (s *InMemoryStore) GetDistribution(distributionID string) (types.DistributionRecord, bool) {
	record, ok := s.distributions[distributionID]
	return record, ok
}

func (s *InMemoryStore) ListDistributions() []types.DistributionRecord {
	records := make([]types.DistributionRecord, 0, len(s.distributions))
	for _, record := range s.distributions {
		records = append(records, record)
	}
	return records
}

func (s *InMemoryStore) ListDistributionsWithError() ([]types.DistributionRecord, error) {
	return s.ListDistributions(), nil
}

func (s *InMemoryStore) UpsertProof(record types.RewardProofRecord) {
	_ = s.UpsertProofWithError(record)
}

func (s *InMemoryStore) UpsertProofWithError(record types.RewardProofRecord) error {
	if existing, found := s.proofs[record.ProofPath]; found && !proofRecordsEqual(normalizeProof(existing), normalizeProof(record)) {
		return conflictError("proof", record.ProofPath)
	}
	s.proofs[record.ProofPath] = record
	return nil
}

func (s *InMemoryStore) GetProof(proofPath string) (types.RewardProofRecord, bool) {
	record, ok := s.proofs[proofPath]
	return record, ok
}

func (s *InMemoryStore) ListProofs() []types.RewardProofRecord {
	records := make([]types.RewardProofRecord, 0, len(s.proofs))
	for _, record := range s.proofs {
		records = append(records, record)
	}
	return records
}

func (s *InMemoryStore) ListProofsWithError() ([]types.RewardProofRecord, error) {
	return s.ListProofs(), nil
}
