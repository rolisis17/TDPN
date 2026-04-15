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

// InMemoryStore is the default keeper store implementation.
type InMemoryStore struct {
	accruals      map[string]types.RewardAccrual
	distributions map[string]types.DistributionRecord
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		accruals:      make(map[string]types.RewardAccrual),
		distributions: make(map[string]types.DistributionRecord),
	}
}

func (s *InMemoryStore) UpsertAccrual(record types.RewardAccrual) {
	s.accruals[record.AccrualID] = record
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

func (s *InMemoryStore) UpsertDistribution(record types.DistributionRecord) {
	s.distributions[record.DistributionID] = record
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
