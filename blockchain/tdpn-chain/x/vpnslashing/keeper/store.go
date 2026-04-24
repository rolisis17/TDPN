package keeper

import "github.com/tdpn/tdpn-chain/x/vpnslashing/types"

// KeeperStore is the internal persistence seam for vpnslashing keeper state.
// A Cosmos KV-backed implementation can be plugged later without changing keeper callers.
type KeeperStore interface {
	UpsertEvidence(record types.SlashEvidence)
	GetEvidence(evidenceID string) (types.SlashEvidence, bool)
	ListEvidence() []types.SlashEvidence
	UpsertPenalty(record types.PenaltyDecision)
	GetPenalty(penaltyID string) (types.PenaltyDecision, bool)
	ListPenalties() []types.PenaltyDecision
}

// KeeperStoreWithWriteErrors allows callers to observe persistence failures.
// Implementations should leave in-memory state unchanged when returning an error.
type KeeperStoreWithWriteErrors interface {
	UpsertEvidenceWithError(record types.SlashEvidence) error
	UpsertPenaltyWithError(record types.PenaltyDecision) error
}

// KeeperStoreWithReadErrors allows callers to fail closed when decoding persisted records.
type KeeperStoreWithReadErrors interface {
	ListEvidenceWithError() ([]types.SlashEvidence, error)
	ListPenaltiesWithError() ([]types.PenaltyDecision, error)
}

// InMemoryStore is the default keeper store implementation.
type InMemoryStore struct {
	evidence  map[string]types.SlashEvidence
	penalties map[string]types.PenaltyDecision
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		evidence:  make(map[string]types.SlashEvidence),
		penalties: make(map[string]types.PenaltyDecision),
	}
}

func (s *InMemoryStore) UpsertEvidence(record types.SlashEvidence) {
	s.evidence[record.EvidenceID] = record
}

func (s *InMemoryStore) UpsertEvidenceWithError(record types.SlashEvidence) error {
	s.UpsertEvidence(record)
	return nil
}

func (s *InMemoryStore) GetEvidence(evidenceID string) (types.SlashEvidence, bool) {
	record, ok := s.evidence[evidenceID]
	return record, ok
}

func (s *InMemoryStore) ListEvidence() []types.SlashEvidence {
	out := make([]types.SlashEvidence, 0, len(s.evidence))
	for _, record := range s.evidence {
		out = append(out, record)
	}
	return out
}

func (s *InMemoryStore) ListEvidenceWithError() ([]types.SlashEvidence, error) {
	return s.ListEvidence(), nil
}

func (s *InMemoryStore) UpsertPenalty(record types.PenaltyDecision) {
	s.penalties[record.PenaltyID] = record
}

func (s *InMemoryStore) UpsertPenaltyWithError(record types.PenaltyDecision) error {
	s.UpsertPenalty(record)
	return nil
}

func (s *InMemoryStore) GetPenalty(penaltyID string) (types.PenaltyDecision, bool) {
	record, ok := s.penalties[penaltyID]
	return record, ok
}

func (s *InMemoryStore) ListPenalties() []types.PenaltyDecision {
	out := make([]types.PenaltyDecision, 0, len(s.penalties))
	for _, record := range s.penalties {
		out = append(out, record)
	}
	return out
}

func (s *InMemoryStore) ListPenaltiesWithError() ([]types.PenaltyDecision, error) {
	return s.ListPenalties(), nil
}
