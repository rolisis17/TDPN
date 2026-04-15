package keeper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

// KeeperStore is the persistence seam for vpngovernance keeper state.
type KeeperStore interface {
	UpsertPolicy(record types.GovernancePolicy)
	GetPolicy(policyID string) (types.GovernancePolicy, bool)
	ListPolicies() []types.GovernancePolicy
	UpsertDecision(record types.GovernanceDecision)
	GetDecision(decisionID string) (types.GovernanceDecision, bool)
	ListDecisions() []types.GovernanceDecision
}

// InMemoryStore is the default keeper store implementation.
type InMemoryStore struct {
	policies  map[string]types.GovernancePolicy
	decisions map[string]types.GovernanceDecision
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		policies:  make(map[string]types.GovernancePolicy),
		decisions: make(map[string]types.GovernanceDecision),
	}
}

func (s *InMemoryStore) UpsertPolicy(record types.GovernancePolicy) {
	s.policies[record.PolicyID] = record
}

func (s *InMemoryStore) GetPolicy(policyID string) (types.GovernancePolicy, bool) {
	record, ok := s.policies[policyID]
	return record, ok
}

func (s *InMemoryStore) ListPolicies() []types.GovernancePolicy {
	ids := make([]string, 0, len(s.policies))
	for id := range s.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernancePolicy, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.policies[id])
	}
	return records
}

func (s *InMemoryStore) UpsertDecision(record types.GovernanceDecision) {
	s.decisions[record.DecisionID] = record
}

func (s *InMemoryStore) GetDecision(decisionID string) (types.GovernanceDecision, bool) {
	record, ok := s.decisions[decisionID]
	return record, ok
}

func (s *InMemoryStore) ListDecisions() []types.GovernanceDecision {
	ids := make([]string, 0, len(s.decisions))
	for id := range s.decisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernanceDecision, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.decisions[id])
	}
	return records
}

type fileStoreSnapshot struct {
	Policies  map[string]types.GovernancePolicy   `json:"policies"`
	Decisions map[string]types.GovernanceDecision `json:"decisions"`
}

// FileStore persists governance policies and decisions in a JSON file.
type FileStore struct {
	mu        sync.RWMutex
	path      string
	policies  map[string]types.GovernancePolicy
	decisions map[string]types.GovernanceDecision
}

// NewFileStore constructs a file-backed keeper store and loads existing state when present.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("file store path cannot be empty")
	}

	store := &FileStore{
		path:      path,
		policies:  make(map[string]types.GovernancePolicy),
		decisions: make(map[string]types.GovernanceDecision),
	}

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("load vpngovernance file store: %w", err)
	}

	return store, nil
}

func (s *FileStore) load() error {
	payload, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	if len(bytes.TrimSpace(payload)) == 0 {
		return nil
	}

	var snapshot fileStoreSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return err
	}

	if snapshot.Policies != nil {
		s.policies = snapshot.Policies
	}
	if snapshot.Decisions != nil {
		s.decisions = snapshot.Decisions
	}

	return nil
}

func (s *FileStore) UpsertPolicy(record types.GovernancePolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.policies[record.PolicyID] = record
	_ = s.persistLocked()
}

func (s *FileStore) GetPolicy(policyID string) (types.GovernancePolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.policies[policyID]
	return record, ok
}

func (s *FileStore) ListPolicies() []types.GovernancePolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.policies))
	for id := range s.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernancePolicy, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.policies[id])
	}
	return records
}

func (s *FileStore) UpsertDecision(record types.GovernanceDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.decisions[record.DecisionID] = record
	_ = s.persistLocked()
}

func (s *FileStore) GetDecision(decisionID string) (types.GovernanceDecision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.decisions[decisionID]
	return record, ok
}

func (s *FileStore) ListDecisions() []types.GovernanceDecision {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.decisions))
	for id := range s.decisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernanceDecision, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.decisions[id])
	}
	return records
}

func (s *FileStore) persistLocked() error {
	snapshot := fileStoreSnapshot{
		Policies:  s.policies,
		Decisions: s.decisions,
	}

	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	return writeFileAtomic(s.path, payload)
}

func writeFileAtomic(path string, payload []byte) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, ".vpngovernance-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	keepTmp := true
	defer func() {
		if keepTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(payload); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	keepTmp = false
	return nil
}
