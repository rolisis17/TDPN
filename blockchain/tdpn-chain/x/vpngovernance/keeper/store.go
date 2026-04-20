package keeper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"sync"

	"github.com/tdpn/tdpn-chain/internal/fsguard"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

const fileStoreMaxSnapshotBytes int64 = 16 << 20

// KeeperStore is the persistence seam for vpngovernance keeper state.
type KeeperStore interface {
	UpsertPolicy(record types.GovernancePolicy)
	GetPolicy(policyID string) (types.GovernancePolicy, bool)
	ListPolicies() []types.GovernancePolicy
	UpsertDecision(record types.GovernanceDecision)
	GetDecision(decisionID string) (types.GovernanceDecision, bool)
	ListDecisions() []types.GovernanceDecision
	PutAuditAction(record types.GovernanceAuditAction)
	GetAuditAction(actionID string) (types.GovernanceAuditAction, bool)
	ListAuditActions() []types.GovernanceAuditAction
}

// KeeperStoreWithWriteErrors allows callers to observe persistence failures.
// Implementations should leave in-memory state unchanged when returning an error.
type KeeperStoreWithWriteErrors interface {
	UpsertPolicyWithError(record types.GovernancePolicy) error
	UpsertDecisionWithError(record types.GovernanceDecision) error
	PutAuditActionWithError(record types.GovernanceAuditAction) error
}

// KeeperStoreWithReadErrors allows callers to fail closed when decoding persisted records.
type KeeperStoreWithReadErrors interface {
	ListPoliciesWithError() ([]types.GovernancePolicy, error)
	ListDecisionsWithError() ([]types.GovernanceDecision, error)
	ListAuditActionsWithError() ([]types.GovernanceAuditAction, error)
}

// InMemoryStore is the default keeper store implementation.
type InMemoryStore struct {
	policies     map[string]types.GovernancePolicy
	decisions    map[string]types.GovernanceDecision
	auditActions map[string]types.GovernanceAuditAction
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		policies:     make(map[string]types.GovernancePolicy),
		decisions:    make(map[string]types.GovernanceDecision),
		auditActions: make(map[string]types.GovernanceAuditAction),
	}
}

func (s *InMemoryStore) UpsertPolicy(record types.GovernancePolicy) {
	s.policies[record.PolicyID] = record
}

func (s *InMemoryStore) UpsertPolicyWithError(record types.GovernancePolicy) error {
	s.UpsertPolicy(record)
	return nil
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

func (s *InMemoryStore) ListPoliciesWithError() ([]types.GovernancePolicy, error) {
	return s.ListPolicies(), nil
}

func (s *InMemoryStore) UpsertDecision(record types.GovernanceDecision) {
	s.decisions[record.DecisionID] = record
}

func (s *InMemoryStore) UpsertDecisionWithError(record types.GovernanceDecision) error {
	s.UpsertDecision(record)
	return nil
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

func (s *InMemoryStore) ListDecisionsWithError() ([]types.GovernanceDecision, error) {
	return s.ListDecisions(), nil
}

func (s *InMemoryStore) PutAuditAction(record types.GovernanceAuditAction) {
	s.auditActions[record.ActionID] = record
}

func (s *InMemoryStore) PutAuditActionWithError(record types.GovernanceAuditAction) error {
	s.PutAuditAction(record)
	return nil
}

func (s *InMemoryStore) GetAuditAction(actionID string) (types.GovernanceAuditAction, bool) {
	record, ok := s.auditActions[actionID]
	return record, ok
}

func (s *InMemoryStore) ListAuditActions() []types.GovernanceAuditAction {
	ids := make([]string, 0, len(s.auditActions))
	for id := range s.auditActions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernanceAuditAction, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.auditActions[id])
	}
	return records
}

func (s *InMemoryStore) ListAuditActionsWithError() ([]types.GovernanceAuditAction, error) {
	return s.ListAuditActions(), nil
}

type fileStoreSnapshot struct {
	Policies     map[string]types.GovernancePolicy      `json:"policies"`
	Decisions    map[string]types.GovernanceDecision    `json:"decisions"`
	AuditActions map[string]types.GovernanceAuditAction `json:"audit_actions"`
}

// FileStore persists governance policies and decisions in a JSON file.
type FileStore struct {
	mu        sync.RWMutex
	path      string
	policies  map[string]types.GovernancePolicy
	decisions map[string]types.GovernanceDecision
	audit     map[string]types.GovernanceAuditAction
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
		audit:     make(map[string]types.GovernanceAuditAction),
	}

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("load vpngovernance file store: %w", err)
	}

	return store, nil
}

func (s *FileStore) load() error {
	payload, err := fsguard.ReadRegularFileBounded(s.path, fileStoreMaxSnapshotBytes)
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
		policies, err := buildPolicySnapshotMap(snapshot.Policies)
		if err != nil {
			return fmt.Errorf("validate policy snapshot: %w", err)
		}
		s.policies = policies
	}
	if snapshot.Decisions != nil {
		decisions, err := buildDecisionSnapshotMap(snapshot.Decisions)
		if err != nil {
			return fmt.Errorf("validate decision snapshot: %w", err)
		}
		s.decisions = decisions
	}
	if snapshot.AuditActions != nil {
		auditActions, err := buildAuditActionSnapshotMap(snapshot.AuditActions)
		if err != nil {
			return fmt.Errorf("validate audit action snapshot: %w", err)
		}
		s.audit = auditActions
	}

	return nil
}

func (s *FileStore) UpsertPolicy(record types.GovernancePolicy) {
	_ = s.UpsertPolicyWithError(record)
}

func (s *FileStore) UpsertPolicyWithError(record types.GovernancePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.policies[record.PolicyID]
	s.policies[record.PolicyID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.policies[record.PolicyID] = previous
		} else {
			delete(s.policies, record.PolicyID)
		}
		return err
	}
	return nil
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

func (s *FileStore) ListPoliciesWithError() ([]types.GovernancePolicy, error) {
	return s.ListPolicies(), nil
}

func (s *FileStore) UpsertDecision(record types.GovernanceDecision) {
	_ = s.UpsertDecisionWithError(record)
}

func (s *FileStore) UpsertDecisionWithError(record types.GovernanceDecision) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.decisions[record.DecisionID]
	s.decisions[record.DecisionID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.decisions[record.DecisionID] = previous
		} else {
			delete(s.decisions, record.DecisionID)
		}
		return err
	}
	return nil
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

func (s *FileStore) ListDecisionsWithError() ([]types.GovernanceDecision, error) {
	return s.ListDecisions(), nil
}

func (s *FileStore) PutAuditAction(record types.GovernanceAuditAction) {
	_ = s.PutAuditActionWithError(record)
}

func (s *FileStore) PutAuditActionWithError(record types.GovernanceAuditAction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.audit[record.ActionID]
	s.audit[record.ActionID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.audit[record.ActionID] = previous
		} else {
			delete(s.audit, record.ActionID)
		}
		return err
	}
	return nil
}

func (s *FileStore) GetAuditAction(actionID string) (types.GovernanceAuditAction, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.audit[actionID]
	return record, ok
}

func (s *FileStore) ListAuditActions() []types.GovernanceAuditAction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.audit))
	for id := range s.audit {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernanceAuditAction, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.audit[id])
	}
	return records
}

func (s *FileStore) ListAuditActionsWithError() ([]types.GovernanceAuditAction, error) {
	return s.ListAuditActions(), nil
}

func (s *FileStore) persistLocked() error {
	snapshot := fileStoreSnapshot{
		Policies:     s.policies,
		Decisions:    s.decisions,
		AuditActions: s.audit,
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
	if err := syncDirectory(dir); err != nil {
		return err
	}

	keepTmp = false
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		if runtime.GOOS == "windows" && (os.IsPermission(err) || errors.Is(err, syscall.EINVAL)) {
			// Windows commonly rejects syncing directory handles even though rename succeeded.
			return nil
		}
		return err
	}
	return nil
}

func buildPolicySnapshotMap(input map[string]types.GovernancePolicy) (map[string]types.GovernancePolicy, error) {
	loaded := make(map[string]types.GovernancePolicy, len(input))
	for key, record := range input {
		normalized := normalizePolicy(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid policy %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.PolicyID]; ok && !policyRecordsEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting policy entries for id %q", normalized.PolicyID)
		}
		loaded[normalized.PolicyID] = normalized
	}
	return loaded, nil
}

func buildDecisionSnapshotMap(input map[string]types.GovernanceDecision) (map[string]types.GovernanceDecision, error) {
	loaded := make(map[string]types.GovernanceDecision, len(input))
	for key, record := range input {
		normalized := normalizeDecision(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid decision %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.DecisionID]; ok && !decisionRecordsEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting decision entries for id %q", normalized.DecisionID)
		}
		loaded[normalized.DecisionID] = normalized
	}
	return loaded, nil
}

func buildAuditActionSnapshotMap(input map[string]types.GovernanceAuditAction) (map[string]types.GovernanceAuditAction, error) {
	loaded := make(map[string]types.GovernanceAuditAction, len(input))
	for key, record := range input {
		normalized := normalizeAuditAction(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid audit action %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.ActionID]; ok && !auditActionRecordsEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting audit action entries for id %q", normalized.ActionID)
		}
		loaded[normalized.ActionID] = normalized
	}
	return loaded, nil
}
