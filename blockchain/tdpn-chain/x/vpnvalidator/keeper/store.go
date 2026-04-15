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

	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

// KeeperStore is the internal persistence seam for vpnvalidator state.
type KeeperStore interface {
	UpsertEligibility(record types.ValidatorEligibility)
	GetEligibility(validatorID string) (types.ValidatorEligibility, bool)
	ListEligibilities() []types.ValidatorEligibility
	UpsertStatusRecord(record types.ValidatorStatusRecord)
	GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool)
	ListStatusRecords() []types.ValidatorStatusRecord
}

// InMemoryStore is the default keeper store implementation.
type InMemoryStore struct {
	eligibilities map[string]types.ValidatorEligibility
	statusRecords map[string]types.ValidatorStatusRecord
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		eligibilities: make(map[string]types.ValidatorEligibility),
		statusRecords: make(map[string]types.ValidatorStatusRecord),
	}
}

func (s *InMemoryStore) UpsertEligibility(record types.ValidatorEligibility) {
	s.eligibilities[record.ValidatorID] = record
}

func (s *InMemoryStore) GetEligibility(validatorID string) (types.ValidatorEligibility, bool) {
	record, ok := s.eligibilities[validatorID]
	return record, ok
}

func (s *InMemoryStore) ListEligibilities() []types.ValidatorEligibility {
	ids := make([]string, 0, len(s.eligibilities))
	for id := range s.eligibilities {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.ValidatorEligibility, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.eligibilities[id])
	}
	return records
}

func (s *InMemoryStore) UpsertStatusRecord(record types.ValidatorStatusRecord) {
	s.statusRecords[record.StatusID] = record
}

func (s *InMemoryStore) GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool) {
	record, ok := s.statusRecords[statusID]
	return record, ok
}

func (s *InMemoryStore) ListStatusRecords() []types.ValidatorStatusRecord {
	ids := make([]string, 0, len(s.statusRecords))
	for id := range s.statusRecords {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.ValidatorStatusRecord, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.statusRecords[id])
	}
	return records
}

type fileStoreSnapshot struct {
	Eligibilities map[string]types.ValidatorEligibility  `json:"eligibilities"`
	StatusRecords map[string]types.ValidatorStatusRecord `json:"status_records"`
}

// FileStore persists validator state in a JSON file.
type FileStore struct {
	mu            sync.RWMutex
	path          string
	eligibilities map[string]types.ValidatorEligibility
	statusRecords map[string]types.ValidatorStatusRecord
}

// NewFileStore builds a file-backed store and loads existing state when present.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("file store path cannot be empty")
	}

	store := &FileStore{
		path:          path,
		eligibilities: make(map[string]types.ValidatorEligibility),
		statusRecords: make(map[string]types.ValidatorStatusRecord),
	}

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("load vpnvalidator file store: %w", err)
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

	if snapshot.Eligibilities != nil {
		s.eligibilities = snapshot.Eligibilities
	}
	if snapshot.StatusRecords != nil {
		s.statusRecords = snapshot.StatusRecords
	}

	return nil
}

func (s *FileStore) UpsertEligibility(record types.ValidatorEligibility) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.eligibilities[record.ValidatorID] = record
	_ = s.persistLocked()
}

func (s *FileStore) GetEligibility(validatorID string) (types.ValidatorEligibility, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.eligibilities[validatorID]
	return record, ok
}

func (s *FileStore) ListEligibilities() []types.ValidatorEligibility {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.eligibilities))
	for id := range s.eligibilities {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.ValidatorEligibility, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.eligibilities[id])
	}
	return records
}

func (s *FileStore) UpsertStatusRecord(record types.ValidatorStatusRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.statusRecords[record.StatusID] = record
	_ = s.persistLocked()
}

func (s *FileStore) GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.statusRecords[statusID]
	return record, ok
}

func (s *FileStore) ListStatusRecords() []types.ValidatorStatusRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.statusRecords))
	for id := range s.statusRecords {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.ValidatorStatusRecord, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.statusRecords[id])
	}
	return records
}

func (s *FileStore) persistLocked() error {
	snapshot := fileStoreSnapshot{
		Eligibilities: s.eligibilities,
		StatusRecords: s.statusRecords,
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

	tmpFile, err := os.CreateTemp(dir, ".vpnvalidator-*.tmp")
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
