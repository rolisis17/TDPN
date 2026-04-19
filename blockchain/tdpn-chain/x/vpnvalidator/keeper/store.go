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

	"github.com/tdpn/tdpn-chain/internal/fsguard"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

const fileStoreMaxSnapshotBytes int64 = 16 << 20

// KeeperStore is the internal persistence seam for vpnvalidator state.
type KeeperStore interface {
	UpsertEligibility(record types.ValidatorEligibility)
	GetEligibility(validatorID string) (types.ValidatorEligibility, bool)
	ListEligibilities() []types.ValidatorEligibility
	UpsertStatusRecord(record types.ValidatorStatusRecord)
	GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool)
	ListStatusRecords() []types.ValidatorStatusRecord
}

// KeeperStoreWithWriteErrors allows callers to observe persistence failures.
// Implementations should leave in-memory state unchanged when returning an error.
type KeeperStoreWithWriteErrors interface {
	UpsertEligibilityWithError(record types.ValidatorEligibility) error
	UpsertStatusRecordWithError(record types.ValidatorStatusRecord) error
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

func (s *InMemoryStore) UpsertEligibilityWithError(record types.ValidatorEligibility) error {
	s.UpsertEligibility(record)
	return nil
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

func (s *InMemoryStore) UpsertStatusRecordWithError(record types.ValidatorStatusRecord) error {
	s.UpsertStatusRecord(record)
	return nil
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

	if snapshot.Eligibilities != nil {
		eligibilities, err := buildEligibilitySnapshotMap(snapshot.Eligibilities)
		if err != nil {
			return fmt.Errorf("validate eligibilities snapshot: %w", err)
		}
		s.eligibilities = eligibilities
	}
	if snapshot.StatusRecords != nil {
		statusRecords, err := buildStatusSnapshotMap(snapshot.StatusRecords)
		if err != nil {
			return fmt.Errorf("validate status records snapshot: %w", err)
		}
		s.statusRecords = statusRecords
	}

	return nil
}

func (s *FileStore) UpsertEligibility(record types.ValidatorEligibility) {
	_ = s.UpsertEligibilityWithError(record)
}

func (s *FileStore) UpsertEligibilityWithError(record types.ValidatorEligibility) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.eligibilities[record.ValidatorID]
	s.eligibilities[record.ValidatorID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.eligibilities[record.ValidatorID] = previous
		} else {
			delete(s.eligibilities, record.ValidatorID)
		}
		return err
	}
	return nil
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
	_ = s.UpsertStatusRecordWithError(record)
}

func (s *FileStore) UpsertStatusRecordWithError(record types.ValidatorStatusRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.statusRecords[record.StatusID]
	s.statusRecords[record.StatusID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.statusRecords[record.StatusID] = previous
		} else {
			delete(s.statusRecords, record.StatusID)
		}
		return err
	}
	return nil
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
	return dir.Sync()
}

func buildEligibilitySnapshotMap(input map[string]types.ValidatorEligibility) (map[string]types.ValidatorEligibility, error) {
	loaded := make(map[string]types.ValidatorEligibility, len(input))
	for key, record := range input {
		normalized := normalizeEligibility(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid eligibility %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.ValidatorID]; ok && !eligibilityRecordsEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting eligibility entries for id %q", normalized.ValidatorID)
		}
		loaded[normalized.ValidatorID] = normalized
	}
	return loaded, nil
}

func buildStatusSnapshotMap(input map[string]types.ValidatorStatusRecord) (map[string]types.ValidatorStatusRecord, error) {
	loaded := make(map[string]types.ValidatorStatusRecord, len(input))
	for key, record := range input {
		normalized := normalizeStatusRecord(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid status record %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.StatusID]; ok && !statusRecordEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting status record entries for id %q", normalized.StatusID)
		}
		loaded[normalized.StatusID] = normalized
	}
	return loaded, nil
}
