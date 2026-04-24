package keeper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/tdpn/tdpn-chain/internal/fsguard"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

const fileStoreMaxSnapshotBytes int64 = 16 << 20

type fileStoreState struct {
	Accruals      map[string]types.RewardAccrual      `json:"accruals"`
	Distributions map[string]types.DistributionRecord `json:"distributions"`
}

// FileStore persists vpnrewards keeper state to a JSON file.
type FileStore struct {
	mu            sync.RWMutex
	path          string
	accruals      map[string]types.RewardAccrual
	distributions map[string]types.DistributionRecord
	persistHook   func() error
}

func NewFileStore(path string) (*FileStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("file store path is required")
	}

	store := &FileStore{
		path:          path,
		accruals:      make(map[string]types.RewardAccrual),
		distributions: make(map[string]types.DistributionRecord),
	}

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("load file store: %w", err)
	}
	if err := store.persist(); err != nil {
		return nil, fmt.Errorf("initialize file store: %w", err)
	}

	return store, nil
}

func (s *FileStore) UpsertAccrual(record types.RewardAccrual) {
	_ = s.UpsertAccrualWithError(record)
}

func (s *FileStore) UpsertAccrualWithError(record types.RewardAccrual) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.accruals[record.AccrualID]
	s.accruals[record.AccrualID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.accruals[record.AccrualID] = previous
		} else {
			delete(s.accruals, record.AccrualID)
		}
		return err
	}
	return nil
}

func (s *FileStore) GetAccrual(accrualID string) (types.RewardAccrual, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.accruals[accrualID]
	return record, ok
}

func (s *FileStore) ListAccruals() []types.RewardAccrual {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]types.RewardAccrual, 0, len(s.accruals))
	for _, record := range s.accruals {
		records = append(records, record)
	}
	return records
}

func (s *FileStore) UpsertDistribution(record types.DistributionRecord) {
	_ = s.UpsertDistributionWithError(record)
}

func (s *FileStore) UpsertDistributionWithError(record types.DistributionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.distributions[record.DistributionID]
	s.distributions[record.DistributionID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.distributions[record.DistributionID] = previous
		} else {
			delete(s.distributions, record.DistributionID)
		}
		return err
	}
	return nil
}

// UpsertDistributionWithAccrualWithError atomically persists a distribution record
// together with the associated accrual state advance in one durable snapshot write.
func (s *FileStore) UpsertDistributionWithAccrualWithError(
	distribution types.DistributionRecord,
	accrual types.RewardAccrual,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previousDistribution, hadDistribution := s.distributions[distribution.DistributionID]
	previousAccrual, hadAccrual := s.accruals[accrual.AccrualID]

	s.distributions[distribution.DistributionID] = distribution
	s.accruals[accrual.AccrualID] = accrual

	if err := s.persistLocked(); err != nil {
		if hadDistribution {
			s.distributions[distribution.DistributionID] = previousDistribution
		} else {
			delete(s.distributions, distribution.DistributionID)
		}

		if hadAccrual {
			s.accruals[accrual.AccrualID] = previousAccrual
		} else {
			delete(s.accruals, accrual.AccrualID)
		}
		return err
	}
	return nil
}

func (s *FileStore) GetDistribution(distributionID string) (types.DistributionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.distributions[distributionID]
	return record, ok
}

func (s *FileStore) ListDistributions() []types.DistributionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]types.DistributionRecord, 0, len(s.distributions))
	for _, record := range s.distributions {
		records = append(records, record)
	}
	return records
}

func (s *FileStore) load() error {
	data, err := fsguard.ReadRegularFileBounded(s.path, fileStoreMaxSnapshotBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var state fileStoreState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	if state.Accruals != nil {
		accruals, err := buildAccrualSnapshotMap(state.Accruals)
		if err != nil {
			return fmt.Errorf("validate accrual snapshot: %w", err)
		}
		s.accruals = accruals
	}
	if state.Distributions != nil {
		distributions, err := buildDistributionSnapshotMap(state.Distributions)
		if err != nil {
			return fmt.Errorf("validate distribution snapshot: %w", err)
		}
		s.distributions = distributions
	}
	return nil
}

func (s *FileStore) persist() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistLocked()
}

func (s *FileStore) persistLocked() error {
	if s.persistHook != nil {
		if err := s.persistHook(); err != nil {
			return err
		}
	}

	state := fileStoreState{
		Accruals:      s.accruals,
		Distributions: s.distributions,
	}

	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
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

	if err := os.Rename(tmpPath, s.path); err != nil {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}

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

func buildAccrualSnapshotMap(input map[string]types.RewardAccrual) (map[string]types.RewardAccrual, error) {
	loaded := make(map[string]types.RewardAccrual, len(input))
	for key, record := range input {
		normalized := normalizeAccrual(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid accrual %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.AccrualID]; ok && !accrualRecordsEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting accrual entries for id %q", normalized.AccrualID)
		}
		loaded[normalized.AccrualID] = normalized
	}
	return loaded, nil
}

func buildDistributionSnapshotMap(input map[string]types.DistributionRecord) (map[string]types.DistributionRecord, error) {
	loaded := make(map[string]types.DistributionRecord, len(input))
	for key, record := range input {
		normalized := normalizeDistribution(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid distribution %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.DistributionID]; ok && !distributionRecordsEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting distribution entries for id %q", normalized.DistributionID)
		}
		loaded[normalized.DistributionID] = normalized
	}
	return loaded, nil
}
