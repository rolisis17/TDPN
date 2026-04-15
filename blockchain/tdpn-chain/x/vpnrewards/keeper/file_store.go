package keeper

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

type fileStoreState struct {
	Accruals      map[string]types.RewardAccrual      `json:"accruals"`
	Distributions map[string]types.DistributionRecord `json:"distributions"`
}

// FileStore persists vpnrewards keeper state to a JSON file.
type FileStore struct {
	mu           sync.RWMutex
	path          string
	accruals      map[string]types.RewardAccrual
	distributions map[string]types.DistributionRecord
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
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accruals[record.AccrualID] = record
	_ = s.persistLocked()
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
	s.mu.Lock()
	defer s.mu.Unlock()

	s.distributions[record.DistributionID] = record
	_ = s.persistLocked()
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
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}

	var state fileStoreState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	if state.Accruals != nil {
		s.accruals = state.Accruals
	}
	if state.Distributions != nil {
		s.distributions = state.Distributions
	}
	return nil
}

func (s *FileStore) persist() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistLocked()
}

func (s *FileStore) persistLocked() error {
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
		removeErr := os.Remove(s.path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(tmpPath, s.path); err != nil {
			return err
		}
	}

	return nil
}
