package keeper

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

type fileStoreState struct {
	Evidence  map[string]types.SlashEvidence   `json:"evidence"`
	Penalties map[string]types.PenaltyDecision `json:"penalties"`
}

// FileStore persists vpnslashing keeper state to a JSON file.
type FileStore struct {
	mu        sync.RWMutex
	path      string
	evidence  map[string]types.SlashEvidence
	penalties map[string]types.PenaltyDecision
}

func NewFileStore(path string) (*FileStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("file store path is required")
	}

	store := &FileStore{
		path:      path,
		evidence:  make(map[string]types.SlashEvidence),
		penalties: make(map[string]types.PenaltyDecision),
	}

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("load file store: %w", err)
	}
	if err := store.persist(); err != nil {
		return nil, fmt.Errorf("initialize file store: %w", err)
	}

	return store, nil
}

func (s *FileStore) UpsertEvidence(record types.SlashEvidence) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.evidence[record.EvidenceID] = record
	_ = s.persistLocked()
}

func (s *FileStore) GetEvidence(evidenceID string) (types.SlashEvidence, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.evidence[evidenceID]
	return record, ok
}

func (s *FileStore) ListEvidence() []types.SlashEvidence {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]types.SlashEvidence, 0, len(s.evidence))
	for _, record := range s.evidence {
		out = append(out, record)
	}
	return out
}

func (s *FileStore) UpsertPenalty(record types.PenaltyDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.penalties[record.PenaltyID] = record
	_ = s.persistLocked()
}

func (s *FileStore) GetPenalty(penaltyID string) (types.PenaltyDecision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.penalties[penaltyID]
	return record, ok
}

func (s *FileStore) ListPenalties() []types.PenaltyDecision {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]types.PenaltyDecision, 0, len(s.penalties))
	for _, record := range s.penalties {
		out = append(out, record)
	}
	return out
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

	if state.Evidence != nil {
		s.evidence = state.Evidence
	}
	if state.Penalties != nil {
		s.penalties = state.Penalties
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
		Evidence:  s.evidence,
		Penalties: s.penalties,
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
