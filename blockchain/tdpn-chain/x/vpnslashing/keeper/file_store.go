package keeper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tdpn/tdpn-chain/internal/fsguard"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

const fileStoreMaxSnapshotBytes int64 = 16 << 20

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
	_ = s.UpsertEvidenceWithError(record)
}

func (s *FileStore) UpsertEvidenceWithError(record types.SlashEvidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.evidence[record.EvidenceID]
	s.evidence[record.EvidenceID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.evidence[record.EvidenceID] = previous
		} else {
			delete(s.evidence, record.EvidenceID)
		}
		return err
	}
	return nil
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
	_ = s.UpsertPenaltyWithError(record)
}

func (s *FileStore) UpsertPenaltyWithError(record types.PenaltyDecision) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.penalties[record.PenaltyID]
	s.penalties[record.PenaltyID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.penalties[record.PenaltyID] = previous
		} else {
			delete(s.penalties, record.PenaltyID)
		}
		return err
	}
	return nil
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

	if state.Evidence != nil {
		evidence, err := buildEvidenceSnapshotMap(state.Evidence)
		if err != nil {
			return fmt.Errorf("validate evidence snapshot: %w", err)
		}
		s.evidence = evidence
	}
	if state.Penalties != nil {
		penalties, err := buildPenaltySnapshotMap(state.Penalties)
		if err != nil {
			return fmt.Errorf("validate penalty snapshot: %w", err)
		}
		s.penalties = penalties
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
	return dir.Sync()
}

func buildEvidenceSnapshotMap(input map[string]types.SlashEvidence) (map[string]types.SlashEvidence, error) {
	loaded := make(map[string]types.SlashEvidence, len(input))
	for key, record := range input {
		normalized := normalizeEvidence(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid evidence %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.EvidenceID]; ok && !slashEvidenceRecordsEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting evidence entries for id %q", normalized.EvidenceID)
		}
		loaded[normalized.EvidenceID] = normalized
	}
	return loaded, nil
}

func buildPenaltySnapshotMap(input map[string]types.PenaltyDecision) (map[string]types.PenaltyDecision, error) {
	loaded := make(map[string]types.PenaltyDecision, len(input))
	for key, record := range input {
		normalized := normalizePenalty(record)
		if err := normalized.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid penalty %q: %w", key, err)
		}
		if existing, ok := loaded[normalized.PenaltyID]; ok && !penaltyRecordsEqual(existing, normalized) {
			return nil, fmt.Errorf("conflicting penalty entries for id %q", normalized.PenaltyID)
		}
		loaded[normalized.PenaltyID] = normalized
	}
	return loaded, nil
}
