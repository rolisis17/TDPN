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

	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

// KeeperStore is the internal persistence seam for vpnsponsor keeper state.
// A Cosmos KV-backed implementation can be plugged in later without changing keeper callers.
type KeeperStore interface {
	UpsertAuthorization(record types.SponsorAuthorization)
	GetAuthorization(authID string) (types.SponsorAuthorization, bool)
	ListAuthorizations() []types.SponsorAuthorization
	UpsertDelegation(record types.DelegatedSessionCredit)
	GetDelegation(reservationID string) (types.DelegatedSessionCredit, bool)
	ListDelegations() []types.DelegatedSessionCredit
}

// InMemoryStore is the default keeper store implementation.
type InMemoryStore struct {
	authorizations map[string]types.SponsorAuthorization
	delegations    map[string]types.DelegatedSessionCredit
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		authorizations: make(map[string]types.SponsorAuthorization),
		delegations:    make(map[string]types.DelegatedSessionCredit),
	}
}

func (s *InMemoryStore) UpsertAuthorization(record types.SponsorAuthorization) {
	s.authorizations[record.AuthorizationID] = record
}

func (s *InMemoryStore) GetAuthorization(authID string) (types.SponsorAuthorization, bool) {
	record, ok := s.authorizations[authID]
	return record, ok
}

func (s *InMemoryStore) ListAuthorizations() []types.SponsorAuthorization {
	ids := make([]string, 0, len(s.authorizations))
	for id := range s.authorizations {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.SponsorAuthorization, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.authorizations[id])
	}
	return records
}

func (s *InMemoryStore) UpsertDelegation(record types.DelegatedSessionCredit) {
	s.delegations[record.ReservationID] = record
}

func (s *InMemoryStore) GetDelegation(reservationID string) (types.DelegatedSessionCredit, bool) {
	record, ok := s.delegations[reservationID]
	return record, ok
}

func (s *InMemoryStore) ListDelegations() []types.DelegatedSessionCredit {
	ids := make([]string, 0, len(s.delegations))
	for id := range s.delegations {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.DelegatedSessionCredit, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.delegations[id])
	}
	return records
}

type fileStoreSnapshot struct {
	Authorizations map[string]types.SponsorAuthorization   `json:"authorizations"`
	Delegations    map[string]types.DelegatedSessionCredit `json:"delegations"`
}

// FileStore persists sponsor authorizations and delegations in a JSON file.
type FileStore struct {
	mu             sync.RWMutex
	path           string
	authorizations map[string]types.SponsorAuthorization
	delegations    map[string]types.DelegatedSessionCredit
}

// NewFileStore constructs a file-backed keeper store and loads existing state when present.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("file store path cannot be empty")
	}

	store := &FileStore{
		path:           path,
		authorizations: make(map[string]types.SponsorAuthorization),
		delegations:    make(map[string]types.DelegatedSessionCredit),
	}

	if err := store.load(); err != nil {
		return nil, fmt.Errorf("load vpnsponsor file store: %w", err)
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

	if snapshot.Authorizations != nil {
		s.authorizations = snapshot.Authorizations
	}
	if snapshot.Delegations != nil {
		s.delegations = snapshot.Delegations
	}

	return nil
}

func (s *FileStore) UpsertAuthorization(record types.SponsorAuthorization) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.authorizations[record.AuthorizationID] = record
	_ = s.persistLocked()
}

func (s *FileStore) GetAuthorization(authID string) (types.SponsorAuthorization, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.authorizations[authID]
	return record, ok
}

func (s *FileStore) ListAuthorizations() []types.SponsorAuthorization {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.authorizations))
	for id := range s.authorizations {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.SponsorAuthorization, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.authorizations[id])
	}
	return records
}

func (s *FileStore) UpsertDelegation(record types.DelegatedSessionCredit) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delegations[record.ReservationID] = record
	_ = s.persistLocked()
}

func (s *FileStore) GetDelegation(reservationID string) (types.DelegatedSessionCredit, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.delegations[reservationID]
	return record, ok
}

func (s *FileStore) ListDelegations() []types.DelegatedSessionCredit {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.delegations))
	for id := range s.delegations {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.DelegatedSessionCredit, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.delegations[id])
	}
	return records
}

func (s *FileStore) persistLocked() error {
	snapshot := fileStoreSnapshot{
		Authorizations: s.authorizations,
		Delegations:    s.delegations,
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

	tmpFile, err := os.CreateTemp(dir, ".vpnsponsor-*.tmp")
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
