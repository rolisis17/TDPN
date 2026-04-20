package keeper

import (
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
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

const fileStoreMaxSnapshotBytes int64 = 16 << 20

// FileStore persists vpnbilling keeper state to disk as JSON snapshots.
type FileStore struct {
	mu    sync.RWMutex
	path  string
	state fileStoreState
}

type fileStoreState struct {
	Reservations map[string]types.CreditReservation
	Settlements  map[string]types.SettlementRecord
}

type fileStoreSnapshot struct {
	Reservations []types.CreditReservation `json:"reservations"`
	Settlements  []types.SettlementRecord  `json:"settlements"`
}

// NewFileStore constructs a keeper store backed by a JSON file at path.
// Existing data is loaded on startup when the file already exists.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("file store path is required")
	}

	cleanPath := filepath.Clean(path)
	parentDir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return nil, fmt.Errorf("create parent directory for file store: %w", err)
	}

	store := &FileStore{
		path: cleanPath,
		state: fileStoreState{
			Reservations: make(map[string]types.CreditReservation),
			Settlements:  make(map[string]types.SettlementRecord),
		},
	}

	if err := store.loadFromDisk(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *FileStore) UpsertReservation(record types.CreditReservation) {
	_ = s.UpsertReservationWithError(record)
}

func (s *FileStore) UpsertReservationWithError(record types.CreditReservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.state.Reservations[record.ReservationID]
	s.state.Reservations[record.ReservationID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.state.Reservations[record.ReservationID] = previous
		} else {
			delete(s.state.Reservations, record.ReservationID)
		}
		return err
	}

	return nil
}

func (s *FileStore) GetReservation(reservationID string) (types.CreditReservation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.state.Reservations[reservationID]
	return record, ok
}

func (s *FileStore) ListReservations() []types.CreditReservation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]types.CreditReservation, 0, len(s.state.Reservations))
	for _, record := range s.state.Reservations {
		records = append(records, record)
	}
	return records
}

func (s *FileStore) ListReservationsWithError() ([]types.CreditReservation, error) {
	return s.ListReservations(), nil
}

func (s *FileStore) UpsertSettlement(record types.SettlementRecord) {
	_ = s.UpsertSettlementWithError(record)
}

func (s *FileStore) UpsertSettlementWithError(record types.SettlementRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, hadPrevious := s.state.Settlements[record.SettlementID]
	s.state.Settlements[record.SettlementID] = record
	if err := s.persistLocked(); err != nil {
		if hadPrevious {
			s.state.Settlements[record.SettlementID] = previous
		} else {
			delete(s.state.Settlements, record.SettlementID)
		}
		return err
	}

	return nil
}

func (s *FileStore) UpsertSettlementAndAdvanceReservationWithError(
	settlement types.SettlementRecord,
	reservation types.CreditReservation,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previousSettlement, hadSettlement := s.state.Settlements[settlement.SettlementID]
	previousReservation, hadReservation := s.state.Reservations[reservation.ReservationID]

	s.state.Settlements[settlement.SettlementID] = settlement
	s.state.Reservations[reservation.ReservationID] = reservation
	if err := s.persistLocked(); err != nil {
		if hadSettlement {
			s.state.Settlements[settlement.SettlementID] = previousSettlement
		} else {
			delete(s.state.Settlements, settlement.SettlementID)
		}
		if hadReservation {
			s.state.Reservations[reservation.ReservationID] = previousReservation
		} else {
			delete(s.state.Reservations, reservation.ReservationID)
		}
		return err
	}

	return nil
}

func (s *FileStore) GetSettlement(settlementID string) (types.SettlementRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.state.Settlements[settlementID]
	return record, ok
}

func (s *FileStore) ListSettlements() []types.SettlementRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]types.SettlementRecord, 0, len(s.state.Settlements))
	for _, record := range s.state.Settlements {
		records = append(records, record)
	}
	return records
}

func (s *FileStore) ListSettlementsWithError() ([]types.SettlementRecord, error) {
	return s.ListSettlements(), nil
}

func (s *FileStore) loadFromDisk() error {
	payload, err := fsguard.ReadRegularFileBounded(s.path, fileStoreMaxSnapshotBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read file store state: %w", err)
	}

	if len(payload) == 0 {
		return nil
	}

	var snapshot fileStoreSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return fmt.Errorf("decode file store state: %w", err)
	}

	reservations, err := buildReservationSnapshotMap(snapshot.Reservations)
	if err != nil {
		return fmt.Errorf("validate file store reservations: %w", err)
	}
	settlements, err := buildSettlementSnapshotMap(snapshot.Settlements)
	if err != nil {
		return fmt.Errorf("validate file store settlements: %w", err)
	}
	s.state.Reservations = reservations
	s.state.Settlements = settlements

	return nil
}

func (s *FileStore) persistLocked() error {
	snapshot := fileStoreSnapshot{
		Reservations: make([]types.CreditReservation, 0, len(s.state.Reservations)),
		Settlements:  make([]types.SettlementRecord, 0, len(s.state.Settlements)),
	}

	for _, reservation := range s.state.Reservations {
		snapshot.Reservations = append(snapshot.Reservations, reservation)
	}
	for _, settlement := range s.state.Settlements {
		snapshot.Settlements = append(snapshot.Settlements, settlement)
	}

	sort.Slice(snapshot.Reservations, func(i, j int) bool {
		return snapshot.Reservations[i].ReservationID < snapshot.Reservations[j].ReservationID
	})
	sort.Slice(snapshot.Settlements, func(i, j int) bool {
		return snapshot.Settlements[i].SettlementID < snapshot.Settlements[j].SettlementID
	})

	payload, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode file store state: %w", err)
	}

	parentDir := filepath.Dir(s.path)
	tmpFile, err := os.CreateTemp(parentDir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file store state: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(payload); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp file store state: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp file store state: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file store state: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace file store state: %w", err)
	}
	if err := syncDirectory(parentDir); err != nil {
		return fmt.Errorf("sync parent directory for file store state: %w", err)
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

func buildReservationSnapshotMap(records []types.CreditReservation) (map[string]types.CreditReservation, error) {
	loaded := make(map[string]types.CreditReservation, len(records))
	for index, record := range records {
		canonical := record.Canonicalize()
		if err := canonical.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid reservation at index %d: %w", index, err)
		}
		if existing, ok := loaded[canonical.ReservationID]; ok && !reservationRecordsEqual(existing, canonical) {
			return nil, fmt.Errorf("conflicting reservation entries for id %q", canonical.ReservationID)
		}
		loaded[canonical.ReservationID] = canonical
	}
	return loaded, nil
}

func buildSettlementSnapshotMap(records []types.SettlementRecord) (map[string]types.SettlementRecord, error) {
	loaded := make(map[string]types.SettlementRecord, len(records))
	for index, record := range records {
		canonical := record.Canonicalize()
		if err := canonical.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("invalid settlement at index %d: %w", index, err)
		}
		if existing, ok := loaded[canonical.SettlementID]; ok && !settlementRecordsEqual(existing, canonical) {
			return nil, fmt.Errorf("conflicting settlement entries for id %q", canonical.SettlementID)
		}
		loaded[canonical.SettlementID] = canonical
	}
	return loaded, nil
}
