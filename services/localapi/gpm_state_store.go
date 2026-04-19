package localapi

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var gpmStateStoreWriteMu sync.Mutex
var gpmAuditWriteMu sync.Mutex

type gpmStateStoreFile struct {
	Version        int                      `json:"version"`
	GeneratedAtUTC string                   `json:"generated_at_utc"`
	Sessions       []gpmSession             `json:"sessions"`
	Operators      []gpmOperatorApplication `json:"operators"`
}

func (st *gpmRuntimeState) snapshotPersistent(now time.Time) ([]gpmSession, []gpmOperatorApplication) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	sessions := make([]gpmSession, 0, len(st.sessions))
	for _, session := range st.sessions {
		if now.After(session.ExpiresAt) {
			continue
		}
		sessions = append(sessions, session)
	}

	operators := make([]gpmOperatorApplication, 0, len(st.operators))
	for _, operator := range st.operators {
		operators = append(operators, operator)
	}
	return sessions, operators
}

func (st *gpmRuntimeState) restorePersistent(now time.Time, sessions []gpmSession, operators []gpmOperatorApplication) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.sessions = map[string]gpmSession{}
	for _, session := range sessions {
		if strings.TrimSpace(session.Token) == "" {
			continue
		}
		if now.After(session.ExpiresAt) {
			continue
		}
		st.sessions[session.Token] = session
	}

	st.operators = map[string]gpmOperatorApplication{}
	for _, operator := range operators {
		wallet := strings.TrimSpace(operator.WalletAddress)
		if wallet == "" {
			continue
		}
		st.operators[wallet] = operator
	}
}

func (s *Service) loadGPMStateBestEffort() {
	path := strings.TrimSpace(s.gpmStateStorePath)
	if path == "" {
		return
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("gpm state load skipped: %v", err)
		}
		return
	}

	var store gpmStateStoreFile
	if err := json.Unmarshal(body, &store); err != nil {
		log.Printf("gpm state load skipped: invalid json (%v)", err)
		return
	}
	if store.Version <= 0 {
		log.Printf("gpm state load skipped: unsupported version=%d", store.Version)
		return
	}

	now := time.Now().UTC()
	s.gpmState.restorePersistent(now, store.Sessions, store.Operators)
	log.Printf("gpm state loaded: sessions=%d operators=%d path=%s", len(store.Sessions), len(store.Operators), path)
}

func (s *Service) persistGPMStateBestEffort(reason string) {
	path := strings.TrimSpace(s.gpmStateStorePath)
	if path == "" {
		return
	}
	gpmStateStoreWriteMu.Lock()
	defer gpmStateStoreWriteMu.Unlock()

	now := time.Now().UTC()
	sessions, operators := s.gpmState.snapshotPersistent(now)
	store := gpmStateStoreFile{
		Version:        1,
		GeneratedAtUTC: now.Format(time.RFC3339),
		Sessions:       sessions,
		Operators:      operators,
	}
	body, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		log.Printf("gpm state persist failed (%s): marshal: %v", reason, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("gpm state persist failed (%s): mkdir: %v", reason, err)
		return
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		log.Printf("gpm state persist failed (%s): write: %v", reason, err)
		return
	}
}

func (s *Service) appendGPMAudit(event string, fields map[string]any) {
	path := strings.TrimSpace(s.gpmAuditLogPath)
	event = strings.TrimSpace(event)
	if path == "" || event == "" {
		return
	}
	gpmAuditWriteMu.Lock()
	defer gpmAuditWriteMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("gpm audit write skipped: mkdir failed: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("gpm audit write skipped: open failed: %v", err)
		return
	}
	defer f.Close()

	record := map[string]any{
		"version":   1,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"event":     event,
		"fields":    fields,
		"component": "localapi",
		"subsystem": "gpm",
	}
	line, err := json.Marshal(record)
	if err != nil {
		log.Printf("gpm audit write skipped: marshal failed: %v", err)
		return
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		log.Printf("gpm audit write skipped: append failed: %v", err)
	}
}
