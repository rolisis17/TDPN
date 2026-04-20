package localapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var gpmStateStoreWriteMu sync.Mutex
var gpmAuditWriteMu sync.Mutex

const (
	gpmStateStoreLoadMaxBytes = 4 << 20
	gpmAuditReadMaxBytes      = 8 << 20
	gpmAuditRecentMaxEntries  = 50000
)

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
	body, err := readFileWithLimit(path, gpmStateStoreLoadMaxBytes)
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

func readFileWithLimit(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	body, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds max size %d bytes", path, maxBytes)
	}
	return body, nil
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

type gpmAuditRecentQuery struct {
	Limit         int
	Offset        int
	Event         string
	WalletAddress string
	Order         string
}

type gpmAuditRecentResult struct {
	Total   int
	Entries []map[string]any
}

func (s *Service) readGPMAuditRecent(query gpmAuditRecentQuery) (gpmAuditRecentResult, error) {
	path := strings.TrimSpace(s.gpmAuditLogPath)
	if path == "" {
		return gpmAuditRecentResult{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return gpmAuditRecentResult{}, nil
		}
		return gpmAuditRecentResult{}, err
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil {
		if info.Size() > gpmAuditReadMaxBytes {
			return gpmAuditRecentResult{}, fmt.Errorf("audit log exceeds maximum readable size (%d bytes)", gpmAuditReadMaxBytes)
		}
	}

	limit := query.Limit
	if limit < 1 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	eventFilter := strings.ToLower(strings.TrimSpace(query.Event))
	walletFilter := normalizeWalletAddress(query.WalletAddress)
	order := strings.ToLower(strings.TrimSpace(query.Order))
	if order == "" {
		order = "desc"
	}

	entries := make([]map[string]any, 0)
	scanner := bufio.NewScanner(f)
	const maxLine = 1 << 20
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, maxLine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		record := map[string]any{}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if eventFilter != "" {
			event, _ := record["event"].(string)
			if strings.ToLower(strings.TrimSpace(event)) != eventFilter {
				continue
			}
		}
		if walletFilter != "" {
			fields, _ := record["fields"].(map[string]any)
			walletAddress, _ := fields["wallet_address"].(string)
			if normalizeWalletAddress(walletAddress) != walletFilter {
				continue
			}
		}
		if len(entries) >= gpmAuditRecentMaxEntries {
			return gpmAuditRecentResult{}, fmt.Errorf("audit query exceeds maximum entries (%d)", gpmAuditRecentMaxEntries)
		}
		entries = append(entries, record)
	}
	if err := scanner.Err(); err != nil {
		return gpmAuditRecentResult{}, fmt.Errorf("scan audit log: %w", err)
	}
	if order == "desc" {
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			entries[i], entries[j] = entries[j], entries[i]
		}
	}
	total := len(entries)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return gpmAuditRecentResult{
		Total:   total,
		Entries: entries[offset:end],
	}, nil
}
