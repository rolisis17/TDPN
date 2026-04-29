package localapi

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
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
	Version           int                      `json:"version"`
	GeneratedAtUTC    string                   `json:"generated_at_utc"`
	Sessions          []gpmSession             `json:"sessions"`
	Operators         []gpmOperatorApplication `json:"operators"`
	Contributions     []gpmContributionState   `json:"contributions,omitempty"`
	RewardHistory     []gpmWeeklyRewardSummary `json:"reward_history,omitempty"`
	RewardHolds       []gpmRewardHold          `json:"reward_holds,omitempty"`
	ReservationClaims []gpmReservationClaim    `json:"reservation_claims,omitempty"`
}

type gpmStateLoadError struct {
	reason string
	err    error
}

func (e gpmStateLoadError) Error() string {
	if e.err == nil {
		return e.reason
	}
	return fmt.Sprintf("%s: %v", e.reason, e.err)
}

func (e gpmStateLoadError) Unwrap() error {
	return e.err
}

func (st *gpmRuntimeState) snapshotPersistent(now time.Time) ([]gpmSession, []gpmOperatorApplication, []gpmContributionState, []gpmWeeklyRewardSummary, []gpmRewardHold, []gpmReservationClaim) {
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

	contributions := make([]gpmContributionState, 0, len(st.contributions))
	for _, contribution := range st.contributions {
		contributions = append(contributions, contribution)
	}

	history := make([]gpmWeeklyRewardSummary, 0)
	for _, entries := range st.rewardHistory {
		history = append(history, entries...)
	}
	holds := make([]gpmRewardHold, 0)
	for _, entries := range st.rewardHolds {
		holds = append(holds, entries...)
	}
	claims := make([]gpmReservationClaim, 0, len(st.reservationClaims))
	for _, claim := range st.reservationClaims {
		status := strings.TrimSpace(claim.Status)
		if status == "pending_launch" && !claim.ClaimedAt.IsZero() && now.Sub(claim.ClaimedAt) > gpmReservationPendingClaimTTL {
			continue
		}
		if status == "pending_launch" && claim.ClaimedAt.IsZero() {
			claim.Status = "launched"
		}
		claims = append(claims, claim)
	}
	return sessions, operators, contributions, history, holds, claims
}

func (st *gpmRuntimeState) restorePersistent(now time.Time, sessions []gpmSession, operators []gpmOperatorApplication, contributions []gpmContributionState, rewardHistory []gpmWeeklyRewardSummary, rewardHolds []gpmRewardHold, reservationClaims []gpmReservationClaim) {
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

	st.contributions = map[string]gpmContributionState{}
	for _, contribution := range contributions {
		wallet := normalizeWalletAddress(contribution.WalletAddress)
		if wallet == "" {
			continue
		}
		contribution.WalletAddress = wallet
		st.contributions[wallet] = contribution
	}

	st.rewardHistory = map[string][]gpmWeeklyRewardSummary{}
	for _, summary := range rewardHistory {
		wallet := normalizeWalletAddress(summary.WalletAddress)
		if wallet == "" {
			continue
		}
		summary.WalletAddress = wallet
		st.rewardHistory[wallet] = append(st.rewardHistory[wallet], summary)
	}

	st.rewardHolds = map[string][]gpmRewardHold{}
	for _, hold := range rewardHolds {
		wallet := normalizeWalletAddress(hold.WalletAddress)
		if wallet == "" || strings.TrimSpace(hold.WeekStartUTC) == "" {
			continue
		}
		hold.WalletAddress = wallet
		if strings.TrimSpace(hold.HoldID) == "" {
			hold.HoldID = fmt.Sprintf("hold-%s-%d", wallet, len(st.rewardHolds[wallet])+1)
		}
		if strings.TrimSpace(hold.Status) == "" {
			hold.Status = "active"
		}
		st.rewardHolds[wallet] = append(st.rewardHolds[wallet], hold)
	}

	st.reservationClaims = map[string]gpmReservationClaim{}
	for _, claim := range reservationClaims {
		reservationID := strings.TrimSpace(claim.ReservationID)
		wallet := normalizeWalletAddress(claim.WalletAddress)
		sessionID := strings.TrimSpace(claim.ReservationSessionID)
		status := strings.TrimSpace(claim.Status)
		if reservationID == "" || wallet == "" || sessionID == "" {
			continue
		}
		if status == "" {
			status = "launched"
		}
		if status == "pending_launch" && !claim.ClaimedAt.IsZero() && now.Sub(claim.ClaimedAt) > gpmReservationPendingClaimTTL {
			continue
		}
		if status == "pending_launch" && claim.ClaimedAt.IsZero() {
			status = "launched"
		}
		claim.ReservationID = reservationID
		claim.WalletAddress = wallet
		claim.ReservationSessionID = sessionID
		claim.Status = status
		st.reservationClaims[reservationID] = claim
	}
}

func (s *Service) markGPMStateStoreLoadFailed(reason string, err error) {
	s.gpmStateStoreLoadFailed = true
	s.gpmStateStoreLoadFailure = gpmStateLoadError{reason: reason, err: err}.Error()
}

func (s *Service) loadGPMStateBestEffort() {
	path := strings.TrimSpace(s.gpmStateStorePath)
	if path == "" {
		return
	}
	body, err := readFileWithLimit(path, gpmStateStoreLoadMaxBytes)
	if err != nil {
		if !os.IsNotExist(err) {
			s.markGPMStateStoreLoadFailed("read state store", err)
			log.Printf("gpm state load skipped: %v", err)
		}
		return
	}

	var store gpmStateStoreFile
	if err := json.Unmarshal(body, &store); err != nil {
		s.markGPMStateStoreLoadFailed("decode state store", err)
		log.Printf("gpm state load skipped: invalid json (%v)", err)
		return
	}
	if store.Version <= 0 {
		s.markGPMStateStoreLoadFailed("unsupported state store version", fmt.Errorf("version=%d", store.Version))
		log.Printf("gpm state load skipped: unsupported version=%d", store.Version)
		return
	}

	now := time.Now().UTC()
	legacySessionCount := len(store.Sessions)
	if legacySessionCount > 0 {
		store.Sessions = nil
		log.Printf("gpm state load stripped legacy persisted sessions: count=%d path=%s", legacySessionCount, path)
	}
	if s.isGPMProductionMode() {
		store.Sessions, store.Operators, store.Contributions = sanitizeGPMProductionStateStoreTrust(store.Sessions, store.Operators, store.Contributions)
	}
	s.gpmState.restorePersistent(now, store.Sessions, store.Operators, store.Contributions, store.RewardHistory, store.RewardHolds, store.ReservationClaims)
	log.Printf("gpm state loaded: sessions=%d operators=%d contributions=%d rewards=%d holds=%d reservation_claims=%d path=%s", len(store.Sessions), len(store.Operators), len(store.Contributions), len(store.RewardHistory), len(store.RewardHolds), len(store.ReservationClaims), path)
}

func sanitizeGPMProductionStateStoreTrust(sessions []gpmSession, operators []gpmOperatorApplication, contributions []gpmContributionState) ([]gpmSession, []gpmOperatorApplication, []gpmContributionState) {
	for i := range sessions {
		sessions[i].EntitlementEvidenceSource = ""
		if strings.EqualFold(strings.TrimSpace(sessions[i].Role), "operator") {
			sessions[i].Role = "client"
			sessions[i].ChainOperatorID = ""
		}
	}
	for i := range operators {
		operators[i].ApprovalEvidenceSource = ""
	}
	for i := range contributions {
		if contributions[i].Enabled {
			contributions[i].Enabled = false
			contributions[i].ExplicitOptIn = false
			contributions[i].DemotionState = "auto_demoted"
			contributions[i].LockReason = "production restart requires fresh trusted chain or signed entitlement evidence before contribution can resume"
			contributions[i].PendingRewardUnits = 0
		}
	}
	return sessions, operators, contributions
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
	if err := s.persistGPMState(reason); err != nil {
		log.Printf("gpm state persist failed (%s): %v", reason, err)
	}
}

func (s *Service) persistGPMState(reason string) error {
	path := strings.TrimSpace(s.gpmStateStorePath)
	if path == "" {
		return nil
	}
	gpmStateStoreWriteMu.Lock()
	defer gpmStateStoreWriteMu.Unlock()

	now := time.Now().UTC()
	_, operators, contributions, rewardHistory, rewardHolds, reservationClaims := s.gpmState.snapshotPersistent(now)
	store := gpmStateStoreFile{
		Version:           1,
		GeneratedAtUTC:    now.Format(time.RFC3339),
		Sessions:          nil,
		Operators:         operators,
		Contributions:     contributions,
		RewardHistory:     rewardHistory,
		RewardHolds:       rewardHolds,
		ReservationClaims: reservationClaims,
	}
	body, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := writeFileAtomic(path, body, 0o600); err != nil {
		return err
	}
	return nil
}

func writeFileAtomic(path string, body []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace file: %w", err)
	}
	if err := syncGPMStateDirectory(dir); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return nil
}

func syncGPMStateDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		if runtime.GOOS == "windows" && (os.IsPermission(err) || errors.Is(err, syscall.EINVAL)) {
			return nil
		}
		return err
	}
	return nil
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
