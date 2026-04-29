package app

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	clientVPNPathModeRelay          = "relay"
	clientVPNPathModeDirect         = "direct"
	clientVPNPathModeDirectFallback = "direct_fallback"
)

type clientVPNRelayIDMap struct {
	Entry  string `json:"entry,omitempty"`
	Middle string `json:"middle,omitempty"`
	Exit   string `json:"exit,omitempty"`
}

type clientVPNStatus struct {
	Schema             string               `json:"schema"`
	UpdatedAtUTC       string               `json:"updated_at_utc"`
	PathMode           string               `json:"path_mode"`
	SessionActive      bool                 `json:"session_active"`
	SessionID          string               `json:"session_id,omitempty"`
	SessionKeyID       string               `json:"session_key_id,omitempty"`
	SessionExpiresUnix int64                `json:"session_expires_unix,omitempty"`
	Transport          string               `json:"transport,omitempty"`
	EntryRelayID       string               `json:"entry_relay_id,omitempty"`
	MiddleRelayID      string               `json:"middle_relay_id,omitempty"`
	ExitRelayID        string               `json:"exit_relay_id,omitempty"`
	SelectedRelayIDs   []string             `json:"selected_relay_ids,omitempty"`
	SelectedRelayIDMap *clientVPNRelayIDMap `json:"selected_relay_id_map,omitempty"`
}

func (c *Client) recordClientVPNStatus(session clientActiveSession, active bool) {
	status := clientVPNStatusFromSession(session, active, time.Now())
	if strings.TrimSpace(status.PathMode) == "" {
		return
	}
	c.statusMu.Lock()
	c.clientStatus = status
	statusFile := strings.TrimSpace(c.clientStatusFile)
	c.statusMu.Unlock()
	if statusFile == "" {
		return
	}
	if err := writeClientVPNStatusFile(statusFile, status); err != nil {
		log.Printf("client status write failed path=%s err=%v", statusFile, err)
	}
}

func (c *Client) snapshotClientVPNStatus() (clientVPNStatus, bool) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	if strings.TrimSpace(c.clientStatus.PathMode) == "" {
		return clientVPNStatus{}, false
	}
	return c.clientStatus, true
}

func clientVPNStatusFromSession(session clientActiveSession, active bool, now time.Time) clientVPNStatus {
	mode := clientVPNPathModeForSession(session)
	relayIDs := clientVPNRelayIDMap{
		Entry:  strings.TrimSpace(session.entryRelayID),
		Middle: strings.TrimSpace(session.middleRelayID),
		Exit:   strings.TrimSpace(session.exitRelayID),
	}
	status := clientVPNStatus{
		Schema:             "tdpn.client_vpn_status.v1",
		UpdatedAtUTC:       now.UTC().Format(time.RFC3339Nano),
		PathMode:           mode,
		SessionActive:      active,
		SessionID:          strings.TrimSpace(session.sessionID),
		SessionKeyID:       strings.TrimSpace(session.sessionKeyID),
		SessionExpiresUnix: session.sessionExp,
		Transport:          strings.TrimSpace(session.transport),
		EntryRelayID:       relayIDs.Entry,
		MiddleRelayID:      relayIDs.Middle,
		ExitRelayID:        relayIDs.Exit,
		SelectedRelayIDs:   orderedClientVPNRelayIDs(relayIDs),
	}
	if relayIDs.Entry != "" || relayIDs.Middle != "" || relayIDs.Exit != "" {
		status.SelectedRelayIDMap = &relayIDs
	}
	return status
}

func clientVPNPathModeForSession(session clientActiveSession) string {
	switch strings.ToLower(strings.TrimSpace(session.pathMode)) {
	case clientVPNPathModeRelay:
		return clientVPNPathModeRelay
	case clientVPNPathModeDirect:
		return clientVPNPathModeDirect
	case clientVPNPathModeDirectFallback:
		return clientVPNPathModeDirectFallback
	}
	if strings.TrimSpace(session.exitRelayID) == "" {
		return ""
	}
	if strings.TrimSpace(session.entryRelayID) == "" && strings.TrimSpace(session.middleRelayID) == "" {
		return clientVPNPathModeDirect
	}
	return clientVPNPathModeRelay
}

func orderedClientVPNRelayIDs(relayIDs clientVPNRelayIDMap) []string {
	out := make([]string, 0, 3)
	if relayIDs.Entry != "" {
		out = append(out, relayIDs.Entry)
	}
	if relayIDs.Middle != "" {
		out = append(out, relayIDs.Middle)
	}
	if relayIDs.Exit != "" {
		out = append(out, relayIDs.Exit)
	}
	return out
}

func writeClientVPNStatusFile(path string, status clientVPNStatus) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(status); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Remove(path)
	return os.Rename(tmpName, path)
}
