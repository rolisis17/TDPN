package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"privacynode/pkg/proto"
	"privacynode/pkg/wg"
)

type recordingClientWGManager struct {
	removeCalls []wg.ClientSessionConfig
	removeErr   error
}

func (m *recordingClientWGManager) ConfigureClientSession(_ context.Context, _ wg.ClientSessionConfig) error {
	return nil
}

func (m *recordingClientWGManager) RemoveClientSession(_ context.Context, cfg wg.ClientSessionConfig) error {
	m.removeCalls = append(m.removeCalls, cfg)
	return m.removeErr
}

func TestActiveSessionSatisfiesCurrentPathPolicyRejectsStaleTwoHopForThreeHop(t *testing.T) {
	client := &Client{
		pathProfile:        "3hop",
		preferMiddleRelay:  true,
		requireMiddleRelay: true,
	}
	session := clientActiveSession{
		sessionID:    "session-two-hop",
		sessionExp:   time.Now().Add(time.Minute).Unix(),
		entryRelayID: "entry-a",
		exitRelayID:  "exit-b",
		transport:    "policy-json",
	}

	ok, reason := client.activeSessionSatisfiesCurrentPathPolicy(session)
	if ok {
		t.Fatalf("expected stale two-hop session to fail 3hop policy")
	}
	if reason != "middle-required" {
		t.Fatalf("reason=%q want=middle-required", reason)
	}
}

func TestActiveSessionSatisfiesCurrentPathPolicyAcceptsThreeHopSession(t *testing.T) {
	client := &Client{
		pathProfile:        "3hop",
		preferMiddleRelay:  true,
		requireMiddleRelay: true,
	}
	session := clientActiveSession{
		sessionID:       "session-three-hop",
		sessionExp:      time.Now().Add(time.Minute).Unix(),
		entryRelayID:    "entry-a",
		middleRelayID:   "middle-c",
		exitRelayID:     "exit-b",
		transport:       "policy-json",
		entryControlURL: "http://entry.local",
	}

	ok, reason := client.activeSessionSatisfiesCurrentPathPolicy(session)
	if !ok {
		t.Fatalf("expected 3hop session to satisfy policy, reason=%q", reason)
	}
}

func TestActiveSessionSatisfiesCurrentPathPolicyAcceptsDistinctOperatorAndCountryMetadata(t *testing.T) {
	client := &Client{
		pathProfile:              "3hop",
		preferMiddleRelay:        true,
		requireMiddleRelay:       true,
		requireDistinctOps:       true,
		requireDistinctCountries: true,
	}
	session := clientActiveSession{
		sessionID:         "session-three-hop",
		sessionExp:        time.Now().Add(time.Minute).Unix(),
		entryRelayID:      "entry-a",
		middleRelayID:     "middle-c",
		exitRelayID:       "exit-b",
		transport:         "policy-json",
		entryControlURL:   "http://entry.local",
		entryOperatorID:   "operator-a",
		middleOperatorID:  "operator-c",
		exitOperatorID:    "operator-b",
		entryCountryCode:  "US",
		middleCountryCode: "CA",
		exitCountryCode:   "BR",
	}

	ok, reason := client.activeSessionSatisfiesCurrentPathPolicy(session)
	if !ok {
		t.Fatalf("expected distinct 3hop session to satisfy policy, reason=%q", reason)
	}
}

func TestActiveSessionSatisfiesCurrentPathPolicyRejectsMissingOperatorMetadata(t *testing.T) {
	client := &Client{
		pathProfile:        "2hop",
		requireDistinctOps: true,
	}
	session := clientActiveSession{
		sessionID:    "session-two-hop",
		sessionExp:   time.Now().Add(time.Minute).Unix(),
		entryRelayID: "entry-a",
		exitRelayID:  "exit-b",
		transport:    "policy-json",
	}

	ok, reason := client.activeSessionSatisfiesCurrentPathPolicy(session)
	if ok {
		t.Fatalf("expected session without operator metadata to fail distinct-operator policy")
	}
	if reason != "missing-operator-metadata" {
		t.Fatalf("reason=%q want=missing-operator-metadata", reason)
	}
}

func TestActiveSessionSatisfiesCurrentPathPolicyRejectsOperatorConflict(t *testing.T) {
	client := &Client{
		pathProfile:        "3hop",
		preferMiddleRelay:  true,
		requireMiddleRelay: true,
		requireDistinctOps: true,
	}
	session := clientActiveSession{
		sessionID:        "session-three-hop",
		sessionExp:       time.Now().Add(time.Minute).Unix(),
		entryRelayID:     "entry-a",
		middleRelayID:    "middle-c",
		exitRelayID:      "exit-b",
		transport:        "policy-json",
		entryControlURL:  "http://entry.local",
		entryOperatorID:  "operator-a",
		middleOperatorID: "operator-b",
		exitOperatorID:   "operator-b",
	}

	ok, reason := client.activeSessionSatisfiesCurrentPathPolicy(session)
	if ok {
		t.Fatalf("expected session with repeated operator to fail distinct-operator policy")
	}
	if reason != "operator-conflict" {
		t.Fatalf("reason=%q want=operator-conflict", reason)
	}
}

func TestActiveSessionSatisfiesCurrentPathPolicyRejectsMissingCountryMetadata(t *testing.T) {
	client := &Client{
		pathProfile:              "2hop",
		requireDistinctCountries: true,
	}
	session := clientActiveSession{
		sessionID:        "session-two-hop",
		sessionExp:       time.Now().Add(time.Minute).Unix(),
		entryRelayID:     "entry-a",
		exitRelayID:      "exit-b",
		transport:        "policy-json",
		entryOperatorID:  "operator-a",
		exitOperatorID:   "operator-b",
		entryCountryCode: "US",
	}

	ok, reason := client.activeSessionSatisfiesCurrentPathPolicy(session)
	if ok {
		t.Fatalf("expected session without exit country metadata to fail distinct-country policy")
	}
	if reason != "missing-country-metadata" {
		t.Fatalf("reason=%q want=missing-country-metadata", reason)
	}
}

func TestActiveSessionSatisfiesCurrentPathPolicyRejectsCountryConflict(t *testing.T) {
	client := &Client{
		pathProfile:              "3hop",
		preferMiddleRelay:        true,
		requireMiddleRelay:       true,
		requireDistinctCountries: true,
	}
	session := clientActiveSession{
		sessionID:         "session-three-hop",
		sessionExp:        time.Now().Add(time.Minute).Unix(),
		entryRelayID:      "entry-a",
		middleRelayID:     "middle-c",
		exitRelayID:       "exit-b",
		transport:         "policy-json",
		entryControlURL:   "http://entry.local",
		entryCountryCode:  "US",
		middleCountryCode: "ca",
		exitCountryCode:   "CA",
	}

	ok, reason := client.activeSessionSatisfiesCurrentPathPolicy(session)
	if ok {
		t.Fatalf("expected session with repeated country to fail distinct-country policy")
	}
	if reason != "country-conflict" {
		t.Fatalf("reason=%q want=country-conflict", reason)
	}
}

func TestActiveSessionSatisfiesCurrentPathPolicyRejectsTwoHopForDirectExit(t *testing.T) {
	client := &Client{
		pathProfile:     "1hop",
		forceDirectExit: true,
	}
	session := clientActiveSession{
		sessionID:    "session-two-hop",
		sessionExp:   time.Now().Add(time.Minute).Unix(),
		entryRelayID: "entry-a",
		exitRelayID:  "exit-b",
		transport:    "policy-json",
	}

	ok, reason := client.activeSessionSatisfiesCurrentPathPolicy(session)
	if ok {
		t.Fatalf("expected stale two-hop session to fail direct-exit policy")
	}
	if reason != "direct-exit-required" {
		t.Fatalf("reason=%q want=direct-exit-required", reason)
	}
}

func TestClientVPNStatusReportsDirectFallbackPath(t *testing.T) {
	statusFile := filepath.Join(t.TempDir(), "client-vpn-status.json")
	client := &Client{clientStatusFile: statusFile}

	client.recordClientVPNStatus(clientActiveSession{
		sessionID:    "session-direct-fallback",
		sessionKeyID: "key-direct-fallback",
		sessionExp:   time.Now().Add(time.Minute).Unix(),
		transport:    "wireguard-udp",
		exitRelayID:  "exit-direct",
		pathMode:     clientVPNPathModeDirectFallback,
	}, false)

	status, ok := client.snapshotClientVPNStatus()
	if !ok {
		t.Fatal("expected client VPN status snapshot")
	}
	if status.PathMode != clientVPNPathModeDirectFallback {
		t.Fatalf("PathMode=%q want=%q", status.PathMode, clientVPNPathModeDirectFallback)
	}
	if status.SessionActive {
		t.Fatal("SessionActive=true want=false for non-durable direct fallback")
	}
	if status.EntryRelayID != "" || status.MiddleRelayID != "" || status.ExitRelayID != "exit-direct" {
		t.Fatalf("unexpected relay ids: entry=%q middle=%q exit=%q", status.EntryRelayID, status.MiddleRelayID, status.ExitRelayID)
	}
	if !reflect.DeepEqual(status.SelectedRelayIDs, []string{"exit-direct"}) {
		t.Fatalf("SelectedRelayIDs=%v want [exit-direct]", status.SelectedRelayIDs)
	}

	persisted := readClientVPNStatusForTest(t, statusFile)
	if persisted.PathMode != clientVPNPathModeDirectFallback || persisted.ExitRelayID != "exit-direct" || persisted.SessionActive {
		t.Fatalf("unexpected persisted direct fallback status: %+v", persisted)
	}
}

func TestStoreActiveSessionReportsRelayPathStatus(t *testing.T) {
	statusFile := filepath.Join(t.TempDir(), "client-vpn-status.json")
	client := &Client{clientStatusFile: statusFile}

	client.storeActiveSession(clientActiveSession{
		sessionID:       "session-relay",
		sessionKeyID:    "key-relay",
		sessionExp:      time.Now().Add(time.Minute).Unix(),
		transport:       "wireguard-udp",
		entryRelayID:    "entry-a",
		middleRelayID:   "middle-b",
		exitRelayID:     "exit-c",
		entryControlURL: "http://entry.local",
		pathMode:        clientVPNPathModeRelay,
	})

	status, ok := client.snapshotClientVPNStatus()
	if !ok {
		t.Fatal("expected client VPN status snapshot")
	}
	if status.PathMode != clientVPNPathModeRelay {
		t.Fatalf("PathMode=%q want=%q", status.PathMode, clientVPNPathModeRelay)
	}
	if !status.SessionActive {
		t.Fatal("SessionActive=false want=true for stored relay session")
	}
	if status.EntryRelayID != "entry-a" || status.MiddleRelayID != "middle-b" || status.ExitRelayID != "exit-c" {
		t.Fatalf("unexpected relay ids: entry=%q middle=%q exit=%q", status.EntryRelayID, status.MiddleRelayID, status.ExitRelayID)
	}
	if !reflect.DeepEqual(status.SelectedRelayIDs, []string{"entry-a", "middle-b", "exit-c"}) {
		t.Fatalf("SelectedRelayIDs=%v want [entry-a middle-b exit-c]", status.SelectedRelayIDs)
	}

	persisted := readClientVPNStatusForTest(t, statusFile)
	if persisted.PathMode != clientVPNPathModeRelay || !persisted.SessionActive {
		t.Fatalf("unexpected persisted relay status: %+v", persisted)
	}
	if !reflect.DeepEqual(persisted.SelectedRelayIDs, []string{"entry-a", "middle-b", "exit-c"}) {
		t.Fatalf("persisted SelectedRelayIDs=%v want [entry-a middle-b exit-c]", persisted.SelectedRelayIDs)
	}
}

func readClientVPNStatusForTest(t *testing.T, path string) clientVPNStatus {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status file: %v", err)
	}
	var status clientVPNStatus
	if err := json.Unmarshal(payload, &status); err != nil {
		t.Fatalf("decode status file: %v", err)
	}
	return status
}

func TestActiveSessionRequiresFreshRelayValidationForStrictThreeHopAndMicroExit(t *testing.T) {
	cases := []struct {
		name    string
		client  Client
		session clientActiveSession
		want    bool
	}{
		{
			name:   "plain two hop does not require fresh lookup",
			client: Client{pathProfile: "2hop"},
			session: clientActiveSession{
				entryRelayID: "entry-a",
				exitRelayID:  "exit-b",
				exitRole:     "exit",
			},
			want: false,
		},
		{
			name: "strict requires fresh lookup",
			client: Client{
				pathProfile: "2hop",
				betaStrict:  true,
			},
			session: clientActiveSession{
				entryRelayID: "entry-a",
				exitRelayID:  "exit-b",
				exitRole:     "exit",
			},
			want: true,
		},
		{
			name: "3hop requires fresh lookup",
			client: Client{
				pathProfile:        "3hop",
				preferMiddleRelay:  true,
				requireMiddleRelay: true,
			},
			session: clientActiveSession{
				entryRelayID:  "entry-a",
				middleRelayID: "middle-c",
				exitRelayID:   "exit-b",
				exitRole:      "exit",
			},
			want: true,
		},
		{
			name:   "micro exit requires fresh lookup",
			client: Client{pathProfile: "1hop"},
			session: clientActiveSession{
				exitRelayID: "exit-b",
				exitRole:    "micro-exit",
			},
			want: true,
		},
	}
	for i := range cases {
		tc := &cases[i]
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.client.activeSessionRequiresFreshRelayValidation(tc.session); got != tc.want {
				t.Fatalf("activeSessionRequiresFreshRelayValidation()=%t want=%t", got, tc.want)
			}
		})
	}
}

func TestActiveSessionFreshRelayStateAcceptsCurrentThreeHop(t *testing.T) {
	client := &Client{
		pathProfile:              "3hop",
		preferMiddleRelay:        true,
		requireMiddleRelay:       true,
		requireDistinctOps:       true,
		requireDistinctCountries: true,
	}
	session := clientActiveSession{
		sessionID:       "session-three-hop",
		sessionExp:      time.Now().Add(time.Minute).Unix(),
		entryRelayID:    "entry-a",
		middleRelayID:   "middle-c",
		exitRelayID:     "exit-b",
		transport:       "policy-json",
		entryControlURL: "http://entry.local",
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", OperatorID: "operator-a", CountryCode: "US"},
		{
			RelayID:      "middle-c",
			Role:         "micro-relay",
			OperatorID:   "operator-c",
			CountryCode:  "CA",
			Endpoint:     "127.0.0.1:52830",
			HopRoles:     []string{"middle"},
			Reputation:   0.9,
			Uptime:       0.9,
			Capacity:     0.9,
			AbusePenalty: 0.1,
		},
		{RelayID: "exit-b", Role: "exit", OperatorID: "operator-b", CountryCode: "BR"},
	}

	ok, reason := client.activeSessionSatisfiesFreshRelayState(session, relays, time.Now())
	if !ok {
		t.Fatalf("expected fresh 3hop relay state to pass, reason=%q", reason)
	}
}

func TestActiveSessionFreshRelayStateRejectsMissingMiddle(t *testing.T) {
	client := &Client{
		pathProfile:        "3hop",
		preferMiddleRelay:  true,
		requireMiddleRelay: true,
	}
	session := clientActiveSession{
		sessionID:       "session-three-hop",
		sessionExp:      time.Now().Add(time.Minute).Unix(),
		entryRelayID:    "entry-a",
		middleRelayID:   "middle-c",
		exitRelayID:     "exit-b",
		transport:       "policy-json",
		entryControlURL: "http://entry.local",
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry"},
		{RelayID: "exit-b", Role: "exit"},
	}

	ok, reason := client.activeSessionSatisfiesFreshRelayState(session, relays, time.Now())
	if ok {
		t.Fatalf("expected missing current middle relay to fail")
	}
	if reason != "middle-not-current" {
		t.Fatalf("reason=%q want=middle-not-current", reason)
	}
}

func TestActiveSessionFreshRelayStateRejectsDemotedMicroExit(t *testing.T) {
	client := &Client{
		pathProfile:     "1hop",
		forceDirectExit: true,
	}
	session := clientActiveSession{
		sessionID:     "session-micro-exit",
		sessionExp:    time.Now().Add(time.Minute).Unix(),
		exitRelayID:   "exit-b",
		exitRole:      "micro-exit",
		transport:     "policy-json",
		entryDataAddr: "127.0.0.1:51821",
	}
	relays := []proto.RelayDescriptor{
		{
			RelayID:      "exit-b",
			Role:         "micro-exit",
			Reputation:   0.9,
			Uptime:       0.2,
			Capacity:     0.9,
			AbusePenalty: 0.1,
		},
	}

	ok, reason := client.activeSessionSatisfiesFreshRelayState(session, relays, time.Now())
	if ok {
		t.Fatalf("expected demoted micro-exit to fail")
	}
	if reason != "exit-not-current" {
		t.Fatalf("reason=%q want=exit-not-current", reason)
	}
}

func TestCloseSessionPassesWireGuardCleanupMetadata(t *testing.T) {
	wgManager := &recordingClientWGManager{}
	client := &Client{
		wgInterface: "wg-client",
		wgManager:   wgManager,
	}

	err := client.closeSession(context.Background(), clientActiveSession{
		sessionID:      "session-1",
		sessionKeyID:   "key-1",
		transport:      "wireguard-udp",
		exitInnerPub:   "exit-public-key",
		clientInnerIP:  "10.44.0.2/32",
		wgAllowedIPs:   "0.0.0.0/0,::/0",
		wgInstallRoute: true,
	})
	if err != nil {
		t.Fatalf("closeSession returned error: %v", err)
	}
	if len(wgManager.removeCalls) != 1 {
		t.Fatalf("remove calls=%d want=1", len(wgManager.removeCalls))
	}
	got := wgManager.removeCalls[0]
	if got.SessionID != "session-1" {
		t.Fatalf("SessionID=%q want=session-1", got.SessionID)
	}
	if got.SessionKeyID != "key-1" {
		t.Fatalf("SessionKeyID=%q want=key-1", got.SessionKeyID)
	}
	if got.Interface != "wg-client" {
		t.Fatalf("Interface=%q want=wg-client", got.Interface)
	}
	if got.ExitPublicKey != "exit-public-key" {
		t.Fatalf("ExitPublicKey=%q want=exit-public-key", got.ExitPublicKey)
	}
	if got.ClientInnerIP != "10.44.0.2/32" {
		t.Fatalf("ClientInnerIP=%q want=10.44.0.2/32", got.ClientInnerIP)
	}
	if got.AllowedIPs != "0.0.0.0/0,::/0" {
		t.Fatalf("AllowedIPs=%q want=0.0.0.0/0,::/0", got.AllowedIPs)
	}
	if !got.InstallRoute {
		t.Fatal("InstallRoute=false want=true")
	}
}

func TestCloseActiveSessionRetainsMetadataWhenWireGuardCleanupFails(t *testing.T) {
	removeErr := errors.New("remove failed")
	wgManager := &recordingClientWGManager{removeErr: removeErr}
	client := &Client{
		wgInterface: "wg-client",
		wgManager:   wgManager,
	}
	client.storeActiveSession(clientActiveSession{
		sessionID:      "session-1",
		sessionKeyID:   "key-1",
		transport:      "wireguard-udp",
		exitInnerPub:   "exit-public-key",
		clientInnerIP:  "10.44.0.2/32",
		wgAllowedIPs:   "0.0.0.0/0,::/0",
		wgInstallRoute: true,
	})

	err := client.closeActiveSession(context.Background(), "test-failure")
	if !errors.Is(err, removeErr) {
		t.Fatalf("closeActiveSession error=%v want wrapped %v", err, removeErr)
	}
	if len(wgManager.removeCalls) != 1 {
		t.Fatalf("remove calls after failure=%d want=1", len(wgManager.removeCalls))
	}
	session, ok := client.snapshotActiveSession()
	if !ok {
		t.Fatal("expected active session metadata retained for cleanup retry")
	}
	if session.sessionID != "session-1" {
		t.Fatalf("retained SessionID=%q want=session-1", session.sessionID)
	}
	if session.sessionKeyID != "key-1" {
		t.Fatalf("retained SessionKeyID=%q want=key-1", session.sessionKeyID)
	}
	if session.exitInnerPub != "exit-public-key" {
		t.Fatalf("retained ExitPublicKey=%q want=exit-public-key", session.exitInnerPub)
	}
	if session.clientInnerIP != "10.44.0.2/32" {
		t.Fatalf("retained ClientInnerIP=%q want=10.44.0.2/32", session.clientInnerIP)
	}
	if session.wgAllowedIPs != "0.0.0.0/0,::/0" {
		t.Fatalf("retained AllowedIPs=%q want=0.0.0.0/0,::/0", session.wgAllowedIPs)
	}
	if !session.wgInstallRoute {
		t.Fatal("retained InstallRoute=false want=true")
	}

	wgManager.removeErr = nil
	if err := client.closeActiveSession(context.Background(), "test-retry"); err != nil {
		t.Fatalf("closeActiveSession retry returned error: %v", err)
	}
	if len(wgManager.removeCalls) != 2 {
		t.Fatalf("remove calls after retry=%d want=2", len(wgManager.removeCalls))
	}
	if _, ok := client.snapshotActiveSession(); ok {
		t.Fatal("expected active session cleared after successful retry")
	}
}

func TestTryReuseActiveSessionClosesKernelProxySession(t *testing.T) {
	now := time.Now()
	wgManager := &recordingClientWGManager{}
	client := &Client{
		sessionReuse:          true,
		wgKernelProxy:         true,
		wgInterface:           "wg-client",
		wgManager:             wgManager,
		sessionRefreshLeadSec: 20,
	}
	client.storeActiveSession(clientActiveSession{
		sessionID:      "session-1",
		sessionKeyID:   "key-1",
		sessionExp:     now.Add(time.Hour).Unix(),
		transport:      "wireguard-udp",
		entryDataAddr:  "127.0.0.1:51820",
		entryRelayID:   "entry-a",
		exitRelayID:    "exit-b",
		exitInnerPub:   "exit-public-key",
		clientInnerIP:  "10.44.0.2/32",
		wgAllowedIPs:   "0.0.0.0/0",
		wgInstallRoute: true,
	})

	if reused := client.tryReuseActiveSession(context.Background(), now); reused {
		t.Fatal("expected kernel proxy session to require fresh runtime setup")
	}
	if _, ok := client.snapshotActiveSession(); ok {
		t.Fatal("expected stale kernel proxy session to be cleared")
	}
	if len(wgManager.removeCalls) != 1 {
		t.Fatalf("remove calls=%d want=1", len(wgManager.removeCalls))
	}
	got := wgManager.removeCalls[0]
	if got.SessionID != "session-1" || got.SessionKeyID != "key-1" {
		t.Fatalf("remove metadata session=%q key=%q", got.SessionID, got.SessionKeyID)
	}
	if got.Interface != "wg-client" || got.ClientInnerIP != "10.44.0.2/32" || got.AllowedIPs != "0.0.0.0/0" || !got.InstallRoute {
		t.Fatalf("unexpected wg cleanup config: %+v", got)
	}
}

func TestCompleteSessionHandoffSkipsWireGuardRemoveForSharedPeer(t *testing.T) {
	wgManager := &recordingClientWGManager{}
	client := &Client{
		wgInterface: "wg-client",
		wgManager:   wgManager,
	}
	previous := clientActiveSession{
		sessionID:     "session-old",
		sessionKeyID:  "key-old",
		transport:     "wireguard-udp",
		exitInnerPub:  "shared-exit-public-key",
		clientInnerIP: "10.44.0.2/32",
		wgAllowedIPs:  "0.0.0.0/0",
	}
	next := clientActiveSession{
		sessionID:     "session-new",
		sessionKeyID:  "key-new",
		transport:     "wireguard-udp",
		exitInnerPub:  "shared-exit-public-key",
		clientInnerIP: "10.44.0.2/32",
		wgAllowedIPs:  "0.0.0.0/0",
	}

	client.completeSessionHandoff(previous, next)

	if len(wgManager.removeCalls) != 0 {
		t.Fatalf("remove calls=%d want=0 for shared WireGuard peer", len(wgManager.removeCalls))
	}
}

func TestCompleteSessionHandoffSkipsRemoteCloseForSameExitClientPub(t *testing.T) {
	entryURL := "http://entry.local"
	closeCalls := 0
	wgManager := &recordingClientWGManager{}
	client := &Client{
		clientWGPub: "client-public-key",
		wgInterface: "wg-client",
		wgManager:   wgManager,
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: map[string]func(*http.Request) (*http.Response, error){
			entryURL + "/v1/path/close": func(req *http.Request) (*http.Response, error) {
				closeCalls++
				return jsonResponse(proto.PathCloseResponse{Closed: true})(req)
			},
		}}},
	}
	previous := clientActiveSession{
		sessionID:       "session-old",
		sessionKeyID:    "key-old",
		transport:       "wireguard-udp",
		entryControlURL: entryURL,
		exitRelayID:     "exit-a",
		exitInnerPub:    "old-exit-public-key",
		clientInnerPub:  "client-public-key",
		clientInnerIP:   "10.44.0.2/32",
		wgAllowedIPs:    "0.0.0.0/0",
	}
	next := clientActiveSession{
		sessionID:      "session-new",
		sessionKeyID:   "key-new",
		transport:      "wireguard-udp",
		exitRelayID:    "exit-a",
		exitInnerPub:   "new-exit-public-key",
		clientInnerPub: "client-public-key",
		clientInnerIP:  "10.45.0.2/32",
		wgAllowedIPs:   "0.0.0.0/0",
	}

	client.completeSessionHandoff(previous, next)

	if closeCalls != 0 {
		t.Fatalf("remote close calls=%d want=0 for same-exit WireGuard handoff with same client pubkey", closeCalls)
	}
	if len(wgManager.removeCalls) != 1 {
		t.Fatalf("local remove calls=%d want=1 for different local exit peer", len(wgManager.removeCalls))
	}
	if wgManager.removeCalls[0].ExitPublicKey != "old-exit-public-key" {
		t.Fatalf("local remove ExitPublicKey=%q want=old-exit-public-key", wgManager.removeCalls[0].ExitPublicKey)
	}
}

func TestCompleteSessionHandoffRemovesDifferentWireGuardPeer(t *testing.T) {
	wgManager := &recordingClientWGManager{}
	client := &Client{
		wgInterface: "wg-client",
		wgManager:   wgManager,
	}
	previous := clientActiveSession{
		sessionID:      "session-old",
		sessionKeyID:   "key-old",
		transport:      "wireguard-udp",
		exitInnerPub:   "old-exit-public-key",
		clientInnerIP:  "10.44.0.2/32",
		wgAllowedIPs:   "0.0.0.0/0",
		wgInstallRoute: true,
	}
	next := clientActiveSession{
		sessionID:      "session-new",
		sessionKeyID:   "key-new",
		transport:      "wireguard-udp",
		exitInnerPub:   "new-exit-public-key",
		clientInnerIP:  "10.45.0.2/32",
		wgAllowedIPs:   "10.45.0.0/24",
		wgInstallRoute: true,
	}

	client.completeSessionHandoff(previous, next)

	if len(wgManager.removeCalls) != 1 {
		t.Fatalf("remove calls=%d want=1 for different WireGuard peer", len(wgManager.removeCalls))
	}
	got := wgManager.removeCalls[0]
	if got.SessionID != "session-old" {
		t.Fatalf("SessionID=%q want=session-old", got.SessionID)
	}
	if got.ExitPublicKey != "old-exit-public-key" {
		t.Fatalf("ExitPublicKey=%q want=old-exit-public-key", got.ExitPublicKey)
	}
	if got.ClientInnerIP != "10.44.0.2/32" {
		t.Fatalf("ClientInnerIP=%q want=10.44.0.2/32", got.ClientInnerIP)
	}
	if got.AllowedIPs != "0.0.0.0/0" {
		t.Fatalf("AllowedIPs=%q want=0.0.0.0/0", got.AllowedIPs)
	}
	if !got.InstallRoute {
		t.Fatal("InstallRoute=false want=true")
	}
}
