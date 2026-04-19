package keeper

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

type trackingStore struct {
	authorizations map[string]types.SponsorAuthorization
	delegations    map[string]types.DelegatedSessionCredit

	upsertAuthorizationCalls int
	getAuthorizationCalls    int
	upsertDelegationCalls    int
	getDelegationCalls       int
	listAuthorizationCalls   int
	listDelegationCalls      int
}

func newTrackingStore() *trackingStore {
	return &trackingStore{
		authorizations: make(map[string]types.SponsorAuthorization),
		delegations:    make(map[string]types.DelegatedSessionCredit),
	}
}

func (s *trackingStore) UpsertAuthorization(record types.SponsorAuthorization) {
	s.upsertAuthorizationCalls++
	s.authorizations[record.AuthorizationID] = record
}

func (s *trackingStore) GetAuthorization(authID string) (types.SponsorAuthorization, bool) {
	s.getAuthorizationCalls++
	record, ok := s.authorizations[authID]
	return record, ok
}

func (s *trackingStore) ListAuthorizations() []types.SponsorAuthorization {
	s.listAuthorizationCalls++
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

func (s *trackingStore) UpsertDelegation(record types.DelegatedSessionCredit) {
	s.upsertDelegationCalls++
	s.delegations[record.ReservationID] = record
}

func (s *trackingStore) GetDelegation(reservationID string) (types.DelegatedSessionCredit, bool) {
	s.getDelegationCalls++
	record, ok := s.delegations[reservationID]
	return record, ok
}

func (s *trackingStore) ListDelegations() []types.DelegatedSessionCredit {
	s.listDelegationCalls++
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

func TestNewKeeperWithStoreNilFallsBackToInMemory(t *testing.T) {
	t.Parallel()

	k := NewKeeperWithStore(nil)

	auth := types.SponsorAuthorization{
		AuthorizationID: "auth-fallback",
		SponsorID:       "sponsor-fallback",
		AppID:           "app-fallback",
		MaxCredits:      10,
	}
	k.UpsertAuthorization(auth)

	got, ok := k.GetAuthorization(auth.AuthorizationID)
	if !ok {
		t.Fatal("expected authorization to be present with nil-store fallback")
	}
	if got.AuthorizationID != auth.AuthorizationID {
		t.Fatalf("expected authorization id %q, got %q", auth.AuthorizationID, got.AuthorizationID)
	}
}

func TestKeeperDelegatesUpsertAndGetToCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	auth := types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}
	k.UpsertAuthorization(auth)

	if store.upsertAuthorizationCalls != 1 {
		t.Fatalf("expected 1 authorization upsert call, got %d", store.upsertAuthorizationCalls)
	}

	gotAuth, ok := k.GetAuthorization(auth.AuthorizationID)
	if !ok {
		t.Fatal("expected authorization from custom store")
	}
	if gotAuth.MaxCredits != auth.MaxCredits {
		t.Fatalf("expected max credits %d, got %d", auth.MaxCredits, gotAuth.MaxCredits)
	}
	if store.getAuthorizationCalls != 1 {
		t.Fatalf("expected 1 authorization get call, got %d", store.getAuthorizationCalls)
	}

	delegation := types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: auth.AuthorizationID,
		SponsorID:       auth.SponsorID,
		AppID:           auth.AppID,
		SessionID:       "sess-1",
		Credits:         10,
	}
	k.UpsertDelegation(delegation)

	if store.upsertDelegationCalls != 1 {
		t.Fatalf("expected 1 delegation upsert call, got %d", store.upsertDelegationCalls)
	}

	gotDelegation, ok := k.GetDelegation(delegation.ReservationID)
	if !ok {
		t.Fatal("expected delegation from custom store")
	}
	if gotDelegation.Credits != delegation.Credits {
		t.Fatalf("expected credits %d, got %d", delegation.Credits, gotDelegation.Credits)
	}
	if store.getDelegationCalls != 1 {
		t.Fatalf("expected 1 delegation get call, got %d", store.getDelegationCalls)
	}
}

func TestKeeperCreateAndDelegateUseCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	createdAuth, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	})
	if err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}
	if createdAuth.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected authorization status %q, got %q", chaintypes.ReconciliationPending, createdAuth.Status)
	}
	if store.upsertAuthorizationCalls == 0 || store.getAuthorizationCalls == 0 {
		t.Fatalf(
			"expected create path to touch custom authorization store, got upsert=%d get=%d",
			store.upsertAuthorizationCalls,
			store.getAuthorizationCalls,
		)
	}

	delegated, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: createdAuth.AuthorizationID,
		SponsorID:       createdAuth.SponsorID,
		AppID:           createdAuth.AppID,
		EndUserID:       "user-1",
		SessionID:       "sess-1",
		Credits:         10,
	})
	if err != nil {
		t.Fatalf("DelegateSessionCredit returned unexpected error: %v", err)
	}
	if delegated.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected delegation status %q, got %q", chaintypes.ReconciliationPending, delegated.Status)
	}
	if store.upsertDelegationCalls == 0 || store.getDelegationCalls == 0 {
		t.Fatalf(
			"expected delegate path to touch custom delegation store, got upsert=%d get=%d",
			store.upsertDelegationCalls,
			store.getDelegationCalls,
		)
	}
}

func TestNewFileStorePersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpnsponsor-store.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	auth := types.SponsorAuthorization{
		AuthorizationID: "auth-persist",
		SponsorID:       "sponsor-persist",
		AppID:           "app-persist",
		MaxCredits:      111,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertAuthorization(auth)

	delegation := types.DelegatedSessionCredit{
		ReservationID:   "res-persist",
		AuthorizationID: auth.AuthorizationID,
		SponsorID:       auth.SponsorID,
		AppID:           auth.AppID,
		EndUserID:       "user-persist",
		SessionID:       "session-persist",
		Credits:         42,
		Status:          chaintypes.ReconciliationConfirmed,
	}
	store.UpsertDelegation(delegation)

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen NewFileStore returned unexpected error: %v", err)
	}

	gotAuth, ok := reopened.GetAuthorization(auth.AuthorizationID)
	if !ok {
		t.Fatal("expected persisted authorization to be loaded after reopen")
	}
	if gotAuth != auth {
		t.Fatalf("expected persisted authorization %+v, got %+v", auth, gotAuth)
	}

	gotDelegation, ok := reopened.GetDelegation(delegation.ReservationID)
	if !ok {
		t.Fatal("expected persisted delegation to be loaded after reopen")
	}
	if gotDelegation != delegation {
		t.Fatalf("expected persisted delegation %+v, got %+v", delegation, gotDelegation)
	}
}

func TestNewFileStoreInvalidPath(t *testing.T) {
	t.Parallel()

	// Passing a directory path instead of a file path should fail during load.
	_, err := NewFileStore(t.TempDir())
	if err == nil {
		t.Fatal("expected NewFileStore to fail for directory path")
	}
}

func TestFileStoreListOrderingAndGetPaths(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpnsponsor-store-ordering.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	authIDs := []string{"auth-2", "auth-10", "auth-1"}
	for i, id := range authIDs {
		store.UpsertAuthorization(types.SponsorAuthorization{
			AuthorizationID: id,
			SponsorID:       "sponsor-ordering",
			AppID:           "app-ordering",
			MaxCredits:      int64(100 + i),
			Status:          chaintypes.ReconciliationPending,
		})
	}
	delegationIDs := []string{"res-2", "res-10", "res-1"}
	for i, id := range delegationIDs {
		store.UpsertDelegation(types.DelegatedSessionCredit{
			ReservationID:   id,
			AuthorizationID: "auth-1",
			SponsorID:       "sponsor-ordering",
			AppID:           "app-ordering",
			EndUserID:       "user-ordering",
			SessionID:       "session-ordering",
			Credits:         int64(10 + i),
			Status:          chaintypes.ReconciliationSubmitted,
		})
	}

	gotAuthorizations := store.ListAuthorizations()
	if len(gotAuthorizations) != len(authIDs) {
		t.Fatalf("expected %d authorizations, got %d", len(authIDs), len(gotAuthorizations))
	}
	expectedAuthIDs := append([]string(nil), authIDs...)
	sort.Strings(expectedAuthIDs)
	for i, expectedID := range expectedAuthIDs {
		if gotAuthorizations[i].AuthorizationID != expectedID {
			t.Fatalf("expected authorization index %d to be %q, got %q", i, expectedID, gotAuthorizations[i].AuthorizationID)
		}
		if _, ok := store.GetAuthorization(expectedID); !ok {
			t.Fatalf("expected GetAuthorization(%q) to succeed", expectedID)
		}
	}

	gotDelegations := store.ListDelegations()
	if len(gotDelegations) != len(delegationIDs) {
		t.Fatalf("expected %d delegations, got %d", len(delegationIDs), len(gotDelegations))
	}
	expectedDelegationIDs := append([]string(nil), delegationIDs...)
	sort.Strings(expectedDelegationIDs)
	for i, expectedID := range expectedDelegationIDs {
		if gotDelegations[i].ReservationID != expectedID {
			t.Fatalf("expected delegation index %d to be %q, got %q", i, expectedID, gotDelegations[i].ReservationID)
		}
		if _, ok := store.GetDelegation(expectedID); !ok {
			t.Fatalf("expected GetDelegation(%q) to succeed", expectedID)
		}
	}
}

func TestFileStoreWhitespaceSnapshotLoadsAndPersists(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpnsponsor-store-whitespace.json")
	if err := os.WriteFile(path, []byte("  \n\t  "), 0o600); err != nil {
		t.Fatalf("write whitespace snapshot: %v", err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore with whitespace snapshot returned unexpected error: %v", err)
	}
	if got := store.ListAuthorizations(); len(got) != 0 {
		t.Fatalf("expected no authorizations from whitespace snapshot, got %d", len(got))
	}
	if got := store.ListDelegations(); len(got) != 0 {
		t.Fatalf("expected no delegations from whitespace snapshot, got %d", len(got))
	}

	store.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-whitespace",
		SponsorID:       "sponsor-whitespace",
		AppID:           "app-whitespace",
		MaxCredits:      77,
		Status:          chaintypes.ReconciliationConfirmed,
	})

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen NewFileStore returned unexpected error: %v", err)
	}
	got, ok := reopened.GetAuthorization("auth-whitespace")
	if !ok {
		t.Fatal("expected persisted authorization after whitespace bootstrap")
	}
	if got.AuthorizationID != "auth-whitespace" || got.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("unexpected persisted authorization: %+v", got)
	}
}
