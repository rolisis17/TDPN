package module

import (
	"errors"
	"strings"
	"testing"
	"time"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestMsgServerAuthorizeSponsorHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-1",
			SponsorID:       "sponsor-1",
			AppID:           "app-1",
			MaxCredits:      100,
		},
	}

	resp, err := server.AuthorizeSponsor(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first authorization")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first authorization")
	}
	if resp.Authorization.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, resp.Authorization.Status)
	}
}

func TestMsgServerAuthorizeSponsorIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-2",
			SponsorID:       "sponsor-2",
			AppID:           "app-2",
			MaxCredits:      200,
		},
	}
	if _, err := server.AuthorizeSponsor(req); err != nil {
		t.Fatalf("first authorize failed: %v", err)
	}

	resp, err := server.AuthorizeSponsor(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed authorization")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed authorization")
	}
}

func TestMsgServerAuthorizeSponsorConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	base := AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-3",
			SponsorID:       "sponsor-3",
			AppID:           "app-3",
			MaxCredits:      150,
		},
	}
	if _, err := server.AuthorizeSponsor(base); err != nil {
		t.Fatalf("seed authorization failed: %v", err)
	}

	conflict := base
	conflict.Authorization.MaxCredits = 151
	resp, err := server.AuthorizeSponsor(conflict)
	if err == nil {
		t.Fatal("expected authorization conflict error")
	}
	if !errors.Is(err, ErrAuthorizationConflict) {
		t.Fatalf("expected ErrAuthorizationConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerAuthorizeSponsorInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-invalid",
			SponsorID:       "",
			AppID:           "app-1",
			MaxCredits:      10,
		},
	})
	if err == nil {
		t.Fatal("expected invalid authorization error")
	}
	if !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("expected ErrInvalidAuthorization, got %v", err)
	}
}

func TestMsgServerDelegateCreditHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-4",
			SponsorID:       "sponsor-4",
			AppID:           "app-4",
			MaxCredits:      1000,
		},
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	req := DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-4",
			AuthorizationID: "auth-4",
			SponsorID:       "sponsor-4",
			AppID:           "app-4",
			EndUserID:       "user-4",
			SessionID:       "sess-4",
			Credits:         100,
		},
	}
	resp, err := server.DelegateCredit(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first delegation")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first delegation")
	}
	if resp.Delegation.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, resp.Delegation.Status)
	}
}

func TestMsgServerDelegateCreditIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-5",
			SponsorID:       "sponsor-5",
			AppID:           "app-5",
			MaxCredits:      200,
		},
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	req := DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-5",
			AuthorizationID: "auth-5",
			SponsorID:       "sponsor-5",
			AppID:           "app-5",
			SessionID:       "sess-5",
			Credits:         50,
		},
	}
	if _, err := server.DelegateCredit(req); err != nil {
		t.Fatalf("first delegate failed: %v", err)
	}

	resp, err := server.DelegateCredit(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed delegation")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed delegation")
	}
}

func TestMsgServerDelegateCreditConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-6",
			SponsorID:       "sponsor-6",
			AppID:           "app-6",
			MaxCredits:      500,
		},
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	base := DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-6",
			AuthorizationID: "auth-6",
			SponsorID:       "sponsor-6",
			AppID:           "app-6",
			SessionID:       "sess-6",
			Credits:         80,
		},
	}
	if _, err := server.DelegateCredit(base); err != nil {
		t.Fatalf("first delegate failed: %v", err)
	}

	conflict := base
	conflict.Delegation.Credits = 81
	resp, err := server.DelegateCredit(conflict)
	if err == nil {
		t.Fatal("expected delegation conflict error")
	}
	if !errors.Is(err, ErrDelegationConflict) {
		t.Fatalf("expected ErrDelegationConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerDelegateCreditInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.DelegateCredit(DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID: "res-invalid",
			SponsorID:     "sponsor-7",
			SessionID:     "sess-7",
			Credits:       10,
		},
	})
	if err == nil {
		t.Fatal("expected invalid delegation error")
	}
	if !errors.Is(err, ErrInvalidDelegation) {
		t.Fatalf("expected ErrInvalidDelegation, got %v", err)
	}
}

func TestMsgServerDelegateCreditMissingAuthorizationPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.DelegateCredit(DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-missing-auth",
			AuthorizationID: "auth-missing",
			SponsorID:       "sponsor-8",
			AppID:           "app-8",
			SessionID:       "sess-8",
			Credits:         10,
		},
	})
	if err == nil {
		t.Fatal("expected missing authorization error")
	}
	if !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("expected ErrAuthorizationNotFound, got %v", err)
	}
}

func TestMsgServerDelegateCreditLinkageMismatchPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-linkage",
			SponsorID:       "sponsor-linkage",
			AppID:           "app-linkage",
			MaxCredits:      50,
		},
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	_, err = server.DelegateCredit(DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-linkage",
			AuthorizationID: "auth-linkage",
			SponsorID:       "sponsor-other",
			AppID:           "app-linkage",
			SessionID:       "sess-linkage",
			Credits:         10,
		},
	})
	if err == nil {
		t.Fatal("expected linkage mismatch error")
	}
	if !errors.Is(err, ErrInvalidDelegation) {
		t.Fatalf("expected ErrInvalidDelegation, got %v", err)
	}
	if !strings.Contains(err.Error(), "linkage does not match") {
		t.Fatalf("expected linkage mismatch details in error, got %v", err)
	}
}

func TestMsgServerDelegateCreditExpiredAuthorizationPropagation(t *testing.T) {
	t.Parallel()

	nowUnix := time.Now().Unix()
	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-expired",
			SponsorID:       "sponsor-expired",
			AppID:           "app-expired",
			MaxCredits:      50,
			ExpiresAtUnix:   nowUnix - 1,
		},
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	_, err = server.DelegateCredit(DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-expired",
			AuthorizationID: "auth-expired",
			SponsorID:       "sponsor-expired",
			AppID:           "app-expired",
			SessionID:       "sess-expired",
			Credits:         10,
		},
		CurrentTimeUnix: nowUnix,
	})
	if err == nil {
		t.Fatal("expected expired authorization error")
	}
	if !errors.Is(err, ErrInvalidDelegation) {
		t.Fatalf("expected ErrInvalidDelegation, got %v", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired details in error, got %v", err)
	}
}

func TestMsgServerDelegateCreditMaxCreditsExceededPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-max",
			SponsorID:       "sponsor-max",
			AppID:           "app-max",
			MaxCredits:      100,
		},
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	if _, err := server.DelegateCredit(DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-max-1",
			AuthorizationID: "auth-max",
			SponsorID:       "sponsor-max",
			AppID:           "app-max",
			SessionID:       "sess-max-1",
			Credits:         60,
		},
	}); err != nil {
		t.Fatalf("first delegation failed: %v", err)
	}

	_, err = server.DelegateCredit(DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-max-2",
			AuthorizationID: "auth-max",
			SponsorID:       "sponsor-max",
			AppID:           "app-max",
			SessionID:       "sess-max-2",
			Credits:         41,
		},
	})
	if err == nil {
		t.Fatal("expected max credits exceeded error")
	}
	if !errors.Is(err, ErrInvalidDelegation) {
		t.Fatalf("expected ErrInvalidDelegation, got %v", err)
	}
	if !strings.Contains(err.Error(), "max credits exceeded") {
		t.Fatalf("expected max credits exceeded details in error, got %v", err)
	}
}

func TestMsgServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewMsgServer(k)

	_, authErr := server.AuthorizeSponsor(AuthorizeSponsorRequest{
		Authorization: types.SponsorAuthorization{
			AuthorizationID: "auth-nil",
			SponsorID:       "sponsor-nil",
			AppID:           "app-nil",
			MaxCredits:      1,
		},
	})
	if !errors.Is(authErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on authorize, got %v", authErr)
	}

	_, delegateErr := server.DelegateCredit(DelegateCreditRequest{
		Delegation: types.DelegatedSessionCredit{
			ReservationID:   "res-nil",
			AuthorizationID: "auth-nil",
			SponsorID:       "sponsor-nil",
			SessionID:       "sess-nil",
			Credits:         1,
		},
	})
	if !errors.Is(delegateErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on delegate, got %v", delegateErr)
	}
}
