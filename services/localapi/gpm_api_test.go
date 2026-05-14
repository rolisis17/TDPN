package localapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func issueGPMAuthChallengeForWallet(t *testing.T, svc *Service, walletAddress string) (string, string) {
	t.Helper()
	return issueGPMAuthChallengeForWalletAndProvider(t, svc, walletAddress, "keplr")
}

func issueGPMAuthChallengeForWalletAndProvider(t *testing.T, svc *Service, walletAddress string, walletProvider string) (string, string) {
	t.Helper()

	bodyBytes, err := json.Marshal(map[string]any{
		"wallet_address":  walletAddress,
		"wallet_provider": walletProvider,
	})
	if err != nil {
		t.Fatalf("json marshal challenge request: %v", err)
	}
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", string(bodyBytes))
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}
	message, _ := payload["message"].(string)
	if strings.TrimSpace(message) == "" {
		t.Fatalf("challenge message missing: %v", payload)
	}
	return challengeID, message
}

func verifyGPMAuthSecp256k1ProofForWallet(t *testing.T, svc *Service, walletAddress string) (int, map[string]any) {
	t.Helper()
	return verifyGPMAuthSecp256k1ProofForWalletWithType(t, svc, walletAddress, "secp256k1")
}

func verifyGPMAuthSecp256k1ProofForWalletWithType(t *testing.T, svc *Service, walletAddress string, publicKeyType string) (int, map[string]any) {
	t.Helper()

	challengeID, message := issueGPMAuthChallengeForWallet(t, svc, walletAddress)
	signature, publicKey := deterministicSecp256k1Proof(message)
	verifyRequest := map[string]any{
		"wallet_address":            walletAddress,
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": publicKeyType,
		"signed_message":            message,
	}
	bodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	return callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(bodyBytes))
}

func verifyGPMAuthSecp256k1WalletExtensionProofForWalletAndProviderWithType(t *testing.T, svc *Service, walletAddress string, walletProvider string, publicKeyType string) (int, map[string]any) {
	t.Helper()

	challengeID, message := issueGPMAuthChallengeForWalletAndProvider(t, svc, walletAddress, walletProvider)
	signature, publicKey := deterministicSecp256k1Proof(message)
	verifyRequest := map[string]any{
		"wallet_address":            walletAddress,
		"wallet_provider":           walletProvider,
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_kind":            "sign_arbitrary",
		"signature_source":          "wallet_extension",
		"signature_public_key":      publicKey,
		"signature_public_key_type": publicKeyType,
		"signed_message":            message,
	}
	bodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	return callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(bodyBytes))
}

func verifyGPMAuthSecp256k1ProofForWalletAndChain(t *testing.T, svc *Service, walletAddress string, challengeChainID string, verifyChainID string) (int, map[string]any) {
	t.Helper()

	challengeBody, err := json.Marshal(map[string]any{
		"wallet_address":  walletAddress,
		"wallet_provider": "keplr",
		"chain_id":        challengeChainID,
	})
	if err != nil {
		t.Fatalf("json marshal challenge request: %v", err)
	}
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", string(challengeBody))
	if code != http.StatusOK {
		return code, payload
	}
	challengeID, _ := payload["challenge_id"].(string)
	message, _ := payload["message"].(string)
	signature, publicKey := deterministicSecp256k1Proof(message)
	verifyRequest := map[string]any{
		"wallet_address":            walletAddress,
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"chain_id":                  verifyChainID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            message,
	}
	bodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}
	return callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(bodyBytes))
}

func deterministicSecp256k1WalletAddress(t *testing.T, hrp string) string {
	t.Helper()

	_, publicKey := deterministicSecp256k1Proof("address-derivation")
	walletAddress, err := deriveGPMAuthCosmosBech32AddressFromSecp256k1PublicKey(hrp, publicKey)
	if err != nil {
		t.Fatalf("derive wallet address: %v", err)
	}
	return walletAddress
}

func TestGPMRuntimeStateCapsChallengesPerWallet(t *testing.T) {
	st := newGPMRuntimeState()
	now := time.Now().UTC()
	for i := 0; i < gpmChallengeMaxEntriesPerWallet; i++ {
		ok := st.putChallenge(gpmWalletChallenge{
			ChallengeID:    fmt.Sprintf("challenge-%d", i),
			WalletAddress:  "cosmos1walletcap",
			WalletProvider: "keplr",
			ExpiresAt:      now.Add(time.Minute),
		}, now)
		if !ok {
			t.Fatalf("challenge %d rejected before per-wallet cap", i)
		}
	}
	if st.putChallenge(gpmWalletChallenge{
		ChallengeID:    "challenge-over-cap",
		WalletAddress:  "cosmos1walletcap",
		WalletProvider: "keplr",
		ExpiresAt:      now.Add(time.Minute),
	}, now) {
		t.Fatalf("expected per-wallet challenge cap rejection")
	}
	if !st.putChallenge(gpmWalletChallenge{
		ChallengeID:    "challenge-other-wallet",
		WalletAddress:  "cosmos1otherwallet",
		WalletProvider: "keplr",
		ExpiresAt:      now.Add(time.Minute),
	}, now) {
		t.Fatalf("challenge cap should not block a different wallet")
	}
}

func TestGPMRuntimeStateCapsSessionsPerWalletAndPrunesExpired(t *testing.T) {
	st := newGPMRuntimeState()
	now := time.Now().UTC()
	st.sessions["expired-session"] = gpmSession{
		Token:          "expired-session",
		WalletAddress:  "cosmos1sessioncap",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now.Add(-2 * time.Hour),
		ExpiresAt:      now.Add(-time.Hour),
	}
	for i := 0; i < gpmSessionMaxEntriesPerWallet; i++ {
		session := gpmSession{
			Token:          fmt.Sprintf("session-%d", i),
			WalletAddress:  "cosmos1sessioncap",
			WalletProvider: "keplr",
			Role:           "client",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		}
		if !st.putSession(session) {
			t.Fatalf("session %d rejected before cap", i)
		}
	}
	if st.putSession(gpmSession{
		Token:          "session-over-cap",
		WalletAddress:  "cosmos1sessioncap",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	}) {
		t.Fatalf("expected per-wallet session cap rejection")
	}
}

func TestGPMRuntimeStateRejectsExpiredSession(t *testing.T) {
	st := newGPMRuntimeState()
	now := time.Now().UTC()
	if st.putSession(gpmSession{
		Token:          "expired-session",
		WalletAddress:  "cosmos1expiredsession",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now.Add(-2 * time.Hour),
		ExpiresAt:      now.Add(-time.Hour),
	}) {
		t.Fatal("expected expired session to be rejected")
	}
	if _, ok := st.getSession("expired-session", now); ok {
		t.Fatal("expired session should not be stored")
	}
}

func TestGPMRuntimeStateRestorePersistentNormalizesSessionTokens(t *testing.T) {
	st := newGPMRuntimeState()
	now := time.Now().UTC()
	st.restorePersistent(now, []gpmSession{{
		Token:          "  persisted-session  ",
		WalletAddress:  "  COSMOS1PERSISTEDSESSION  ",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	}}, nil, nil, nil, nil, nil)

	session, ok := st.getSession("persisted-session", now)
	if !ok {
		t.Fatal("expected trimmed session token to be restored")
	}
	if session.Token != "persisted-session" {
		t.Fatalf("restored session token=%q want trimmed token", session.Token)
	}
	if session.WalletAddress != "cosmos1persistedsession" {
		t.Fatalf("restored wallet=%q want normalized wallet", session.WalletAddress)
	}
	if _, ok := st.getSession("  persisted-session  ", now); ok {
		t.Fatal("whitespace-padded session key should not be restored")
	}
}

func TestGPMRuntimeStateCapsGlobalApplicationStores(t *testing.T) {
	st := newGPMRuntimeState()
	for i := 0; i < gpmOperatorApplicationMaxEntries; i++ {
		st.operators[fmt.Sprintf("cosmos1operatorcap%d", i)] = gpmOperatorApplication{
			WalletAddress:   fmt.Sprintf("cosmos1operatorcap%d", i),
			ChainOperatorID: fmt.Sprintf("operator-%d", i),
			Status:          "pending",
		}
	}
	if st.upsertOperator(gpmOperatorApplication{
		WalletAddress:   "cosmos1operatoroverflow",
		ChainOperatorID: "operator-overflow",
		Status:          "pending",
	}) {
		t.Fatalf("expected operator application cap rejection for new wallet")
	}
	if !st.upsertOperator(gpmOperatorApplication{
		WalletAddress:   "cosmos1operatorcap0",
		ChainOperatorID: "operator-updated",
		Status:          "approved",
	}) {
		t.Fatalf("expected existing operator application update to be allowed at cap")
	}

	for i := 0; i < gpmContributionMaxEntries; i++ {
		st.contributions[fmt.Sprintf("cosmos1contribcap%d", i)] = gpmContributionState{
			WalletAddress: fmt.Sprintf("cosmos1contribcap%d", i),
			Role:          "micro-relay",
		}
	}
	if st.upsertContribution(gpmContributionState{
		WalletAddress: "cosmos1contriboverflow",
		Role:          "micro-relay",
	}) {
		t.Fatalf("expected contribution cap rejection for new wallet")
	}
	if !st.upsertContribution(gpmContributionState{
		WalletAddress: "cosmos1contribcap0",
		Role:          "micro-exit",
	}) {
		t.Fatalf("expected existing contribution update to be allowed at cap")
	}
}

func TestGPMOperatorSerializationIncludesBackendNextAction(t *testing.T) {
	tests := []struct {
		name                string
		app                 gpmOperatorApplication
		wantNextAction      string
		wantCondition       string
		wantEvidenceTrusted bool
	}{
		{
			name: "pending",
			app: gpmOperatorApplication{
				WalletAddress:   "cosmos1operatorpending",
				ChainOperatorID: "gpmvaloper1pending",
				Status:          "pending",
				UpdatedAt:       time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC),
			},
			wantNextAction: "wait_for_operator_approval",
			wantCondition:  "approved_operator_application",
		},
		{
			name: "rejected",
			app: gpmOperatorApplication{
				WalletAddress:   "cosmos1operatorrejected",
				ChainOperatorID: "gpmvaloper1rejected",
				Status:          "rejected",
				Reason:          "insufficient evidence",
				UpdatedAt:       time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC),
			},
			wantNextAction: "reapply_operator_application",
			wantCondition:  "updated_operator_application",
		},
		{
			name: "approved without trusted evidence",
			app: gpmOperatorApplication{
				WalletAddress:          "cosmos1operatorapprovedlocal",
				ChainOperatorID:        "gpmvaloper1approvedlocal",
				Status:                 "approved",
				ApprovalEvidenceSource: "local-admin",
				UpdatedAt:              time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC),
			},
			wantNextAction: "wait_for_trusted_approval_evidence",
			wantCondition:  "trusted_approval_evidence_source",
		},
		{
			name: "approved with trusted evidence",
			app: gpmOperatorApplication{
				WalletAddress:          "cosmos1operatorapprovedchain",
				ChainOperatorID:        "gpmvaloper1approvedchain",
				Status:                 "approved",
				ApprovalEvidenceSource: "chain-governance",
				UpdatedAt:              time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC),
			},
			wantNextAction:      "refresh_operator_session",
			wantCondition:       "matching_chain_operator_id",
			wantEvidenceTrusted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serializeGPMOperator(tt.app)
			if got["next_action"] != tt.wantNextAction {
				t.Fatalf("next_action=%v want=%s payload=%v", got["next_action"], tt.wantNextAction, got)
			}
			if got["approval_evidence_trusted"] != tt.wantEvidenceTrusted {
				t.Fatalf("approval_evidence_trusted=%v want=%v payload=%v", got["approval_evidence_trusted"], tt.wantEvidenceTrusted, got)
			}
			conditions, ok := got["required_conditions"].([]string)
			if !ok {
				t.Fatalf("required_conditions type=%T payload=%v", got["required_conditions"], got)
			}
			if !slices.Contains(conditions, tt.wantCondition) {
				t.Fatalf("required_conditions=%v missing %q", conditions, tt.wantCondition)
			}
		})
	}

	notSubmitted := serializeGPMOperatorNotSubmitted("COSMOS1OPERATORNEW")
	if notSubmitted["wallet_address"] != "cosmos1operatornew" {
		t.Fatalf("not-submitted wallet_address=%v payload=%v", notSubmitted["wallet_address"], notSubmitted)
	}
	if notSubmitted["next_action"] != "submit_operator_application" {
		t.Fatalf("not-submitted next_action=%v payload=%v", notSubmitted["next_action"], notSubmitted)
	}
	conditions, ok := notSubmitted["required_conditions"].([]string)
	if !ok || !slices.Contains(conditions, "chain_operator_id") {
		t.Fatalf("not-submitted required_conditions=%v payload=%v", notSubmitted["required_conditions"], notSubmitted)
	}
}

func TestGPMAuthVerifyRejectsSaturatedSessionStore(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCryptoProof = true
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")
	now := time.Now().UTC()
	for i := 0; i < gpmSessionMaxEntriesPerWallet; i++ {
		if !svc.gpmState.putSession(gpmSession{
			Token:          fmt.Sprintf("existing-session-%d", i),
			WalletAddress:  walletAddress,
			WalletProvider: "keplr",
			Role:           "client",
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
		}) {
			t.Fatalf("failed to prefill session %d", i)
		}
	}

	code, payload := verifyGPMAuthSecp256k1ProofForWallet(t, svc, walletAddress)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusServiceUnavailable, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "session store") {
		t.Fatalf("error=%q want session store saturation payload=%v", errMsg, payload)
	}
}

func TestGPMAuthChallengeAndVerifyBindExpectedChainIDAndWalletHRP(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCryptoProof = true
	svc.gpmAuthExpectedChainID = "gpm-testnet-1"
	svc.gpmAuthExpectedChainIDSource = "test"
	svc.gpmAuthExpectedWalletHRP = "gpm"
	svc.gpmAuthExpectedWalletHRPSource = "test"
	walletAddress := deterministicSecp256k1WalletAddress(t, "gpm")

	code, payload := verifyGPMAuthSecp256k1ProofForWalletAndChain(t, svc, walletAddress, "", "gpm-testnet-1")
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	sessionPayload, _ := payload["session"].(map[string]any)
	if got, _ := sessionPayload["chain_id"].(string); got != "gpm-testnet-1" {
		t.Fatalf("session chain_id=%q want=gpm-testnet-1 payload=%v", got, payload)
	}
	token, _ := payload["session_token"].(string)
	session, ok := svc.gpmState.getSession(token, time.Now().UTC())
	if !ok {
		t.Fatalf("session not stored for token %q", token)
	}
	if session.ChainID != "gpm-testnet-1" {
		t.Fatalf("stored session ChainID=%q want=gpm-testnet-1", session.ChainID)
	}
}

func TestGPMAuthVerifyRejectsMismatchedChainIDAgainstChallenge(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCryptoProof = true
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")

	code, payload := verifyGPMAuthSecp256k1ProofForWalletAndChain(t, svc, walletAddress, "gpm-testnet-1", "cosmoshub-4")
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "chain_id does not match issued challenge") {
		t.Fatalf("error=%q want chain mismatch payload=%v", errMsg, payload)
	}
}

func TestGPMAuthVerifyRejectsChainIDNotBoundToChallenge(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCryptoProof = true
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")

	code, payload := verifyGPMAuthSecp256k1ProofForWalletAndChain(t, svc, walletAddress, "", "gpm-testnet-1")
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "not part of the issued challenge") {
		t.Fatalf("error=%q want unbound chain rejection payload=%v", errMsg, payload)
	}
}

func TestGPMAuthChallengeRejectsWalletHRPMismatch(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmAuthExpectedWalletHRP = "gpm"
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")

	bodyBytes, err := json.Marshal(map[string]any{
		"wallet_address":  walletAddress,
		"wallet_provider": "keplr",
		"chain_id":        "gpm-testnet-1",
	})
	if err != nil {
		t.Fatalf("json marshal challenge request: %v", err)
	}
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", string(bodyBytes))
	if code != http.StatusBadRequest {
		t.Fatalf("challenge status=%d want=%d body=%v", code, http.StatusBadRequest, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "wallet_address HRP") {
		t.Fatalf("error=%q want wallet HRP mismatch payload=%v", errMsg, payload)
	}
}

func TestGPMAuthVerifyLocalSecp256k1WalletBindingMatchesDerivedAddress(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCryptoProof = true
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")

	code, payload := verifyGPMAuthSecp256k1ProofForWallet(t, svc, strings.ToUpper(walletAddress))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["wallet_binding_verified"].(bool); !got {
		t.Fatalf("wallet_binding_verified=%v want=true payload=%v", got, payload)
	}
	token, _ := payload["session_token"].(string)
	session, ok := svc.gpmState.getSession(token, time.Now().UTC())
	if !ok {
		t.Fatalf("session not stored for token %q", token)
	}
	if !session.WalletBindingVerified {
		t.Fatalf("session.WalletBindingVerified=%v want=true", session.WalletBindingVerified)
	}
	if session.AuthVerificationSource != "local_wallet" {
		t.Fatalf("AuthVerificationSource=%q want=local_wallet", session.AuthVerificationSource)
	}
}

func TestGPMAuthVerifyLocalSecp256k1WalletBindingAcceptsCosmosPubKeyTypeAlias(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCryptoProof = true
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")

	code, payload := verifyGPMAuthSecp256k1ProofForWalletWithType(t, svc, walletAddress, "/cosmos.crypto.secp256k1.PubKey")
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["wallet_binding_verified"].(bool); !got {
		t.Fatalf("wallet_binding_verified=%v want=true for Cosmos pubkey type alias payload=%v", got, payload)
	}
}

func TestGPMAuthVerifyWalletExtensionKeplrLeapAcceptAliasSecp256k1PubKeyTypes(t *testing.T) {
	tests := []struct {
		name           string
		walletProvider string
		publicKeyType  string
	}{
		{
			name:           "keplr type url cosmos alias",
			walletProvider: "keplr",
			publicKeyType:  "type.googleapis.com/cosmos.crypto.secp256k1.PubKey",
		},
		{
			name:           "leap tendermint alias",
			walletProvider: "leap",
			publicKeyType:  "tendermint/PubKeySecp256k1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			svc.gpmState = newGPMRuntimeState()
			svc.gpmRoleDefault = "client"
			svc.gpmAuthVerifyRequireCryptoProof = true
			svc.gpmAuthVerifyRequireWalletExt = true
			walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")

			code, payload := verifyGPMAuthSecp256k1WalletExtensionProofForWalletAndProviderWithType(t, svc, walletAddress, tc.walletProvider, tc.publicKeyType)
			if code != http.StatusOK {
				t.Fatalf("verify status=%d body=%v", code, payload)
			}
			if got, _ := payload["wallet_binding_verified"].(bool); !got {
				t.Fatalf("wallet_binding_verified=%v want=true for %s alias payload=%v", got, tc.walletProvider, payload)
			}
			sessionPayload, _ := payload["session"].(map[string]any)
			if role, _ := sessionPayload["role"].(string); role != "client" {
				t.Fatalf("role=%q want=client payload=%v", role, payload)
			}
		})
	}
}

func TestGPMAuthVerifyLocalSecp256k1WalletBindingMismatchUnboundAndStrictRejects(t *testing.T) {
	mismatchedWalletAddress, err := encodeGPMBech32Address("cosmos", []byte{
		0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10, 0x11, 0x12, 0x13,
	})
	if err != nil {
		t.Fatalf("encode mismatched wallet address: %v", err)
	}

	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	code, payload := verifyGPMAuthSecp256k1ProofForWallet(t, svc, mismatchedWalletAddress)
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["wallet_binding_verified"].(bool); got {
		t.Fatalf("wallet_binding_verified=%v want=false payload=%v", got, payload)
	}

	strictSvc, _ := newFakeService(t, false)
	strictSvc.gpmState = newGPMRuntimeState()
	strictSvc.gpmRoleDefault = "client"
	strictSvc.gpmAuthVerifyRequireCryptoProof = true
	code, payload = verifyGPMAuthSecp256k1ProofForWallet(t, strictSvc, mismatchedWalletAddress)
	if code != http.StatusUnauthorized {
		t.Fatalf("strict verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "local address binding matches") {
		t.Fatalf("error=%q want local address binding requirement payload=%v", errMsg, payload)
	}
}

func TestGPMAuthVerifyWalletExtensionMismatchedDerivedAddressRejectsAdminElevation(t *testing.T) {
	mismatchedWalletAddress, err := encodeGPMBech32Address("cosmos", []byte{
		0x14, 0x13, 0x12, 0x11, 0x10,
		0x0f, 0x0e, 0x0d, 0x0c, 0x0b,
		0x0a, 0x09, 0x08, 0x07, 0x06,
		0x05, 0x04, 0x03, 0x02, 0x01,
	})
	if err != nil {
		t.Fatalf("encode mismatched wallet address: %v", err)
	}

	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthVerifyRequireCryptoProof = true
	svc.gpmAuthVerifyRequireWalletExt = true
	svc.gpmAdminWalletAllowlist = normalizeGPMAdminWalletAllowlist(mismatchedWalletAddress)

	code, payload := verifyGPMAuthSecp256k1WalletExtensionProofForWalletAndProviderWithType(t, svc, mismatchedWalletAddress, "leap", "type.googleapis.com/cosmos.crypto.secp256k1.PubKey")
	if code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d want=%d body=%v", code, http.StatusUnauthorized, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "local address binding matches") {
		t.Fatalf("error=%q want local address binding requirement payload=%v", errMsg, payload)
	}
	if len(svc.gpmState.sessions) != 0 {
		t.Fatalf("stored sessions=%d want=0 after rejected mismatched admin-allowlisted wallet", len(svc.gpmState.sessions))
	}
}

func TestGPMAuthVerifyLocalSecp256k1WalletBindingChecksumHRPMismatchStaysUnbound(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")
	corruptHRPAddress := strings.Replace(walletAddress, "cosmos1", "osmo1", 1)
	if corruptHRPAddress == walletAddress {
		t.Fatalf("failed to corrupt wallet HRP: %q", walletAddress)
	}

	code, payload := verifyGPMAuthSecp256k1ProofForWallet(t, svc, corruptHRPAddress)
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["wallet_binding_verified"].(bool); got {
		t.Fatalf("wallet_binding_verified=%v want=false for invalid bech32 checksum payload=%v", got, payload)
	}
}

func TestGPMAuthVerifyEd25519ProofRemainsSignatureOnlyForCosmosWallet(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")
	challengeID, message := issueGPMAuthChallengeForWallet(t, svc, walletAddress)
	signature, publicKey := deterministicEd25519Proof(message)
	verifyRequest := map[string]any{
		"wallet_address":            walletAddress,
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "ed25519",
		"signed_message":            message,
	}
	bodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal verify request: %v", err)
	}

	code, payload := callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(bodyBytes))
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	if got, _ := payload["wallet_binding_verified"].(bool); got {
		t.Fatalf("wallet_binding_verified=%v want=false for ed25519 payload=%v", got, payload)
	}
}

func TestGPMAuthVerifyLocalSecp256k1BindingDoesNotReplaceCommandBackedAdminVerification(t *testing.T) {
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")

	localSvc, _ := newFakeService(t, false)
	localSvc.gpmState = newGPMRuntimeState()
	localSvc.gpmRoleDefault = "client"
	localSvc.gpmAdminWalletAllowlist = normalizeGPMAdminWalletAllowlist(walletAddress)
	code, payload := verifyGPMAuthSecp256k1ProofForWallet(t, localSvc, walletAddress)
	if code != http.StatusOK {
		t.Fatalf("local verify status=%d body=%v", code, payload)
	}
	sessionPayload, _ := payload["session"].(map[string]any)
	if role, _ := sessionPayload["role"].(string); role != "client" {
		t.Fatalf("role=%q want=client without command-backed admin verification payload=%v", role, payload)
	}
	token, _ := payload["session_token"].(string)
	session, ok := localSvc.gpmState.getSession(token, time.Now().UTC())
	if !ok {
		t.Fatalf("local session not stored for token %q", token)
	}
	if !session.WalletBindingVerified || session.AuthVerificationSource != "local_wallet" {
		t.Fatalf("session=%+v want local wallet-bound non-admin", session)
	}

	commandSvc, _ := newFakeService(t, false)
	commandSvc.gpmState = newGPMRuntimeState()
	commandSvc.gpmRoleDefault = "client"
	commandSvc.gpmAdminWalletAllowlist = normalizeGPMAdminWalletAllowlist(walletAddress)
	challengeID, message := issueGPMAuthChallengeForWallet(t, commandSvc, walletAddress)
	signature, publicKey := deterministicSecp256k1Proof(message)
	commandSvc.gpmAuthVerifyCommand = authVerifierCommandExpectSignature(signature, "bad-signature", 12)
	verifyRequest := map[string]any{
		"wallet_address":            walletAddress,
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            message,
	}
	bodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal command verify request: %v", err)
	}
	code, payload = callJSONHandler(t, commandSvc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(bodyBytes))
	if code != http.StatusOK {
		t.Fatalf("command verify status=%d body=%v", code, payload)
	}
	sessionPayload, _ = payload["session"].(map[string]any)
	if role, _ := sessionPayload["role"].(string); role != "admin" {
		t.Fatalf("role=%q want=admin with command-backed admin verification payload=%v", role, payload)
	}
	token, _ = payload["session_token"].(string)
	session, ok = commandSvc.gpmState.getSession(token, time.Now().UTC())
	if !ok {
		t.Fatalf("command session not stored for token %q", token)
	}
	if !session.WalletBindingVerified || session.AuthVerificationSource != "command" {
		t.Fatalf("session=%+v want command wallet-bound admin", session)
	}
}

func TestGPMAuthVerifyCommandUsesCommandSlotLimit(t *testing.T) {
	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.commandSlots = make(chan struct{}, 1)
	svc.commandSlots <- struct{}{}

	challengeID, message := issueGPMAuthChallengeForWallet(t, svc, walletAddress)
	signature, publicKey := deterministicSecp256k1Proof(message)
	svc.gpmAuthVerifyCommand = authVerifierCommandExpectSignature(signature, "bad-signature", 12)
	verifyRequest := map[string]any{
		"wallet_address":            walletAddress,
		"wallet_provider":           "keplr",
		"challenge_id":              challengeID,
		"signature":                 signature,
		"signature_public_key":      publicKey,
		"signature_public_key_type": "secp256k1",
		"signed_message":            message,
	}
	bodyBytes, err := json.Marshal(verifyRequest)
	if err != nil {
		t.Fatalf("json marshal command verify request: %v", err)
	}
	code, payload := callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", string(bodyBytes))
	if code != http.StatusUnauthorized {
		t.Fatalf("status=%d want unauthorized when verifier slot is saturated payload=%v", code, payload)
	}
	if got, _ := payload["error"].(string); !strings.Contains(got, "concurrency limit") {
		t.Fatalf("error=%q want concurrency limit payload=%v", got, payload)
	}
}
