package localapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGPMClientRegisterRejectsSessionAfterWalletChainPolicyRotation(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthExpectedChainID = "gpm-mainnet-1"
	svc.gpmAuthExpectedChainIDSource = "test"

	bootstrapDirectory := "https://directory.globalprivatemesh.example:8081"
	now := time.Now().UTC()
	manifestHits := 0
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{bootstrapDirectory},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	const token = "gpm-session-token-policy-rotated-client-register"
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1policyrotatedclient",
		WalletProvider:        "keplr",
		ChainID:               "gpm-testnet-1",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","bootstrap_directory":"` + bootstrapDirectory + `","path_profile":"2hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusForbidden {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "session no longer satisfies wallet auth policy") || !strings.Contains(errMsg, "chain_id") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
	if manifestHits != 0 {
		t.Fatalf("expected wallet policy revalidation before manifest fetch, got %d manifest hits", manifestHits)
	}

	session, ok := svc.gpmState.getSession(token, now)
	if !ok {
		t.Fatal("expected rejected session to remain present")
	}
	if session.BootstrapDirectory != "" || session.InviteKey != "" || session.PathProfile != "" {
		t.Fatalf("session was provisioned despite policy rejection: %+v", session)
	}
}

func TestGPMOperatorApplyRejectsSessionAfterWalletChainPolicyRotation(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthExpectedChainID = "gpm-mainnet-1"
	svc.gpmAuthExpectedChainIDSource = "test"

	const token = "gpm-session-token-policy-rotated-operator-apply"
	now := time.Now().UTC()
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         "cosmos1policyrotatedoperator",
		WalletProvider:        "keplr",
		ChainID:               "gpm-testnet-1",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	applyBody := `{"session_token":"` + token + `","chain_operator_id":"gpmvaloper1policyrotated","server_label":"rotated"}`
	code, payload := callJSONHandler(t, svc.handleGPMOperatorApply, http.MethodPost, "/v1/gpm/onboarding/operator/apply", applyBody)
	if code != http.StatusForbidden {
		t.Fatalf("operator apply status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "session no longer satisfies wallet auth policy") || !strings.Contains(errMsg, "chain_id") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
	if _, ok := svc.gpmState.getOperator("cosmos1policyrotatedoperator"); ok {
		t.Fatalf("operator application was persisted despite policy rejection")
	}
}

func TestGPMOperatorApplyRejectsSessionAfterWalletHRPPolicyRotation(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmAuthExpectedWalletHRP = "gpm"
	svc.gpmAuthExpectedWalletHRPSource = "test"

	walletAddress := deterministicSecp256k1WalletAddress(t, "cosmos")
	const token = "gpm-session-token-policy-rotated-operator-hrp"
	now := time.Now().UTC()
	svc.gpmState.putSession(gpmSession{
		Token:                 token,
		WalletAddress:         walletAddress,
		WalletProvider:        "keplr",
		Role:                  "client",
		WalletBindingVerified: true,
		CreatedAt:             now,
		ExpiresAt:             now.Add(time.Hour),
	})

	applyBody := `{"session_token":"` + token + `","chain_operator_id":"gpmvaloper1policyrotatedhrp","server_label":"rotated-hrp"}`
	code, payload := callJSONHandler(t, svc.handleGPMOperatorApply, http.MethodPost, "/v1/gpm/onboarding/operator/apply", applyBody)
	if code != http.StatusForbidden {
		t.Fatalf("operator apply status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "session no longer satisfies wallet auth policy") || !strings.Contains(errMsg, "wallet_address HRP") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
	if _, ok := svc.gpmState.getOperator(walletAddress); ok {
		t.Fatalf("operator application was persisted despite HRP policy rejection")
	}
}
