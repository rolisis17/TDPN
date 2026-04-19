package directory

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProviderTokenProofReplayPersistsAcrossReload(t *testing.T) {
	now := time.Now()
	storePath := filepath.Join(t.TempDir(), "provider_replay_store.json")

	s := &Service{
		providerTokenProofStoreFile: storePath,
		providerTokenProofSeen:      make(map[string]time.Time),
	}
	if err := s.markProviderTokenProofReplay("provider-token-1", "nonce-1", now); err != nil {
		t.Fatalf("mark replay nonce: %v", err)
	}

	loaded := &Service{providerTokenProofStoreFile: storePath}
	if err := loaded.loadProviderTokenProofReplayStore(now.Add(time.Second)); err != nil {
		t.Fatalf("load replay store: %v", err)
	}
	if err := loaded.markProviderTokenProofReplay("provider-token-1", "nonce-1", now.Add(2*time.Second)); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("expected replay rejection after reload, got %v", err)
	}
}

func TestLoadProviderTokenProofReplayStorePrunesExpiredEntries(t *testing.T) {
	now := time.Now()
	storePath := filepath.Join(t.TempDir(), "provider_replay_store.json")

	seed := &Service{
		providerTokenProofStoreFile: storePath,
		providerTokenProofSeen:      make(map[string]time.Time),
	}
	expired := now.Add(-providerRelayUpsertProofReplayTTL - time.Second)
	if err := seed.markProviderTokenProofReplay("provider-token-2", "nonce-old", expired); err != nil {
		t.Fatalf("seed old nonce: %v", err)
	}
	if err := seed.markProviderTokenProofReplay("provider-token-2", "nonce-new", now); err != nil {
		t.Fatalf("seed new nonce: %v", err)
	}

	loaded := &Service{providerTokenProofStoreFile: storePath}
	if err := loaded.loadProviderTokenProofReplayStore(now); err != nil {
		t.Fatalf("load replay store: %v", err)
	}
	if got := len(loaded.providerTokenProofSeen); got != 1 {
		t.Fatalf("expected only non-expired replay entry retained, got %d", got)
	}
	if _, ok := loaded.providerTokenProofSeen["provider-token-2:nonce-new"]; !ok {
		t.Fatalf("expected newest replay entry retained")
	}
}
