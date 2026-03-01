package directory

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestParseDNSPeerHints(t *testing.T) {
	hints := parseDNSPeerHints([]string{
		"url=http://peer-a.local",
		"https://peer-b.local",
		"not-a-url",
		"http://peer-a.local",
	})
	if len(hints) != 2 {
		t.Fatalf("expected two normalized hints, got %d", len(hints))
	}
	if hints[0].URL != "http://peer-a.local" {
		t.Fatalf("unexpected first hint url %q", hints[0].URL)
	}
	if hints[1].URL != "https://peer-b.local" {
		t.Fatalf("unexpected second hint url %q", hints[1].URL)
	}
}

func TestParseDNSPeerHintsWithMetadata(t *testing.T) {
	validPub := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	hints := parseDNSPeerHints([]string{
		"url=https://peer-meta-a.local;operator=op-a;pub_key=" + validPub,
		"url=https://peer-meta-b.local,operator=op-b,pub_key=invalid",
	})
	if len(hints) != 2 {
		t.Fatalf("expected two normalized metadata hints, got %d", len(hints))
	}
	if hints[0].URL != "https://peer-meta-a.local" || hints[0].Operator != "op-a" || hints[0].PubKey != validPub {
		t.Fatalf("unexpected metadata hint[0]: %+v", hints[0])
	}
	if hints[1].URL != "https://peer-meta-b.local" || hints[1].Operator != "op-b" || hints[1].PubKey != "" {
		t.Fatalf("unexpected metadata hint[1]: %+v", hints[1])
	}
}

func TestSyncDNSDiscoveredPeers(t *testing.T) {
	seed := "seed.example"
	s := &Service{
		peerDiscoveryEnabled:  true,
		peerDiscoveryMax:      16,
		peerDiscoveryTTL:      10 * time.Minute,
		peerDiscoveryMinVotes: 1,
		peerDiscoveryDNSSeeds: []string{seed},
		dnsLookupTXT: func(_ context.Context, host string) ([]string, error) {
			if host != seed {
				t.Fatalf("unexpected dns lookup host %q", host)
			}
			return []string{"url=http://peer-dns-1.local"}, nil
		},
	}
	now := time.Now()
	if err := s.syncDNSDiscoveredPeers(context.Background(), now); err != nil {
		t.Fatalf("sync dns discovery failed: %v", err)
	}
	peers := s.snapshotSyncPeers(now)
	if len(peers) != 1 || peers[0] != "http://peer-dns-1.local" {
		t.Fatalf("expected discovered dns peer, got %+v", peers)
	}
}

func TestSyncDNSDiscoveredPeersRequireHintMetadata(t *testing.T) {
	seed := "seed.example"
	validPub := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	s := &Service{
		peerDiscoveryEnabled:     true,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMax:         16,
		peerDiscoveryTTL:         10 * time.Minute,
		peerDiscoveryMinVotes:    1,
		peerDiscoveryDNSSeeds:    []string{seed},
		dnsLookupTXT: func(_ context.Context, host string) ([]string, error) {
			if host != seed {
				t.Fatalf("unexpected dns lookup host %q", host)
			}
			return []string{"url=http://peer-dns-hinted.local;operator=op-dns-hinted;pub_key=" + validPub}, nil
		},
	}
	now := time.Now()
	if err := s.syncDNSDiscoveredPeers(context.Background(), now); err != nil {
		t.Fatalf("sync dns discovery failed: %v", err)
	}
	peers := s.snapshotSyncPeers(now)
	if len(peers) != 1 || peers[0] != "http://peer-dns-hinted.local" {
		t.Fatalf("expected discovered hinted dns peer, got %+v", peers)
	}
	if got := s.peerHintOperator("http://peer-dns-hinted.local"); got != "op-dns-hinted" {
		t.Fatalf("expected hinted operator persisted, got %q", got)
	}
	if got := s.peerHintPubKey("http://peer-dns-hinted.local"); got != validPub {
		t.Fatalf("expected hinted pubkey persisted, got %q", got)
	}
}

func TestSyncDNSDiscoveredPeersRequireHintDropsMissingMetadata(t *testing.T) {
	seed := "seed.example"
	s := &Service{
		peerDiscoveryEnabled:     true,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMax:         16,
		peerDiscoveryTTL:         10 * time.Minute,
		peerDiscoveryMinVotes:    1,
		peerDiscoveryDNSSeeds:    []string{seed},
		dnsLookupTXT: func(_ context.Context, host string) ([]string, error) {
			if host != seed {
				t.Fatalf("unexpected dns lookup host %q", host)
			}
			return []string{"url=http://peer-dns-nohint.local"}, nil
		},
	}
	now := time.Now()
	if err := s.syncDNSDiscoveredPeers(context.Background(), now); err != nil {
		t.Fatalf("sync dns discovery failed: %v", err)
	}
	peers := s.snapshotSyncPeers(now)
	if len(peers) != 0 {
		t.Fatalf("expected no discovered peers without dns hint metadata in strict mode, got %+v", peers)
	}
}
