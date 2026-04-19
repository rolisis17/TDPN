package wg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDerivePublicKeyFromPrivateFile(t *testing.T) {
	privateKeyPath := "/tmp/exit.key"
	validPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	pub, err := derivePublicKeyFromPrivateFile(context.Background(), privateKeyPath, pubkeyDeps{
		readFile: func(path string) ([]byte, error) {
			if path != privateKeyPath {
				t.Fatalf("unexpected private key path: %s", path)
			}
			return []byte("private-key"), nil
		},
		runPubkey: func(_ context.Context, stdin []byte) ([]byte, error) {
			if got := string(stdin); got != "private-key\n" {
				t.Fatalf("unexpected stdin payload: %q", got)
			}
			return []byte(validPub + "\n"), nil
		},
	})
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if pub != validPub {
		t.Fatalf("unexpected public key: %q", pub)
	}
}

func TestDerivePublicKeyFromPrivateFileMissingPath(t *testing.T) {
	if _, err := derivePublicKeyFromPrivateFile(context.Background(), "", pubkeyDeps{}); err == nil {
		t.Fatalf("expected error for missing private key path")
	}
}

func TestDerivePublicKeyFromPrivateFileReadError(t *testing.T) {
	_, err := derivePublicKeyFromPrivateFile(context.Background(), "/tmp/missing.key", pubkeyDeps{
		readFile: func(string) ([]byte, error) {
			return nil, errors.New("not found")
		},
		runPubkey: func(context.Context, []byte) ([]byte, error) {
			return nil, nil
		},
	})
	if err == nil {
		t.Fatalf("expected read error")
	}
}

func TestDerivePublicKeyFromPrivateFileEmptyKey(t *testing.T) {
	_, err := derivePublicKeyFromPrivateFile(context.Background(), "/tmp/empty.key", pubkeyDeps{
		readFile: func(string) ([]byte, error) {
			return []byte("   "), nil
		},
		runPubkey: func(context.Context, []byte) ([]byte, error) {
			return nil, nil
		},
	})
	if err == nil {
		t.Fatalf("expected empty private key error")
	}
}

func TestDerivePublicKeyFromPrivateFileRunError(t *testing.T) {
	_, err := derivePublicKeyFromPrivateFile(context.Background(), "/tmp/exit.key", pubkeyDeps{
		readFile: func(string) ([]byte, error) {
			return []byte("private-key"), nil
		},
		runPubkey: func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New("wg pubkey failed")
		},
	})
	if err == nil {
		t.Fatalf("expected run error")
	}
}

func TestDerivePublicKeyFromPrivateFileRejectsInvalidOutput(t *testing.T) {
	_, err := derivePublicKeyFromPrivateFile(context.Background(), "/tmp/exit.key", pubkeyDeps{
		readFile: func(string) ([]byte, error) {
			return []byte("private-key"), nil
		},
		runPubkey: func(context.Context, []byte) ([]byte, error) {
			return []byte("not-a-valid-key"), nil
		},
	})
	if err == nil {
		t.Fatalf("expected invalid output error")
	}
}

func TestRunWGPubkeyCommandFailsWhenBinaryLookupFails(t *testing.T) {
	original := commandManagerLookPath
	t.Cleanup(func() { commandManagerLookPath = original })
	commandManagerLookPath = func(string) (string, error) {
		return "", fmt.Errorf("wg not found")
	}

	_, err := runWGPubkeyCommand(context.Background(), []byte("private-key\n"))
	if err == nil {
		t.Fatalf("expected binary lookup failure")
	}
	if !strings.Contains(err.Error(), "resolve wg binary") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadPrivateKeyFileStrictRejectsOversizedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "wg-private.key")
	data := []byte(strings.Repeat("a", int(wgPrivateKeyFileMaxBytes+1)))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	_, err := readPrivateKeyFileStrict(path)
	if err == nil {
		t.Fatalf("expected max size error")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected max size error, got: %v", err)
	}
}

func TestReadPrivateKeyFileStrictReadsValidFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "wg-private.key")
	expected := []byte("private-key-material")
	if err := os.WriteFile(path, expected, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	got, err := readPrivateKeyFileStrict(path)
	if err != nil {
		t.Fatalf("read private key file: %v", err)
	}
	if string(got) != string(expected) {
		t.Fatalf("unexpected key file content: got %q want %q", string(got), string(expected))
	}
}
