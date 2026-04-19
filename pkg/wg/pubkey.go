package wg

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"privacynode/internal/fileperm"
)

const wgPrivateKeyFileMaxBytes int64 = 8 * 1024

type pubkeyDeps struct {
	readFile  func(string) ([]byte, error)
	runPubkey func(context.Context, []byte) ([]byte, error)
}

func defaultPubkeyDeps() pubkeyDeps {
	return pubkeyDeps{
		readFile:  readPrivateKeyFileStrict,
		runPubkey: runWGPubkeyCommand,
	}
}

func DerivePublicKeyFromPrivateFile(ctx context.Context, privateKeyPath string) (string, error) {
	return derivePublicKeyFromPrivateFile(ctx, privateKeyPath, defaultPubkeyDeps())
}

func derivePublicKeyFromPrivateFile(ctx context.Context, privateKeyPath string, deps pubkeyDeps) (string, error) {
	privateKeyPath = strings.TrimSpace(privateKeyPath)
	if privateKeyPath == "" {
		return "", fmt.Errorf("wg private key path is required")
	}
	if deps.readFile == nil || deps.runPubkey == nil {
		return "", fmt.Errorf("wg pubkey dependencies are not configured")
	}
	raw, err := deps.readFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("read private key: %w", err)
	}
	priv := strings.TrimSpace(string(raw))
	if priv == "" {
		return "", fmt.Errorf("private key file is empty")
	}
	out, err := deps.runPubkey(ctx, []byte(priv+"\n"))
	if err != nil {
		return "", err
	}
	pub := strings.TrimSpace(string(out))
	if !IsValidPublicKey(pub) {
		return "", fmt.Errorf("wg pubkey output is invalid")
	}
	return pub, nil
}

func runWGPubkeyCommand(ctx context.Context, stdin []byte) ([]byte, error) {
	wgBinary, err := resolveClientBinaryPath("wg", commandManagerLookPath)
	if err != nil {
		return nil, fmt.Errorf("resolve wg binary: %w", err)
	}
	cmd := exec.CommandContext(ctx, wgBinary, "pubkey")
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("wg pubkey failed: %w (%s)", err, string(out))
	}
	return out, nil
}

func readPrivateKeyFileStrict(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("private key file path is required")
	}
	linfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat private key file: %w", err)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("private key file %q must not be a symlink", path)
	}
	if !linfo.Mode().IsRegular() {
		return nil, fmt.Errorf("private key file %q must be a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private key file: %w", err)
	}
	defer f.Close()
	finfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open private key file: %w", err)
	}
	if !os.SameFile(linfo, finfo) {
		return nil, fmt.Errorf("private key file %q changed during open", path)
	}
	if err := fileperm.ValidateOwnerOnly(path, finfo); err != nil {
		return nil, err
	}
	if finfo.Size() > wgPrivateKeyFileMaxBytes {
		return nil, fmt.Errorf("private key file %q exceeds max size %d bytes", path, wgPrivateKeyFileMaxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, wgPrivateKeyFileMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	if int64(len(b)) > wgPrivateKeyFileMaxBytes {
		return nil, fmt.Errorf("private key file %q exceeds max size %d bytes", path, wgPrivateKeyFileMaxBytes)
	}
	return b, nil
}
