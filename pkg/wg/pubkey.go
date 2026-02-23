package wg

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type pubkeyDeps struct {
	readFile  func(string) ([]byte, error)
	runPubkey func(context.Context, []byte) ([]byte, error)
}

func defaultPubkeyDeps() pubkeyDeps {
	return pubkeyDeps{
		readFile:  os.ReadFile,
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
	cmd := exec.CommandContext(ctx, "wg", "pubkey")
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("wg pubkey failed: %w (%s)", err, string(out))
	}
	return out, nil
}
