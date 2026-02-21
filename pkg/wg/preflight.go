package wg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

type preflightDeps struct {
	lookPath func(string) (string, error)
	stat     func(string) (os.FileInfo, error)
	open     func(string) (*os.File, error)
	run      func(context.Context, string, ...string) error
}

func defaultPreflightDeps() preflightDeps {
	r := execRunner{}
	return preflightDeps{
		lookPath: exec.LookPath,
		stat:     os.Stat,
		open:     os.Open,
		run:      r.Run,
	}
}

func PreflightCommandBackend(ctx context.Context, iface string, privateKeyPath string) error {
	return runPreflight(ctx, iface, privateKeyPath, "exit", defaultPreflightDeps())
}

func PreflightCommandClientBackend(ctx context.Context, iface string, privateKeyPath string) error {
	return runPreflight(ctx, iface, privateKeyPath, "client", defaultPreflightDeps())
}

func runPreflight(ctx context.Context, iface string, privateKeyPath string, role string, deps preflightDeps) error {
	if iface == "" {
		return fmt.Errorf("%s wg interface is required", role)
	}
	if privateKeyPath == "" {
		return fmt.Errorf("%s wg private key path is required", role)
	}
	if _, err := deps.lookPath("wg"); err != nil {
		return fmt.Errorf("wg binary not found: %w", err)
	}
	if _, err := deps.lookPath("ip"); err != nil {
		return fmt.Errorf("ip binary not found: %w", err)
	}
	info, err := deps.stat(privateKeyPath)
	if err != nil {
		return fmt.Errorf("%s private key path invalid: %w", role, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s private key path points to directory: %s", role, privateKeyPath)
	}
	f, err := deps.open(privateKeyPath)
	if err != nil {
		return fmt.Errorf("%s private key path unreadable: %w", role, err)
	}
	_ = f.Close()
	if err := deps.run(ctx, "ip", "link", "show", "dev", iface); err != nil {
		return fmt.Errorf("wg interface %s unavailable: %w", iface, err)
	}
	return nil
}
