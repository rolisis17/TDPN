package wg

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"

	"privacynode/internal/fileperm"
)

type preflightDeps struct {
	platform          string
	lookPath          func(string) (string, error)
	stat              func(string) (os.FileInfo, error)
	lstat             func(string) (os.FileInfo, error)
	open              func(string) (*os.File, error)
	run               func(context.Context, string, ...string) error
	interfaceByName   func(string) (*net.Interface, error)
	validateOwnerOnly func(string, os.FileInfo) error
}

func defaultPreflightDeps() preflightDeps {
	r := execRunner{}
	return preflightDeps{
		platform:          commandBackendPlatform(),
		lookPath:          exec.LookPath,
		stat:              os.Stat,
		lstat:             os.Lstat,
		open:              os.Open,
		run:               r.Run,
		interfaceByName:   net.InterfaceByName,
		validateOwnerOnly: fileperm.ValidateOwnerOnly,
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
	if err := commandBackendPlatformError(preflightPlatform(deps)); err != nil {
		return err
	}
	wgPath, err := resolveClientBinaryPath("wg", deps.lookPath)
	if err != nil {
		return fmt.Errorf("wg binary not found: %w", err)
	}
	if wgPath == "" {
		return fmt.Errorf("wg binary resolution failed")
	}
	lstatFn := deps.lstat
	if lstatFn == nil {
		lstatFn = deps.stat
	}
	if lstatFn == nil {
		lstatFn = os.Lstat
	}
	info, err := lstatFn(privateKeyPath)
	if err != nil {
		return fmt.Errorf("%s private key path invalid: %w", role, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s private key path must not be a symlink: %s", role, privateKeyPath)
	}
	if info.IsDir() {
		return fmt.Errorf("%s private key path points to directory: %s", role, privateKeyPath)
	}
	validateOwnerOnly := deps.validateOwnerOnly
	if validateOwnerOnly == nil {
		validateOwnerOnly = fileperm.ValidateOwnerOnly
	}
	if err := validateOwnerOnly(privateKeyPath, info); err != nil {
		return fmt.Errorf("%s private key path permissions are too broad (expected owner-only): %w", role, err)
	}
	f, err := deps.open(privateKeyPath)
	if err != nil {
		return fmt.Errorf("%s private key path unreadable: %w", role, err)
	}
	openedInfo, statErr := f.Stat()
	if statErr != nil {
		_ = f.Close()
		return fmt.Errorf("%s private key path stat failed: %w", role, statErr)
	}
	if !openedInfo.Mode().IsRegular() {
		_ = f.Close()
		return fmt.Errorf("%s private key path must be a regular file: %s", role, privateKeyPath)
	}
	if info.Sys() != nil && openedInfo.Sys() != nil && !os.SameFile(info, openedInfo) {
		_ = f.Close()
		return fmt.Errorf("%s private key path changed while opening: %s", role, privateKeyPath)
	}
	if err := validateOwnerOnly(privateKeyPath, openedInfo); err != nil {
		_ = f.Close()
		return fmt.Errorf("%s private key path permissions are too broad (expected owner-only): %w", role, err)
	}
	_ = f.Close()
	if err := runPreflightInterfaceCheck(ctx, iface, deps); err != nil {
		return fmt.Errorf("wg interface %s unavailable: %w", iface, err)
	}
	return nil
}

func runPreflightInterfaceCheck(ctx context.Context, iface string, deps preflightDeps) error {
	if preflightPlatform(deps) == "windows" {
		interfaceByName := deps.interfaceByName
		if interfaceByName == nil {
			interfaceByName = net.InterfaceByName
		}
		_, err := interfaceByName(iface)
		return err
	}
	ipPath, err := resolveClientBinaryPath("ip", deps.lookPath)
	if err != nil {
		return fmt.Errorf("ip binary not found: %w", err)
	}
	if ipPath == "" {
		return fmt.Errorf("ip binary resolution failed")
	}
	return deps.run(ctx, ipPath, "link", "show", "dev", iface)
}

func preflightPlatform(deps preflightDeps) string {
	return normalizeCommandBackendPlatform(deps.platform)
}
