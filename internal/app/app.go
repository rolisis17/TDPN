package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"privacynode/services/directory"
	"privacynode/services/entry"
	"privacynode/services/exit"
	"privacynode/services/issuer"
	"privacynode/services/wgio"
	"privacynode/services/wgioinject"
	"privacynode/services/wgiotap"
)

type Roles struct {
	Client     bool
	Entry      bool
	Exit       bool
	Directory  bool
	Issuer     bool
	WGIO       bool
	WGIOTap    bool
	WGIOInject bool
}

func (r Roles) Any() bool {
	return r.Client || r.Entry || r.Exit || r.Directory || r.Issuer || r.WGIO || r.WGIOTap || r.WGIOInject
}

type Config struct {
	ConfigPath string
	Roles      Roles
}

func Run(ctx context.Context, cfg Config) error {
	autoWireRoleURLs(cfg.Roles)

	var runners []func(context.Context) error

	if cfg.Roles.Directory {
		svc := directory.New()
		runners = append(runners, svc.Run)
	}
	if cfg.Roles.Issuer {
		svc := issuer.New()
		runners = append(runners, svc.Run)
	}
	if cfg.Roles.Entry {
		svc := entry.New()
		runners = append(runners, svc.Run)
	}
	if cfg.Roles.Exit {
		svc := exit.New()
		runners = append(runners, svc.Run)
	}
	if cfg.Roles.Client {
		c := NewClient()
		runners = append(runners, c.Run)
	}
	if cfg.Roles.WGIO {
		svc := wgio.New()
		runners = append(runners, svc.Run)
	}
	if cfg.Roles.WGIOTap {
		svc := wgiotap.New()
		runners = append(runners, svc.Run)
	}
	if cfg.Roles.WGIOInject {
		svc := wgioinject.New()
		runners = append(runners, svc.Run)
	}

	if len(runners) == 0 {
		return errors.New("no services enabled")
	}

	errCh := make(chan error, len(runners))
	for _, runner := range runners {
		go func(runFn func(context.Context) error) {
			errCh <- runFn(ctx)
		}(runner)
	}

	for i := 0; i < len(runners); i++ {
		err := <-errCh
		if err == nil || errors.Is(err, context.Canceled) {
			continue
		}
		return fmt.Errorf("node stopped: %w", err)
	}

	log.Println("node stopped")
	return nil
}

func autoWireRoleURLs(roles Roles) {
	if roles.Issuer && (roles.Entry || roles.Exit || roles.Client) {
		setURLFromAddrIfUnset("ISSUER_URL", "ISSUER_ADDR")
	}
	if roles.Directory && roles.Client {
		setURLFromAddrIfUnset("DIRECTORY_URL", "DIRECTORY_ADDR")
	}
	if roles.Entry && (roles.Client || roles.Directory) {
		setURLFromAddrIfUnset("ENTRY_URL", "ENTRY_ADDR")
	}
	if roles.Exit && (roles.Client || roles.Directory) {
		setURLFromAddrIfUnset("EXIT_CONTROL_URL", "EXIT_ADDR")
	}
}

func setURLFromAddrIfUnset(urlEnv string, addrEnv string) {
	if strings.TrimSpace(os.Getenv(urlEnv)) != "" {
		return
	}
	addr := strings.TrimSpace(os.Getenv(addrEnv))
	if addr == "" {
		return
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	_ = os.Setenv(urlEnv, addr)
}
