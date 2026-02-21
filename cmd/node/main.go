package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"privacynode/internal/app"
)

func main() {
	cfgPath := flag.String("config", "", "optional path to config file")
	client := flag.Bool("client", false, "enable client role")
	entry := flag.Bool("entry", false, "enable entry role")
	exit := flag.Bool("exit", false, "enable exit role")
	directory := flag.Bool("directory", false, "enable directory role")
	issuer := flag.Bool("issuer", false, "enable token issuer role")
	wgio := flag.Bool("wgio", false, "enable wg I/O udp bridge role")
	wgiotap := flag.Bool("wgiotap", false, "enable wg I/O tap listener role")
	wgioinject := flag.Bool("wgioinject", false, "enable wg I/O packet injector role")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	nodeCfg := app.Config{
		ConfigPath: *cfgPath,
		Roles: app.Roles{
			Client:     *client,
			Entry:      *entry,
			Exit:       *exit,
			Directory:  *directory,
			Issuer:     *issuer,
			WGIO:       *wgio,
			WGIOTap:    *wgiotap,
			WGIOInject: *wgioinject,
		},
	}

	if !nodeCfg.Roles.Any() {
		log.Fatal("no role selected; pass one or more of --client --entry --exit --directory --issuer --wgio --wgiotap --wgioinject")
	}

	if err := app.Run(ctx, nodeCfg); err != nil {
		log.Fatal(err)
	}
}
