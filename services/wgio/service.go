package wgio

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
)

type Service struct {
	fromWGAddr    string
	toClientAddr  string
	fromExitAddr  string
	toWGAddr      string
	logEvery      uint64
	uplinkCount   uint64
	downlinkCount uint64
}

func New() *Service {
	fromWG := envOr("WGIO_FROM_WG_ADDR", "127.0.0.1:52000")
	toClient := envOr("WGIO_TO_CLIENT_ADDR", "127.0.0.1:51900")
	fromExit := envOr("WGIO_FROM_EXIT_ADDR", "127.0.0.1:51910")
	toWG := envOr("WGIO_TO_WG_ADDR", "127.0.0.1:52001")
	return &Service{
		fromWGAddr:   fromWG,
		toClientAddr: toClient,
		fromExitAddr: fromExit,
		toWGAddr:     toWG,
		logEvery:     20,
	}
}

func (s *Service) Run(ctx context.Context) error {
	log.Printf("wgio enabled: from_wg=%s to_client=%s from_exit=%s to_wg=%s", s.fromWGAddr, s.toClientAddr, s.fromExitAddr, s.toWGAddr)

	errCh := make(chan error, 2)
	go func() { errCh <- s.pipe(ctx, "uplink", s.fromWGAddr, s.toClientAddr, &s.uplinkCount) }()
	go func() { errCh <- s.pipe(ctx, "downlink", s.fromExitAddr, s.toWGAddr, &s.downlinkCount) }()

	for i := 0; i < 2; i++ {
		err := <-errCh
		if err == nil || strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "closed") {
			continue
		}
		return err
	}
	return nil
}

func (s *Service) pipe(ctx context.Context, dir string, listenAddr string, forwardAddr string, count *uint64) error {
	laddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve %s listen addr: %w", dir, err)
	}
	taddr, err := net.ResolveUDPAddr("udp", forwardAddr)
	if err != nil {
		return fmt.Errorf("resolve %s target addr: %w", dir, err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", dir, err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, _, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			return readErr
		}
		if n <= 0 {
			continue
		}
		if _, writeErr := conn.WriteToUDP(buf[:n], taddr); writeErr != nil {
			return writeErr
		}
		newCount := atomic.AddUint64(count, 1)
		if newCount%s.logEvery == 0 {
			log.Printf("wgio %s forwarded packets=%d", dir, newCount)
		}
	}
}

func envOr(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
