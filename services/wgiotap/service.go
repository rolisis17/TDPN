package wgiotap

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"privacynode/pkg/relay"
)

type Service struct {
	addr      string
	logEvery  uint64
	total     uint64
	wgLike    uint64
	nonWGLike uint64
}

func New() *Service {
	addr := os.Getenv("WGIOTAP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:52001"
	}
	return &Service{addr: addr, logEvery: 8}
}

func (s *Service) Run(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("resolve tap addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen tap addr: %w", err)
	}
	defer conn.Close()

	log.Printf("wgiotap listening on %s", s.addr)
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, _, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if strings.Contains(readErr.Error(), "use of closed network connection") || strings.Contains(readErr.Error(), "closed") {
				return nil
			}
			return readErr
		}
		if n <= 0 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		total := atomic.AddUint64(&s.total, 1)
		if relay.LooksLikeWireGuardMessage(pkt) {
			atomic.AddUint64(&s.wgLike, 1)
		} else {
			atomic.AddUint64(&s.nonWGLike, 1)
		}
		if total%s.logEvery == 0 {
			log.Printf("wgiotap packets=%d wg_like=%d non_wg_like=%d", total, atomic.LoadUint64(&s.wgLike), atomic.LoadUint64(&s.nonWGLike))
		}
	}
}
