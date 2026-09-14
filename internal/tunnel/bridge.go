package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"tunnel-lab/internal/transport"
)

func ValidateIP(b []byte) error {
	if len(b) < 1 || len(b) > transport.MTU {
		return errors.New("invalid IP packet size")
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 || int(b[0]&15)*4 < 20 || int(b[0]&15)*4 > len(b) || int(binary.BigEndian.Uint16(b[2:4])) != len(b) {
			return errors.New("invalid IPv4 length")
		}
	case 6:
		if len(b) < 40 || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) {
			return errors.New("invalid IPv6 length")
		}
	default:
		return errors.New("unknown IP version")
	}
	return nil
}
func Source(b []byte) netip.Addr {
	if b[0]>>4 == 4 {
		return netip.AddrFrom4([4]byte(b[12:16]))
	}
	return netip.AddrFrom16([16]byte(b[8:24]))
}

// Bridge owns both ends. Closing either end interrupts the other reader.
func Bridge(ctx context.Context, dev, remote transport.PacketConn, allowed []netip.Addr) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var sent, received, txBytes, rxBytes atomic.Uint64
	stop := context.AfterFunc(ctx, func() { dev.Close(); remote.Close() })
	defer stop()
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	copyPackets := func(dst, src transport.PacketConn, inbound bool) {
		defer wg.Done()
		for {
			b, e := src.ReadPacket()
			if e != nil {
				errs <- e
				return
			}
			if e = ValidateIP(b); e != nil {
				errs <- e
				return
			}
			if inbound && len(allowed) > 0 {
				source := Source(b)
				ok := false
				for _, a := range allowed {
					if a == source {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
			if e = dst.WritePacket(b); e != nil {
				errs <- e
				return
			}
			if inbound {
				received.Add(1)
				rxBytes.Add(uint64(len(b)))
			} else {
				sent.Add(1)
				txBytes.Add(uint64(len(b)))
			}
		}
	}
	go copyPackets(remote, dev, false)
	go copyPackets(dev, remote, true)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	report := func() {
		log.Printf("packets tx=%d rx=%d; inner bytes tx=%d rx=%d", sent.Load(), received.Load(), txBytes.Load(), rxBytes.Load())
	}
	var result error
selectLoop:
	for {
		select {
		case result = <-errs:
			break selectLoop
		case <-ctx.Done():
			result = ctx.Err()
			break selectLoop
		case <-ticker.C:
			report()
		}
	}
	cancel()
	dev.Close()
	remote.Close()
	wg.Wait()
	report()
	return result
}
