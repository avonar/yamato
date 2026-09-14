package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestValidateIP(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
	binary.BigEndian.PutUint16(v4[2:], 20)
	v6 := make([]byte, 40)
	v6[0] = 0x60
	for _, b := range [][]byte{v4, v6} {
		if e := ValidateIP(b); e != nil {
			t.Fatal(e)
		}
	}
	for _, b := range [][]byte{nil, {0x45}, append(v4, 0), append(v6, 0), make([]byte, 1281)} {
		if e := ValidateIP(b); e == nil {
			t.Fatal("invalid IP accepted")
		}
	}
}

type testPackets struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func newTestPackets() *testPackets {
	return &testPackets{in: make(chan []byte, 8), out: make(chan []byte, 8), done: make(chan struct{})}
}
func (p *testPackets) ReadPacket() ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-p.done:
		return nil, io.EOF
	}
}
func (p *testPackets) WritePacket(b []byte) error {
	select {
	case p.out <- b:
		return nil
	case <-p.done:
		return io.EOF
	}
}
func (p *testPackets) Close() error { p.once.Do(func() { close(p.done) }); return nil }
func TestBridgeAndShutdown(t *testing.T) {
	dev, remote := newTestPackets(), newTestPackets()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Bridge(ctx, dev, remote, []netip.Addr{netip.MustParseAddr("10.77.0.2")}) }()
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], 20)
	copy(packet[12:], []byte{10, 77, 0, 2})
	dev.in <- packet
	select {
	case got := <-remote.out:
		if !bytes.Equal(packet, got) {
			t.Fatal("outbound packet changed")
		}
	case <-ctx.Done():
		t.Fatal("outbound blocked")
	}
	spoofed := append([]byte(nil), packet...)
	spoofed[15] = 99
	remote.in <- spoofed
	remote.in <- packet
	select {
	case got := <-dev.out:
		if !bytes.Equal(got, packet) {
			t.Fatal("spoofed source reached TUN")
		}
	case <-ctx.Done():
		t.Fatal("inbound blocked")
	}
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop")
	}
	for _, p := range []*testPackets{dev, remote} {
		select {
		case <-p.done:
		default:
			t.Fatal("endpoint not closed")
		}
	}
}
