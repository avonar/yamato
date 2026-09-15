package tun

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"tunnel-lab/internal/transport"
)

// Linux's virtio-net header needs 10 bytes; Darwin's utun header needs 4.
// Both drivers use the space immediately before the supplied packet offset.
const packetOffset = 16

type Device struct {
	dev      wgtun.Device
	Name     string
	once     sync.Once
	closeErr error
	bufs     [][]byte
	sizes    []int
	pending  [][]byte
}

func Open(name string) (*Device, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, errors.New("TUN supported on macOS and Linux")
	}
	if name == "" {
		name = "tlab0"
		if runtime.GOOS == "darwin" {
			name = "utun"
		}
	}
	d, e := wgtun.CreateTUN(name, transport.MTU)
	if e != nil {
		return nil, e
	}
	actual, e := d.Name()
	if e != nil {
		d.Close()
		return nil, e
	}
	dev := &Device{dev: d, Name: actual, bufs: make([][]byte, d.BatchSize()), sizes: make([]int, d.BatchSize())}
	for i := range dev.bufs {
		dev.bufs[i] = make([]byte, 65535+packetOffset)
	}
	go func() {
		for range d.Events() {
		}
	}()
	return dev, nil
}
func (d *Device) ReadPacket() ([]byte, error) {
	for {
		if len(d.pending) > 0 {
			b := d.pending[0]
			d.pending = d.pending[1:]
			return b, nil
		}
		n, e := d.dev.Read(d.bufs, d.sizes, packetOffset)
		if e != nil {
			return nil, fmt.Errorf("TUN %s read: %w", d.Name, e)
		}
		for i := 0; i < n; i++ {
			size := d.sizes[i]
			if size < 1 || size > transport.MTU {
				continue
			}
			d.pending = append(d.pending, append([]byte(nil), d.bufs[i][packetOffset:packetOffset+size]...))
		}
	}
}
func (d *Device) WritePacket(b []byte) error {
	if len(b) == 0 || len(b) > transport.MTU {
		return errors.New("invalid TUN packet size")
	}
	buf := make([]byte, len(b)+packetOffset)
	copy(buf[packetOffset:], b)
	// The pinned native Linux driver returns bytes, while Darwin returns
	// packets. Like wireguard-go's receive path, rely on the write error.
	if _, e := d.dev.Write([][]byte{buf}, packetOffset); e != nil {
		return fmt.Errorf("TUN %s write: %w", d.Name, e)
	}
	return nil
}
func (d *Device) Close() error {
	d.once.Do(func() {
		d.closeErr = d.dev.Close()
		if d.closeErr == nil {
			log.Printf("TUN closed: %s", d.Name)
		} else {
			log.Printf("TUN close failed: %s: %v", d.Name, d.closeErr)
		}
	})
	return d.closeErr
}
