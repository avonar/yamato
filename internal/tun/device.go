package tun

import (
	"errors"
	"io"
	"runtime"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"tunnel-lab/internal/transport"
)

type Device struct {
	dev     wgtun.Device
	Name    string
	once    sync.Once
	bufs    [][]byte
	sizes   []int
	pending [][]byte
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
		dev.bufs[i] = make([]byte, 65535+4)
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
		n, e := d.dev.Read(d.bufs, d.sizes, 4)
		if e != nil {
			return nil, e
		}
		for i := 0; i < n; i++ {
			size := d.sizes[i]
			if size < 1 || size > transport.MTU {
				continue
			}
			d.pending = append(d.pending, append([]byte(nil), d.bufs[i][4:4+size]...))
		}
	}
}
func (d *Device) WritePacket(b []byte) error {
	buf := make([]byte, len(b)+4)
	copy(buf[4:], b)
	n, e := d.dev.Write([][]byte{buf}, 4)
	if e == nil && n != 1 {
		return io.ErrShortWrite
	}
	return e
}
func (d *Device) Close() error { var e error; d.once.Do(func() { e = d.dev.Close() }); return e }
