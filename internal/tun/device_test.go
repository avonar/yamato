package tun

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"tunnel-lab/internal/transport"
)

type stubDevice struct {
	wgtun.Device
	write func([][]byte, int) (int, error)
	read  func([][]byte, []int, int) (int, error)
}

func (d *stubDevice) Write(b [][]byte, offset int) (int, error) { return d.write(b, offset) }
func (d *stubDevice) Read(b [][]byte, sizes []int, offset int) (int, error) {
	return d.read(b, sizes, offset)
}

func TestWritePacketNativeDriverConventions(t *testing.T) {
	for _, tc := range []struct {
		name         string
		header       int
		bytesWritten bool
	}{
		{"linux-virtio", 10, true},
		{"linux-no-offload", 0, true},
		{"darwin", 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := bytes.Repeat([]byte{0x45}, transport.MTU)
			d := &Device{Name: "test0", dev: &stubDevice{write: func(bufs [][]byte, offset int) (int, error) {
				// Mirror the driver boundary: reserve the native header, then
				// return bytes on Linux and packets on Darwin.
				if offset < tc.header {
					return 0, errors.New("invalid offset")
				}
				if len(bufs) != 1 || !bytes.Equal(bufs[0][offset:], packet) {
					t.Fatal("packet changed at driver boundary")
				}
				for i := offset - tc.header; i < offset; i++ {
					bufs[0][i] = 0xff
				}
				if tc.bytesWritten {
					return len(packet) + tc.header, nil
				}
				return 1, nil
			}}}
			if err := d.WritePacket(packet); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(packet, bytes.Repeat([]byte{0x45}, transport.MTU)) {
				t.Fatal("driver modified caller's packet")
			}
		})
	}
}

func TestReadPacketStripsHeadroomAndPreservesBatch(t *testing.T) {
	packets := [][]byte{bytes.Repeat([]byte{0x45}, 60), bytes.Repeat([]byte{0x60}, transport.MTU)}
	reads := 0
	d := &Device{bufs: [][]byte{make([]byte, 65535+packetOffset), make([]byte, 65535+packetOffset)}, sizes: make([]int, 2)}
	d.dev = &stubDevice{read: func(bufs [][]byte, sizes []int, offset int) (int, error) {
		reads++
		if reads != 1 {
			t.Fatal("read again before draining batch")
		}
		for i, p := range packets {
			for j := 0; j < offset; j++ {
				bufs[i][j] = 0xff
			}
			sizes[i] = copy(bufs[i][offset:], p)
		}
		return len(packets), nil
	}}
	for _, want := range packets {
		got, err := d.ReadPacket()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("packet corrupted or contains native header")
		}
	}
}

func TestNativeErrorsKeepOperationAndCause(t *testing.T) {
	cause := errors.New("driver failure")
	d := &Device{Name: "test0", dev: &stubDevice{
		write: func([][]byte, int) (int, error) { return 0, cause },
		read:  func([][]byte, []int, int) (int, error) { return 0, cause },
	}}
	if err := d.WritePacket([]byte{0x45}); !errors.Is(err, cause) || !strings.Contains(err.Error(), "TUN test0 write") {
		t.Fatalf("write error: %v", err)
	}
	if _, err := d.ReadPacket(); !errors.Is(err, cause) || !strings.Contains(err.Error(), "TUN test0 read") {
		t.Fatalf("read error: %v", err)
	}
}
