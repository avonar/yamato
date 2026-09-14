package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tunnel-lab/internal/config"
)

const testToken = "0123456789abcdef0123456789abcdef"

func TestFragments(t *testing.T) {
	for _, size := range []int{1, 899, 900, 901, 1280} {
		b := make([]byte, size)
		rand.Read(b)
		f := splitPacket(123, b)
		var a assembler
		var got []byte
		for i := len(f) - 1; i >= 0; i-- {
			out, e := a.push(f[i], time.Now())
			if e != nil {
				t.Fatal(e)
			}
			if out != nil {
				got = out
			}
		}
		if !bytes.Equal(b, got) {
			t.Fatalf("size %d differs", size)
		}
		if out, e := a.push(f[0], time.Now()); e != nil || out != nil {
			t.Fatal("duplicate emitted")
		}
	}
	var a assembler
	f := splitPacket(1, make([]byte, 1280))
	a.push(f[0], time.Now().Add(-3*time.Second))
	if b, e := a.push(f[1], time.Now()); e != nil || b != nil {
		t.Fatal("expired fragment reused")
	}
	for i := uint32(2); i < 1000; i++ {
		a.push(splitPacket(i, make([]byte, 1280))[0], time.Now())
	}
	if len(a.pending) > 64 {
		t.Fatal("unbounded assembly")
	}
	f[0][10] = 255
	if _, e := a.push(f[0], time.Now()); e == nil {
		t.Fatal("invalid count accepted")
	}
}
func FuzzFragments(f *testing.F) {
	f.Add(splitPacket(1, []byte("hello"))[0])
	f.Add([]byte("TL00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var a assembler
		out, _ := a.push(b, time.Now())
		if len(out) > MTU {
			t.Fatal("oversized packet")
		}
	})
}
func TestSIPParser(t *testing.T) {
	valid := "MESSAGE sip:peer@tunnel.invalid SIP/2.0\r\nVia: SIP/2.0/TCP localhost;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:b@b>\r\nCall-ID: abc\r\nCSeq: 1 MESSAGE\r\nContent-Length: 3\r\n\r\na\x00b"
	m, e := readSIP(bufio.NewReader(strings.NewReader(valid)))
	if e != nil || !bytes.Equal(m.body, []byte{'a', 0, 'b'}) {
		t.Fatalf("binary body: %v", e)
	}
	for _, bad := range []string{strings.Replace(valid, "Content-Length: 3", "Content-Length: -1", 1), strings.Replace(valid, "Content-Length: 3", "Content-Length: 999999", 1), strings.Replace(valid, "Content-Length: 3", "Content-Length: 3\r\nContent-Length: 3", 1), strings.ReplaceAll(valid, "\r\n", "\n"), valid[:len(valid)-1], "SIP/2.0 " + strings.Repeat("x", 9000)} {
		if _, e := readSIP(bufio.NewReaderSize(strings.NewReader(bad), 8192)); e == nil {
			t.Fatal("malformed SIP accepted")
		}
	}
}
func FuzzSIP(f *testing.F) {
	f.Add("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
	f.Fuzz(func(t *testing.T, b string) { readSIP(bufio.NewReaderSize(strings.NewReader(b), 8192)) })
}
func sipPair(t *testing.T) (*sipConn, *sipConn) {
	t.Helper()
	a, b := net.Pipe()
	x, y := newSIP(a, testToken, false), newSIP(b, testToken, false)
	t.Cleanup(func() { x.Close(); y.Close() })
	done := make(chan error, 1)
	go func() {
		e := y.serverAuth()
		if e == nil {
			y.start()
		}
		done <- e
	}()
	if e := x.clientAuth(); e != nil {
		t.Fatal(e)
	}
	x.start()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	return x, y
}
func TestSIPBidirectional(t *testing.T) {
	a, b := sipPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	var wg sync.WaitGroup
	for _, pair := range [][2]PacketConn{{a, b}, {b, a}} {
		wg.Add(1)
		go func(p [2]PacketConn) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				body := make([]byte, MTU)
				rand.Read(body)
				if e := p[0].WritePacket(body); e != nil {
					t.Error(e)
					return
				}
				got, e := p[1].ReadPacket()
				if e != nil || !bytes.Equal(body, got) {
					t.Errorf("SIP payload: %v", e)
					return
				}
			}
		}(pair)
	}
	wg.Wait()
}
func TestSIPWrongToken(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	x, y := newSIP(a, "wrong-wrong-wrong-wrong-wrong-wrong", false), newSIP(b, testToken, false)
	done := make(chan error, 1)
	go func() { done <- y.serverAuth() }()
	if e := x.clientAuth(); e == nil {
		t.Fatal("wrong token accepted")
	}
	a.Close()
	<-done
}
func TestFrameBounds(t *testing.T) {
	for _, size := range []uint16{0, 1281, 65535} {
		a, b := net.Pipe()
		f := &framed{Conn: a}
		done := make(chan struct{})
		go func() {
			defer close(done)
			var h [2]byte
			binary.BigEndian.PutUint16(h[:], size)
			b.Write(h[:])
			b.Close()
		}()
		if _, e := f.ReadPacket(); e == nil {
			t.Fatal("invalid size accepted")
		}
		a.Close()
		<-done
	}
}
func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), 0600)
	return certPath, keyPath
}
func freeAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func startServer(t *testing.T, c config.Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, c, func(_ context.Context, p PacketConn) error {
			for {
				b, e := p.ReadPacket()
				if e != nil {
					return e
				}
				if e = p.WritePacket(b); e != nil {
					return e
				}
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Errorf("server exit: %v", e)
			}
		case <-time.After(10 * time.Second):
			t.Error("server shutdown hung")
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		n, e := net.DialTimeout("tcp", c.Listen, 100*time.Millisecond)
		if e == nil {
			n.Close()
			time.Sleep(50 * time.Millisecond)
			return
		}
		select {
		case e := <-done:
			t.Fatalf("server startup: %v", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func checkEcho(t *testing.T, c config.Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, e := Dial(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	stop := context.AfterFunc(ctx, func() { p.Close() })
	defer stop()
	for _, size := range []int{1, 900, 901, 1280} {
		for i := 0; i < 5; i++ {
			b := make([]byte, size)
			rand.Read(b)
			if e = p.WritePacket(b); e != nil {
				t.Fatal(e)
			}
			got, e := p.ReadPacket()
			if e != nil || !bytes.Equal(b, got) {
				t.Fatalf("echo size %d: %v", size, e)
			}
		}
	}
}
func TestLoopbackTransports(t *testing.T) {
	cert, key := testCertificate(t)
	for _, mode := range []string{"sip", "sips", "vp8", "h264"} {
		t.Run(mode, func(t *testing.T) {
			s := config.Config{Role: "server", Transport: "sip", Listen: freeAddress(t), Token: testToken, TLS: config.TLS{Cert: cert, Key: key}}
			if mode == "sips" {
				s.SIP.TLS = true
			}
			if mode == "vp8" || mode == "h264" {
				s.Transport = "webrtc"
				s.WebRTC.Codec = mode
			}
			startServer(t, s)
			c := s
			c.Role = "client"
			c.Endpoint = s.Listen
			c.TLS = config.TLS{CA: cert, ServerName: "localhost"}
			checkEcho(t, c)
		})
	}
}
func TestRealityLoopback(t *testing.T) {
	cert, key := testCertificate(t)
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	target, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, CurvePreferences: []tls.CurveID{tls.X25519}})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	go func() {
		for {
			n, e := target.Accept()
			if e != nil {
				return
			}
			go func() { defer n.Close(); n.SetDeadline(time.Now().Add(10 * time.Second)); io.Copy(io.Discard, n) }()
		}
	}()
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s := config.Config{Role: "server", Transport: "reality", Listen: freeAddress(t), Token: testToken, Reality: config.Reality{UUID: "d03dbd51-cf63-4c29-aa28-2598d6702b39", ServerName: "localhost", Target: target.Addr().String(), PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()), ShortID: "0123456789abcdef", Fingerprint: "chrome"}}
	startServer(t, s)
	c := s
	c.Role = "client"
	c.Endpoint = s.Listen
	c.Reality.Password = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	c.Reality.PrivateKey = ""
	checkEcho(t, c)
}
