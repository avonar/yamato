package transport

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
	"tunnel-lab/internal/config"
)

const MTU = 1280

type PacketConn interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	Close() error
}
type Handler func(context.Context, PacketConn) error

func Dial(ctx context.Context, c config.Config) (PacketConn, error) {
	switch c.Transport {
	case "webrtc":
		return dialWebRTC(ctx, c)
	case "reality":
		return dialReality(ctx, c)
	case "sip":
		var nc net.Conn
		var e error
		if c.SIP.TLS {
			tc, err := clientTLS(c)
			if err != nil {
				return nil, err
			}
			nc, e = (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: tc}).DialContext(ctx, "tcp", c.Endpoint)
		} else {
			nc, e = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", c.Endpoint)
		}
		if e != nil {
			return nil, e
		}
		s := newSIP(nc, c.Token, c.SIP.TLS)
		stop := context.AfterFunc(ctx, func() { nc.Close() })
		defer stop()
		if e = s.clientAuth(); e != nil {
			nc.Close()
			return nil, e
		}
		s.start()
		return s, nil
	}
	return nil, errors.New("unknown transport")
}
func Serve(ctx context.Context, c config.Config, h Handler) error {
	switch c.Transport {
	case "webrtc":
		return serveWebRTC(ctx, c, h)
	case "reality":
		return serveReality(ctx, c, h)
	case "sip":
		var ln net.Listener
		var e error
		if c.SIP.TLS {
			tc, err := serverTLS(c)
			if err != nil {
				return err
			}
			ln, e = tls.Listen("tcp", c.Listen, tc)
		} else {
			ln, e = net.Listen("tcp", c.Listen)
		}
		if e != nil {
			return e
		}
		return serveStream(ctx, ln, func(n net.Conn) (PacketConn, error) {
			s := newSIP(n, c.Token, c.SIP.TLS)
			e := s.serverAuth()
			if e == nil {
				s.start()
			}
			return s, e
		}, h)
	}
	return errors.New("unknown transport")
}
func serverTLS(c config.Config) (*tls.Config, error) {
	pair, e := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if e != nil {
		return nil, e
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}
func clientTLS(c config.Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.TLS.ServerName}
	if c.TLS.CA != "" {
		b, e := os.ReadFile(c.TLS.CA)
		if e != nil {
			return nil, e
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid CA PEM")
		}
	}
	return tc, nil
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func serveStream(ctx context.Context, ln net.Listener, auth func(net.Conn) (PacketConn, error), h Handler) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	// One TUN address pair means one active client. Bound unauthenticated work too.
	gate := make(chan struct{}, 1)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		n, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case gate <- struct{}{}:
		default:
			n.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			defer n.Close()
			stop := context.AfterFunc(ctx, func() { n.Close() })
			defer stop()
			n.SetDeadline(time.Now().Add(15 * time.Second))
			p, e := auth(n)
			if e != nil {
				log.Printf("authentication: %v", e)
				return
			}
			defer p.Close()
			n.SetDeadline(time.Time{})
			if e = h(ctx, p); e != nil && ctx.Err() == nil {
				log.Printf("session: %v", e)
			}
		}()
	}
}

type framed struct {
	net.Conn
	mu sync.Mutex
}

func (f *framed) ReadPacket() ([]byte, error) {
	var hdr [2]byte
	if _, e := io.ReadFull(f.Conn, hdr[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 1 || n > MTU {
		return nil, errors.New("invalid packet length")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(f.Conn, b)
	return b, e
}
func (f *framed) WritePacket(b []byte) error {
	if len(b) < 1 || len(b) > MTU {
		return errors.New("packet exceeds MTU")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer f.SetWriteDeadline(time.Time{})
	buf := make([]byte, len(b)+2)
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	return writeAll(f.Conn, buf)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func authStream(n net.Conn, token string, server bool) (PacketConn, error) {
	n.SetDeadline(time.Now().Add(15 * time.Second))
	defer n.SetDeadline(time.Time{})
	f := &framed{Conn: n}
	if server {
		b, e := f.ReadPacket()
		if e != nil {
			return nil, e
		}
		if !equal(string(b), token) {
			return nil, errors.New("invalid token")
		}
		if e = f.WritePacket([]byte("OK")); e != nil {
			return nil, e
		}
	} else {
		if e := f.WritePacket([]byte(token)); e != nil {
			return nil, e
		}
		b, e := f.ReadPacket()
		if e != nil {
			return nil, e
		}
		if string(b) != "OK" {
			return nil, fmt.Errorf("authentication rejected")
		}
	}
	return f, nil
}
