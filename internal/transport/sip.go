package transport

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This is direct SIP MESSAGE over one persistent TCP/TLS connection. Authentication
// uses a private OPTIONS challenge extension; it is not a SIP registrar or Digest UAS.
type sipMessage struct {
	first   string
	headers map[string]string
	body    []byte
}

func readSIP(r *bufio.Reader) (sipMessage, error) {
	m := sipMessage{headers: map[string]string{}}
	total := 0
	line := func() (string, error) {
		b, e := r.ReadSlice('\n')
		total += len(b)
		if e != nil {
			return "", e
		}
		if total > 8192 || len(b) < 2 || b[len(b)-2] != '\r' {
			return "", errors.New("invalid or oversized SIP header")
		}
		return string(b[:len(b)-2]), nil
	}
	var e error
	m.first, e = line()
	if e != nil {
		return m, e
	}
	if !strings.HasPrefix(m.first, "SIP/2.0 ") && !strings.HasSuffix(m.first, " SIP/2.0") {
		return m, errors.New("invalid SIP start line")
	}
	for {
		s, e := line()
		if e != nil {
			return m, e
		}
		if s == "" {
			break
		}
		k, v, ok := strings.Cut(s, ":")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok || k == "" {
			return m, errors.New("invalid SIP header")
		}
		if _, ok = m.headers[k]; ok {
			return m, errors.New("duplicate SIP header")
		}
		m.headers[k] = strings.TrimSpace(v)
	}
	n, e := strconv.Atoi(m.headers["content-length"])
	if e != nil || n < 0 || n > 2048 {
		return m, errors.New("invalid SIP Content-Length")
	}
	for _, k := range []string{"via", "from", "to", "call-id", "cseq"} {
		if m.headers[k] == "" {
			return m, fmt.Errorf("missing SIP %s", k)
		}
	}
	m.body = make([]byte, n)
	_, e = io.ReadFull(r, m.body)
	return m, e
}

type sipConn struct {
	net.Conn
	reader            *bufio.Reader
	token, proto, id  string
	aead, receiveAEAD cipher.AEAD
	wire, tx          sync.Mutex
	seq               uint64
	rx                chan []byte
	ack               chan string
	responses         chan sipMessage
	done              chan struct{}
	once              sync.Once
	recvSeq           uint64
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func newSIP(n net.Conn, token string, secure bool) *sipConn {
	proto := "TCP"
	if secure {
		proto = "TLS"
	}
	return &sipConn{Conn: n, reader: bufio.NewReaderSize(n, 8192), token: token, proto: proto, id: randomHex(12), rx: make(chan []byte, 256), ack: make(chan string, 8), done: make(chan struct{})}
}
func (s *sipConn) Close() error { s.once.Do(func() { close(s.done); s.Conn.Close() }); return nil }
func (s *sipConn) send(first string, h map[string]string, b []byte) error {
	var out strings.Builder
	out.WriteString(first + "\r\n")
	for k, v := range h {
		if strings.ContainsAny(k+v, "\r\n") {
			return errors.New("SIP header injection")
		}
		fmt.Fprintf(&out, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(&out, "Content-Length: %d\r\n\r\n", len(b))
	s.wire.Lock()
	defer s.wire.Unlock()
	s.SetWriteDeadline(time.Now().Add(15 * time.Second))
	defer s.SetWriteDeadline(time.Time{})
	return writeAll(s.Conn, append([]byte(out.String()), b...))
}
func (s *sipConn) request(method string, extra map[string]string, b []byte) (string, error) {
	s.seq++
	cseq := fmt.Sprintf("%d %s", s.seq, method)
	h := map[string]string{"Via": "SIP/2.0/" + s.proto + " " + s.LocalAddr().String() + ";branch=z9hG4bK" + randomHex(10), "From": "<sip:peer@tunnel.invalid>;tag=" + s.id, "To": "<sip:peer@tunnel.invalid>", "Call-ID": s.id, "CSeq": cseq, "Max-Forwards": "0", "Content-Type": "application/octet-stream"}
	for k, v := range extra {
		h[k] = v
	}
	return cseq, s.send(method+" sip:peer@tunnel.invalid SIP/2.0", h, b)
}
func (s *sipConn) reply(m sipMessage, status string, extra map[string]string) error {
	h := map[string]string{}
	for _, k := range []string{"via", "from", "to", "call-id", "cseq"} {
		h[k] = m.headers[k]
	}
	if !strings.Contains(h["to"], ";tag=") {
		h["to"] += ";tag=" + s.id
	}
	for k, v := range extra {
		h[k] = v
	}
	return s.send("SIP/2.0 "+status, h, nil)
}
func proof(token, label, challenge string) string {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte(label + challenge))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *sipConn) setKey(challenge string, server bool) error {
	makeKey := func(label string) (cipher.AEAD, error) {
		k := sha256.Sum256([]byte(proof(s.token, label, challenge)))
		b, e := aes.NewCipher(k[:])
		if e != nil {
			return nil, e
		}
		return cipher.NewGCM(b)
	}
	tx, rx := "client-key:", "server-key:"
	if server {
		tx, rx = rx, tx
	}
	var e error
	s.aead, e = makeKey(tx)
	if e != nil {
		return e
	}
	s.receiveAEAD, e = makeKey(rx)
	return e
}
func (s *sipConn) clientAuth() error {
	s.SetDeadline(time.Now().Add(15 * time.Second))
	defer s.SetDeadline(time.Time{})
	clientNonce := randomHex(32)
	seq, e := s.request("OPTIONS", map[string]string{"X-Tunnel-Version": "1", "X-Tunnel-Nonce": clientNonce}, nil)
	if e != nil {
		return e
	}
	m, e := readSIP(s.reader)
	if e != nil {
		return e
	}
	challenge := m.headers["x-tunnel-nonce"]
	if m.first != "SIP/2.0 200 OK" || m.headers["cseq"] != seq || len(challenge) != 64 || !equal(m.headers["x-tunnel-proof"], proof(s.token, "server:", clientNonce+challenge)) {
		return errors.New("SIP server authentication failed")
	}
	seq, e = s.request("OPTIONS", map[string]string{"X-Tunnel-Proof": proof(s.token, "client:", clientNonce+challenge)}, nil)
	if e != nil {
		return e
	}
	m, e = readSIP(s.reader)
	if e != nil {
		return e
	}
	if m.first != "SIP/2.0 200 OK" || m.headers["cseq"] != seq {
		return errors.New("SIP authentication rejected")
	}
	return s.setKey(clientNonce+challenge, false)
}
func (s *sipConn) serverAuth() error {
	m, e := readSIP(s.reader)
	if e != nil {
		return e
	}
	nonce := m.headers["x-tunnel-nonce"]
	if !strings.HasPrefix(m.first, "OPTIONS ") || m.headers["x-tunnel-version"] != "1" || len(nonce) != 64 {
		return errors.New("invalid SIP handshake")
	}
	challenge := randomHex(32)
	if e = s.reply(m, "200 OK", map[string]string{"X-Tunnel-Nonce": challenge, "X-Tunnel-Proof": proof(s.token, "server:", nonce+challenge)}); e != nil {
		return e
	}
	m, e = readSIP(s.reader)
	if e != nil {
		return e
	}
	if !strings.HasPrefix(m.first, "OPTIONS ") || !equal(m.headers["x-tunnel-proof"], proof(s.token, "client:", nonce+challenge)) {
		s.reply(m, "403 Forbidden", nil)
		return errors.New("invalid SIP client proof")
	}
	if e = s.reply(m, "200 OK", nil); e != nil {
		return e
	}
	return s.setKey(nonce+challenge, true)
}
func (s *sipConn) start() {
	s.responses = make(chan sipMessage, 8)
	go func() {
		for {
			select {
			case m := <-s.responses:
				if e := s.reply(m, "200 OK", nil); e != nil {
					s.Close()
					return
				}
			case <-s.done:
				return
			}
		}
	}()
	go s.readLoop()
}
func (s *sipConn) readLoop() {
	defer s.Close()
	for {
		m, e := readSIP(s.reader)
		if e != nil {
			return
		}
		if strings.HasPrefix(m.first, "SIP/2.0 ") {
			if m.first != "SIP/2.0 200 OK" {
				return
			}
			select {
			case s.ack <- m.headers["cseq"]:
			case <-s.done:
				return
			}
			continue
		}
		fields := strings.Fields(m.headers["cseq"])
		if len(fields) != 2 || fields[1] != "MESSAGE" || !strings.HasPrefix(m.first, "MESSAGE ") {
			return
		}
		seq, e := strconv.ParseUint(fields[0], 10, 64)
		if e != nil || seq <= s.recvSeq {
			return
		}
		s.recvSeq = seq
		if m.headers["content-type"] != "application/octet-stream" || len(m.body) < s.receiveAEAD.NonceSize()+s.receiveAEAD.Overhead() {
			return
		}
		nonce := m.body[:s.receiveAEAD.NonceSize()]
		b, e := s.receiveAEAD.Open(nil, nonce, m.body[len(nonce):], []byte(m.headers["cseq"]))
		if e != nil || len(b) == 0 || len(b) > MTU {
			return
		}
		select {
		case s.responses <- m:
		case <-s.done:
			return
		default:
			return
		}
		select {
		case s.rx <- b:
		case <-s.done:
			return
		default:
			return
		}
	}
}
func (s *sipConn) ReadPacket() ([]byte, error) {
	select {
	case b := <-s.rx:
		return b, nil
	case <-s.done:
		return nil, io.EOF
	}
}
func (s *sipConn) WritePacket(b []byte) error {
	if len(b) == 0 || len(b) > MTU {
		return errors.New("packet exceeds MTU")
	}
	s.tx.Lock()
	defer s.tx.Unlock()
	nonce := make([]byte, s.aead.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return e
	}
	expected := fmt.Sprintf("%d MESSAGE", s.seq+1)
	body := s.aead.Seal(nonce, nonce, b, []byte(expected))
	seq, e := s.request("MESSAGE", nil, body)
	if e != nil {
		return e
	}
	t := time.NewTimer(15 * time.Second)
	defer t.Stop()
	select {
	case got := <-s.ack:
		if got != seq {
			return errors.New("unexpected SIP transaction")
		}
		return nil
	case <-s.done:
		return io.EOF
	case <-t.C:
		s.Close()
		return errors.New("SIP transaction timeout")
	}
}
