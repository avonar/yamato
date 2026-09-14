package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"tunnel-lab/internal/config"
)

type rtcConn struct {
	pc              *webrtc.PeerConnection
	track           *webrtc.TrackLocalStaticRTP
	rx              chan []byte
	ready, done     chan struct{}
	once, connected sync.Once
	mu              sync.Mutex
	seq             uint16
	id              uint32
	start           time.Time
	remotes         []string
	dropped         atomic.Uint64
}

func newPeer(c config.Config, loopback bool) (*rtcConn, error) {
	mime, pt, fmtp := webrtc.MimeTypeVP8, webrtc.PayloadType(96), ""
	if c.WebRTC.Codec == "h264" {
		mime, pt, fmtp = webrtc.MimeTypeH264, 102, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
	}
	codec := webrtc.RTPCodecCapability{MimeType: mime, ClockRate: 90000, SDPFmtpLine: fmtp}
	m := &webrtc.MediaEngine{}
	if e := m.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: codec, PayloadType: pt}, webrtc.RTPCodecTypeVideo); e != nil {
		return nil, e
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(loopback)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	se.SetICETimeouts(5*time.Second, 15*time.Second, 2*time.Second)
	se.SetInterfaceFilter(func(name string) bool { return !strings.HasPrefix(name, "utun") && !strings.HasPrefix(name, "tlab") })
	if c.WebRTC.UDPMin != 0 {
		if e := se.SetEphemeralUDPPortRange(c.WebRTC.UDPMin, c.WebRTC.UDPMax); e != nil {
			return nil, e
		}
	}
	if len(c.WebRTC.NATIPs) > 0 {
		se.SetNAT1To1IPs(c.WebRTC.NATIPs, webrtc.ICECandidateTypeHost)
	}
	wc := webrtc.Configuration{}
	if len(c.WebRTC.ICEURLs) > 0 {
		wc.ICEServers = []webrtc.ICEServer{{URLs: c.WebRTC.ICEURLs, Username: c.WebRTC.ICEUsername, Credential: c.WebRTC.ICECredential}}
	}
	pc, e := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithSettingEngine(se)).NewPeerConnection(wc)
	if e != nil {
		return nil, e
	}
	track, e := webrtc.NewTrackLocalStaticRTP(codec, "video", "tunnel")
	if e != nil {
		pc.Close()
		return nil, e
	}
	sender, e := pc.AddTrack(track)
	if e != nil {
		pc.Close()
		return nil, e
	}
	p := &rtcConn{pc: pc, track: track, rx: make(chan []byte, 256), ready: make(chan struct{}), done: make(chan struct{}), start: time.Now()}
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		log.Printf("WebRTC: %s", s)
		switch s {
		case webrtc.PeerConnectionStateConnected:
			p.connected.Do(func() { close(p.ready) })
		case webrtc.PeerConnectionStateFailed:
			go p.Close()
		}
	})
	pc.OnTrack(func(t *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		var a assembler
		for {
			packet, _, e := t.ReadRTP()
			if e != nil {
				return
			}
			if bytes.Equal(packet.Payload, []byte("TL00")) {
				continue
			}
			b, e := a.push(packet.Payload, time.Now())
			if e != nil {
				go p.Close()
				return
			}
			if b != nil {
				select {
				case p.rx <- b:
				case <-p.done:
					return
				default:
					p.dropped.Add(1)
				}
			}
		}
	})
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, e := sender.Read(buf); e != nil {
				return
			}
		}
	}()
	go func() {
		select {
		case <-p.ready:
		case <-p.done:
			return
		}
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			if e := p.sendPayloads([][]byte{[]byte("TL00")}); e != nil {
				p.Close()
				return
			}
			select {
			case <-tick.C:
			case <-p.done:
				return
			}
		}
	}()
	return p, nil
}
func (p *rtcConn) Close() error {
	p.once.Do(func() { close(p.done); p.pc.Close(); log.Printf("WebRTC receive queue drops: %d", p.dropped.Load()) })
	return nil
}
func (p *rtcConn) ReadPacket() ([]byte, error) {
	select {
	case b := <-p.rx:
		return b, nil
	case <-p.done:
		return nil, io.EOF
	}
}
func (p *rtcConn) WritePacket(b []byte) error {
	if len(b) == 0 || len(b) > MTU {
		return errors.New("packet exceeds MTU")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.id++
	return p.sendLocked(splitPacket(p.id, b))
}
func (p *rtcConn) sendPayloads(b [][]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sendLocked(b)
}
func (p *rtcConn) sendLocked(parts [][]byte) error {
	select {
	case <-p.done:
		return io.EOF
	default:
	}
	ts := uint32(time.Since(p.start).Microseconds() * 90 / 1000)
	for i, b := range parts {
		p.seq++
		if e := p.track.WriteRTP(&rtp.Packet{Header: rtp.Header{Version: 2, SequenceNumber: p.seq, Timestamp: ts, Marker: i == len(parts)-1}, Payload: b}); e != nil {
			return e
		}
	}
	return nil
}
func (p *rtcConn) wait(ctx context.Context) error {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-p.ready:
		return nil
	case <-p.done:
		return io.EOF
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("ICE/DTLS connection timeout")
	}
}
func (p *rtcConn) UnderlayIPs() []string { return append([]string(nil), p.remotes...) }
func (p *rtcConn) remote(s webrtc.SessionDescription) error {
	// Pin every advertised remote address before installing client default routes.
	for _, line := range strings.Split(s.SDP, "\n") {
		if strings.HasPrefix(line, "a=candidate:") {
			f := strings.Fields(line)
			if len(f) > 4 && net.ParseIP(f[4]) != nil {
				p.remotes = append(p.remotes, f[4])
			}
		}
	}
	return p.pc.SetRemoteDescription(s)
}
func localSDP(ctx context.Context, p *rtcConn, offer bool) (*webrtc.SessionDescription, error) {
	var s webrtc.SessionDescription
	var e error
	if offer {
		s, e = p.pc.CreateOffer(nil)
	} else {
		s, e = p.pc.CreateAnswer(nil)
	}
	if e != nil {
		return nil, e
	}
	done := webrtc.GatheringCompletePromise(p.pc)
	if e = p.pc.SetLocalDescription(s); e != nil {
		return nil, e
	}
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return p.pc.LocalDescription(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errors.New("ICE gathering timeout")
	}
}
func dialWebRTC(ctx context.Context, c config.Config) (PacketConn, error) {
	p, e := newPeer(c, false)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			p.Close()
		}
	}()
	offer, e := localSDP(ctx, p, true)
	if e != nil {
		return nil, e
	}
	body, e := json.Marshal(offer)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "https://"+c.Endpoint+"/offer", bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	tc, e := clientTLS(c)
	if e != nil {
		return nil, e
	}
	tr := &http.Transport{TLSClientConfig: tc}
	defer tr.CloseIdleConnections()
	resp, e := (&http.Client{Transport: tr, Timeout: 45 * time.Second}).Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("signaling HTTP status %d", resp.StatusCode)
	}
	var answer webrtc.SessionDescription
	if e = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&answer); e != nil {
		return nil, e
	}
	if e = p.remote(answer); e != nil {
		return nil, e
	}
	if e = p.wait(ctx); e != nil {
		return nil, e
	}
	ok = true
	return p, nil
}
func serveWebRTC(ctx context.Context, c config.Config, h Handler) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tc, e := serverTLS(c)
	if e != nil {
		return e
	}
	ln, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return e
	}
	defer ln.Close()
	var busy atomic.Bool
	var wg sync.WaitGroup
	mux := http.NewServeMux()
	mux.HandleFunc("/offer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		if !equal(r.Header.Get("Authorization"), "Bearer "+c.Token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		if !busy.CompareAndSwap(false, true) {
			http.Error(w, "one client already active", 409)
			return
		}
		handed := false
		defer func() {
			if !handed {
				busy.Store(false)
			}
		}()
		var offer webrtc.SessionDescription
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		if e := json.NewDecoder(r.Body).Decode(&offer); e != nil || offer.Type != webrtc.SDPTypeOffer {
			http.Error(w, "invalid offer", 400)
			return
		}
		p, e := newPeer(c, false)
		if e != nil {
			http.Error(w, "peer creation failed", 500)
			return
		}
		defer func() {
			if !handed {
				p.Close()
			}
		}()
		if e = p.remote(offer); e != nil {
			http.Error(w, "invalid SDP", 400)
			return
		}
		answer, e := localSDP(r.Context(), p, false)
		if e != nil {
			http.Error(w, "gathering failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if e = json.NewEncoder(w).Encode(answer); e != nil {
			return
		}
		handed = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer busy.Store(false)
			defer p.Close()
			stop := context.AfterFunc(ctx, func() { p.Close() })
			defer stop()
			if e := p.wait(ctx); e != nil {
				log.Printf("WebRTC connect: %v", e)
				return
			}
			if e := h(ctx, p); e != nil && ctx.Err() == nil {
				log.Printf("session: %v", e)
			}
		}()
	})
	srv := &http.Server{Handler: mux, TLSConfig: tc, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	// Shutdown waits for offer handlers before waiting for their session goroutines.
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if srv.Shutdown(shutdown) != nil {
			srv.Close()
		}
		close(stopped)
	})
	defer stop()
	e = srv.ServeTLS(ln, "", "")
	cancel()
	<-stopped
	wg.Wait()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
