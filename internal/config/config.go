package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Role      string  `json:"role"`
	Transport string  `json:"transport"`
	Listen    string  `json:"listen"`
	Endpoint  string  `json:"endpoint"`
	Token     string  `json:"token"`
	TUN       string  `json:"tun"`
	SIP       SIP     `json:"sip"`
	Network   Network `json:"network"`
	TLS       TLS     `json:"tls"`
	WebRTC    WebRTC  `json:"webrtc"`
	Reality   Reality `json:"reality"`
}
type SIP struct {
	TLS bool `json:"tls"`
}
type Network struct {
	Auto       bool     `json:"auto"`
	IPv4       string   `json:"ipv4"`
	Peer4      string   `json:"peer4"`
	IPv6       string   `json:"ipv6"`
	Peer6      string   `json:"peer6"`
	Egress     string   `json:"egress"`
	DNSService string   `json:"dns_service"`
	DNS        []string `json:"dns"`
	BypassIPs  []string `json:"bypass_ips"`
}
type TLS struct {
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	CA         string `json:"ca"`
	ServerName string `json:"server_name"`
}
type WebRTC struct {
	Codec         string   `json:"codec"`
	ICEURLs       []string `json:"ice_urls"`
	ICEUsername   string   `json:"ice_username"`
	ICECredential string   `json:"ice_credential"`
	UDPMin        uint16   `json:"udp_min"`
	UDPMax        uint16   `json:"udp_max"`
	NATIPs        []string `json:"nat_ips"`
}
type Reality struct {
	UUID        string `json:"uuid"`
	PrivateKey  string `json:"private_key"`
	Password    string `json:"password"`
	ShortID     string `json:"short_id"`
	ServerName  string `json:"server_name"`
	Target      string `json:"target"`
	Fingerprint string `json:"fingerprint"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return c, e
	}
	if len(b) > 65536 {
		return c, errors.New("config exceeds 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("extra JSON after config")
	}
	if e = c.Validate(); e != nil {
		return c, e
	}
	base, e := filepath.Abs(filepath.Dir(path))
	if e != nil {
		return c, e
	}
	for _, p := range []*string{&c.TLS.Cert, &c.TLS.Key, &c.TLS.CA} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	return c, nil
}
func (c *Config) Validate() error {
	if c.Role != "client" && c.Role != "server" {
		return errors.New("role must be client or server")
	}
	if c.Transport != "webrtc" && c.Transport != "sip" && c.Transport != "reality" {
		return errors.New("transport must be webrtc, sip or reality")
	}
	if len(c.Token) < 32 || len(c.Token) > 256 {
		return errors.New("token must have 32..256 characters")
	}
	if strings.ContainsAny(c.Token, "\r\n") {
		return errors.New("token cannot contain newlines")
	}
	addr := c.Endpoint
	if c.Role == "server" {
		addr = c.Listen
	}
	if _, _, e := net.SplitHostPort(addr); e != nil {
		return fmt.Errorf("listen/endpoint: %w", e)
	}
	if c.Network.IPv4 == "" {
		if c.Role == "server" {
			c.Network.IPv4 = "10.77.0.1/30"
			c.Network.Peer4 = "10.77.0.2"
		} else {
			c.Network.IPv4 = "10.77.0.2/30"
			c.Network.Peer4 = "10.77.0.1"
		}
	}
	p, e := netip.ParsePrefix(c.Network.IPv4)
	if e != nil || !p.Addr().Is4() || p.Bits() != 30 {
		return errors.New("network.ipv4 must be an IPv4 /30")
	}
	peer, e := netip.ParseAddr(c.Network.Peer4)
	if e != nil || !p.Contains(peer) || peer == p.Addr() {
		return errors.New("network.peer4 must be the other endpoint in the /30")
	}
	if c.Network.IPv6 != "" {
		p, e := netip.ParsePrefix(c.Network.IPv6)
		if e != nil || !p.Addr().Is6() || p.Bits() != 126 {
			return errors.New("network.ipv6 must be an IPv6 /126")
		}
		peer, e := netip.ParseAddr(c.Network.Peer6)
		if e != nil || !p.Contains(peer) || peer == p.Addr() {
			return errors.New("invalid network.peer6")
		}
	}
	for _, ip := range append(append([]string(nil), c.Network.DNS...), c.Network.BypassIPs...) {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid DNS/bypass IP %q", ip)
		}
	}
	if c.WebRTC.Codec == "" {
		c.WebRTC.Codec = "vp8"
	}
	if c.WebRTC.Codec != "vp8" && c.WebRTC.Codec != "h264" {
		return errors.New("webrtc.codec must be vp8 or h264")
	}
	if (c.WebRTC.UDPMin == 0) != (c.WebRTC.UDPMax == 0) || c.WebRTC.UDPMin > c.WebRTC.UDPMax {
		return errors.New("invalid WebRTC UDP range")
	}
	if c.Transport == "reality" {
		if c.Reality.UUID == "" || c.Reality.ServerName == "" || c.Reality.ShortID == "" {
			return errors.New("reality requires uuid, server_name and short_id")
		}
		if c.Role == "server" && (c.Reality.PrivateKey == "" || c.Reality.Target == "") {
			return errors.New("reality server requires private_key and target")
		}
		if c.Role == "client" && c.Reality.Password == "" {
			return errors.New("reality client requires password (server X25519 public key)")
		}
		if c.Reality.Fingerprint == "" {
			c.Reality.Fingerprint = "chrome"
		}
	} else if c.Role == "server" && (c.Transport == "webrtc" || c.SIP.TLS) {
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return errors.New("server requires tls.cert and tls.key")
		}
	}
	return nil
}
