package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"tunnel-lab/internal/config"
)

func generate(args []string) error {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := f.String("out", "lab-config", "new output directory")
	endpoint := f.String("server", "127.0.0.1:8443", "server address reachable by client")
	mode := f.String("transport", "webrtc", "webrtc, sip or reality")
	target := f.String("target", "", "REALITY target host:port")
	sni := f.String("sni", "", "REALITY target TLS name")
	dns := f.String("dns-service", "Wi-Fi", "macOS network service to configure")
	codec := f.String("codec", "vp8", "vp8 or h264")
	secureSIP := f.Bool("sip-tls", false, "wrap SIP in TLS")
	if e := f.Parse(args); e != nil {
		return e
	}
	host, port, e := net.SplitHostPort(*endpoint)
	if e != nil {
		return e
	}
	if *mode == "reality" && (*target == "" || *sni == "") {
		return errors.New("REALITY requires -target host:port and -sni hostname")
	}
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	server := config.Config{Role: "server", Transport: *mode, Listen: net.JoinHostPort("0.0.0.0", port), Token: token, TUN: "tlab0", SIP: config.SIP{TLS: *secureSIP}, TLS: config.TLS{Cert: "cert.pem", Key: "server-key.pem"}, WebRTC: config.WebRTC{Codec: *codec, UDPMin: 40000, UDPMax: 40100}, Network: config.Network{Auto: true, IPv4: "10.77.0.1/30", Peer4: "10.77.0.2", IPv6: "fd77::1/126", Peer6: "fd77::2"}}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		server.Listen = net.JoinHostPort("::", port)
	}
	client := server
	client.Role = "client"
	client.Listen = ""
	client.Endpoint = *endpoint
	client.TUN = "utun"
	client.TLS = config.TLS{CA: "cert.pem", ServerName: host}
	client.WebRTC.UDPMin = 0
	client.WebRTC.UDPMax = 0
	client.Network = config.Network{Auto: true, IPv4: "10.77.0.2/30", Peer4: "10.77.0.1", IPv6: "fd77::2/126", Peer6: "fd77::1", DNSService: *dns, DNS: []string{"1.1.1.1"}}
	if *mode == "reality" {
		key, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		short := make([]byte, 8)
		rand.Read(short)
		r := config.Reality{UUID: uuid.NewString(), ShortID: hex.EncodeToString(short), ServerName: *sni, Fingerprint: "chrome"}
		server.Reality = r
		server.Reality.PrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
		server.Reality.Target = *target
		client.Reality = r
		client.Reality.Password = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	if e = server.Validate(); e != nil {
		return e
	}
	if e = client.Validate(); e != nil {
		return e
	}
	if e = os.Mkdir(*dir, 0700); e != nil {
		return e
	}
	save := func(name string, b []byte) error { return os.WriteFile(filepath.Join(*dir, name), b, 0600) }
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "tunnel-lab"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else {
		cert.DNSNames = append(cert.DNSNames, host)
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return e
	}
	priv, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	if e = save("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return e
	}
	if e = save("server-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})); e != nil {
		return e
	}
	for name, c := range map[string]config.Config{"server.json": server, "client.json": client} {
		b, e := json.MarshalIndent(c, "", "  ")
		if e != nil {
			return e
		}
		if e = save(name, append(b, '\n')); e != nil {
			return e
		}
	}
	return nil
}
