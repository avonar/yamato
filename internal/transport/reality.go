package transport

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"sync"
	"time"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/json"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	"tunnel-lab/internal/config"
)

type obj = map[string]any

func realityJSON(c config.Config, backend string) ([]byte, error) {
	address := c.Endpoint
	if c.Role == "server" {
		address = c.Listen
	}
	host, p, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	port, e := strconv.Atoi(p)
	if e != nil {
		return nil, e
	}
	r := c.Reality
	root := obj{"log": obj{"loglevel": "warning"}}
	if c.Role == "server" {
		root["inbounds"] = []any{obj{"listen": host, "port": port, "protocol": "vless", "settings": obj{"clients": []any{obj{"id": r.UUID}}, "decryption": "none"}, "streamSettings": obj{"network": "tcp", "security": "reality", "realitySettings": obj{"target": r.Target, "serverNames": []string{r.ServerName}, "privateKey": r.PrivateKey, "shortIds": []string{r.ShortID}}}}}
		// Every authenticated VLESS stream is confined to the local tunnel endpoint.
		root["outbounds"] = []any{obj{"protocol": "freedom", "settings": obj{"redirect": backend}}}
	} else {
		root["outbounds"] = []any{obj{"protocol": "vless", "settings": obj{"vnext": []any{obj{"address": host, "port": port, "users": []any{obj{"id": r.UUID, "encryption": "none"}}}}}, "streamSettings": obj{"network": "tcp", "security": "reality", "realitySettings": obj{"serverName": r.ServerName, "password": r.Password, "shortId": r.ShortID, "fingerprint": r.Fingerprint}}}}
	}
	return json.Marshal(root)
}

type realityConn struct {
	PacketConn
	instance *core.Instance
	once     sync.Once
}

func (r *realityConn) Close() error {
	r.once.Do(func() { r.PacketConn.Close(); r.instance.Close() })
	return nil
}
func dialReality(ctx context.Context, c config.Config) (PacketConn, error) {
	b, e := realityJSON(c, "")
	if e != nil {
		return nil, e
	}
	instance, e := core.StartInstance("json", b)
	if e != nil {
		return nil, e
	}
	n, e := core.Dial(ctx, instance, xnet.TCPDestination(xnet.LocalHostIP, 1))
	if e != nil {
		instance.Close()
		return nil, e
	}
	// Xray's virtual net.Conn may not implement read deadlines. Close on timeout.
	authCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(authCtx, func() { n.Close() })
	defer stop()
	p, e := authStream(n, c.Token, false)
	if e != nil {
		n.Close()
		instance.Close()
		return nil, e
	}
	return &realityConn{PacketConn: p, instance: instance}, nil
}
func serveReality(ctx context.Context, c config.Config, h Handler) error {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer ln.Close()
	b, e := realityJSON(c, ln.Addr().String())
	if e != nil {
		return e
	}
	instance, e := core.StartInstance("json", b)
	if e != nil {
		return e
	}
	defer instance.Close()
	return serveStream(ctx, ln, func(n net.Conn) (PacketConn, error) { return authStream(n, c.Token, true) }, h)
}
