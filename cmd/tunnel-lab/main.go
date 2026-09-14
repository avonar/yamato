package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tunnel-lab/internal/config"
	"tunnel-lab/internal/network"
	"tunnel-lab/internal/transport"
	"tunnel-lab/internal/tun"
	"tunnel-lab/internal/tunnel"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run() (result error) {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		return generate(os.Args[2:])
	}
	f := flag.NewFlagSet("tunnel-lab", flag.ContinueOnError)
	path := f.String("config", "", "JSON configuration")
	mode := f.String("mode", "tun", "tun, echo (server), probe (client)")
	count := f.Int("count", 100, "probe packet count")
	size := f.Int("size", 1280, "probe payload bytes")
	reconnect := f.Bool("reconnect", true, "reconnect TUN client after link failure")
	if e := f.Parse(os.Args[1:]); e != nil {
		return e
	}
	if *path == "" {
		return errors.New("use -config file.json; generate a pair with: tunnel-lab init -help")
	}
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	if (*mode != "tun" && *mode != "echo" && *mode != "probe") || (*mode == "echo" && c.Role != "server") || (*mode == "probe" && c.Role != "client") {
		return errors.New("invalid mode for role")
	}
	if *count < 1 || *size < 1 || *size > transport.MTU {
		return errors.New("count must be positive; size must be 1..1280")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	logged := make(chan struct{})
	stopLog := context.AfterFunc(ctx, func() { log.Print("shutdown requested: closing connections and restoring network"); close(logged) })
	defer func() {
		if !stopLog() {
			<-logged
		}
		if ctx.Err() != nil {
			if result == nil {
				log.Print("shutdown complete")
			} else {
				log.Printf("shutdown failed: %v", result)
			}
		}
		cancel()
	}()
	log.Printf("role=%s transport=%s mode=%s", c.Role, c.Transport, *mode)
	if c.Role == "server" {
		var cleanupErr error
		err := transport.Serve(ctx, c, func(ctx context.Context, p transport.PacketConn) error {
			if *mode == "echo" {
				return echo(p)
			}
			err := runTUN(ctx, c, p)
			if network.CleanupFailed(err) {
				cleanupErr = err
				cancel()
			}
			return err
		})
		// Serve joins all session handlers before returning.
		return errors.Join(err, cleanupErr)
	}
	for {
		p, e := transport.Dial(ctx, c)
		if e == nil {
			if *mode == "probe" {
				e = probe(ctx, p, *count, *size)
				p.Close()
				if ctx.Err() != nil {
					return nil
				}
				return e
			}
			e = runTUN(ctx, c, p)
			p.Close()
		}
		if network.CleanupFailed(e) {
			return e
		}
		if ctx.Err() != nil {
			return nil
		}
		if !*reconnect || *mode != "tun" {
			return e
		}
		log.Printf("connection ended: %v; reconnect in 3s", e)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
		}
	}
}
func echo(p transport.PacketConn) error {
	for {
		b, e := p.ReadPacket()
		if e != nil {
			return e
		}
		if e = p.WritePacket(b); e != nil {
			return e
		}
	}
}
func runTUN(ctx context.Context, c config.Config, p transport.PacketConn) (result error) {
	defer p.Close()
	if e := ctx.Err(); e != nil {
		return e
	}
	d, e := tun.Open(c.TUN)
	if e != nil {
		return fmt.Errorf("create TUN (root required): %w", e)
	}
	defer func() {
		if err := d.Close(); err != nil {
			result = errors.Join(result, &network.CleanupError{Err: fmt.Errorf("close TUN %s: %w", d.Name, err)})
		}
	}()
	var remoteIPs []string
	if rp, ok := p.(interface{ UnderlayIPs() []string }); ok {
		remoteIPs = rp.UnderlayIPs()
	}
	manager, e := network.Setup(ctx, c, d.Name, remoteIPs)
	if e != nil {
		return e
	}
	defer func() {
		log.Printf("session cleanup: restoring network for %s", d.Name)
		if err := manager.Close(); err != nil {
			result = errors.Join(result, err)
			return
		}
		log.Printf("session cleanup: network restored for %s", d.Name)
	}()
	log.Printf("TUN ready: %s MTU=%d IPv4=%s IPv6=%s auto=%t", d.Name, transport.MTU, c.Network.IPv4, c.Network.IPv6, c.Network.Auto)
	var allowed []netip.Addr
	if c.Role == "server" {
		allowed = append(allowed, netip.MustParseAddr(c.Network.Peer4))
		if c.Network.Peer6 != "" {
			allowed = append(allowed, netip.MustParseAddr(c.Network.Peer6))
		}
	}
	return tunnel.Bridge(ctx, d, p, allowed)
}
func probe(ctx context.Context, p transport.PacketConn, count, size int) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { p.Close() })
	defer stop()
	start := time.Now()
	for i := 0; i < count; i++ {
		b := make([]byte, size)
		if _, e := rand.Read(b); e != nil {
			return e
		}
		if e := p.WritePacket(b); e != nil {
			return e
		}
		got, e := p.ReadPacket()
		if e != nil {
			return fmt.Errorf("probe %d: %w", i, e)
		}
		if !bytes.Equal(got, b) {
			return errors.New("probe data mismatch")
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("PASS: %d round trips, %d bytes each, %s, mean RTT=%s, useful bidirectional rate=%.2f Mbit/s\n", count, size, elapsed, elapsed/time.Duration(count), float64(count*size*16)/elapsed.Seconds()/1e6)
	return nil
}
