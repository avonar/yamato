package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"tunnel-lab/internal/config"
)

type command []string
type Manager struct {
	undo []command
	run  func(command) (string, error)
	ctx  context.Context
}

// CleanupError prevents reconnecting over a network setup that was not restored.
type CleanupError struct{ Err error }

func (e *CleanupError) Error() string { return "network cleanup incomplete: " + e.Err.Error() }
func (e *CleanupError) Unwrap() error { return e.Err }
func CleanupFailed(err error) bool    { var cleanup *CleanupError; return errors.As(err, &cleanup) }

func execute(c command) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	// Terminal SIGINT must not interrupt an in-flight mutation or its rollback.
	// Finish the bounded command, record its undo, then observe cancellation.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, e := cmd.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s: %w: %s", strings.Join(c, " "), e, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
func (m *Manager) add(do, undo command) error {
	if m.ctx != nil {
		if err := m.ctx.Err(); err != nil {
			return err
		}
	}
	log.Printf("network: %s", strings.Join(do, " "))
	if _, e := m.run(do); e != nil {
		return e
	}
	if len(undo) > 0 {
		m.undo = append(m.undo, undo)
	}
	if m.ctx != nil {
		return m.ctx.Err()
	}
	return nil
}
func (m *Manager) Close() error {
	var result error
	failed := make([]command, 0)
	for i := len(m.undo) - 1; i >= 0; i-- {
		log.Printf("network restore: %s", strings.Join(m.undo[i], " "))
		if _, e := m.run(m.undo[i]); e != nil {
			// Destroying utun also removes routes bound to it on macOS.
			if len(m.undo[i]) > 2 && m.undo[i][0] == "route" && m.undo[i][2] == "delete" && strings.Contains(e.Error(), "not in table") {
				continue
			}
			log.Printf("network restore failed: %v", e)
			result = errors.Join(result, e)
			failed = append(failed, m.undo[i])
		}
	}
	// Retain failed operations in their original order so Close can retry them.
	for i, j := 0, len(failed)-1; i < j; i, j = i+1, j-1 {
		failed[i], failed[j] = failed[j], failed[i]
	}
	m.undo = failed
	if result != nil {
		return &CleanupError{Err: result}
	}
	return nil
}
func Setup(ctx context.Context, c config.Config, iface string, remoteIPs []string) (*Manager, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := &Manager{run: execute, ctx: ctx}
	if !c.Network.Auto {
		return m, nil
	}
	var e error
	if runtime.GOOS == "darwin" && c.Role == "client" {
		e = m.mac(ctx, c, iface, remoteIPs)
	} else if runtime.GOOS == "linux" {
		e = m.linux(c, iface)
	} else {
		e = errors.New("automatic network setup supports macOS client and Linux")
	}
	if e != nil {
		return nil, errors.Join(e, m.Close())
	}
	return m, nil
}
func field(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
func (m *Manager) mac(ctx context.Context, c config.Config, iface string, remoteIPs []string) error {
	n := c.Network
	v4 := netip.MustParsePrefix(n.IPv4)
	if e := m.add(command{"ifconfig", iface, "inet", v4.Addr().String(), n.Peer4, "netmask", "255.255.255.252", "mtu", "1280", "up"}, nil); e != nil {
		return e
	}
	if n.IPv6 != "" {
		if e := m.add(command{"ifconfig", iface, "inet6", n.IPv6, "alias"}, nil); e != nil {
			return e
		}
	}
	// All lookups happen before installing split default routes.
	host, _, _ := net.SplitHostPort(c.Endpoint)
	hosts := append([]string{host}, n.BypassIPs...)
	hosts = append(hosts, remoteIPs...)
	for _, u := range c.WebRTC.ICEURLs {
		_, tail, ok := strings.Cut(u, ":")
		if !ok {
			continue
		}
		tail, _, _ = strings.Cut(tail, "?")
		tail = strings.TrimPrefix(tail, "//")
		h, _, e := net.SplitHostPort(tail)
		if e != nil {
			h = tail
		}
		hosts = append(hosts, h)
	}
	ips := map[string]bool{}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips[ip.String()] = true
			continue
		}
		addresses, e := net.DefaultResolver.LookupIPAddr(ctx, h)
		if e != nil {
			return e
		}
		for _, a := range addresses {
			ips[a.IP.String()] = true
		}
	}
	for ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed.IsLoopback() {
			continue
		}
		args := command{"route", "-n", "get", ip}
		out, e := m.run(args)
		if e != nil {
			return e
		}
		gw, dev := field(out, "gateway"), field(out, "interface")
		if dev == "" {
			return fmt.Errorf("cannot determine original route to %s", ip)
		}
		family := "-inet"
		if parsed.To4() == nil {
			family = "-inet6"
		}
		// A pre-existing host route already survives the split default routes.
		if strings.Contains(field(out, "flags"), "HOST") {
			continue
		}
		add := command{"route", "-n", "add", family, "-host", ip}
		if net.ParseIP(strings.Split(gw, "%")[0]) != nil {
			add = append(add, gw)
		} else {
			add = append(add, "-interface", dev)
		}
		if e = m.add(add, command{"route", "-n", "delete", family, "-host", ip}); e != nil {
			return e
		}
	}
	if n.DNSService != "" && len(n.DNS) > 0 {
		old, e := m.run(command{"networksetup", "-getdnsservers", n.DNSService})
		if e != nil {
			return e
		}
		restore := []string{"Empty"}
		if !strings.Contains(old, "aren't any DNS Servers") {
			restore = strings.Fields(old)
			for _, ip := range restore {
				if net.ParseIP(ip) == nil {
					return fmt.Errorf("cannot parse current DNS settings: %s", old)
				}
			}
		}
		if e = m.add(append(command{"networksetup", "-setdnsservers", n.DNSService}, n.DNS...), append(command{"networksetup", "-setdnsservers", n.DNSService}, restore...)); e != nil {
			return e
		}
	}
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if e := m.add(command{"route", "-n", "add", "-inet", "-net", cidr, "-interface", iface}, command{"route", "-n", "delete", "-inet", "-net", cidr}); e != nil {
			return e
		}
	}
	if n.IPv6 != "" {
		for _, cidr := range []string{"::/1", "8000::/1"} {
			if e := m.add(command{"route", "-n", "add", "-inet6", "-net", cidr, "-interface", iface}, command{"route", "-n", "delete", "-inet6", "-net", cidr}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (m *Manager) linux(c config.Config, iface string) error {
	n := c.Network
	for _, prefix := range []string{n.IPv4, n.IPv6} {
		if prefix != "" {
			if e := m.add(command{"ip", "addr", "add", prefix, "dev", iface}, nil); e != nil {
				return e
			}
		}
	}
	if e := m.add(command{"ip", "link", "set", "dev", iface, "mtu", "1280", "up"}, nil); e != nil {
		return e
	}
	if c.Role != "server" {
		return errors.New("Linux client: use network.auto=false and configure namespace routes explicitly")
	}
	egress := n.Egress
	if egress == "" {
		out, e := m.run(command{"ip", "-j", "route", "show", "default"})
		if e != nil {
			return e
		}
		var rows []struct {
			Dev string `json:"dev"`
		}
		if e = json.Unmarshal([]byte(out), &rows); e != nil || len(rows) == 0 {
			return errors.New("no Linux default route; set network.egress")
		}
		egress = rows[0].Dev
	}
	for _, v6 := range []bool{false, true} {
		prefix, peer, tool, key := n.IPv4, n.Peer4, "iptables", "net.ipv4.ip_forward"
		if v6 {
			if n.IPv6 == "" {
				continue
			}
			prefix, peer, tool, key = n.IPv6, n.Peer6, "ip6tables", "net.ipv6.conf.all.forwarding"
		}
		old, e := m.run(command{"sysctl", "-n", key})
		if e != nil {
			return e
		}
		if old != "1" {
			if e = m.add(command{"sysctl", "-w", key + "=1"}, command{"sysctl", "-w", key + "=" + old}); e != nil {
				return e
			}
		}
		subnet := netip.MustParsePrefix(prefix).Masked().String()
		rules := []command{{"-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", egress, "-j", "MASQUERADE"}, {"-I", "FORWARD", "-i", iface, "-o", egress, "-s", peer, "-j", "ACCEPT"}, {"-I", "FORWARD", "-i", egress, "-o", iface, "-d", peer, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}}
		for _, r := range rules {
			del := append(command(nil), r...)
			for i, a := range del {
				if a == "-A" || a == "-I" {
					del[i] = "-D"
				}
			}
			if e = m.add(append(command{tool, "-w"}, r...), append(command{tool, "-w"}, del...)); e != nil {
				return e
			}
		}
	}
	return nil
}
