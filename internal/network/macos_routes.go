package network

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type macRoute struct {
	ip, gateway, iface string
	flags              map[string]bool
	requireStatic      bool
}

func (m *Manager) readMacRoute(ip string) (macRoute, error) {
	out, err := m.run(command{"route", "-n", "get", ip})
	if err != nil {
		return macRoute{}, fmt.Errorf("read route to %s: %w", ip, err)
	}
	r := macRoute{ip: ip, gateway: field(out, "gateway"), iface: field(out, "interface"), flags: map[string]bool{}}
	for _, flag := range strings.Split(strings.Trim(field(out, "flags"), "<>"), ",") {
		r.flags[strings.TrimSpace(flag)] = true
	}
	if r.iface == "" {
		return r, fmt.Errorf("cannot determine original route to %s", ip)
	}
	log.Printf("underlay route: %s via %s dev %s flags=%s", ip, r.gateway, r.iface, field(out, "flags"))
	return r, nil
}

func (r macRoute) persistentHost() bool {
	return r.flags["HOST"] && r.flags["STATIC"] && !r.flags["WASCLONED"] && !r.flags["DYNAMIC"] && !r.flags["IFSCOPE"]
}

func (r macRoute) directlyConnected() bool {
	// ARP/ND/local host entries can expire, but their connected subnet still
	// outranks the /1 routes. Do not replace the user's neighbor-cache entry.
	return r.flags["HOST"] && !r.flags["GATEWAY"] && (r.flags["LLINFO"] || r.flags["LOCAL"])
}

func (m *Manager) pinMacRoute(ip, tun string) (macRoute, error) {
	r, err := m.readMacRoute(ip)
	if err != nil {
		return r, err
	}
	if r.iface == tun || r.flags["REJECT"] || r.flags["BLACKHOLE"] {
		return r, fmt.Errorf("unusable original route to %s via %s", ip, r.iface)
	}
	if r.persistentHost() {
		r.requireStatic = true
		log.Printf("underlay: preserving static host route to %s", ip)
		return r, nil
	}
	if r.directlyConnected() {
		log.Printf("underlay: preserving connected route to %s", ip)
		return r, nil
	}
	family := "-inet"
	if net.ParseIP(ip).To4() == nil {
		family = "-inet6"
	}
	add := command{"route", "-n", "add", family, "-host", ip}
	if net.ParseIP(strings.Split(r.gateway, "%")[0]) != nil {
		add = append(add, r.gateway)
	} else {
		add = append(add, "-interface", r.iface)
	}
	// route add creates an unscoped STATIC host route. XNU replaces a colliding
	// protocol-cloned entry itself; never delete or change pre-existing routes.
	if err = m.add(add, command{"route", "-n", "delete", family, "-host", ip}); err != nil {
		return r, fmt.Errorf("pin server/ICE route to %s: %w", ip, err)
	}
	r.requireStatic = true
	return r, nil
}

func (m *Manager) verifyMacRoutes(routes []macRoute, tun string) error {
	for _, want := range routes {
		if m.ctx != nil {
			if err := m.ctx.Err(); err != nil {
				return err
			}
		}
		got, err := m.readMacRoute(want.ip)
		if err != nil {
			return err
		}
		if got.iface == tun || got.iface != want.iface || got.flags["REJECT"] || got.flags["BLACKHOLE"] {
			return fmt.Errorf("underlay route to %s changed from %s to %s after split routes", want.ip, want.iface, got.iface)
		}
		if net.ParseIP(strings.Split(want.gateway, "%")[0]) != nil && got.gateway != want.gateway {
			return fmt.Errorf("underlay gateway to %s changed from %s to %s", want.ip, want.gateway, got.gateway)
		}
		if want.requireStatic && (!got.flags["HOST"] || !got.flags["STATIC"] || got.flags["WASCLONED"] || got.flags["DYNAMIC"]) {
			return fmt.Errorf("underlay route to %s is not a persistent static host route after setup", want.ip)
		}
		log.Printf("underlay verified: %s via %s dev %s", want.ip, got.gateway, got.iface)
	}
	return nil
}
