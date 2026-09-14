package network

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"tunnel-lab/internal/config"
)

func TestMacHostRouteOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, ip, gateway, flags, family string
		wantAdd                          bool
	}{
		{"observed-clone", "134.209.200.14", "192.168.1.1", "UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL", "-inet", true},
		{"static-host", "192.0.2.10", "192.168.1.1", "UP,GATEWAY,HOST,STATIC", "-inet", false},
		{"scoped-static-host", "192.0.2.10", "192.168.1.1", "UP,GATEWAY,HOST,STATIC,IFSCOPE", "-inet", true},
		{"static-subnet", "192.0.2.10", "192.168.1.1", "UP,GATEWAY,STATIC", "-inet", true},
		{"redirect", "192.0.2.10", "192.168.1.1", "UP,GATEWAY,HOST,DYNAMIC", "-inet", true},
		{"neighbor", "192.168.1.10", "aa:bb:cc:dd:ee:ff", "UP,HOST,LLINFO,WASCLONED,IFSCOPE", "-inet", false},
		{"ipv6-clone", "2001:db8::10", "fe80::1%en0", "UP,GATEWAY,HOST,WASCLONED,IFSCOPE", "-inet6", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mutations []command
			pinned := false
			m := &Manager{run: func(c command) (string, error) {
				if c[2] == "get" {
					flags := tc.flags
					if pinned {
						flags = "UP,GATEWAY,HOST,STATIC"
					}
					return fmt.Sprintf("gateway: %s\ninterface: en0\nflags: <%s>", tc.gateway, flags), nil
				}
				mutations = append(mutations, c)
				pinned = c[2] == "add"
				return "", nil
			}}
			r, err := m.pinMacRoute(tc.ip, "utun99")
			if err != nil {
				t.Fatal(err)
			}
			if err := m.verifyMacRoutes([]macRoute{r}, "utun99"); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			if !tc.wantAdd {
				if len(mutations) != 0 {
					t.Fatalf("changed pre-existing route: %v", mutations)
				}
				return
			}
			want := []command{
				{"route", "-n", "add", tc.family, "-host", tc.ip, tc.gateway},
				{"route", "-n", "delete", tc.family, "-host", tc.ip},
			}
			if !reflect.DeepEqual(mutations, want) {
				t.Fatalf("route ownership: got %v, want %v", mutations, want)
			}
		})
	}
}

func TestMacPinCollisionDoesNotDeleteExistingRoute(t *testing.T) {
	var calls []command
	m := &Manager{run: func(c command) (string, error) {
		calls = append(calls, c)
		if c[2] == "get" {
			return "gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,HOST,DYNAMIC>", nil
		}
		return "", errors.New("File exists")
	}}
	if _, err := m.pinMacRoute("192.0.2.10", "utun99"); err == nil {
		t.Fatal("collision ignored")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[1][2] != "add" {
		t.Fatalf("pre-existing route modified on collision: %v", calls)
	}
}

func TestMacSplitRoutesVerifyUnderlayAndRollback(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("route-lost-%v", broken), func(t *testing.T) {
			var mutations []command
			pinned, split, checked := false, false, false
			m := &Manager{run: func(c command) (string, error) {
				if c[0] == "route" && c[2] == "get" {
					if split {
						checked = true
						if broken {
							return "interface: utun99\nflags: <UP,DONE,STATIC>", nil
						}
					}
					flags := "UP,GATEWAY,HOST,WASCLONED,IFSCOPE"
					if pinned {
						flags = "UP,GATEWAY,HOST,STATIC"
					}
					return "gateway: 192.168.1.1\ninterface: en0\nflags: <" + flags + ">", nil
				}
				mutations = append(mutations, c)
				if c[0] == "route" && c[2] == "add" {
					if c[4] == "-host" {
						pinned = true
					}
					if c[4] == "-net" {
						if !pinned {
							t.Error("split route installed before endpoint was pinned")
						}
						split = true
					}
				}
				return "", nil
			}}
			c := config.Config{Endpoint: "134.209.200.14:5060", Network: config.Network{IPv4: "10.77.0.2/30", Peer4: "10.77.0.1"}}
			err := m.mac(context.Background(), c, "utun99", nil)
			if (err != nil) != broken {
				t.Fatalf("route verification result: %v", err)
			}
			if !checked {
				t.Fatal("underlay not verified after split routes")
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			wantCleanup := []command{
				{"route", "-n", "delete", "-inet", "-net", "128.0.0.0/1"},
				{"route", "-n", "delete", "-inet", "-net", "0.0.0.0/1"},
				{"route", "-n", "delete", "-inet", "-host", "134.209.200.14"},
			}
			if len(mutations) < 3 || !reflect.DeepEqual(mutations[len(mutations)-3:], wantCleanup) {
				t.Fatalf("rollback: %v", mutations)
			}
		})
	}
}

func TestMacVerifyRejectsUnstableOrChangedRoute(t *testing.T) {
	want := macRoute{ip: "192.0.2.10", iface: "en0", gateway: "192.168.1.1", requireStatic: true}
	for _, out := range []string{
		"gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,HOST,WASCLONED>",
		"gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,HOST,STATIC,DYNAMIC>",
		"gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,HOST,STATIC,REJECT>",
		"gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,GHOST,STATIC>",
		"gateway: 192.168.1.2\ninterface: en0\nflags: <UP,GATEWAY,HOST,STATIC>",
		"gateway: 192.168.1.1\ninterface: en1\nflags: <UP,GATEWAY,HOST,STATIC>",
	} {
		t.Run(strings.ReplaceAll(out, "\n", ";"), func(t *testing.T) {
			m := &Manager{run: func(command) (string, error) { return out, nil }}
			if err := m.verifyMacRoutes([]macRoute{want}, "utun99"); err == nil {
				t.Fatal("unsafe route accepted")
			}
		})
	}
}
