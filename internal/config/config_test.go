package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidation(t *testing.T) {
	base := Config{Role: "client", Transport: "sip", Endpoint: "127.0.0.1:5060", Token: strings.Repeat("a", 32)}
	if e := base.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Role = "typo" }, func(c *Config) { c.Transport = "tls" }, func(c *Config) { c.Token = "short" }, func(c *Config) { c.Token = strings.Repeat("a", 32) + "\r\n" }, func(c *Config) { c.Endpoint = "noport" }, func(c *Config) { c.WebRTC.UDPMin = 100 }, func(c *Config) { c.Network.IPv4 = "::/30" }, func(c *Config) { c.Network.Peer4 = "192.0.2.1" }, func(c *Config) { c.Transport = "reality" }} {
		c := base
		mutate(&c)
		if e := c.Validate(); e == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}
func TestLoadStrict(t *testing.T) {
	for _, data := range []string{`{"typo":true}`, `{} {}`, `{}`} {
		path := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(path, []byte(data), 0600)
		if _, e := Load(path); e == nil {
			t.Fatal("invalid JSON config accepted")
		}
	}
}
