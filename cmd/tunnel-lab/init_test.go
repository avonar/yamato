package main

import (
	"os"
	"path/filepath"
	"testing"
	"tunnel-lab/internal/config"
)

func TestGenerate(t *testing.T) {
	for _, mode := range []string{"sip", "webrtc", "reality"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "pair")
			args := []string{"-out", dir, "-transport", mode, "-server", "192.0.2.1:8443"}
			if mode == "reality" {
				args = append(args, "-target", "localhost:443", "-sni", "localhost")
			}
			if e := generate(args); e != nil {
				t.Fatal(e)
			}
			server, e := config.Load(filepath.Join(dir, "server.json"))
			if e != nil {
				t.Fatal(e)
			}
			client, e := config.Load(filepath.Join(dir, "client.json"))
			if e != nil {
				t.Fatal(e)
			}
			if server.Token != client.Token {
				t.Fatal("different tokens")
			}
			if !filepath.IsAbs(client.TLS.CA) {
				t.Fatal("relative CA path")
			}
			info, e := os.Stat(filepath.Join(dir, "server-key.pem"))
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private key permissions")
			}
			if e = generate(args); e == nil {
				t.Fatal("existing files overwritten")
			}
		})
	}
}
