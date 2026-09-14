package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Execute the real CLI signal handler in a child process. No TUN/root is needed.
func TestShutdownHelper(t *testing.T) {
	if os.Getenv("TUNNEL_LAB_SHUTDOWN_HELPER") != "1" {
		return
	}
	os.Args = []string{"tunnel-lab", "-config", os.Getenv("TUNNEL_LAB_TEST_CONFIG"), "-mode", "echo"}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestCLISignalShutdown(t *testing.T) {
	for _, mode := range []string{"sip", "sips", "webrtc", "reality"} {
		for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
			t.Run(mode+"/"+sig.String(), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address := listener.Addr().String()
				listener.Close()
				dir := filepath.Join(t.TempDir(), "config")
				transport := mode
				if mode == "sips" {
					transport = "sip"
				}
				args := []string{"-out", dir, "-server", address, "-transport", transport}
				if mode == "sips" {
					args = append(args, "-sip-tls")
				}
				if mode == "reality" {
					args = append(args, "-target", "127.0.0.1:1", "-sni", "localhost")
				}
				if err = generate(args); err != nil {
					t.Fatal(err)
				}
				logPath := filepath.Join(dir, "process.log")
				output, err := os.Create(logPath)
				if err != nil {
					t.Fatal(err)
				}
				defer output.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShutdownHelper$")
				cmd.Env = append(os.Environ(), "TUNNEL_LAB_SHUTDOWN_HELPER=1", "TUNNEL_LAB_TEST_CONFIG="+filepath.Join(dir, "server.json"))
				cmd.Stdout = output
				cmd.Stderr = output
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				defer func() { cmd.Process.Kill() }()
				var connection net.Conn
				for ctx.Err() == nil {
					connection, err = net.DialTimeout("tcp", address, 50*time.Millisecond)
					if err == nil {
						break
					}
					select {
					case err := <-done:
						t.Fatalf("server startup failed: %v", err)
					default:
					}
					time.Sleep(20 * time.Millisecond)
				}
				if connection == nil {
					t.Fatal("server did not start")
				}
				defer connection.Close()
				// Keep an incomplete authentication/handshake open during SIGINT.
				if err = cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-done:
					if err != nil {
						b, _ := os.ReadFile(logPath)
						t.Fatalf("signal exit: %v\n%s", err, b)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("shutdown hung")
				}
				b, _ := os.ReadFile(logPath)
				if !strings.Contains(string(b), "shutdown complete") {
					t.Fatalf("missing completion log:\n%s", b)
				}
				check, err := net.Listen("tcp", address)
				if err != nil {
					t.Fatalf("listener leaked: %v", err)
				}
				check.Close()
			})
		}
	}
}
