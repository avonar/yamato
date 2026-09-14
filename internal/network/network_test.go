package network

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"tunnel-lab/internal/config"
)

func TestRollback(t *testing.T) {
	var called []command
	m := &Manager{run: func(c command) (string, error) {
		called = append(called, c)
		if c[0] == "fail" {
			return "", errors.New("failure")
		}
		return "", nil
	}}
	m.add(command{"first"}, command{"undo-first"})
	m.add(command{"second"}, command{"undo-second"})
	if m.add(command{"fail"}, command{"never"}) == nil {
		t.Fatal("failure ignored")
	}
	m.Close()
	m.Close()
	want := []command{{"first"}, {"second"}, {"fail"}, {"undo-second"}, {"undo-first"}}
	if !reflect.DeepEqual(called, want) {
		t.Fatalf("rollback sequence: %v", called)
	}
}

func TestMacPreservesDNSAndUnderlay(t *testing.T) {
	var calls []command
	m := &Manager{run: func(c command) (string, error) {
		calls = append(calls, c)
		if reflect.DeepEqual(c, command{"route", "-n", "get", "192.0.2.10"}) {
			return "gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,STATIC>", nil
		}
		if c[0] == "networksetup" && c[1] == "-getdnsservers" {
			return "8.8.8.8\n8.8.4.4", nil
		}
		return "", nil
	}}
	c := config.Config{Endpoint: "192.0.2.10:8443", Network: config.Network{IPv4: "10.77.0.2/30", Peer4: "10.77.0.1", DNSService: "Wi-Fi", DNS: []string{"1.1.1.1"}}}
	if e := m.mac(context.Background(), c, "utun99", nil); e != nil {
		t.Fatal(e)
	}
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
	foundPin, foundRestore := false, false
	for _, cmd := range calls {
		if reflect.DeepEqual(cmd, command{"route", "-n", "add", "-inet", "-host", "192.0.2.10", "192.168.1.1"}) {
			foundPin = true
		}
		if reflect.DeepEqual(cmd, command{"networksetup", "-setdnsservers", "Wi-Fi", "8.8.8.8", "8.8.4.4"}) {
			foundRestore = true
		}
	}
	if !foundPin || !foundRestore {
		t.Fatalf("underlay pin=%v DNS restore=%v", foundPin, foundRestore)
	}
}

func TestCancelDuringMutationStillRollsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls []command
	m := &Manager{ctx: ctx, run: func(c command) (string, error) {
		calls = append(calls, c)
		if c[0] == "add-rule" {
			cancel()
		}
		return "", nil
	}}
	if err := m.add(command{"add-rule"}, command{"delete-rule"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("mutation cancellation: %v", err)
	}
	if err := m.add(command{"add-next-rule"}, command{"delete-next-rule"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("new mutation after cancellation: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []command{{"add-rule"}, {"delete-rule"}}) {
		t.Fatalf("cancellation leaked or added rules: %v", calls)
	}
}

func TestCleanupFailureIsReportedAndRetryable(t *testing.T) {
	blocked := true
	var calls []command
	m := &Manager{undo: []command{{"restore-dns"}, {"delete-route"}}, run: func(c command) (string, error) {
		calls = append(calls, c)
		if c[0] == "delete-route" && blocked {
			return "", errors.New("route table busy")
		}
		return "", nil
	}}
	if err := m.Close(); !CleanupFailed(err) {
		t.Fatalf("cleanup failure hidden: %v", err)
	}
	blocked = false
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m.Close()
	want := []command{{"delete-route"}, {"restore-dns"}, {"delete-route"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("retry repeated successful operations or lost failed operation: %v", calls)
	}
}

func TestSetupAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if m, err := Setup(ctx, config.Config{}, "unused", nil); m != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("setup ignored cancellation: %v", err)
	}
}
