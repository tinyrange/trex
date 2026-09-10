package native

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestResolvedAddressDialerFailsOverAndRemembersSuccess(t *testing.T) {
	var attempts []string
	dialer := &resolvedAddressDialer{
		preferred: make(map[string]string),
		lookup: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.2")}}, nil
		},
		dial: func(_ context.Context, _, address string) (net.Conn, error) {
			attempts = append(attempts, address)
			if strings.HasPrefix(address, "192.0.2.1:") {
				return nil, fmt.Errorf("unreachable")
			}
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		},
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", "download.example:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if len(attempts) != 2 || attempts[0] != "192.0.2.1:80" || attempts[1] != "192.0.2.2:80" {
		t.Fatalf("first dial attempts = %#v", attempts)
	}
	attempts = nil
	connection, err = dialer.DialContext(context.Background(), "tcp", "download.example:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if len(attempts) != 1 || attempts[0] != "192.0.2.2:80" {
		t.Fatalf("preferred dial attempts = %#v", attempts)
	}
}

// Windows-release live discovery policy is exercised in TinyRangeX's Starlark
// discovery smoke. Transport tests here do not embed an OS profile or selector.
