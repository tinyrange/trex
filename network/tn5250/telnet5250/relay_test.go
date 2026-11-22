package telnet5250

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tinyrange/trex/network/tn5250"
)

func gds(opcode byte, body []byte) []byte {
	b := append([]byte{0, 0, 0x12, 0xa0, 0, 0, 4, 0, 0, opcode}, body...)
	binary.BigEndian.PutUint16(b, uint16(len(b)))
	return b
}

// readUntil reads from r until the accumulated bytes contain want.
func readUntil(t *testing.T, r *bufio.Reader, got *[]byte, want []byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !bytes.Contains(*got, want) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %x in %x", want, *got)
		}
		b, err := r.ReadByte()
		if err != nil {
			t.Fatalf("read: %v (have %x)", err, *got)
		}
		*got = append(*got, b)
	}
}

func TestRelayNegotiatesStartsFromScreenAndRelays(t *testing.T) {
	host := tn5250.New()
	// The host's current display: "HI" at row 1 and an input field.
	screen := gds(3, []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 1, 1, 0xc8, 0xc9, 0x11, 2, 9, 0x1d, 0x40, 0, 0x24, 0, 5, 0x40, 0x40, 0x40, 0x40, 0x40})
	if err := host.Apply(screen); err != nil {
		t.Fatal(err)
	}
	relay := New()
	server, client := net.Pipe()
	go relay.Serve(server)
	r := bufio.NewReader(client)
	var got []byte
	readUntil(t, r, &got, []byte{iac, do, optTermType})
	go client.Write([]byte{iac, will, optTermType})
	readUntil(t, r, &got, []byte{iac, sb, optTermType, 1, iac, se})
	go client.Write(append(append([]byte{iac, sb, optTermType, 0}, "IBM-3179-2"...), iac, se))
	readUntil(t, r, &got, []byte{iac, will, optEOR, iac, do, optBinary})
	// The owner's next Sync starts the client from the current screen.
	deadline := time.Now().Add(5 * time.Second)
	for len(relay.Clients()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c := relay.Clients(); len(c) != 1 || c[0] != "IBM-3179-2" {
		t.Fatalf("clients %q", c)
	}
	relay.Sync(host)
	got = got[:0]
	readUntil(t, r, &got, []byte{iac, eor})
	if !bytes.Contains(got, []byte{0xc8, 0xc9}) || bytes.Contains(got, []byte{0x10, 0, 2, 0xc8}) {
		t.Fatalf("initial screen %x lacks the display text", got)
	}
	if !bytes.Contains(got, []byte{0x1d, 0x40, 0, 0x24, 0, 5}) {
		t.Fatalf("initial screen %x lacks the input field", got)
	}
	// A later host display record is forwarded as sent.
	update := gds(2, []byte{4, 0x11, 0, 0, 0x11, 24, 1, 0xc1})
	wire := append(bytes.Clone(update), iac, eor)
	if _, err := host.Feed(wire); err != nil {
		t.Fatal(err)
	}
	relay.Sync(host)
	got = got[:0]
	readUntil(t, r, &got, wire)
	// Client AID input reaches the host; a query reply does not.
	input := gds(3, []byte{2, 9, 0xf1})
	query := gds(0, []byte{0x88, 0, 1})
	go client.Write(append(append(append(bytes.Clone(query), iac, eor), input...), iac, eor))
	var sent []byte
	deadline = time.Now().Add(5 * time.Second)
	for len(sent) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		sent = relay.Sync(host)
	}
	if !bytes.Equal(sent, append(bytes.Clone(input), iac, eor)) {
		t.Fatalf("host input %x", sent)
	}
	client.Close()
	_, _ = io.ReadAll(r)
}

func TestFieldAddressesFromAttributeBytesAreCorrected(t *testing.T) {
	fields := []tn5250.Field{{Row: 20, Column: 7, Length: 153}}
	// A client that addressed the command line from its attribute (20,6),
	// as the attribute cell (blank) then "1".
	bad := gds(3, []byte{20, 8, 0xf1, 0x11, 20, 6, 0x40, 0xf1, 0x40})
	want := gds(3, []byte{20, 8, 0xf1, 0x11, 20, 7, 0xf1, 0x40})
	if got := fieldAddresses(bad, fields); !bytes.Equal(got, want) {
		t.Fatalf("corrected %x, want %x", got, want)
	}
	good := gds(3, []byte{20, 8, 0xf1, 0x11, 20, 7, 0xf1})
	if got := fieldAddresses(good, fields); !bytes.Equal(got, good) {
		t.Fatalf("correct input changed: %x", got)
	}
}
