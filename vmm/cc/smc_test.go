package cc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"j5.nz/cc/hypervisor"
	"testing"
)

// Exercise the consumer's wire contract through native exit routing, rather
// than poking internal transaction fields. Byte-status assertions distinguish
// a real complete read from a permanently-ready/dummy-data device.
func smcPort(t *testing.T, s *smc, port uint16, write bool, data ...byte) []byte {
	t.Helper()
	if len(data) == 0 {
		data = []byte{0}
	}
	ex := hypervisor.X86Exit{Port: port, Write: write, Size: 1, Count: uint32(len(data)), Data: data}
	if err := s.io(ex); err != nil {
		t.Fatal(err)
	}
	return ex.Data
}
func smcRequest(t *testing.T, s *smc, command byte, key []byte, length byte) {
	t.Helper()
	smcPort(t, s, 0x304, true, command)
	if status := smcPort(t, s, 0x304, false)[0]; status&6 != 4 {
		t.Fatalf("command not accepting input: %x", status)
	}
	smcPort(t, s, 0x300, true, key...)
	smcPort(t, s, 0x300, true, length)
}
func smcRead(t *testing.T, s *smc, length int) []byte {
	t.Helper()
	out := make([]byte, length)
	for i := range out {
		if status := smcPort(t, s, 0x304, false)[0]; status&7 != 5 {
			t.Fatalf("byte%d not ready: %x", i, status)
		}
		out[i] = smcPort(t, s, 0x300, false)[0]
	}
	if status := smcPort(t, s, 0x304, false)[0]; status&5 != 0 {
		t.Fatalf("read never completes: %x", status)
	}
	return out
}
func TestSMCConsumerEnumerationAndMetadata(t *testing.T) {
	s := newSMC(nil)
	smcRequest(t, s, 0x10, []byte("#KEY"), 4)
	count := binary.BigEndian.Uint32(smcRead(t, s, 4))
	if count != 4 {
		t.Fatalf("unexpected key count %d", count)
	}
	for i := uint32(0); i < count; i++ {
		index := make([]byte, 4)
		binary.BigEndian.PutUint32(index, i)
		smcRequest(t, s, 0x12, index, 4)
		key := smcRead(t, s, 4)
		smcRequest(t, s, 0x13, key, 6)
		info := smcRead(t, s, 6)
		if info[5] != 0x80 || info[0] == 0 || info[0] > 32 {
			t.Fatalf("bad metadata for %q: %x", key, info)
		}
		smcRequest(t, s, 0x10, key, info[0])
		smcRead(t, s, int(info[0]))
	}
}
func TestSMCMissingOSKAndErrorRecovery(t *testing.T) {
	s := newSMC(nil)
	for _, request := range []struct {
		cmd            byte
		key            string
		length, result byte
	}{
		{0x10, "OSK0", 32, 0x84}, {0x10, "OSK1", 32, 0x84},
		{0x10, "#KEY", 255, 0x85}, {0x11, "#KEY", 4, 0x86},
		{0x13, "NONE", 6, 0x84}, {0x10, "#KEY", 3, 0x85},
	} {
		smcRequest(t, s, request.cmd, []byte(request.key), request.length)
		if result := smcPort(t, s, 0x31e, false)[0]; result != request.result {
			t.Fatalf("%q result %x", request.key, result)
		}
		if status := smcPort(t, s, 0x304, false)[0]; status != 0 {
			t.Fatalf("error still busy: %x", status)
		}
		smcRequest(t, s, 0x10, []byte("#KEY"), 4)
		if binary.BigEndian.Uint32(smcRead(t, s, 4)) != 4 {
			t.Fatal("error poisoned next transaction")
		}
	}
}
func TestSMCExplicitKeyOwnershipAndTraceRedaction(t *testing.T) {
	key := bytes.Repeat([]byte{0xa5}, 64) // synthetic test bytes, not Apple material
	s := newSMC(key)
	clear(key)
	for _, name := range []string{"OSK0", "OSK1"} {
		smcRequest(t, s, 0x10, []byte(name), 32)
		if !bytes.Equal(smcRead(t, s, 32), bytes.Repeat([]byte{0xa5}, 32)) {
			t.Fatal("did not retain caller key")
		}
	}
	for i := 0; i < 100; i++ {
		smcRequest(t, s, 0x10, []byte("OSK0"), 32)
		smcRead(t, s, 32)
	}
	if len(s.trace) != 64 {
		t.Fatal("unbounded trace")
	}
	if bytes.Contains([]byte(fmt.Sprint(s.trace)), []byte("165")) {
		t.Fatal("key bytes disclosed by trace")
	}
}
