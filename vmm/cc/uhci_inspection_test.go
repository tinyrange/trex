package cc

import (
	"encoding/binary"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
)

func TestUHCIRegisterHistoryIsBoundedAndDetached(t *testing.T) {
	u, _, _ := usbTestController()
	now := time.Unix(1, 0)
	for i := 0; i < 80; i++ {
		u.frame = uint16(i)
		data := make([]byte, 2)
		if err := u.io(hypervisor.X86Exit{Port: uint16(u.ioBase() + 6), Size: 2, Count: 1, Data: data}, now); err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint16(data); got != uint16(i) {
			t.Fatalf("inspection changed register read: %d", got)
		}
	}
	history := u.accessHistory()
	if len(history) != 64 || history[0].(map[string]any)["value"] != int64(16) || history[63].(map[string]any)["value"] != int64(79) {
		t.Fatalf("wrong bounded order: %v", history)
	}
	u.writeConfig(4, 0)
	u.writeConfig(5, 4)
	current := u.accessHistory()
	if current[63].(map[string]any)["space"] != "pci" || current[63].(map[string]any)["offset"] != 5 || current[63].(map[string]any)["value"] != int64(4) {
		t.Fatalf("lost PCI disable: %v", current[63])
	}
	current[0].(map[string]any)["value"] = int64(999)
	if u.accessHistory()[0].(map[string]any)["value"] == int64(999) || history[63].(map[string]any)["value"] != int64(79) {
		t.Fatal("inspection aliases controller or previous snapshot")
	}
}

func TestUHCIActivePollGapDoesNotCountDisabledTime(t *testing.T) {
	u, ram, _ := usbTestController()
	// Every frame list entry terminates: only scheduling cadence is observed.
	for i := 0; i < 1024; i++ {
		binary.LittleEndian.PutUint32(ram[i*4:], 1)
	}
	now := time.Unix(1, 0)
	if err := u.poll(now); err != nil {
		t.Fatal(err)
	}
	if err := u.poll(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if u.maxPollGap != 0 {
		t.Fatal("disabled time counted")
	}
	u.command = 1
	if err := u.poll(now.Add(time.Hour + 7*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if u.maxPollGap != 7*time.Millisecond {
		t.Fatalf("missing active gap: %s", u.maxPollGap)
	}
	u.config[4] = 0
	if err := u.poll(now.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if u.maxPollGap != 7*time.Millisecond {
		t.Fatal("PCI-disabled time counted")
	}
}
