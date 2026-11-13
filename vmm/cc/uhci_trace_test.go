package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestUHCIFrameEvidenceSurvivesDriverDisable(t *testing.T) {
	u, ram, irq := usbTestController()
	// NAKing keyboard QH followed by an inactive IOC liveness TD. Neither
	// descriptor may be consumed; the liveness interrupt must still occur.
	u.devices[0].configuration = 1
	u.ports[0] |= 4
	binary.LittleEndian.PutUint32(ram[0x1000:], 0x3000)
	binary.LittleEndian.PutUint32(ram[0x1004:], 0x2000)
	usbTestTD(ram, 0x2000, 1, 0x69, 0, 1, 8)
	usbTestTD(ram, 0x3000, 1, 0x69, 0, 1, 8)
	binary.LittleEndian.PutUint32(ram[0x3004:], 1<<24)
	for i := 0; i < 1024; i++ {
		binary.LittleEndian.PutUint32(ram[i*4:], 0x1002)
	}
	u.command = 1
	u.status = 0
	u.interrupt = 4
	now := time.Unix(1, 0)
	if err := u.poll(now); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 80; i++ {
		if err := u.poll(now.Add(time.Duration(i) * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if !*irq {
			t.Fatal("liveness interrupt lost")
		}
		if err := u.io(hypervisor.X86Exit{Port: uint16(u.ioBase() + 2), Size: 2, Count: 1, Write: true, Data: []byte{1, 0}}, now); err != nil {
			t.Fatal(err)
		}
	}
	u.writeConfig(4, 0)
	u.writeConfig(5, 4)
	if err := u.poll(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	history := u.frameHistory()
	if len(history) != 64 {
		t.Fatalf("history length %d", len(history))
	}
	for i, item := range history {
		row := item.(map[string]any)
		if row["frames"] != int64(i+16) || row["tds"] != int64(2) || row["active"] != int64(1) || row["ioc"] != int64(2) || row["last_td"] != int64(0x3000) || row["status_after"] != 1 {
			t.Fatalf("lost NAK/IOC evidence: %v", row)
		}
	}
	if u.irqLevel || u.irqRises != 80 || u.irqFalls != 80 {
		t.Fatalf("incorrect IRQ edges: %v %d %d", u.irqLevel, u.irqRises, u.irqFalls)
	}
	if binary.LittleEndian.Uint32(ram[0x1004:]) != 0x2000 || u.devices[0].reports != 0 || u.transactions != 80 {
		t.Fatal("observation changed schedule behavior")
	}
	history[0].(map[string]any)["last_td"] = int64(0)
	if u.frameHistory()[0].(map[string]any)["last_td"] != int64(0x3000) {
		t.Fatal("inspection aliases live evidence")
	}
}
