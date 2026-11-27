package r3000

import (
	"testing"

	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestIP24CheckpointBranchesMachineAndDisk(t *testing.T) {
	m, err := newIP24(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	base, err := block.NewFileDevice(&starfile.Bytes{Data: make([]byte, 512)}, block.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	disk, err := blockstar.NewOverlayDevice(base, 512, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AttachDisk(1, disk); err != nil {
		t.Fatal(err)
	}
	m.ram[0], m.newport.rgb[0], m.cpu.gpr[4] = 5, 6, 7
	m.cycles, m.int3.microseconds, m.keyboard.deadline = 100, 44, 103
	m.scsi.writeData = []byte{8}
	if _, err := disk.WriteAt([]byte{9}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.console.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	saved, err := m.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	m.ram[0], m.newport.rgb[0], m.scsi.writeData[0] = 55, 66, 88
	if _, err := disk.WriteAt([]byte{99}, 0); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		machine, err := saved.Restore()
		if err != nil {
			t.Fatal(err)
		}
		if machine.ram[0] != 5 || machine.newport.rgb[0] != 6 || machine.cpu.gpr[4] != 7 || machine.scsi.writeData[0] != 8 ||
			machine.cycles != 100 || machine.int3.microseconds != 44 || machine.keyboard.deadline != 103 {
			t.Fatalf("branch %d lost checkpoint state", i)
		}
		media := machine.targets[1].Media()
		var value [1]byte
		if _, err := media.ReadAt(value[:], 0); err != nil || value[0] != 9 {
			t.Fatalf("branch %d disk = %v, %v", i, value, err)
		}
		if _, err := media.(block.Writer).WriteAt([]byte{42}, 0); err != nil {
			t.Fatal(err)
		}
		serial := machine.scc.ports[ip24SerialPort].stream
		if _, err := serial.ReadAvailable(value[:]); err != nil || value[0] != 'x' {
			t.Fatalf("branch %d serial = %v, %v", i, value, err)
		}
		machine.ram[0], machine.newport.rgb[0], machine.scsi.writeData[0] = 42, 42, 42
		if err := machine.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
