package uefi

import (
	"bytes"
	"github.com/tinyrange/trex/block"
	blocknative "github.com/tinyrange/trex/block/native"
	"io"
	"testing"
)

func TestFirmwareBlockViewsAndCheckpointsShareCoherentOverlay(t *testing.T) {
	m := machine(t, 0xd65f03c0)
	original := bytes.Repeat([]byte{0x5a}, 4096)
	source := io.NewSectionReader(bytes.NewReader(original), 0, int64(len(original)))
	disk, err := m.AttachBlockDevice(source, BlockOptions{OverlayBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	partition, err := m.AttachBlockPartition(disk, 512, 1024, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	diskInterface := m.protocols[disk][blockIOGUID]
	partitionInterface := m.protocols[partition][blockIOGUID]
	buffer := ramBase + 0x200000
	checkpoint, err := m.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	m.put(buffer, bytes.Repeat([]byte{0xa5}, 512))
	if status := m.blockCall("Block.Write", [8]uint64{partitionInterface, 1, 0, 512, buffer}); status != 0 {
		t.Fatalf("write status=%x", status)
	}
	if status := m.blockCall("Block.Read", [8]uint64{diskInterface, 1, 1, 512, buffer}); status != 0 {
		t.Fatalf("read status=%x", status)
	}
	if !bytes.Equal(m.get(buffer, 512), bytes.Repeat([]byte{0xa5}, 512)) {
		t.Fatal("partition and disk do not share writes")
	}
	if !bytes.Equal(original, bytes.Repeat([]byte{0x5a}, 4096)) {
		t.Fatal("input source modified")
	}
	if err := m.Restore(checkpoint); err != nil {
		t.Fatal(err)
	}
	if status := m.blockCall("Block.Read", [8]uint64{partitionInterface, 1, 0, 512, buffer}); status != 0 {
		t.Fatal(status)
	}
	if !bytes.Equal(m.get(buffer, 512), bytes.Repeat([]byte{0x5a}, 512)) {
		t.Fatal("checkpoint did not restore disk bytes")
	}
	if status := m.blockCall("Block.Read", [8]uint64{partitionInterface, 1, 2, 512, buffer}); status != invalidParameter {
		t.Fatal("partition bounds ignored")
	}
	if status := m.blockCall("Block.Read", [8]uint64{partitionInterface, 2, 0, 512, buffer}); status != efiError|13 {
		t.Fatal("media ID ignored")
	}
}

func TestCallerBackingSharedAcrossFirmwareAndNative(t *testing.T) {
	m := machine(t, 0xd65f03c0)
	defer m.Close()
	original := bytes.Repeat([]byte{0x5a}, 4096)
	base, err := block.NewFileDevice(io.NewSectionReader(bytes.NewReader(original), 0, 4096), block.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	backing, err := blocknative.NewTemporaryOverlay(base, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Close()
	disk, err := m.AttachDevice(backing, BlockOptions{})
	if err != nil {
		t.Fatal(err)
	}
	part, err := m.AttachBlockPartition(disk, 512, 1024, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	buffer := ramBase + 0x200000
	m.put(buffer, []byte{1, 2, 3})
	if status := m.blockCall("Disk.Write", [8]uint64{m.protocols[part][diskIOGUID], 1, 0, 3, buffer}); status != 0 {
		t.Fatal(status)
	}
	device, err := m.diskStores[0].nativeDevice()
	if err != nil || device != backing {
		t.Fatalf("handoff replaced backing: %v", err)
	}
	native := nativeDisk{device}
	got := make([]byte, 3)
	if _, err := native.ReadAt(got, 512); err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("firmware writes lost: %v %v", got, err)
	}
	if _, err := native.WriteAt([]byte{4, 5, 6}, 512); err != nil {
		t.Fatal(err)
	}
	if status := m.blockCall("Disk.Read", [8]uint64{m.protocols[part][diskIOGUID], 1, 0, 3, buffer}); status != 0 {
		t.Fatal(status)
	}
	if !bytes.Equal(m.get(buffer, 3), []byte{4, 5, 6}) {
		t.Fatal("native writes not visible to firmware")
	}
	if _, err := m.Checkpoint(); err == nil {
		t.Fatal("mutable caller backing checkpointed")
	}
	if !bytes.Equal(original, bytes.Repeat([]byte{0x5a}, 4096)) {
		t.Fatal("source changed")
	}
}
