package uefi

import (
	"bytes"
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
