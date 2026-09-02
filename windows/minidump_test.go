package windows

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"

	"go.starlark.net/starlark"
)

func TestMinidumpExceptionRecord(t *testing.T) {
	raw := make([]byte, 168)
	binary.LittleEndian.PutUint32(raw[0:4], 42)
	binary.LittleEndian.PutUint32(raw[8:12], 0xe06d7363)
	binary.LittleEndian.PutUint32(raw[12:16], 1)
	binary.LittleEndian.PutUint64(raw[16:24], 0x1111)
	binary.LittleEndian.PutUint64(raw[24:32], 0x2222)
	binary.LittleEndian.PutUint32(raw[32:36], 2)
	binary.LittleEndian.PutUint64(raw[40:48], 0x3333)
	binary.LittleEndian.PutUint64(raw[48:56], 0x4444)
	value, err := minidumpExceptionRecord(&starfile.Bytes{Name: "exception", Data: raw}, minidumpLocation{size: uint32(len(raw))})
	if err != nil {
		t.Fatal(err)
	}
	record := value.(*starfile.Record)
	code, _ := record.Attr("code")
	if got := code.String(); got != "3765269347" {
		t.Fatalf("code = %s", got)
	}
	threadID, _ := record.Attr("thread_id")
	if got := threadID.String(); got != "42" {
		t.Fatalf("thread_id = %s", got)
	}
	information, _ := record.Attr("information")
	if got := information.(*starlark.List).Len(); got != 2 {
		t.Fatalf("information length = %d", got)
	}
}

func TestMinidumpRegistersI386(t *testing.T) {
	context := make([]byte, 200)
	binary.LittleEndian.PutUint32(context[180:184], 0x11223344)
	binary.LittleEndian.PutUint32(context[184:188], 0x55667788)
	binary.LittleEndian.PutUint32(context[196:200], 0x99aabbcc)
	pc, sp, fp := minidumpRegisters(context, 0)
	if pc != 0x55667788 || sp != 0x99aabbcc || fp != 0x11223344 {
		t.Fatalf("registers = pc %#x sp %#x fp %#x", pc, sp, fp)
	}
}

func TestMinidumpString(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[8:12], 8)
	copy(data[12:], []byte{'g', 0, 'p', 0, 's', 0, 'v', 0})
	got, err := minidumpString(&starfile.Bytes{Name: "dump", Data: data}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got != "gpsv" {
		t.Fatalf("string = %q", got)
	}
}

func TestMinidumpFramesI386(t *testing.T) {
	stack := make([]byte, 0x80)
	start := uint64(0x1000)
	binary.LittleEndian.PutUint32(stack[0x20:0x24], 0x1040)
	binary.LittleEndian.PutUint32(stack[0x24:0x28], 0x401234)
	binary.LittleEndian.PutUint32(stack[0x40:0x44], 0x1060)
	binary.LittleEndian.PutUint32(stack[0x44:0x48], 0x402345)
	binary.LittleEndian.PutUint32(stack[0x60:0x64], 0)
	binary.LittleEndian.PutUint32(stack[0x64:0x68], 0x403456)

	frames := minidumpFrames(stack, start, 0x400123, 0x1010, 0x1020, 0)
	if len(frames) != 4 {
		t.Fatalf("frame count = %d, want 4", len(frames))
	}
	wantAddresses := []uint64{0x400123, 0x401234, 0x402345, 0x403456}
	wantStacks := []uint64{0x1010, 0x1024, 0x1044, 0x1064}
	for index := range frames {
		if frames[index].address != wantAddresses[index] || frames[index].stackAddress != wantStacks[index] {
			t.Fatalf("frame %d = %+v", index, frames[index])
		}
	}
}

func TestMinidumpFramesRejectsNonIncreasingChain(t *testing.T) {
	stack := make([]byte, 0x40)
	binary.LittleEndian.PutUint32(stack[0x20:0x24], 0x1020)
	binary.LittleEndian.PutUint32(stack[0x24:0x28], 0x401234)
	frames := minidumpFrames(stack, 0x1000, 0x400123, 0x1010, 0x1020, 0)
	if len(frames) != 2 {
		t.Fatalf("frame count = %d, want 2", len(frames))
	}
}

func TestMinidumpMemory64Ranges(t *testing.T) {
	raw := make([]byte, 96)
	binary.LittleEndian.PutUint64(raw[8:16], 2)
	binary.LittleEndian.PutUint64(raw[16:24], 64)
	binary.LittleEndian.PutUint64(raw[24:32], 0x1000)
	binary.LittleEndian.PutUint64(raw[32:40], 4)
	binary.LittleEndian.PutUint64(raw[40:48], 0x2000)
	binary.LittleEndian.PutUint64(raw[48:56], 3)
	copy(raw[64:71], []byte("abcdefg"))
	file := &starfile.Bytes{Name: "dump", Data: raw}
	ranges, err := minidumpMemoryRanges(file, map[uint32]minidumpLocation{
		minidumpMemory64List: {rva: 8, size: 48},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 {
		t.Fatalf("range count = %d", len(ranges))
	}
	first := ranges[0].(*starfile.Record)
	address := first.Get("address")
	if address.String() != "4096" {
		t.Fatalf("first address = %s", address)
	}
	data, err := starfile.ReadAll(first.Get("file").(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "abcd" {
		t.Fatalf("first data = %q", data)
	}
}
