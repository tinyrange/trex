package x86

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"math"
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"golang.org/x/arch/x86/x86asm"
)

func TestPESectionMappingAcceptsTruncatedRawPadding(t *testing.T) {
	data := make([]byte, 0x1310)
	section := &pe.Section{SectionHeader: pe.SectionHeader{
		Name:           ".reloc",
		VirtualSize:    0x108,
		VirtualAddress: 0x2000,
		Size:           0x200,
		Offset:         0x1200,
	}}
	got, err := peSectionDataForMapping(data, section)
	if err != nil {
		t.Fatal(err)
	}
	if gotSize, want := len(got), 0x110; gotSize != want {
		t.Fatalf("mapped section size = %#x, want %#x", gotSize, want)
	}
}

func TestPESectionMappingRejectsMissingVirtualData(t *testing.T) {
	data := make([]byte, 0x1300)
	section := &pe.Section{SectionHeader: pe.SectionHeader{
		Name:           ".text",
		VirtualSize:    0x180,
		VirtualAddress: 0x2000,
		Size:           0x200,
		Offset:         0x1200,
	}}
	if _, err := peSectionDataForMapping(data, section); err == nil {
		t.Fatal("section mapping accepted missing virtual data")
	}
}

func TestPE32TLSMetadataPreservesTemplateIndexAndCallbacks(t *testing.T) {
	const base = uint32(0x00400000)
	mapped := make([]byte, 0x1000)
	optional := &pe.OptionalHeader32{}
	optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS] = pe.DataDirectory{VirtualAddress: 0x100, Size: 24}
	tls := mapped[0x100:0x118]
	binary.LittleEndian.PutUint32(tls[0:4], base+0x200)
	binary.LittleEndian.PutUint32(tls[4:8], base+0x204)
	binary.LittleEndian.PutUint32(tls[8:12], base+0x300)
	binary.LittleEndian.PutUint32(tls[12:16], base+0x400)
	binary.LittleEndian.PutUint32(tls[16:20], 3)
	copy(mapped[0x200:0x204], []byte{0xff, 0xff, 0xff, 0xff})
	binary.LittleEndian.PutUint32(mapped[0x400:0x404], base+0x500)
	binary.LittleEndian.PutUint32(mapped[0x404:0x408], base+0x600)

	template, zeroFill, index, callbacks, err := pe32TLSMetadata(mapped, optional, base)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := template, []byte{0xff, 0xff, 0xff, 0xff}; !bytes.Equal(got, want) {
		t.Fatalf("template = %x, want %x", got, want)
	}
	if zeroFill != 3 || index != base+0x300 {
		t.Fatalf("zero fill/index = %#x/%#x, want 3/%#x", zeroFill, index, base+0x300)
	}
	if len(callbacks) != 2 || callbacks[0] != base+0x500 || callbacks[1] != base+0x600 {
		t.Fatalf("callbacks = %#v", callbacks)
	}
}

func TestEmulatorX86FreeReclaimsPluginAllocation(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	allocate := func(size, alignment int) uint32 {
		value, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
			{starlark.String("size"), starlark.MakeInt(size)},
			{starlark.String("alignment"), starlark.MakeInt(alignment)},
		})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	first := allocate(31, 16)
	second := allocate(64, 64)
	before := machine.mappedBytes
	if _, err := machine.freeBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint(uint(first))}, nil); err != nil {
		t.Fatal(err)
	}
	if machine.mappedBytes != before-31 {
		t.Fatalf("mapped bytes = %d, want %d", machine.mappedBytes, before-31)
	}
	if _, _, err := machine.mapping(first, 1, 'r'); err == nil {
		t.Fatal("freed allocation remains mapped")
	}
	if got := allocate(16, 16); got != first {
		t.Fatalf("reused address = %#x, want %#x", got, first)
	}
	if got := allocate(64, 64); got == second {
		t.Fatal("allocator reused a live allocation")
	}
	if _, err := machine.freeBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint(uint(first + 1))}, nil); err == nil {
		t.Fatal("free accepted an interior pointer")
	}
}

func TestEmulatorX86RequestedAllocationConsumesReclaimedRange(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	allocate := func(size int, address *uint32) uint32 {
		kwargs := []starlark.Tuple{{starlark.String("size"), starlark.MakeInt(size)}}
		if address != nil {
			kwargs = append(kwargs, starlark.Tuple{starlark.String("address"), starlark.MakeUint(uint(*address))})
		}
		value, err := machine.allocateBuiltin(nil, nil, nil, kwargs)
		if err != nil {
			t.Fatal(err)
		}
		result, _ := value.(starlark.Int).Uint64()
		return uint32(result)
	}
	first := allocate(0x100, nil)
	if _, err := machine.freeBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint(uint(first))}, nil); err != nil {
		t.Fatal(err)
	}
	fixed := first + 0x40
	if got := allocate(0x40, &fixed); got != fixed {
		t.Fatalf("fixed allocation = %#x, want %#x", got, fixed)
	}
	if got := allocate(0x40, nil); got != first {
		t.Fatalf("leading reclaimed allocation = %#x, want %#x", got, first)
	}
	if got := allocate(0x40, nil); got != first+0x80 {
		t.Fatalf("trailing reclaimed allocation = %#x, want %#x", got, first+0x80)
	}
}

func TestEmulatorX86PrefetchIsNonFaultingHint(t *testing.T) {
	// mov eax,0xdeadbeef; prefetcht0 [eax]; mov eax,42; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\xef\xbe\xad\xde\x0f\x18\x08\xb8\x2a\x00\x00\x00\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-prefetch-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 42 {
		t.Fatalf("value = %d, want 42", got)
	}
}

func TestEmulatorX86MemoryFencesPreserveSequentialExecution(t *testing.T) {
	// mov eax,42; lfence; mfence; sfence; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x2a\x00\x00\x00\x0f\xae\xe8\x0f\xae\xf0\x0f\xae\xf8\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-memory-fence-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 42 {
		t.Fatalf("value = %d, want 42", got)
	}
}

func TestEmulatorX86PackedDwordEquality(t *testing.T) {
	// pcmpeqd xmm0,xmm0; movd eax,xmm0; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\x66\x0f\x76\xc0\x66\x0f\x7e\xc0\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-pcmpeqd-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != math.MaxUint32 {
		t.Fatalf("value = %#x, want %#x", got, uint32(math.MaxUint32))
	}
}

func TestEmulatorX86CPUIDReportsStableVendor(t *testing.T) {
	// xor eax,eax; cpuid; mov eax,ebx; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\x31\xc0\x0f\xa2\x89\xd8\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-cpuid-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0x756e6547 {
		t.Fatalf("vendor prefix = %#x, want %#x", got, uint32(0x756e6547))
	}
}

func TestEmulatorX86ConvertsSignedIntegerToScalarDouble(t *testing.T) {
	// mov eax,-2; cvtsi2sd xmm0,eax; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\xfe\xff\xff\xff\xf2\x0f\x2a\xc0\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-cvtsi2sd-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(machine.xmm[0][:8])); got != -2 {
		t.Fatalf("xmm0 scalar = %g, want -2", got)
	}
}

func TestEmulatorX86TruncatesScalarDoubleToSignedInteger(t *testing.T) {
	// mov eax,-2; cvtsi2sd xmm0,eax; addsd xmm0,xmm0; cvttsd2si eax,xmm0; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\xfe\xff\xff\xff\xf2\x0f\x2a\xc0\xf2\x0f\x58\xc0\xf2\x0f\x2c\xc0\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-cvttsd2si-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != uint32(0xfffffffc) {
		t.Fatalf("value = %#x, want -4", got)
	}
}

func TestEmulatorX86ScalarFloatMultiply(t *testing.T) {
	// mov eax,2.0f; movd xmm0,eax; mulss xmm0,xmm0; movd eax,xmm0; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x00\x00\x00\x40\x66\x0f\x6e\xc0\xf3\x0f\x59\xc0\x66\x0f\x7e\xc0\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-mulss-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := math.Float32frombits(recordUint32(t, result, "value")); got != 4 {
		t.Fatalf("value = %g, want 4", got)
	}
}

func TestEmulatorX86RoundsX87ValueToIntegral(t *testing.T) {
	// fld qword ptr [0x2000]; frndint; fstp qword ptr [0x2008]; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xdd\x05\x00\x20\x00\x00\xd9\xfc\xdd\x1d\x08\x20\x00\x00\xc3"), nil)
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data, math.Float64bits(2.5))
	if err := machine.addMapping("x87 round operands", 0x2000, data, true, true, false); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-frndint-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	stored, err := machine.readMemory(0x2008, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(stored)); got != 2 {
		t.Fatalf("rounded value = %g, want 2", got)
	}
}

func TestEmulatorX86PacksSignedWordsToUnsignedBytes(t *testing.T) {
	// packuswb xmm0,xmm1; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\x66\x0f\x67\xc1\xc3"), nil)
	left := []int16{-1, 0, 1, 254, 255, 256, 32767, -32768}
	right := []int16{2, 3, 4, 5, 6, 7, 8, 9}
	for index, value := range left {
		binary.LittleEndian.PutUint16(machine.xmm[0][index*2:], uint16(value))
	}
	for index, value := range right {
		binary.LittleEndian.PutUint16(machine.xmm[1][index*2:], uint16(value))
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-packuswb-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	want := [16]byte{0, 0, 1, 254, 255, 255, 255, 0, 2, 3, 4, 5, 6, 7, 8, 9}
	if machine.xmm[0] != want {
		t.Fatalf("packed bytes = %v, want %v", machine.xmm[0], want)
	}
}

func TestEmulatorX86UnpacksLowBytes(t *testing.T) {
	// punpcklbw xmm0,xmm0; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\x66\x0f\x60\xc0\xc3"), nil)
	for index := range machine.xmm[0] {
		machine.xmm[0][index] = byte(index)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-punpcklbw-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	want := [16]byte{0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7}
	if machine.xmm[0] != want {
		t.Fatalf("unpacked bytes = %v, want %v", machine.xmm[0], want)
	}
}

func TestEmulatorX86PackedArithmeticWordShift(t *testing.T) {
	// psraw xmm0,8; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\x66\x0f\x71\xe0\x08\xc3"), nil)
	binary.LittleEndian.PutUint16(machine.xmm[0][0:], 0x8000)
	binary.LittleEndian.PutUint16(machine.xmm[0][2:], 0x7f00)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-psraw-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := binary.LittleEndian.Uint16(machine.xmm[0][0:]); got != 0xff80 {
		t.Fatalf("negative shifted word = %#x, want 0xff80", got)
	}
	if got := binary.LittleEndian.Uint16(machine.xmm[0][2:]); got != 0x007f {
		t.Fatalf("positive shifted word = %#x, want 0x007f", got)
	}
}

func TestEmulatorX86PackedByteMoveMask(t *testing.T) {
	// pmovmskb eax,xmm1; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\x66\x0f\xd7\xc1\xc3"), nil)
	for index := range machine.xmm[1] {
		if index%2 == 0 {
			machine.xmm[1][index] = 0x80
		}
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-pmovmskb-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0x5555 {
		t.Fatalf("move mask = %#x, want 0x5555", got)
	}
}

func TestEmulatorX86U32MultiplyAccumulate(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	allocate := func(words ...uint32) uint32 {
		data := make([]byte, len(words)*4)
		for index, word := range words {
			binary.LittleEndian.PutUint32(data[index*4:], word)
		}
		value, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
			{starlark.String("value"), starlark.Bytes(data)},
		})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	invoke := func(destination, source uint32, count, scalar uint64, subtract bool) uint64 {
		value, err := machine.u32MultiplyAccumulateBuiltin(nil, nil, nil, []starlark.Tuple{
			{starlark.String("destination"), starlark.MakeUint64(uint64(destination))},
			{starlark.String("source"), starlark.MakeUint64(uint64(source))},
			{starlark.String("count"), starlark.MakeUint64(count)},
			{starlark.String("scalar"), starlark.MakeUint64(scalar)},
			{starlark.String("subtract"), starlark.Bool(subtract)},
		})
		if err != nil {
			t.Fatal(err)
		}
		carry, _ := value.(starlark.Int).Uint64()
		return carry
	}

	source := allocate(math.MaxUint32, 2)
	destination := allocate(1, 3)
	if carry := invoke(destination, source, 2, 2, false); carry != 0 {
		t.Fatalf("addition carry = %#x, want 0", carry)
	}
	data, err := machine.readMemory(destination, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data[:4]); got != math.MaxUint32 {
		t.Fatalf("addition word 0 = %#x, want %#x", got, uint32(math.MaxUint32))
	}
	if got := binary.LittleEndian.Uint32(data[4:]); got != 8 {
		t.Fatalf("addition word 1 = %#x, want 8", got)
	}

	borrowSource := allocate(1, 0)
	borrowDestination := allocate(0, 0)
	if carry := invoke(borrowDestination, borrowSource, 2, 1, true); carry != 1 {
		t.Fatalf("subtraction carry = %#x, want 1", carry)
	}
	data, err = machine.readMemory(borrowDestination, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data[:4]); got != math.MaxUint32 {
		t.Fatalf("subtraction word 0 = %#x, want %#x", got, uint32(math.MaxUint32))
	}
	if got := binary.LittleEndian.Uint32(data[4:]); got != math.MaxUint32 {
		t.Fatalf("subtraction word 1 = %#x, want %#x", got, uint32(math.MaxUint32))
	}
}

func TestEmulatorX86RDTSCUsesDeterministicInstructionClock(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\x0f\x31\xc3"), nil)
	thread := &starlark.Thread{Name: "emulator-rdtsc-test"}

	firstValue, err := machine.callAddress(thread, machine.entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondValue, err := machine.callAddress(thread, machine.entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := firstValue.(*starlarkRecord)
	second := secondValue.(*starlarkRecord)
	if got, want := recordUint32(t, first, "value"), uint32(1); got != want {
		t.Fatalf("first RDTSC = %d, want %d", got, want)
	}
	if got, want := recordUint32(t, second, "value"), uint32(3); got != want {
		t.Fatalf("second RDTSC = %d, want %d", got, want)
	}

	replayed := newRawX86TestMachine(t, starlark.Bytes("\x0f\x31\xc3"), nil)
	replayedValue, err := replayed.callAddress(thread, replayed.entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recordUint32(t, replayedValue.(*starlarkRecord), "value"), uint32(1); got != want {
		t.Fatalf("replayed RDTSC = %d, want %d", got, want)
	}
}

func TestEmulatorX86BitTestRegisterAndMemoryBitString(t *testing.T) {
	thread := &starlark.Thread{Name: "emulator-bt-test"}
	register := newRawX86TestMachine(t, starlark.Bytes("\xb8\x08\x00\x00\x00\x0f\xba\xe0\x03\x0f\x92\xc0\x0f\xb6\xc0\xc3"), nil)
	result, err := register.callAddress(thread, register.entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := recordUint32(t, result.(*starlarkRecord), "value"); got != 1 {
		t.Fatalf("BT register carry = %d, want 1", got)
	}

	// ECX=63 selects bit 31 in the second DWORD rooted at [ESP].
	memory := newRawX86TestMachine(t, starlark.Bytes("\xb8\x00\x00\x00\x80\x50\x6a\x01\xb9\x3f\x00\x00\x00\x0f\xa3\x0c\x24\x0f\x92\xc0\x0f\xb6\xc0\x83\xc4\x08\xc3"), nil)
	result, err = memory.callAddress(thread, memory.entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := recordUint32(t, result.(*starlarkRecord), "value"); got != 1 {
		t.Fatalf("BT memory bit-string carry = %d, want 1", got)
	}
}

func TestEmulatorX86BSWAPReversesRegisterBytes(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x78\x56\x34\x12\x0f\xc8\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-bswap-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got, want := recordUint32(t, result, "value"), uint32(0x78563412); got != want {
		t.Fatalf("eax = %#x, want %#x", got, want)
	}
}

func TestEmulatorX86SAHFLoadsStatusFlagsFromAH(t *testing.T) {
	tests := []struct {
		name string
		ah   byte
		want bool
	}{
		{name: "set", ah: 0xc5, want: true},
		{name: "clear", ah: 0x00, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := starlark.Bytes([]byte{0xb8, 0x00, test.ah, 0x00, 0x00, 0x9e, 0xc3})
			machine := newRawX86TestMachine(t, code, nil)
			machine.carry = !test.want
			machine.parity = !test.want
			machine.zero = !test.want
			machine.sign = !test.want
			machine.direction = true
			machine.overflow = true

			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-sahf-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got, want := recordString(t, result, "reason"), "return"; got != want {
				t.Fatalf("reason = %q, want %q (detail %s)", got, want, recordString(t, result, "detail"))
			}
			if machine.carry != test.want || machine.parity != test.want || machine.zero != test.want || machine.sign != test.want {
				t.Fatalf("status flags = CF:%t PF:%t ZF:%t SF:%t, want all %t", machine.carry, machine.parity, machine.zero, machine.sign, test.want)
			}
			if !machine.direction || !machine.overflow {
				t.Fatalf("SAHF changed unrelated flags: DF:%t OF:%t", machine.direction, machine.overflow)
			}
		})
	}
}

func TestEmulatorX86CWDESignExtendsAX(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x01\x80\x34\x12\x98\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-cwde-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got, want := recordString(t, result, "reason"), "return"; got != want {
		t.Fatalf("reason = %q, want %q (detail %s)", got, want, recordString(t, result, "detail"))
	}
	if got, want := recordUint32(t, result, "value"), uint32(0xffff8001); got != want {
		t.Fatalf("EAX = %#x, want %#x", got, want)
	}
}

func TestEmulatorX86WordSignExtensionInstructionsPreserveUpperHalves(t *testing.T) {
	// mov eax,12345680h; cbw; mov edx,56780000h; cwd; mov eax,edx; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x80\x56\x34\x12\x66\x98\xba\x00\x00\x78\x56\x66\x99\x89\xd0\xc3"), nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-cbw-cwd-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got, want := recordString(t, result, "reason"), "return"; got != want {
		t.Fatalf("reason = %q, want %q (detail %s)", got, want, recordString(t, result, "detail"))
	}
	if got, want := recordUint32(t, result, "value"), uint32(0x5678ffff); got != want {
		t.Fatalf("EDX after CWD = %#x, want %#x", got, want)
	}
}

func TestEmulatorX86StackAndFramePointerWordAliases(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	machine.registers[x86asm.ESP] = 0x1234abcd
	machine.registers[x86asm.EBP] = 0x5678cdef

	if got, want := machine.registerValue(x86asm.SP), uint32(0xabcd); got != want {
		t.Fatalf("SP = %#x, want %#x", got, want)
	}
	if got, want := machine.registerValue(x86asm.BP), uint32(0xcdef); got != want {
		t.Fatalf("BP = %#x, want %#x", got, want)
	}
	if got, want := machine.operandWidth(x86asm.SP, 0), 2; got != want {
		t.Fatalf("SP width = %d, want %d", got, want)
	}
	if got, want := machine.operandWidth(x86asm.BP, 0), 2; got != want {
		t.Fatalf("BP width = %d, want %d", got, want)
	}

	machine.setRegisterValue(x86asm.SP, 0x1111)
	machine.setRegisterValue(x86asm.BP, 0x2222)
	if got, want := machine.registers[x86asm.ESP], uint32(0x12341111); got != want {
		t.Fatalf("ESP = %#x after SP write, want %#x", got, want)
	}
	if got, want := machine.registers[x86asm.EBP], uint32(0x56782222); got != want {
		t.Fatalf("EBP = %#x after BP write, want %#x", got, want)
	}
}

func TestEmulatorX86DoublePrecisionShifts(t *testing.T) {
	tests := []struct {
		name string
		op   []byte
		want uint32
	}{
		{name: "left", op: []byte{0x0f, 0xa4, 0xd0, 0x08}, want: 0x345678ab},
		{name: "right", op: []byte{0x0f, 0xac, 0xd0, 0x08}, want: 0x01123456},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := []byte{0xb8, 0x78, 0x56, 0x34, 0x12, 0xba, 0x01, 0xef, 0xcd, 0xab}
			code = append(code, test.op...)
			code = append(code, 0xc3)
			machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-double-shift-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.want {
				t.Fatalf("eax = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestEmulatorX86RotateThroughCarry(t *testing.T) {
	tests := []struct {
		name string
		code starlark.Bytes
		want uint32
	}{
		{
			name: "right uses and updates carry",
			// MOV EAX, 2; RCR EAX, 1; ADC EAX, 0; RET.
			code: starlark.Bytes("\xb8\x02\x00\x00\x00\xd1\xd8\x83\xd0\x00\xc3"),
			want: 0x80000001,
		},
		{
			name: "left uses and updates carry",
			// MOV EAX, 0x80000000; RCL EAX, 1; ADC EAX, 0; RET.
			code: starlark.Bytes("\xb8\x00\x00\x00\x80\xd1\xd0\x83\xd0\x00\xc3"),
			want: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			machine.carry = true
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-rotate-through-carry-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.want {
				t.Fatalf("eax = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestEmulatorX86SetOverflowConditions(t *testing.T) {
	tests := []struct {
		name string
		code starlark.Bytes
		want uint32
	}{
		{
			name: "overflow",
			code: starlark.Bytes("\xb8\xff\xff\xff\x7f\x83\xc0\x01\x0f\x90\xc0\xc3"),
			want: 0x80000001,
		},
		{
			name: "no overflow",
			code: starlark.Bytes("\x31\xc0\x0f\x91\xc0\xc3"),
			want: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-set-overflow-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.want {
				t.Fatalf("eax = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestEmulatorX86JumpOverflowConditions(t *testing.T) {
	tests := []struct {
		name string
		code starlark.Bytes
		want uint32
	}{
		{
			name: "jump on overflow",
			// MOV EAX, 0x7fffffff; ADD EAX, 1; JO return; MOV EAX, 0; RET.
			code: starlark.Bytes("\xb8\xff\xff\xff\x7f\x83\xc0\x01\x70\x05\xb8\x00\x00\x00\x00\xc3"),
			want: 0x80000000,
		},
		{
			name: "jump on no overflow",
			// XOR EAX, EAX; ADD EAX, 1; JNO return; MOV EAX, 0; RET.
			code: starlark.Bytes("\x31\xc0\x83\xc0\x01\x71\x05\xb8\x00\x00\x00\x00\xc3"),
			want: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-jump-overflow-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.want {
				t.Fatalf("eax = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestEmulatorX86XORPS(t *testing.T) {
	// XORPS XMM0, XMM1; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\x0f\x57\xc1\xc3"), nil)
	for index := range machine.xmm[0] {
		machine.xmm[0][index] = byte(index)
		machine.xmm[1][index] = byte(0xf0 + index)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-xorps-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	for index, got := range machine.xmm[0] {
		want := byte(index) ^ byte(0xf0+index)
		if got != want {
			t.Fatalf("xmm0[%d] = %#x, want %#x", index, got, want)
		}
	}
}

func TestEmulatorX86MOVUPS(t *testing.T) {
	// MOVUPS XMM0, XMM1; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\x0f\x10\xc1\xc3"), nil)
	for index := range machine.xmm[1] {
		machine.xmm[1][index] = byte(0x80 + index)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-movups-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if machine.xmm[0] != machine.xmm[1] {
		t.Fatalf("xmm0 = %x, want %x", machine.xmm[0], machine.xmm[1])
	}
}

func TestEmulatorX86MOVSDXMM(t *testing.T) {
	// MOVSD XMM0, XMM1; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\xf2\x0f\x10\xc1\xc3"), nil)
	for index := range machine.xmm[0] {
		machine.xmm[0][index] = byte(0x40 + index)
		machine.xmm[1][index] = byte(0x80 + index)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-movsd-xmm-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	for index, got := range machine.xmm[0] {
		want := byte(0x40 + index)
		if index < 8 {
			want = byte(0x80 + index)
		}
		if got != want {
			t.Fatalf("xmm0[%d] = %#x, want %#x", index, got, want)
		}
	}
}

func TestEmulatorX86MOVQXMM(t *testing.T) {
	// MOVQ XMM0, XMM1; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\xf3\x0f\x7e\xc1\xc3"), nil)
	for index := range machine.xmm[0] {
		machine.xmm[0][index] = 0xff
		machine.xmm[1][index] = byte(0x80 + index)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-movq-xmm-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	for index, got := range machine.xmm[0] {
		want := byte(0)
		if index < 8 {
			want = byte(0x80 + index)
		}
		if got != want {
			t.Fatalf("xmm0[%d] = %#x, want %#x", index, got, want)
		}
	}
}

func TestEmulatorX86ConditionalMove(t *testing.T) {
	tests := []struct {
		name string
		code starlark.Bytes
		want uint32
	}{
		{
			name: "taken",
			// MOV EAX, 1; MOV EBX, 2; CMP EAX, EAX; CMOVE EAX, EBX; RET.
			code: starlark.Bytes("\xb8\x01\x00\x00\x00\xbb\x02\x00\x00\x00\x39\xc0\x0f\x44\xc3\xc3"),
			want: 2,
		},
		{
			name: "not taken",
			// MOV EAX, 1; MOV EBX, 2; CMP EAX, EBX; CMOVE EAX, EBX; RET.
			code: starlark.Bytes("\xb8\x01\x00\x00\x00\xbb\x02\x00\x00\x00\x39\xd8\x0f\x44\xc3\xc3"),
			want: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-conditional-move-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.want {
				t.Fatalf("eax = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestEmulatorX86MOVD(t *testing.T) {
	// MOV EBX, 0x12345678; MOVD XMM0, EBX; MOVD EAX, XMM0; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\xbb\x78\x56\x34\x12\x66\x0f\x6e\xc3\x66\x0f\x7e\xc0\xc3"), nil)
	for index := range machine.xmm[0] {
		machine.xmm[0][index] = 0xff
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-movd-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0x12345678 {
		t.Fatalf("eax = %#x, want %#x", got, uint32(0x12345678))
	}
	for index, got := range machine.xmm[0][4:] {
		if got != 0 {
			t.Fatalf("xmm0[%d] = %#x, want zero", index+4, got)
		}
	}
}

func TestEmulatorX86PackedBitwise(t *testing.T) {
	// POR XMM0, XMM1; PAND XMM0, XMM2; PXOR XMM0, XMM3; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\x66\x0f\xeb\xc1\x66\x0f\xdb\xc2\x66\x0f\xef\xc3\xc3"), nil)
	for index := range machine.xmm[0] {
		machine.xmm[0][index] = 0x0f
		machine.xmm[1][index] = 0x30
		machine.xmm[2][index] = 0x3c
		machine.xmm[3][index] = 0x03
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-packed-bitwise-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	for index, got := range machine.xmm[0] {
		if got != 0x3f {
			t.Fatalf("xmm0[%d] = %#x, want 0x3f", index, got)
		}
	}
}

func TestEmulatorX86ScalarDoubleArithmetic(t *testing.T) {
	// SUBSD XMM0, XMM1; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\xf2\x0f\x5c\xc1\xc3"), nil)
	binary.LittleEndian.PutUint64(machine.xmm[0][:], math.Float64bits(10.5))
	binary.LittleEndian.PutUint64(machine.xmm[1][:], math.Float64bits(2.25))
	for index := 8; index < len(machine.xmm[0]); index++ {
		machine.xmm[0][index] = byte(0x40 + index)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-scalar-double-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(machine.xmm[0][:])); got != 8.25 {
		t.Fatalf("xmm0 low double = %g, want 8.25", got)
	}
	for index, got := range machine.xmm[0][8:] {
		want := byte(0x48 + index)
		if got != want {
			t.Fatalf("xmm0[%d] = %#x, want %#x", index+8, got, want)
		}
	}
}

func TestEmulatorX86ScalarDoubleCompare(t *testing.T) {
	// UCOMISD XMM0, XMM1; SETB AL; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\x66\x0f\x2e\xc1\x0f\x92\xc0\xc3"), nil)
	binary.LittleEndian.PutUint64(machine.xmm[0][:], math.Float64bits(1.0))
	binary.LittleEndian.PutUint64(machine.xmm[1][:], math.Float64bits(2.0))
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-scalar-double-compare-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 1 {
		t.Fatalf("eax = %#x, want 1", got)
	}
	if !machine.carry || machine.zero || machine.parity || machine.sign || machine.overflow {
		t.Fatalf("flags after 1.0 < 2.0: c=%t z=%t p=%t s=%t o=%t", machine.carry, machine.zero, machine.parity, machine.sign, machine.overflow)
	}
}

func TestEmulatorX86ScalarDoubleMinimum(t *testing.T) {
	// MINSD XMM0, XMM1; RET.
	machine := newRawX86TestMachine(t, starlark.Bytes("\xf2\x0f\x5d\xc1\xc3"), nil)
	binary.LittleEndian.PutUint64(machine.xmm[0][:], math.Float64bits(9.5))
	binary.LittleEndian.PutUint64(machine.xmm[1][:], math.Float64bits(3.25))
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-scalar-double-minimum-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(machine.xmm[0][:])); got != 3.25 {
		t.Fatalf("xmm0 low double = %g, want 3.25", got)
	}
}

func TestEmulatorX86AllocationSkipsMappedRange(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if err := machine.addMapping("module at plugin base", emulatorAllocationBase, make([]byte, 0x2345), true, true, true); err != nil {
		t.Fatal(err)
	}
	value, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("size"), starlark.MakeInt(32)},
		{starlark.String("alignment"), starlark.MakeInt(0x1000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, _ := value.(starlark.Int).Uint64()
	if got, want := uint32(address), emulatorAllocationBase+0x3000; got != want {
		t.Fatalf("allocation = %#x, want %#x", got, want)
	}
}

func TestEmulatorX86RelocatesCollidingPE32Module(t *testing.T) {
	const preferred = uint32(0x00400000)
	image := relocatablePE32TestImage(t, preferred)
	value, err := Builtin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("image"), image},
		{starlark.String("image_name"), starlark.String("first.dll")},
	})
	if err != nil {
		t.Fatal(err)
	}
	machine := value.(*emulatorX86)
	loadedValue, err := machine.loadModuleBuiltin(nil, nil, starlark.Tuple{image, starlark.String("second.dll")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	loaded := loadedValue.(*starlarkRecord)
	base := recordUint32(t, loaded, "base")
	entry := recordUint32(t, loaded, "entry")
	if base == preferred {
		t.Fatalf("second module retained colliding preferred base %#x", base)
	}
	resultValue, err := machine.callAddress(&starlark.Thread{Name: "pe32-relocation-test"}, entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got, want := recordString(t, result, "reason"), "return"; got != want {
		t.Fatalf("reason = %q, want %q (detail %s)", got, want, recordString(t, result, "detail"))
	}
	if got, want := recordUint32(t, result, "value"), base+0x1006; got != want {
		t.Fatalf("relocated absolute address = %#x, want %#x", got, want)
	}
}

func TestEmulatorX86PlacesStackAroundPrimaryPE32Image(t *testing.T) {
	const preferred = emulatorStackTop - 0x8000
	image := relocatablePE32TestImage(t, preferred)
	value, err := Builtin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("image"), image},
		{starlark.String("image_name"), starlark.String("legacy.dll")},
	})
	if err != nil {
		t.Fatal(err)
	}
	machine := value.(*emulatorX86)
	if machine.stackHigh > preferred {
		t.Fatalf("stack high = %#x, want at or below image base %#x", machine.stackHigh, preferred)
	}
	resultValue, err := machine.callAddress(&starlark.Thread{Name: "pe32-stack-placement-test"}, machine.entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got, want := recordString(t, result, "reason"), "return"; got != want {
		t.Fatalf("reason = %q, want %q (detail %s)", got, want, recordString(t, result, "detail"))
	}
}

func TestEmulatorX86RejectsCollidingPE32WithoutRelocations(t *testing.T) {
	image := relocatablePE32TestImage(t, 0x00400000)
	data := []byte(image)
	// Clear the base-relocation data-directory entry while retaining the
	// absolute instruction operand that requires rebasing.
	optional := 0x80 + 4 + 20
	for index := optional + 136; index < optional+144; index++ {
		data[index] = 0
	}
	value, err := Builtin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("image"), starlark.Bytes(data)},
		{starlark.String("image_name"), starlark.String("first.dll")},
	})
	if err != nil {
		t.Fatal(err)
	}
	machine := value.(*emulatorX86)
	_, err = machine.loadModuleBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data), starlark.String("second.dll")}, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be relocated") {
		t.Fatalf("load error = %v, want missing relocation rejection", err)
	}
}

func relocatablePE32TestImage(t *testing.T, imageBase uint32) starlark.Bytes {
	t.Helper()
	section := []byte{0xb8, 0, 0, 0, 0, 0xc3, 0}
	labels := starlark.NewDict(2)
	_ = labels.SetKey(starlark.String("entry"), starlark.MakeInt(0))
	_ = labels.SetKey(starlark.String("target"), starlark.MakeInt(6))
	fixups := starlark.NewList([]starlark.Value{peFixupValue(t, 1, "target")})
	value, err := callWindowsRuntime(t, "pe32_executable", starlark.Tuple{starlark.Bytes(section), labels, fixups}, []starlark.Tuple{
		{starlark.String("image_base"), starlark.MakeUint(uint(imageBase))},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value.(starlark.Bytes)
}

func TestEmulatorX86AcceleratesTableDrivenCRC32(t *testing.T) {
	code := []byte{
		0x8b, 0x45, 0x08, 0x0f, 0xb6, 0x14, 0x01, 0x8b, 0x45, 0x10,
		0x0f, 0xb6, 0xf0, 0x33, 0xd6, 0xc1, 0xe8, 0x08, 0x33, 0x04, 0x95,
		0, 0, 0, 0, 0x41, 0x3b, 0x4d, 0x0c, 0x89, 0x45, 0x10, 0x72, 0xde,
		0x8b, 0x45, 0x10, 0xc3,
	}
	binary.LittleEndian.PutUint32(code[21:25], 0x3000)
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	input := []byte("123456789")
	if err := machine.addMapping("crc input", 0x2000, input, true, false, false); err != nil {
		t.Fatal(err)
	}
	tableBytes := make([]byte, 256*4)
	for index, value := range crc32.MakeTable(crc32.IEEE) {
		binary.LittleEndian.PutUint32(tableBytes[index*4:], value)
	}
	if err := machine.addMapping("crc table", 0x3000, tableBytes, true, false, false); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 20)
	binary.LittleEndian.PutUint32(frame[8:], 0x2000)
	binary.LittleEndian.PutUint32(frame[12:], uint32(len(input)))
	binary.LittleEndian.PutUint32(frame[16:], 0xffffffff)
	if err := machine.addMapping("crc frame", 0x4000, frame, true, true, false); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.EBP] = 0x4000
	machine.registers[x86asm.ECX] = 0
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-crc32-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	want := crc32.ChecksumIEEE(input) ^ 0xffffffff
	if got := recordUint32(t, result, "value"); got != want {
		t.Fatalf("crc = %#x, want %#x", got, want)
	}
	if got := recordUint32(t, result, "steps"); got != 3 {
		t.Fatalf("accelerated steps = %d, want 3", got)
	}
}

func TestEmulatorX86AcceleratesCRC16BitLoop(t *testing.T) {
	code := append(bytes.Clone(emulatorCRC16BitLoop), 0xc3)
	newMachine := func(trace bool) *emulatorX86 {
		machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
		machine.trace = trace
		machine.registers[x86asm.EAX] = 0x12345678
		machine.registers[x86asm.EBX] = 0xabcdef08
		machine.registers[x86asm.ECX] = 0x987654a5
		machine.registers[x86asm.EDX] = 0xdeadbeef
		return machine
	}

	accelerated := newMachine(false)
	if got := accelerated.accelerator(accelerated.entry); got != emulatorAcceleratorCRC16BitLoop {
		t.Fatalf("accelerator = %d, want CRC16 bit loop", got)
	}
	acceleratedValue, err := accelerated.run(&starlark.Thread{Name: "emulator-crc16-accelerated-test"})
	if err != nil {
		t.Fatal(err)
	}
	interpreted := newMachine(true)
	interpretedValue, err := interpreted.run(&starlark.Thread{Name: "emulator-crc16-interpreted-test"})
	if err != nil {
		t.Fatal(err)
	}
	acceleratedResult := acceleratedValue.(*starlarkRecord)
	interpretedResult := interpretedValue.(*starlarkRecord)
	if got := recordString(t, acceleratedResult, "reason"); got != "return" {
		t.Fatalf("accelerated reason = %q, detail = %s", got, recordString(t, acceleratedResult, "detail"))
	}
	if got, want := recordUint32(t, acceleratedResult, "steps"), recordUint32(t, interpretedResult, "steps"); got != want || got != 81 {
		t.Fatalf("accelerated steps = %d, interpreted = %d, want 81", got, want)
	}
	if accelerated.registers != interpreted.registers {
		t.Fatalf("accelerated registers differ: got %#v, want %#v", accelerated.registers, interpreted.registers)
	}
	if accelerated.carry != interpreted.carry || accelerated.parity != interpreted.parity ||
		accelerated.zero != interpreted.zero || accelerated.sign != interpreted.sign ||
		accelerated.overflow != interpreted.overflow {
		t.Fatal("accelerated flags differ from interpreted flags")
	}
}

func TestEmulatorX86AcceleratesLinkedListReverse(t *testing.T) {
	code := append(bytes.Clone(emulatorLinkedListReverseLoop), 0xc3)
	newMachine := func(trace bool) *emulatorX86 {
		machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
		machine.trace = trace
		nodes := make([]byte, 20)
		binary.LittleEndian.PutUint32(nodes[0:], 0x2008)
		binary.LittleEndian.PutUint32(nodes[8:], 0x2010)
		if err := machine.addMapping("linked list", 0x2000, nodes, true, true, false); err != nil {
			t.Fatal(err)
		}
		machine.registers[x86asm.EBX] = 0xdeadbeef
		machine.registers[x86asm.ECX] = 0x12345678
		machine.registers[x86asm.EDX] = 0x2000
		return machine
	}

	accelerated := newMachine(false)
	if got := accelerated.accelerator(accelerated.entry); got != emulatorAcceleratorLinkedListReverse {
		t.Fatalf("accelerator = %d, want linked-list reverse", got)
	}
	acceleratedValue, err := accelerated.run(&starlark.Thread{Name: "emulator-list-reverse-accelerated-test"})
	if err != nil {
		t.Fatal(err)
	}
	interpreted := newMachine(true)
	interpretedValue, err := interpreted.run(&starlark.Thread{Name: "emulator-list-reverse-interpreted-test"})
	if err != nil {
		t.Fatal(err)
	}
	acceleratedResult := acceleratedValue.(*starlarkRecord)
	interpretedResult := interpretedValue.(*starlarkRecord)
	if got, want := recordUint32(t, acceleratedResult, "steps"), recordUint32(t, interpretedResult, "steps"); got != want || got != 19 {
		t.Fatalf("accelerated steps = %d, interpreted = %d, want 19", got, want)
	}
	if accelerated.registers != interpreted.registers {
		t.Fatalf("accelerated registers differ: got %#v, want %#v", accelerated.registers, interpreted.registers)
	}
	acceleratedNodes, err := accelerated.readMemory(0x2000, 20, 'r')
	if err != nil {
		t.Fatal(err)
	}
	interpretedNodes, err := interpreted.readMemory(0x2000, 20, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(acceleratedNodes, interpretedNodes) {
		t.Fatalf("accelerated list = %x, interpreted = %x", acceleratedNodes, interpretedNodes)
	}
	if accelerated.carry != interpreted.carry || accelerated.parity != interpreted.parity ||
		accelerated.zero != interpreted.zero || accelerated.sign != interpreted.sign ||
		accelerated.overflow != interpreted.overflow {
		t.Fatal("accelerated flags differ from interpreted flags")
	}
}

func TestEmulatorX86AcceleratesLinkedListSearches(t *testing.T) {
	for _, test := range []struct {
		name        string
		loop        []byte
		accelerator emulatorAccelerator
		comparison  uint32
		initialize  func([]byte)
	}{
		{
			name:        "signed 16-bit value",
			loop:        emulatorI16LinkedListSearchLoop,
			accelerator: emulatorAcceleratorI16LinkedListSearch,
			comparison:  0x1234,
			initialize: func(data []byte) {
				binary.LittleEndian.PutUint16(data[0x22:], 0x1234)
			},
		},
		{
			name:        "unsigned 8-bit value",
			loop:        emulatorU8LinkedListSearchLoop,
			accelerator: emulatorAcceleratorU8LinkedListSearch,
			comparison:  0x34,
			initialize: func(data []byte) {
				data[0x20] = 0x34
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := append(bytes.Clone(test.loop), 0xc3)
			newMachine := func(trace bool) *emulatorX86 {
				machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
				machine.trace = trace
				data := make([]byte, 0x30)
				binary.LittleEndian.PutUint32(data[0:], 0x2008)
				binary.LittleEndian.PutUint32(data[0x0c:], 0x2020)
				test.initialize(data)
				if err := machine.addMapping("linked list", 0x2000, data, true, true, false); err != nil {
					t.Fatal(err)
				}
				machine.registers[x86asm.EAX] = 0x2000
				machine.registers[x86asm.ECX] = 0xdeadbeef
				machine.registers[x86asm.EDX] = test.comparison
				machine.registers[x86asm.ESI] = 0xabcdef01
				machine.registers[x86asm.EDI] = 0x98765432
				return machine
			}

			accelerated := newMachine(false)
			if got := accelerated.accelerator(accelerated.entry); got != test.accelerator {
				t.Fatalf("accelerator = %d, want %d", got, test.accelerator)
			}
			acceleratedValue, err := accelerated.run(&starlark.Thread{Name: "emulator-list-search-accelerated-test"})
			if err != nil {
				t.Fatal(err)
			}
			interpreted := newMachine(true)
			interpretedValue, err := interpreted.run(&starlark.Thread{Name: "emulator-list-search-interpreted-test"})
			if err != nil {
				t.Fatal(err)
			}
			acceleratedResult := acceleratedValue.(*starlarkRecord)
			interpretedResult := interpretedValue.(*starlarkRecord)
			if got, want := recordUint32(t, acceleratedResult, "steps"), recordUint32(t, interpretedResult, "steps"); got != want || got != 8 {
				t.Fatalf("accelerated steps = %d, interpreted = %d, want 8", got, want)
			}
			if accelerated.registers != interpreted.registers {
				t.Fatalf("accelerated registers differ: got %#v, want %#v", accelerated.registers, interpreted.registers)
			}
			if accelerated.carry != interpreted.carry || accelerated.parity != interpreted.parity ||
				accelerated.zero != interpreted.zero || accelerated.sign != interpreted.sign ||
				accelerated.overflow != interpreted.overflow {
				t.Fatal("accelerated flags differ from interpreted flags")
			}
		})
	}
}

func TestEmulatorX86AcceleratesMSBTableDrivenCRC32(t *testing.T) {
	for _, test := range []struct {
		name string
		sib  byte
	}{
		{name: "edx_index", sib: 0x16},
		{name: "esi_index", sib: 0x32},
	} {
		t.Run(test.name, func(t *testing.T) {
			testEmulatorX86AcceleratesMSBTableDrivenCRC32(t, test.sib)
		})
	}
}

func TestEmulatorX86RegisteredLoopMatchesInterpreter(t *testing.T) {
	loop := starlark.Bytes("\x8b\x10\x33\xd3\x89\x10\x83\xc0\x04\x49\x75\xf4")
	code := starlark.Bytes(string(loop) + "\xc3")
	newMachine := func(accelerated bool) *emulatorX86 {
		machine := newRawX86TestMachine(t, code, nil)
		data := make([]byte, 64*4)
		for offset := 0; offset < len(data); offset += 4 {
			binary.LittleEndian.PutUint32(data[offset:], uint32(offset)*0x10203+0x456789ab)
		}
		if err := machine.addMapping("loop data", 0x3000, data, true, true, false); err != nil {
			t.Fatal(err)
		}
		machine.registers[x86asm.EAX] = 0x3000
		machine.registers[x86asm.EBX] = 0xa5c3917e
		machine.registers[x86asm.ECX] = 64
		if accelerated {
			if _, err := machine.accelerateLoopBuiltin(nil, nil, nil, []starlark.Tuple{
				{starlark.String("address"), starlark.MakeInt(0x1000)},
				{starlark.String("pattern"), loop},
			}); err != nil {
				t.Fatal(err)
			}
		}
		return machine
	}

	reference := newMachine(false)
	fast := newMachine(true)
	thread := &starlark.Thread{Name: "emulator-registered-loop-test"}
	referenceValue, err := reference.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	fastValue, err := fast.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	referenceResult := referenceValue.(*starlarkRecord)
	fastResult := fastValue.(*starlarkRecord)
	if got := recordString(t, fastResult, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, fastResult, "detail"))
	}
	if got, want := recordUint32(t, fastResult, "value"), recordUint32(t, referenceResult, "value"); got != want {
		t.Errorf("value = %#x, want %#x", got, want)
	}
	if got, want := fast.flagsValue(), reference.flagsValue(); got != want {
		t.Errorf("flags = %#x, want %#x", got, want)
	}
	got, _ := fast.readMemory(0x3000, 64*4, 'r')
	want, _ := reference.readMemory(0x3000, 64*4, 'r')
	if !bytes.Equal(got, want) {
		t.Fatal("accelerated loop output differs from interpreted output")
	}
	if got, want := recordUint32(t, fastResult, "steps"), recordUint32(t, referenceResult, "steps"); got >= want {
		t.Fatalf("accelerated steps = %d, interpreted steps = %d", got, want)
	}
}

func TestEmulatorX86RegisteredLoopRejectsUnboundedPattern(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xeb\xfe"), nil)
	_, err := machine.accelerateLoopBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x1000)},
		{starlark.String("pattern"), starlark.Bytes("\xeb\xfe")},
	})
	if err == nil || !strings.Contains(err.Error(), "bounded back edge") {
		t.Fatalf("accelerate_loop error = %v, want bounded-loop rejection", err)
	}
}

func TestEmulatorX86RegisteredRegionPreservesIndirectControlFlow(t *testing.T) {
	code := starlark.Bytes("\x41\x83\xf9\x40\x73\x07\xb8\x00\x10\x00\x00\xff\xe0\x8b\xc1\xc3")
	newMachine := func(accelerated bool) *emulatorX86 {
		machine := newRawX86TestMachine(t, code, nil)
		if accelerated {
			region := []byte(code[:15])
			digest := sha256.Sum256(region)
			if _, err := machine.accelerateRegionBuiltin(nil, nil, nil, []starlark.Tuple{
				{starlark.String("entry"), starlark.MakeInt(0x1000)},
				{starlark.String("start"), starlark.MakeInt(0x1000)},
				{starlark.String("size"), starlark.MakeInt(len(region))},
				{starlark.String("digest"), starlark.Bytes(digest[:])},
			}); err != nil {
				t.Fatal(err)
			}
		}
		return machine
	}
	reference := newMachine(false)
	fast := newMachine(true)
	thread := &starlark.Thread{Name: "emulator-region-test"}
	referenceValue, err := reference.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	fastValue, err := fast.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	referenceResult := referenceValue.(*starlarkRecord)
	fastResult := fastValue.(*starlarkRecord)
	if got, want := recordUint32(t, fastResult, "value"), recordUint32(t, referenceResult, "value"); got != want || got != 64 {
		t.Fatalf("value = %d, want %d", got, want)
	}
	if got, want := fast.flagsValue(), reference.flagsValue(); got != want {
		t.Fatalf("flags = %#x, want %#x", got, want)
	}
	if got, want := recordUint32(t, fastResult, "steps"), recordUint32(t, referenceResult, "steps"); got >= want {
		t.Fatalf("accelerated steps = %d, interpreted steps = %d", got, want)
	}
}

func TestEmulatorX86RegisteredRegionReentersAfterExternalCall(t *testing.T) {
	region := append([]byte{0xe8, 0x65, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0x40}, 100)...)
	region = append(region, 0xc3)
	code := append([]byte{0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3}, bytes.Repeat([]byte{0xcc}, 10)...)
	code = append(code, region...)
	code = append(code, 0x31, 0xc0, 0xc3)
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	digest := sha256.Sum256(region)
	if _, err := machine.accelerateRegionBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("entry"), starlark.MakeInt(0x1010)},
		{starlark.String("start"), starlark.MakeInt(0x1010)},
		{starlark.String("size"), starlark.MakeInt(len(region))},
		{starlark.String("digest"), starlark.Bytes(digest[:])},
		{starlark.String("reenter"), starlark.True},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-region-reentry-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 100 {
		t.Fatalf("value = %d, want 100", got)
	}
	if got := recordUint32(t, result, "steps"); got >= 10 {
		t.Fatalf("accelerated steps = %d, want fewer than 10", got)
	}
}

func TestEmulatorX86RegisteredRegionPropagatesHookStop(t *testing.T) {
	region := []byte{0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xc3} // call 0x2000; ret
	machine := newRawX86TestMachine(t, starlark.Bytes(region), nil)
	thread := &starlark.Thread{Name: "emulator-region-stop-test"}
	callback := starlark.NewBuiltin("region stop", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if _, err := machine.stopBuiltin(nil, nil, starlark.Tuple{starlark.String("service-ready")}, []starlark.Tuple{
			{starlark.String("detail"), starlark.String("target service is running")},
		}); err != nil {
			return nil, err
		}
		return starlark.MakeInt(0x1234), nil
	})
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{callback}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
	}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(region)
	if _, err := machine.accelerateRegionBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("entry"), starlark.MakeInt(0x1000)},
		{starlark.String("start"), starlark.MakeInt(0x1000)},
		{starlark.String("size"), starlark.MakeInt(len(region))},
		{starlark.String("digest"), starlark.Bytes(digest[:])},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "service-ready" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordString(t, result, "detail"); got != "target service is running" {
		t.Fatalf("detail = %q", got)
	}
	if got := recordUint32(t, result, "value"); got != 0x1234 {
		t.Fatalf("eax = %#x, want hook result", got)
	}
}

func TestEmulatorX86InlineRewriteRequiresExplicitTransfer(t *testing.T) {
	code := starlark.Bytes("\x40\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	callback := starlark.NewBuiltin("test rewrite", func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		machine.registers[x86asm.EAX] += 9
		return machine.transferBuiltin(thread, nil, starlark.Tuple{starlark.MakeInt(0x1001)}, nil)
	})
	if _, err := machine.rewriteBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x1000)},
		{starlark.String("pattern"), starlark.Bytes("\x40")},
		{starlark.String("callback"), callback},
		{starlark.String("name"), starlark.String("test increment")},
	}); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.EAX] = 1
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-rewrite-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 10 {
		t.Fatalf("value = %d, want 10", got)
	}
	if got := recordUint32(t, result, "steps"); got != 2 {
		t.Fatalf("steps = %d, want rewrite plus RET", got)
	}

	missingTransfer := newRawX86TestMachine(t, code, nil)
	noTransfer := starlark.NewBuiltin("missing transfer", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return starlark.None, nil
	})
	if _, err := missingTransfer.rewriteBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x1000)},
		{starlark.String("pattern"), starlark.Bytes("\x40")},
		{starlark.String("callback"), noTransfer},
	}); err != nil {
		t.Fatal(err)
	}
	missingValue, err := missingTransfer.run(&starlark.Thread{Name: "emulator-rewrite-transfer-test"})
	if err != nil {
		t.Fatal(err)
	}
	missing := missingValue.(*starlarkRecord)
	if got := recordString(t, missing, "reason"); got != "plugin" || !strings.Contains(recordString(t, missing, "detail"), "did not transfer control") {
		t.Fatalf("missing transfer result = %q: %s", got, recordString(t, missing, "detail"))
	}
}

func TestEmulatorX86InlineRewriteTransfersCallFrame(t *testing.T) {
	// main: mov ecx,0x12345678; push 7; rewritten call; add esp,4; ret
	// helper: mov eax,ecx; add eax,[esp+4]; push eax; call hook; ret
	code := []byte{
		0xb9, 0x78, 0x56, 0x34, 0x12,
		0x6a, 0x07,
		0xe8, 0xf4, 0x0f, 0x00, 0x00,
		0x83, 0xc4, 0x04,
		0xc3,
		0x8b, 0xc1,
		0x03, 0x44, 0x24, 0x04,
		0x50,
		0xe8, 0xe4, 0x0f, 0x00, 0x00,
		0xc3,
	}
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	thread := &starlark.Thread{Name: "emulator-rewrite-call-transfer-test"}
	rewrite := starlark.NewBuiltin("call transfer", func(thread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return machine.transferBuiltin(thread, nil, starlark.Tuple{starlark.MakeInt(0x1010)}, []starlark.Tuple{
			{starlark.String("return_address"), starlark.MakeInt(0x100c)},
		})
	})
	if _, err := machine.rewriteBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x1007)},
		{starlark.String("pattern"), starlark.Bytes(code[7:12])},
		{starlark.String("callback"), rewrite},
	}); err != nil {
		t.Fatal(err)
	}
	hook := starlark.NewBuiltin("observe call frame", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if machine.callDepth != 1 || len(machine.callFrames) != 1 {
			return nil, fmt.Errorf("transferred call has depth %d and %d frames", machine.callDepth, len(machine.callFrames))
		}
		event := args[0].(*starlarkRecord)
		arguments, _ := event.Attr("args")
		return arguments.(*starlark.List).Index(0), nil
	})
	if _, err := machine.hookBuiltin(nil, nil, starlark.Tuple{hook}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
		{starlark.String("argc"), starlark.MakeInt(1)},
		{starlark.String("convention"), starlark.String("stdcall")},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0x1234567f {
		t.Fatalf("value = %#x, want %#x", got, uint32(0x1234567f))
	}
	if machine.callDepth != 0 || len(machine.callFrames) != 0 {
		t.Fatalf("transferred call left depth %d and %d frames", machine.callDepth, len(machine.callFrames))
	}
}

func TestEmulatorX86RuntimeTransformationMatchesNormalizedCode(t *testing.T) {
	code := starlark.Bytes("\xe8\x78\x56\x34\x12\x31\xc0\x40\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	region := []byte(code[:8])
	digest, err := emulatorCodeDigest(region, true)
	if err != nil {
		t.Fatal(err)
	}
	callback := starlark.NewBuiltin("runtime transform", func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		event := args[0].(*starlarkRecord)
		end := recordUint32(t, event, "end")
		machine.registers[x86asm.EAX] = 9
		return machine.transferBuiltin(thread, nil, starlark.Tuple{starlark.MakeUint64(uint64(end))}, nil)
	})
	if _, err := machine.transformBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("anchor"), starlark.Bytes("\xe8\x00\x00\x00\x00\x31\xc0\x40")},
		{starlark.String("anchor_mask"), starlark.Bytes("\xff\x00\x00\x00\x00\xff\xff\xff")},
		{starlark.String("size"), starlark.MakeInt(len(region))},
		{starlark.String("digest"), starlark.Bytes(digest[:])},
		{starlark.String("callback"), callback},
		{starlark.String("name"), starlark.String("normalized generated code")},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-runtime-transformation-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 9 {
		t.Fatalf("value = %d, want 9", got)
	}
}

func TestEmulatorX86RuntimeRegionAcceleration(t *testing.T) {
	code := starlark.Bytes("\x40\x40\x40\x40\x40\x40\x40\x40\xc3")
	machine := newRawX86TestMachine(t, code, []starlark.Tuple{
		{starlark.String("instruction_limit"), starlark.MakeInt(2)},
	})
	digest := sha256.Sum256([]byte(code[:8]))
	if _, err := machine.accelerateRuntimeRegionBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("anchor"), starlark.Bytes(code[:4])},
		{starlark.String("size"), starlark.MakeInt(8)},
		{starlark.String("digest"), starlark.Bytes(digest[:])},
		{starlark.String("normalize_relative"), starlark.False},
		{starlark.String("name"), starlark.String("generated increment region")},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-runtime-region-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 8 {
		t.Fatalf("value = %d, want 8", got)
	}
	if len(machine.runtimeRegions) != 1 {
		t.Fatalf("runtime region matches = %d, want 1", len(machine.runtimeRegions))
	}
	if _, err := machine.protectBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x1000)},
		{starlark.String("size"), starlark.MakeInt(len(code))},
		{starlark.String("readable"), starlark.True},
		{starlark.String("writable"), starlark.True},
		{starlark.String("executable"), starlark.True},
	}); err != nil {
		t.Fatal(err)
	}
	if err := machine.writeMemory(0x1000, []byte{0x41}); err != nil {
		t.Fatal(err)
	}
	if len(machine.runtimeRegions) != 0 || len(machine.transformationCache) != 0 {
		t.Fatal("executable write retained a runtime region match")
	}
}

func TestEmulatorX86RuntimeTransformationRejectsAmbiguousSignatures(t *testing.T) {
	code := starlark.Bytes("\x31\xc0\x40\x90\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	region := []byte(code[:4])
	digest, err := emulatorCodeDigest(region, false)
	if err != nil {
		t.Fatal(err)
	}
	callback := starlark.NewBuiltin("ambiguous transform", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return starlark.None, nil
	})
	for _, anchor := range []starlark.Bytes{"\x31\xc0\x40\x90", "\x31\xc0\x40\x90\xc3"} {
		size := 4
		candidateDigest := digest
		if len(anchor) == 5 {
			size = 5
			candidateDigest, err = emulatorCodeDigest([]byte(code), false)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := machine.transformBuiltin(nil, nil, nil, []starlark.Tuple{
			{starlark.String("anchor"), anchor},
			{starlark.String("size"), starlark.MakeInt(size)},
			{starlark.String("digest"), starlark.Bytes(candidateDigest[:])},
			{starlark.String("callback"), callback},
		}); err != nil {
			t.Fatal(err)
		}
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-runtime-transformation-ambiguity-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "plugin" || !strings.Contains(recordString(t, result, "detail"), "ambiguous runtime transformation") {
		t.Fatalf("ambiguous transformation result = %q: %s", got, recordString(t, result, "detail"))
	}
}

func testEmulatorX86AcceleratesMSBTableDrivenCRC32(t *testing.T, sib byte) {
	code := []byte{
		0x8b, 0x01, 0x8b, 0x55, 0x0c, 0x0f, 0xb6, 0x14, sib, 0x8b, 0xf8,
		0xc1, 0xef, 0x18, 0x33, 0xd7, 0x81, 0xe2, 0xff, 0x00, 0x00, 0x00,
		0xc1, 0xe0, 0x08, 0x33, 0x04, 0x95, 0, 0, 0, 0, 0x46, 0x3b, 0x75,
		0x10, 0x89, 0x01, 0x7c, 0xd8, 0x8b, 0x01, 0xc3,
	}
	binary.LittleEndian.PutUint32(code[28:32], 0x3000)
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	input := []byte("123456789")
	if err := machine.addMapping("crc input", 0x2000, input, true, false, false); err != nil {
		t.Fatal(err)
	}
	tableBytes := make([]byte, 256*4)
	for index := uint32(0); index < 256; index++ {
		value := index << 24
		for bit := 0; bit < 8; bit++ {
			if value&0x80000000 != 0 {
				value = value<<1 ^ 0x04c11db7
			} else {
				value <<= 1
			}
		}
		binary.LittleEndian.PutUint32(tableBytes[index*4:], value)
	}
	if err := machine.addMapping("crc table", 0x3000, tableBytes, true, false, false); err != nil {
		t.Fatal(err)
	}
	crc := make([]byte, 4)
	binary.LittleEndian.PutUint32(crc, 0xffffffff)
	if err := machine.addMapping("crc state", 0x3800, crc, true, true, false); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 20)
	binary.LittleEndian.PutUint32(frame[12:], 0x2000)
	binary.LittleEndian.PutUint32(frame[16:], uint32(len(input)))
	if err := machine.addMapping("crc frame", 0x4000, frame, true, true, false); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.EBP] = 0x4000
	machine.registers[x86asm.ECX] = 0x3800
	machine.registers[x86asm.ESI] = 0
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-msb-crc32-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	const want = 0x0376e6e7
	if got := recordUint32(t, result, "value"); got != want {
		t.Fatalf("crc = %#x, want %#x", got, want)
	}
	if got := recordUint32(t, result, "steps"); got != 3 {
		t.Fatalf("accelerated steps = %d, want 3", got)
	}
}

func TestEmulatorX86AcceleratesASCIILowercaseHelper(t *testing.T) {
	code := []byte{
		0x8b, 0xff, 0x55, 0x8b, 0xec, 0x51, 0x8b, 0x45, 0x08,
		0x66, 0x3d, 0x7f, 0x00, 0x77, 0x15, 0x66, 0x3d, 0x41, 0x00,
		0x72, 0x35, 0x66, 0x3d, 0x5a, 0x00, 0x77, 0x2f, 0x83, 0xc0,
		0x20, 0x8b, 0xe5, 0x5d, 0xc2, 0x04, 0x00,
	}
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	esp := machine.registers[x86asm.ESP] - 8
	if err := machine.writeUint32(esp, 0); err != nil {
		t.Fatal(err)
	}
	if err := machine.writeUint32(esp+4, 'Q'); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.ESP] = esp
	machine.callDepth = 1
	machine.callFrames = []emulatorCallFrame{{site: 0x900, target: 0x1000}}
	accelerated, err := machine.accelerateASCIILower(0x1000)
	if err != nil || !accelerated {
		t.Fatalf("accelerate = %t, %v", accelerated, err)
	}
	if got := machine.registers[x86asm.EAX]; got != 'q' {
		t.Fatalf("eax = %#x, want 'q'", got)
	}
	if machine.eip != 0 || machine.registers[x86asm.ESP] != esp+8 || machine.callDepth != 0 || len(machine.callFrames) != 0 {
		t.Fatalf("return state = eip %#x esp %#x depth %d frames %d", machine.eip, machine.registers[x86asm.ESP], machine.callDepth, len(machine.callFrames))
	}
	if err := machine.writeUint32(esp+4, 0x100); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.ESP] = esp
	accelerated, err = machine.accelerateASCIILower(0x1000)
	if err != nil || accelerated {
		t.Fatalf("non-ASCII accelerate = %t, %v; want fallback", accelerated, err)
	}
}

func TestEmulatorX86AcceleratesWideASCIIValidation(t *testing.T) {
	code, err := hex.DecodeString("8bff558bec8b45088bc80fb700eb0984e475114141668b016685c075f233c0405dc2040033c0ebf8")
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	if err := machine.addMapping("wide", 0x2000, []byte("A\x00z\x00\x00\x00"), true, true, false); err != nil {
		t.Fatal(err)
	}
	esp := machine.registers[x86asm.ESP] - 8
	for address, value := range map[uint32]uint32{esp: 0x1234, esp + 4: 0x2000} {
		if err := machine.writeUint32(address, value); err != nil {
			t.Fatal(err)
		}
	}
	machine.registers[x86asm.ESP] = esp
	machine.callDepth = 1
	machine.callFrames = []emulatorCallFrame{{site: 0x900, target: 0x1000}}
	accelerated, err := machine.accelerateWideASCIIValidate(0x1000)
	if err != nil || !accelerated {
		t.Fatalf("accelerate = %t, %v", accelerated, err)
	}
	if got := machine.registers[x86asm.EAX]; got != 1 {
		t.Fatalf("ASCII result = %#x, want 1", got)
	}
	if machine.eip != 0x1234 || machine.registers[x86asm.ESP] != esp+8 || machine.callDepth != 0 || len(machine.callFrames) != 0 {
		t.Fatalf("return state = eip %#x esp %#x depth %d frames %d", machine.eip, machine.registers[x86asm.ESP], machine.callDepth, len(machine.callFrames))
	}
	if err := machine.writeMemory(0x2000, []byte{0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.ESP] = esp
	machine.eip = 0x1000
	accelerated, err = machine.accelerateWideASCIIValidate(0x1000)
	if err != nil || !accelerated || machine.registers[x86asm.EAX] != 0 {
		t.Fatalf("non-ASCII result = %#x, accelerated %t, %v; want 0", machine.registers[x86asm.EAX], accelerated, err)
	}
}

func TestEmulatorX86AcceleratesMixedASCIIFoldCompare(t *testing.T) {
	code, err := hex.DecodeString("8bff558bec53568b7508578b7d0ceb318a07ff4d1084c0750666833e007428660fb6c050e8b7effdff0fb7d833c0668b0650e8a9effdff0fb7c02bc3750b474646837d100075c933c05f5e5b5dc20c00")
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	wide := []byte{'A', 0, 'b', 0, 0, 0}
	if err := machine.addMapping("wide", 0x2000, wide, true, true, false); err != nil {
		t.Fatal(err)
	}
	if err := machine.addMapping("narrow", 0x3000, []byte("aB\x00"), true, false, false); err != nil {
		t.Fatal(err)
	}
	esp := machine.registers[x86asm.ESP] - 16
	for index, value := range []uint32{0, 0x2000, 0x3000, math.MaxUint32} {
		if err := machine.writeUint32(esp+uint32(index*4), value); err != nil {
			t.Fatal(err)
		}
	}
	machine.registers[x86asm.ESP] = esp
	accelerated, err := machine.accelerateMixedASCIIFoldCompare(0x1000)
	if err != nil || !accelerated {
		t.Fatalf("accelerate = %t, %v", accelerated, err)
	}
	if got := machine.registers[x86asm.EAX]; got != 0 {
		t.Fatalf("eax = %#x, want equal", got)
	}
	if machine.eip != 0 || machine.registers[x86asm.ESP] != esp+16 {
		t.Fatalf("return state = eip %#x esp %#x", machine.eip, machine.registers[x86asm.ESP])
	}
	if err := machine.writeMemory(0x2000, []byte{0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.ESP] = esp
	machine.eip = 0x1000
	accelerated, err = machine.accelerateMixedASCIIFoldCompare(0x1000)
	if err != nil || accelerated {
		t.Fatalf("non-ASCII accelerate = %t, %v; want fallback", accelerated, err)
	}
	if machine.eip != 0x1000 || machine.registers[x86asm.ESP] != esp {
		t.Fatal("non-ASCII fallback modified control state")
	}
}

func TestEmulatorX86AcceleratesZeroByteScan(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\x8a\x10\x40\x84\xd2\x75\xf9"), nil)
	if err := machine.addMapping("string", 0x2000, []byte("hello\x00tail"), true, false, false); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.EAX] = 0x2000
	machine.registers[x86asm.EDX] = 0x123456ff
	consumed, accelerated, err := machine.accelerateZeroByteScan(0x1000, 10)
	if err != nil || !accelerated || consumed != 1 {
		t.Fatalf("accelerate = %d, %t, %v", consumed, accelerated, err)
	}
	if got := machine.registers[x86asm.EAX]; got != 0x2006 {
		t.Fatalf("eax = %#x, want byte after terminator", got)
	}
	if got := machine.registers[x86asm.EDX]; got != 0x12345600 {
		t.Fatalf("edx = %#x, want zero DL", got)
	}
	if machine.eip != 0x1007 || !machine.zero || !machine.parity || machine.sign || machine.carry || machine.overflow {
		t.Fatalf("exit state = eip %#x flags z=%t p=%t s=%t c=%t o=%t", machine.eip, machine.zero, machine.parity, machine.sign, machine.carry, machine.overflow)
	}
	for index := range machine.mappings {
		if machine.mappings[index].name == "code" {
			machine.mappings[index].writable = true
		}
	}
	if err := machine.writeMemory(0x1000, []byte{0x90}); err != nil {
		t.Fatal(err)
	}
	if got := machine.accelerator(0x1000); got != emulatorAcceleratorNone {
		t.Fatalf("accelerator after code write = %d, want none", got)
	}
	clMachine := newRawX86TestMachine(t, starlark.Bytes("\x8a\x08\x40\x84\xc9\x75\xf9"), nil)
	if err := clMachine.addMapping("string", 0x2000, []byte("x\x00"), true, false, false); err != nil {
		t.Fatal(err)
	}
	clMachine.registers[x86asm.EAX] = 0x2000
	clMachine.registers[x86asm.ECX] = 0xabcdef7f
	if _, accelerated, err := clMachine.accelerateZeroByteScan(0x1000, 10); err != nil || !accelerated {
		t.Fatalf("CL scan accelerate = %t, %v", accelerated, err)
	}
	if got := clMachine.registers[x86asm.ECX]; got != 0xabcdef00 {
		t.Fatalf("ecx = %#x, want zero CL", got)
	}
}

func TestEmulatorX86AcceleratesWideUnitScan(t *testing.T) {
	tests := []struct {
		name       string
		code       starlark.Bytes
		cursor     x86asm.Reg
		terminator uint16
	}{
		{
			name:   "zero",
			code:   starlark.Bytes("\x66\x8b\x06\x83\xc6\x02\x66\x85\xc0\x75\xf5"),
			cursor: x86asm.ESI,
		},
		{
			name:   "zero ECX",
			code:   starlark.Bytes("\x66\x8b\x01\x83\xc1\x02\x66\x85\xc0\x75\xf5"),
			cursor: x86asm.ECX,
		},
		{
			name:       "register terminator",
			code:       starlark.Bytes("\x66\x8b\x01\x83\xc1\x02\x66\x3b\xc6\x75\xf5"),
			cursor:     x86asm.ECX,
			terminator: 0x1234,
		},
		{
			name:       "DI terminator",
			code:       starlark.Bytes("\x66\x8b\x01\x83\xc1\x02\x66\x3b\xc7\x75\xf5"),
			cursor:     x86asm.ECX,
			terminator: 0x1234,
		},
		{
			name:       "EDI cursor",
			code:       starlark.Bytes("\x66\x8b\x07\x83\xc7\x02\x66\x3b\xc6\x75\xf5"),
			cursor:     x86asm.EDI,
			terminator: 0x1234,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			data := []byte{'A', 0, 'B', 0, byte(test.terminator), byte(test.terminator >> 8)}
			if err := machine.addMapping("wide string", 0x2000, data, true, false, false); err != nil {
				t.Fatal(err)
			}
			machine.registers[test.cursor] = 0x2000
			machine.registers[x86asm.ESI] = (machine.registers[x86asm.ESI] & 0xffff0000) | uint32(test.terminator)
			if test.cursor != x86asm.EDI {
				machine.registers[x86asm.EDI] = (machine.registers[x86asm.EDI] & 0xffff0000) | uint32(test.terminator)
			}
			if test.cursor == x86asm.ESI {
				machine.registers[x86asm.ESI] = 0x2000
			}
			consumed, accelerated, err := machine.accelerateWideUnitScan(0x1000, 10)
			if err != nil || !accelerated || consumed != 1 {
				t.Fatalf("accelerate = %d, %t, %v", consumed, accelerated, err)
			}
			if got := machine.registers[test.cursor]; got != 0x2006 {
				t.Fatalf("cursor = %#x, want 0x2006", got)
			}
			if got := uint16(machine.registers[x86asm.EAX]); got != test.terminator {
				t.Fatalf("AX = %#x, want %#x", got, test.terminator)
			}
			if machine.eip != 0x100b || !machine.zero || !machine.parity || machine.sign || machine.carry || machine.overflow {
				t.Fatalf("exit state = eip %#x flags z=%t p=%t s=%t c=%t o=%t", machine.eip, machine.zero, machine.parity, machine.sign, machine.carry, machine.overflow)
			}
		})
	}
}

func TestEmulatorX86AcceleratesBoundedWideCopy(t *testing.T) {
	code := starlark.Bytes(string([]byte{
		0x85, 0xf6, 0x74, 0x13, 0x0f, 0xb7, 0x1c, 0x08,
		0x66, 0x85, 0xdb, 0x74, 0x0a, 0x66, 0x89, 0x19,
		0x83, 0xc1, 0x02, 0x4e, 0x4a, 0x75, 0xe9,
	}))
	tests := []struct {
		name         string
		source       []byte
		capacity     uint32
		count        uint32
		want         []byte
		wantCursor   uint32
		wantCapacity uint32
		wantCount    uint32
		wantLastUnit uint16
	}{
		{name: "count", source: []byte{'A', 0, 'B', 0, 'C', 0}, capacity: 5, count: 2, want: []byte{'A', 0, 'B', 0}, wantCursor: 0x2004, wantCapacity: 3, wantCount: 0, wantLastUnit: 'B'},
		{name: "terminator", source: []byte{'A', 0, 0, 0}, capacity: 5, count: 4, want: []byte{'A', 0}, wantCursor: 0x2002, wantCapacity: 4, wantCount: 3},
		{name: "capacity", source: []byte{'A', 0, 'B', 0}, capacity: 1, count: 4, want: []byte{'A', 0}, wantCursor: 0x2002, wantCapacity: 0, wantCount: 3, wantLastUnit: 'A'},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, code, nil)
			if err := machine.addMapping("destination", 0x2000, make([]byte, 16), true, true, false); err != nil {
				t.Fatal(err)
			}
			if err := machine.addMapping("source", 0x3000, test.source, true, false, false); err != nil {
				t.Fatal(err)
			}
			machine.registers[x86asm.EAX] = 0x1000
			machine.registers[x86asm.ECX] = 0x2000
			machine.registers[x86asm.ESI] = test.capacity
			machine.registers[x86asm.EDX] = test.count
			consumed, accelerated, err := machine.accelerateBoundedWideCopy(0x1000, 10)
			if err != nil || !accelerated || consumed != 1 {
				t.Fatalf("accelerate = %d, %t, %v", consumed, accelerated, err)
			}
			got, err := machine.readMemory(0x2000, len(test.want), 'r')
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("destination = %x, want %x", got, test.want)
			}
			if machine.registers[x86asm.ECX] != test.wantCursor || machine.registers[x86asm.ESI] != test.wantCapacity || machine.registers[x86asm.EDX] != test.wantCount {
				t.Fatalf("state = ecx %#x esi %#x edx %#x", machine.registers[x86asm.ECX], machine.registers[x86asm.ESI], machine.registers[x86asm.EDX])
			}
			if got := uint16(machine.registers[x86asm.EBX]); got != test.wantLastUnit {
				t.Fatalf("BX = %#x, want %#x", got, test.wantLastUnit)
			}
			if machine.eip != 0x1017 || !machine.zero || !machine.parity || machine.sign || machine.carry || machine.overflow {
				t.Fatalf("exit state = eip %#x flags z=%t p=%t s=%t c=%t o=%t", machine.eip, machine.zero, machine.parity, machine.sign, machine.carry, machine.overflow)
			}
		})
	}
}

func TestEmulatorX86AcceleratesBoundedWideScan(t *testing.T) {
	code := starlark.Bytes("\x66\x39\x19\x74\x06\x83\xc1\x02\x4a\x75\xf5")
	for _, test := range []struct {
		name       string
		count      uint32
		terminator uint16
		wantCursor uint32
		wantCount  uint32
	}{
		{name: "terminator", count: 3, terminator: 'B', wantCursor: 0x2002, wantCount: 2},
		{name: "count", count: 2, terminator: 'Z', wantCursor: 0x2004, wantCount: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, code, nil)
			if err := machine.addMapping("wide string", 0x2000, []byte{'A', 0, 'B', 0, 'C', 0}, true, false, false); err != nil {
				t.Fatal(err)
			}
			machine.registers[x86asm.ECX] = 0x2000
			machine.registers[x86asm.EDX] = test.count
			machine.registers[x86asm.EBX] = uint32(test.terminator)
			consumed, accelerated, err := machine.accelerateBoundedWideScan(0x1000, 10)
			if err != nil || !accelerated || consumed != 1 {
				t.Fatalf("accelerate = %d, %t, %v", consumed, accelerated, err)
			}
			if machine.registers[x86asm.ECX] != test.wantCursor || machine.registers[x86asm.EDX] != test.wantCount {
				t.Fatalf("state = ecx %#x edx %#x", machine.registers[x86asm.ECX], machine.registers[x86asm.EDX])
			}
			if machine.eip != 0x100b || !machine.zero {
				t.Fatalf("exit state = eip %#x zero=%t", machine.eip, machine.zero)
			}
		})
	}
}

func TestEmulatorX86AcceleratesRegisterCRC32(t *testing.T) {
	code := []byte{
		0x0f, 0xb6, 0x02, 0x8b, 0xce, 0xc1, 0xe9, 0x18,
		0x33, 0xc8, 0xc1, 0xe6, 0x08, 0x81, 0xe1, 0xff,
		0x00, 0x00, 0x00, 0x33, 0x34, 0x8d, 0, 0, 0, 0,
		0x42, 0x4f, 0x75, 0xe2,
	}
	binary.LittleEndian.PutUint32(code[22:26], 0x3000)
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	input := []byte("123456789")
	if err := machine.addMapping("crc input", 0x2000, input, true, false, false); err != nil {
		t.Fatal(err)
	}
	table := make([]byte, 256*4)
	for index := uint32(0); index < 256; index++ {
		value := index << 24
		for bit := 0; bit < 8; bit++ {
			if value&0x80000000 != 0 {
				value = value<<1 ^ 0x04c11db7
			} else {
				value <<= 1
			}
		}
		binary.LittleEndian.PutUint32(table[index*4:], value)
	}
	if err := machine.addMapping("crc table", 0x3000, table, true, false, false); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.EDX] = 0x2000
	machine.registers[x86asm.ESI] = 0xffffffff
	machine.registers[x86asm.EDI] = uint32(len(input))
	consumed, accelerated, err := machine.accelerateRegisterCRC32(0x1000, 10)
	if err != nil || !accelerated || consumed != 1 {
		t.Fatalf("accelerate = %d, %t, %v", consumed, accelerated, err)
	}
	if got, want := machine.registers[x86asm.ESI], uint32(0x0376e6e7); got != want {
		t.Fatalf("CRC = %#x, want %#x", got, want)
	}
	if machine.registers[x86asm.EDX] != 0x2000+uint32(len(input)) || machine.registers[x86asm.EDI] != 0 || machine.eip != 0x101e {
		t.Fatalf("state = edx %#x edi %#x eip %#x", machine.registers[x86asm.EDX], machine.registers[x86asm.EDI], machine.eip)
	}
	if !machine.zero || machine.carry || machine.overflow {
		t.Fatalf("flags = z=%t c=%t o=%t", machine.zero, machine.carry, machine.overflow)
	}
}

func TestEmulatorX86IntegerFloatMultiplyAndStore(t *testing.T) {
	// fild dword ptr [0x2000]; fmul qword ptr [0x2010];
	// fstp qword ptr [0x2020]; fld qword ptr [0x2020];
	// fstp qword ptr [0x2028]; fld qword ptr [0x2028]; fld st0;
	// fst dword ptr [0x2030]; fistp qword ptr [0x2038];
	// fild qword ptr [0x2038]; fsubp st1,st0; fstp dword ptr [0x2040];
	// fld qword ptr [0x2028]; fdivr qword ptr [0x2048];
	// fstp qword ptr [0x2050]; fld qword ptr [0x2028];
	// fld qword ptr [0x2050]; faddp st1,st0; fld qword ptr [0x2050];
	// fsub st0,st1; fstp qword ptr [0x2058]; fstp qword ptr [0x2060]; ret
	code := starlark.Bytes("\xdb\x05\x00\x20\x00\x00\xdc\x0d\x10\x20\x00\x00\xdd\x1d\x20\x20\x00\x00\xdd\x05\x20\x20\x00\x00\xdd\x1d\x28\x20\x00\x00\xdd\x05\x28\x20\x00\x00\xd9\xc0\xd9\x15\x30\x20\x00\x00\xdf\x3d\x38\x20\x00\x00\xdf\x2d\x38\x20\x00\x00\xde\xe9\xd9\x1d\x40\x20\x00\x00\xdd\x05\x28\x20\x00\x00\xdc\x3d\x48\x20\x00\x00\xdd\x1d\x50\x20\x00\x00\xdd\x05\x28\x20\x00\x00\xdd\x05\x50\x20\x00\x00\xde\xc1\xdd\x05\x50\x20\x00\x00\xd8\xe1\xdd\x1d\x58\x20\x00\x00\xdd\x1d\x60\x20\x00\x00\x31\xc0\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	data := make([]byte, 104)
	binary.LittleEndian.PutUint32(data, 9)
	binary.LittleEndian.PutUint64(data[16:], math.Float64bits(1.5))
	binary.LittleEndian.PutUint64(data[72:], math.Float64bits(27))
	if err := machine.addMapping("x87 operands", 0x2000, data, true, true, false); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-x87-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	stored, err := machine.readMemory(0x2020, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(stored)); got != 13.5 {
		t.Fatalf("stored result = %g, want 13.5", got)
	}
	copied, err := machine.readMemory(0x2028, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(copied)); got != 13.5 {
		t.Fatalf("copied result = %g, want 13.5", got)
	}
	storedFloat, err := machine.readMemory(0x2030, 4, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float32frombits(binary.LittleEndian.Uint32(storedFloat)); got != 13.5 {
		t.Fatalf("single-precision result = %g, want 13.5", got)
	}
	storedInteger, err := machine.readMemory(0x2038, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := int64(binary.LittleEndian.Uint64(storedInteger)); got != 14 {
		t.Fatalf("rounded integer result = %d, want 14", got)
	}
	remainder, err := machine.readMemory(0x2040, 4, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float32frombits(binary.LittleEndian.Uint32(remainder)); got != -0.5 {
		t.Fatalf("subtraction result = %g, want -0.5", got)
	}
	quotient, err := machine.readMemory(0x2050, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(quotient)); got != 2 {
		t.Fatalf("reverse division result = %g, want 2", got)
	}
	difference, err := machine.readMemory(0x2058, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(difference)); got != -13.5 {
		t.Fatalf("stack subtraction result = %g, want -13.5", got)
	}
	sum, err := machine.readMemory(0x2060, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(sum)); got != 15.5 {
		t.Fatalf("stack addition result = %g, want 15.5", got)
	}
	if machine.x87Depth != 0 {
		t.Fatalf("x87 depth = %d, want empty stack", machine.x87Depth)
	}
}

func TestEmulatorX86FloatConstants(t *testing.T) {
	// fldz; fstp qword ptr [0x2000]; fld1; fstp qword ptr [0x2008]; ret
	code := starlark.Bytes("\xd9\xee\xdd\x1d\x00\x20\x00\x00\xd9\xe8\xdd\x1d\x08\x20\x00\x00\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	if err := machine.addMapping("x87 constants", 0x2000, make([]byte, 16), true, true, false); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-x87-constants-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	zero, err := machine.readMemory(0x2000, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	one, err := machine.readMemory(0x2008, 8, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(zero)); got != 0 {
		t.Fatalf("fldz result = %g, want 0", got)
	}
	if got := math.Float64frombits(binary.LittleEndian.Uint64(one)); got != 1 {
		t.Fatalf("fld1 result = %g, want 1", got)
	}
}

func TestEmulatorX86FloatComparePopStatus(t *testing.T) {
	tests := []struct {
		name        string
		left, right float64
		condition   uint16
	}{
		{name: "greater", left: 3, right: 2, condition: 0},
		{name: "less", left: 2, right: 3, condition: 0x0100},
		{name: "equal", left: 2, right: 2, condition: 0x4000},
		{name: "unordered", left: math.NaN(), right: 2, condition: 0x4500},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// fld right; fld left; fcompp; fnstsw ax; mov [0x2010],ax; xor eax,eax; ret
			code := starlark.Bytes("\xdd\x05\x08\x20\x00\x00\xdd\x05\x00\x20\x00\x00\xde\xd9\xdf\xe0\x66\xa3\x10\x20\x00\x00\x31\xc0\xc3")
			machine := newRawX86TestMachine(t, code, nil)
			data := make([]byte, 18)
			binary.LittleEndian.PutUint64(data, math.Float64bits(test.left))
			binary.LittleEndian.PutUint64(data[8:], math.Float64bits(test.right))
			if err := machine.addMapping("x87 comparison", 0x2000, data, true, true, false); err != nil {
				t.Fatal(err)
			}
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-x87-compare-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			status, err := machine.readMemory(0x2010, 2, 'r')
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.LittleEndian.Uint16(status) & 0x4500; got != test.condition {
				t.Fatalf("condition flags = %#x, want %#x", got, test.condition)
			}
			if machine.x87Depth != 0 || machine.x87Top != 0 {
				t.Fatalf("x87 stack depth/top = %d/%d, want 0/0", machine.x87Depth, machine.x87Top)
			}
		})
	}
}

func TestEmulatorX86ParityBranches(t *testing.T) {
	tests := []struct {
		name string
		code starlark.Bytes
	}{
		{
			name: "even parity jumps",
			// mov al,3; test al,3; jp taken; mov eax,1; ret; taken: mov eax,2; ret
			code: starlark.Bytes("\xb0\x03\xa8\x03\x7a\x06\xb8\x01\x00\x00\x00\xc3\xb8\x02\x00\x00\x00\xc3"),
		},
		{
			name: "odd parity jumps",
			// mov al,1; test al,1; jnp taken; mov eax,1; ret; taken: mov eax,2; ret
			code: starlark.Bytes("\xb0\x01\xa8\x01\x7b\x06\xb8\x01\x00\x00\x00\xc3\xb8\x02\x00\x00\x00\xc3"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-parity-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != 2 {
				t.Fatalf("branch result = %d, want 2", got)
			}
		})
	}
}

func TestEmulatorX86ArithmeticAndReturn(t *testing.T) {
	// mov eax, 5; add eax, 3; ret
	code := starlark.Bytes("\xb8\x05\x00\x00\x00\x05\x03\x00\x00\x00\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 8 {
		t.Fatalf("eax = %d, want 8", got)
	}
}

func TestEmulatorX86InvalidatesDecodedInstructionsOnCodeWrite(t *testing.T) {
	for _, trace := range []bool{false, true} {
		t.Run(fmt.Sprintf("trace=%t", trace), func(t *testing.T) {
			// mov eax,1; ret
			machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x01\x00\x00\x00\xc3"), nil)
			machine.mappings[0].writable = true
			machine.trace = trace
			thread := &starlark.Thread{Name: "emulator-code-cache-test"}
			firstValue, err := machine.run(thread)
			if err != nil {
				t.Fatal(err)
			}
			if got := recordUint32(t, firstValue.(*starlarkRecord), "value"); got != 1 {
				t.Fatalf("first eax = %d, want 1", got)
			}
			if err := machine.writeMemory(machine.entry+1, []byte{2}); err != nil {
				t.Fatal(err)
			}
			if err := machine.push(0); err != nil {
				t.Fatal(err)
			}
			machine.eip = machine.entry
			secondValue, err := machine.run(thread)
			if err != nil {
				t.Fatal(err)
			}
			if got := recordUint32(t, secondValue.(*starlarkRecord), "value"); got != 2 {
				t.Fatalf("second eax = %d, want 2", got)
			}
		})
	}
}

func TestEmulatorX86DataWriteSkipsUnrelatedCodeCacheInvalidation(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x01\x00\x00\x00\xc3"), nil)
	if _, err := machine.run(&starlark.Thread{Name: "emulator-data-write-cache-test"}); err != nil {
		t.Fatal(err)
	}
	if len(machine.decoded) == 0 {
		t.Fatal("execution did not populate the decoded instruction cache")
	}
	before := len(machine.decoded)
	if err := machine.addMapping("writable executable data", 0x200000, make([]byte, 4096), true, true, true); err != nil {
		t.Fatal(err)
	}
	if err := machine.writeMemory(0x200000, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if got := len(machine.decoded); got != before {
		t.Fatalf("decoded cache size = %d after unrelated data write, want %d", got, before)
	}
}

func TestInvalidateOverlappingCacheHandlesBoundariesAndLargeWrites(t *testing.T) {
	cache := map[uint32]bool{0: true, 1: true, 0x1001: true, 0x100f: true, 0x1010: true, math.MaxUint32: true}
	invalidateOverlappingCache(cache, 0x100f, 1, 15)
	for _, address := range []uint32{0x1001, 0x100f} {
		if cache[address] {
			t.Fatalf("overlapping cache entry %#x was retained", address)
		}
	}
	for _, address := range []uint32{0, 1, 0x1010, math.MaxUint32} {
		if !cache[address] {
			t.Fatalf("unrelated cache entry %#x was removed", address)
		}
	}
	invalidateOverlappingCache(cache, 0, math.MaxInt32, 15)
	if cache[0] || cache[1] || cache[0x1010] || !cache[math.MaxUint32] {
		t.Fatalf("large-write invalidation left unexpected cache state: %v", cache)
	}
}

func TestEmulatorX86Exchange(t *testing.T) {
	// mov eax,1; mov ebx,2; xchg eax,ebx; mov [0x2000],eax;
	// xchg eax,[0x2000]; mov eax,ebx; ret
	code := starlark.Bytes("\xb8\x01\x00\x00\x00\xbb\x02\x00\x00\x00\x93\xa3\x00\x20\x00\x00\x87\x05\x00\x20\x00\x00\x89\xd8\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	if err := machine.addMapping("exchange", 0x2000, make([]byte, 4), true, true, false); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-xchg-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 1 {
		t.Fatalf("eax = %#x, want exchanged ebx value", got)
	}
	if got, err := machine.readUint32(0x2000); err != nil || got != 2 {
		t.Fatalf("memory = %#x, %v; want 2", got, err)
	}
}

func TestEmulatorX86ExchangeAdd(t *testing.T) {
	// xadd eax,ebx leaves the sum in EAX and the old EAX in EBX. The locked
	// memory form leaves the sum in memory and its old value in EAX.
	code := starlark.Bytes("\xb8\x01\x00\x00\x00\xbb\x02\x00\x00\x00\x0f\xc1\xd8" +
		"\xb9\x00\x20\x00\x00\xc7\x01\x04\x00\x00\x00\xb8\x03\x00\x00\x00\xf0\x0f\xc1\x01\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	if err := machine.addMapping("exchange-add", 0x2000, make([]byte, 4), true, true, false); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-xadd-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 4 {
		t.Fatalf("eax = %#x, want prior memory value 4", got)
	}
	if got, err := machine.readUint32(0x2000); err != nil || got != 7 {
		t.Fatalf("memory = %#x, %v; want sum 7", got, err)
	}
	if got := machine.registers[x86asm.EBX]; got != 1 {
		t.Fatalf("ebx = %#x, want prior register destination 1", got)
	}
	registers := result.Values["registers"].(*starlarkRecord)
	if got := recordUint32(t, registers, "ebx"); got != 1 {
		t.Fatalf("result ebx = %#x, want 1", got)
	}
}

func TestEmulatorX86PushadPopad(t *testing.T) {
	// Initialize all general registers, save them, clear them, restore them, ret.
	code := starlark.Bytes("\xb8\x01\x00\x00\x00\xb9\x02\x00\x00\x00\xba\x03\x00\x00\x00\xbb\x04\x00\x00\x00\xbd\x05\x00\x00\x00\xbe\x06\x00\x00\x00\xbf\x07\x00\x00\x00\x60\x31\xc0\x31\xc9\x31\xd2\x31\xdb\x31\xed\x31\xf6\x31\xff\x61\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-pushad-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	for register, want := range map[x86asm.Reg]uint32{
		x86asm.EAX: 1, x86asm.ECX: 2, x86asm.EDX: 3, x86asm.EBX: 4,
		x86asm.EBP: 5, x86asm.ESI: 6, x86asm.EDI: 7,
	} {
		if got := machine.registers[register]; got != want {
			t.Fatalf("%s = %#x, want %#x", register, got, want)
		}
	}
}

func TestEmulatorX86CompareExchange(t *testing.T) {
	// First comparison fails and loads EBX into EAX; the second succeeds and
	// stores ECX into EBX.
	code := starlark.Bytes("\xb8\x01\x00\x00\x00\xbb\x02\x00\x00\x00\xb9\x03\x00\x00\x00\x0f\xb1\xcb\x0f\xb1\xcb\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-cmpxchg-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 2 {
		t.Fatalf("eax = %#x, want prior destination 2", got)
	}
	if got := machine.registers[x86asm.EBX]; got != 3 {
		t.Fatalf("ebx = %#x, want exchanged source 3", got)
	}
	if !machine.zero {
		t.Fatal("zero flag is false after successful comparison")
	}
}

func TestEmulatorX86SignedBranchesRespectOperandWidth(t *testing.T) {
	tests := []struct {
		name string
		code starlark.Bytes
	}{
		{
			name: "dword overflow",
			// mov eax, 0x80000000; cmp eax, 1; jl taken
			code: starlark.Bytes("\xb8\x00\x00\x00\x80\x83\xf8\x01\x7c\x06\xb8\x00\x00\x00\x00\xc3\xb8\x01\x00\x00\x00\xc3"),
		},
		{
			name: "byte overflow",
			// mov al, 0x80; cmp al, 1; jl taken
			code: starlark.Bytes("\xb0\x80\x3c\x01\x7c\x06\xb8\x00\x00\x00\x00\xc3\xb8\x01\x00\x00\x00\xc3"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-signed-branch-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != 1 {
				t.Fatalf("eax = %d, want taken branch", got)
			}
		})
	}
}

func TestEmulatorX86JumpWhenECXZero(t *testing.T) {
	tests := []struct {
		name string
		ecx  byte
		want uint32
	}{
		{name: "taken", ecx: 0, want: 1},
		{name: "not taken", ecx: 1, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// mov ecx,value; jecxz taken; mov eax,0; ret; mov eax,1; ret
			code := starlark.Bytes([]byte{
				0xb9, test.ecx, 0, 0, 0, 0xe3, 0x06,
				0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
			})
			machine := newRawX86TestMachine(t, code, nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-jecxz-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.want {
				t.Fatalf("eax = %d, want %d", got, test.want)
			}
		})
	}
}

func TestEmulatorX86CompareStringPrefixes(t *testing.T) {
	tests := []struct {
		name          string
		prefix        byte
		left, right   string
		count         byte
		wantRemaining uint32
		wantOffset    uint32
		wantZero      bool
	}{
		{name: "repeat while equal", prefix: 0xf3, left: "abXd", right: "abYd", count: 4, wantRemaining: 1, wantOffset: 3},
		{name: "repeat while not equal", prefix: 0xf2, left: "Xab", right: "Yac", count: 3, wantRemaining: 1, wantOffset: 2, wantZero: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// cld; mov esi,0x2000; mov edi,0x3000; mov ecx,count;
			// repe/repne cmpsb; mov eax,ecx; ret
			code := starlark.Bytes([]byte{
				0xfc, 0xbe, 0x00, 0x20, 0x00, 0x00, 0xbf, 0x00, 0x30, 0x00, 0x00,
				0xb9, test.count, 0x00, 0x00, 0x00, test.prefix, 0xa6, 0x89, 0xc8, 0xc3,
			})
			machine := newRawX86TestMachine(t, code, nil)
			if err := machine.addMapping("left", 0x2000, []byte(test.left), true, false, false); err != nil {
				t.Fatal(err)
			}
			if err := machine.addMapping("right", 0x3000, []byte(test.right), true, false, false); err != nil {
				t.Fatal(err)
			}
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-cmps-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.wantRemaining {
				t.Fatalf("remaining count = %d, want %d", got, test.wantRemaining)
			}
			if got := machine.registers[x86asm.ESI]; got != 0x2000+test.wantOffset {
				t.Fatalf("esi = %#x, want %#x", got, 0x2000+test.wantOffset)
			}
			if got := machine.registers[x86asm.EDI]; got != 0x3000+test.wantOffset {
				t.Fatalf("edi = %#x, want %#x", got, 0x3000+test.wantOffset)
			}
			if machine.zero != test.wantZero {
				t.Fatalf("zero = %v, want %v", machine.zero, test.wantZero)
			}
		})
	}
}

func TestEmulatorX86ScanStringPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		prefix byte
		value  byte
		data   string
	}{
		{name: "repeat while not equal", prefix: 0xf2, value: 0, data: "ab\x00x"},
		{name: "repeat while equal", prefix: 0xf3, value: 'a', data: "aabx"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// mov edi,0x2000; mov ecx,4; mov al,value; repe/repne scasb;
			// mov eax,ecx; ret
			code := starlark.Bytes([]byte{
				0xbf, 0x00, 0x20, 0x00, 0x00, 0xb9, 0x04, 0x00, 0x00, 0x00,
				0xb0, test.value, test.prefix, 0xae, 0x89, 0xc8, 0xc3,
			})
			machine := newRawX86TestMachine(t, code, nil)
			if err := machine.addMapping("scan", 0x2000, []byte(test.data), true, false, false); err != nil {
				t.Fatal(err)
			}
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-scas-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != 1 {
				t.Fatalf("remaining count = %d, want 1", got)
			}
			if got := machine.registers[x86asm.EDI]; got != 0x2003 {
				t.Fatalf("edi = %#x, want 0x2003", got)
			}
		})
	}
}

func TestEmulatorX86ScanStringWithUnboundedCount(t *testing.T) {
	// mov edi,0x2000; or ecx,-1; xor eax,eax; repne scasb;
	// mov eax,edi; ret
	code := starlark.Bytes([]byte{
		0xbf, 0x00, 0x20, 0x00, 0x00,
		0x83, 0xc9, 0xff,
		0x31, 0xc0,
		0xf2, 0xae,
		0x89, 0xf8,
		0xc3,
	})
	machine := newRawX86TestMachine(t, code, nil)
	if err := machine.addMapping("scan", 0x2000, []byte("abc\x00"), true, false, false); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-unbounded-scas-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0x2004 {
		t.Fatalf("edi after scan = %#x, want 0x2004", got)
	}
	if got := machine.registers[x86asm.ECX]; got != math.MaxUint32-4 {
		t.Fatalf("remaining count = %#x, want %#x", got, uint32(math.MaxUint32-4))
	}
}

func TestEmulatorX86SegmentMemoryOperand(t *testing.T) {
	// push dword ptr fs:[0]; pop eax; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\x64\xff\x35\x00\x00\x00\x00\x58\xc3"), []starlark.Tuple{
		{starlark.String("fs_base"), starlark.MakeInt(0x2000)},
	})
	if err := machine.writeUint32(0x2000, 0x12345678); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-segment-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordUint32(t, result, "value"); got != 0x12345678 {
		t.Fatalf("eax = %#x, want segmented memory value", got)
	}
}

func TestEmulatorX86PluggableHook(t *testing.T) {
	// push 42; call 0x2000; ret
	code := starlark.Bytes("\x6a\x2a\xe8\xf9\x0f\x00\x00\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	thread := &starlark.Thread{Name: "emulator-hook-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "hook.star", []byte("def callback(event):\n    if event.return_address != 0x1007: fail(\"bad return address\")\n    if event.machine.read_u32le(event.argument_address) != event.args[0]: fail(\"bad argument address\")\n    return event.args[0] + 1\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = machine.hookBuiltin(thread, nil, starlark.Tuple{globals["callback"]}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
		{starlark.String("argc"), starlark.MakeInt(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 43 {
		t.Fatalf("hook result = %d, want 43", got)
	}
}

func TestEmulatorRunResumesSavedHookContext(t *testing.T) {
	// Model a saved context immediately after CALL transferred control to the
	// hook. The physical return address and logical frame already exist.
	code := append([]byte{0xc3}, make([]byte, 15)...)
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	thread := &starlark.Thread{Name: "emulator-hook-budget-resume-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "hook_resume.star", []byte("def callback(event):\n    if event.return_address != 0x1000: fail(\"bad return address\")\n    return 42\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{globals["callback"]}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x1010)},
	}); err != nil {
		t.Fatal(err)
	}

	if err := machine.push(0x1000); err != nil {
		t.Fatal(err)
	}
	machine.eip = 0x1010
	machine.callDepth = 1
	machine.callFrames = append(machine.callFrames, emulatorCallFrame{site: 0x0ffb, target: 0x1010})

	secondValue, err := machine.runBuiltin(thread, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second := secondValue.(*starlarkRecord)
	if got := recordString(t, second, "reason"); got != "return" {
		t.Fatalf("second reason = %q, detail = %s", got, recordString(t, second, "detail"))
	}
	if got := recordUint32(t, second, "value"); got != 42 {
		t.Fatalf("hook result = %d, want 42", got)
	}
	if machine.callDepth != 0 || len(machine.callFrames) != 0 {
		t.Fatalf("resumed hook left depth %d and %d frames", machine.callDepth, len(machine.callFrames))
	}
}

func TestEmulatorTailHookRetiresPhysicalThunkFrame(t *testing.T) {
	// Repeat a call to a physical import thunk that tail-jumps to a semantic
	// hook. A limit of two catches leaked logical frames on the third call.
	code := []byte{
		0xb9, 0x04, 0x00, 0x00, 0x00, // mov ecx,4
		0xe8, 0xf6, 0x00, 0x00, 0x00, // call 0x1100
		0x49,       // dec ecx
		0x75, 0xf8, // jnz 0x1005
		0xc3, // ret
	}
	code = append(code, make([]byte, 0x100-len(code))...)
	code = append(code, 0xe9, 0xfb, 0x0e, 0x00, 0x00) // jmp 0x2000
	machine := newRawX86TestMachine(t, starlark.Bytes(code), []starlark.Tuple{
		{starlark.String("call_depth_limit"), starlark.MakeInt(2)},
	})
	thread := &starlark.Thread{Name: "emulator-tail-hook-depth-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "tail_hook.star", []byte("def callback(event):\n    if event.return_address != 0x100a: fail(\"bad return address\")\n    return 0\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{globals["callback"]}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if machine.callDepth != 0 || len(machine.callFrames) != 0 {
		t.Fatalf("tail hook left depth %d and %d frames", machine.callDepth, len(machine.callFrames))
	}
}

func TestEmulatorInvokeInitialRegisters(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\x89\xe8\xc3"), nil) // mov eax,ebp; ret
	registers := starlark.NewDict(1)
	if err := registers.SetKey(starlark.String("ebp"), starlark.MakeInt(0x12345678)); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.invokeBuiltin(&starlark.Thread{Name: "emulator-invoke-register-test"}, nil, starlark.Tuple{starlark.MakeInt(0x1000)}, []starlark.Tuple{
		{starlark.String("registers"), registers},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordUint32(t, result, "value"); got != 0x12345678 {
		t.Fatalf("eax = %#x, want initial ebp", got)
	}
}

func TestEmulatorInvokeIsolatesExceptionList(t *testing.T) {
	code := append([]byte{0xc3}, make([]byte, 15)...)
	// mov eax,fs:[0]; ret
	code = append(code, 0x64, 0xa1, 0x00, 0x00, 0x00, 0x00, 0xc3)
	machine := newRawX86TestMachine(t, starlark.Bytes(code), []starlark.Tuple{
		{starlark.String("fs_base"), starlark.MakeInt(0x3000)},
	})
	if err := machine.writeUint32(0x3000, 0x12345678); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.invokeBuiltin(&starlark.Thread{Name: "emulator-invoke-seh-test"}, nil, starlark.Tuple{starlark.MakeInt(0x1010)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordUint32(t, result, "value"); got != math.MaxUint32 {
		t.Fatalf("nested exception head = %#x, want %#x", got, uint32(math.MaxUint32))
	}
	if got, err := machine.readUint32(0x3000); err != nil || got != 0x12345678 {
		t.Fatalf("restored exception head = %#x, %v", got, err)
	}
}

func TestEmulatorInvokePreservesCallerMemory(t *testing.T) {
	// The outer call passes a pointer to its stack local through a semantic
	// hook. The hook invokes target code on an isolated stack, and that target
	// writes through the caller-owned pointer.
	code := []byte{
		0x83, 0xec, 0x04, // sub esp,4
		0x89, 0xe0, // mov eax,esp
		0x50,                         // push eax
		0xe8, 0xf5, 0x0f, 0x00, 0x00, // call 0x2000
		0x8b, 0x04, 0x24, // mov eax,[esp]
		0x83, 0xc4, 0x04, // add esp,4
		0xc3, // ret
	}
	code = append(code, make([]byte, 0x100-len(code))...)
	code = append(code,
		0x8b, 0x44, 0x24, 0x04, // mov eax,[esp+4]
		0xc7, 0x00, 0x78, 0x56, 0x34, 0x12, // mov dword ptr [eax],0x12345678
		0x31, 0xc0, // xor eax,eax
		0xc2, 0x04, 0x00, // ret 4
	)
	machine := newRawX86TestMachine(t, starlark.Bytes(code), nil)
	thread := &starlark.Thread{Name: "emulator-invoke-memory-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "invoke.star", []byte("def callback(event):\n    result = event.machine.invoke(0x1100, args = [event.args[0]])\n    if result.reason != \"return\": fail(result.detail)\n    return 0\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{globals["callback"]}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
		{starlark.String("argc"), starlark.MakeInt(1)},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0x12345678 {
		t.Fatalf("caller local = %#x, want %#x", got, uint32(0x12345678))
	}
}

func TestEmulatorHardwareExceptionTransfer(t *testing.T) {
	// mov eax,[0]; mov eax,0x12345678; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xa1\x00\x00\x00\x00\xb8\x78\x56\x34\x12\xc3"), nil)
	thread := &starlark.Thread{Name: "emulator-exception-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "exception.star", []byte("def handler(event):\n    if event.code != 0xc0000005 or event.information != [0, 0]: fail(\"unexpected exception\")\n    event.machine.transfer(0x1005)\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.onExceptionBuiltin(thread, nil, starlark.Tuple{globals["handler"]}, nil); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0x12345678 {
		t.Fatalf("eax = %#x, want %#x", got, uint32(0x12345678))
	}
}

func TestEmulatorHookTransfer(t *testing.T) {
	// call 0x2000; mov eax,1; ret; padding; at 0x1010: mov eax,2; ret
	code := starlark.Bytes("\xe8\xfb\x0f\x00\x00\xb8\x01\x00\x00\x00\xc3\x90\x90\x90\x90\x90\xb8\x02\x00\x00\x00\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	thread := &starlark.Thread{Name: "emulator-transfer-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "transfer.star", []byte("def callback(event):\n    event.machine.transfer(0x1010)\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{globals["callback"]}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 2 {
		t.Fatalf("eax = %d, want transferred branch", got)
	}
}

func TestEmulatorHookStop(t *testing.T) {
	// call 0x2000; mov eax,1; ret. The semantic hook reports a scheduler wait.
	code := starlark.Bytes("\xe8\xfb\x0f\x00\x00\xb8\x01\x00\x00\x00\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	thread := &starlark.Thread{Name: "emulator-stop-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "stop.star", []byte("def callback(event):\n    event.machine.stop(\"wait\", detail=\"message queue\")\n    return 0x102\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{globals["callback"]}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "wait" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordString(t, result, "detail"); got != "message queue" {
		t.Fatalf("detail = %q", got)
	}
	if got := recordUint32(t, result, "value"); got != 0x102 {
		t.Fatalf("eax = %#x, want WAIT_TIMEOUT", got)
	}
	if got := recordUint32(t, result, "eip"); got != 0x1000 {
		t.Fatalf("eip = %#x, want stopped call instruction", got)
	}
}

func TestEmulatorHookStopExplicitValue(t *testing.T) {
	code := starlark.Bytes("\xe8\xfb\x0f\x00\x00\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	thread := &starlark.Thread{Name: "emulator-stop-value-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "stop_value.star", []byte("def callback(event):\n    event.machine.stop(\"rpc-exception\", detail=\"status\", value=0xd000003e)\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{globals["callback"]}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "rpc-exception" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0xd000003e {
		t.Fatalf("value = %#x, want propagated RPC status", got)
	}
}

func TestEmulatorExecutionResumesStoppedCall(t *testing.T) {
	// call hook; mov eax,7; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\xe8\xfb\x0f\x00\x00\xb8\x07\x00\x00\x00\xc3"), nil)
	thread := &starlark.Thread{Name: "emulator-execution-test"}
	ready := false
	callback := starlark.NewBuiltin("wait", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if !ready {
			if _, err := machine.stopBuiltin(nil, nil, starlark.Tuple{starlark.String("wait")}, nil); err != nil {
				return nil, err
			}
			return starlark.MakeInt(0x102), nil
		}
		return starlark.MakeInt(0), nil
	})
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{callback}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
	}); err != nil {
		t.Fatal(err)
	}
	machine.registers[x86asm.EAX] = 0x12345678
	value, err := machine.spawnBuiltin(thread, nil, starlark.Tuple{starlark.MakeInt(0x1000)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	execution := value.(*emulatorExecution)
	firstValue, err := execution.runBuiltin(thread, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := firstValue.(*starlarkRecord)
	if got := recordString(t, first, "reason"); got != "wait" {
		t.Fatalf("first reason = %q", got)
	}
	if got := recordUint32(t, first, "eip"); got != 0x1000 {
		t.Fatalf("first eip = %#x, want call instruction", got)
	}
	if got := machine.registers[x86asm.EAX]; got != 0x12345678 {
		t.Fatalf("caller eax = %#x after suspended execution", got)
	}
	ready = true
	secondValue, err := execution.runBuiltin(thread, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second := secondValue.(*starlarkRecord)
	if got := recordString(t, second, "reason"); got != "return" {
		t.Fatalf("second reason = %q, detail = %s", got, recordString(t, second, "detail"))
	}
	if got := recordUint32(t, second, "value"); got != 7 {
		t.Fatalf("second eax = %#x, want 7", got)
	}
	if !execution.done {
		t.Fatal("execution did not retain completion state")
	}
	if machine.stackSlots[execution.stackSlot] {
		t.Fatal("completed execution retained its reserved stack slot")
	}
}

func TestEmulatorExecutionCloseReleasesStoppedStack(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xeb\xfe"), []starlark.Tuple{
		{starlark.String("instruction_limit"), starlark.MakeInt(10)},
	})
	thread := &starlark.Thread{Name: "emulator-execution-close-test"}

	for attempt := 0; attempt < 16; attempt++ {
		value, err := machine.spawnBuiltin(thread, nil, starlark.Tuple{starlark.MakeInt(0x1000)}, nil)
		if err != nil {
			t.Fatalf("spawn %d: %v", attempt, err)
		}
		execution := value.(*emulatorExecution)
		resultValue, err := execution.runBuiltin(thread, nil, nil, []starlark.Tuple{
			{starlark.String("instruction_limit"), starlark.MakeInt(1)},
		})
		if err != nil {
			t.Fatalf("run %d: %v", attempt, err)
		}
		if got := recordString(t, resultValue.(*starlarkRecord), "reason"); got != "budget" {
			t.Fatalf("run %d reason = %q, want budget", attempt, got)
		}
		if _, err := execution.closeBuiltin(thread, nil, nil, nil); err != nil {
			t.Fatalf("close %d: %v", attempt, err)
		}
		if !execution.closed {
			t.Fatalf("execution %d did not retain closed state", attempt)
		}
		if machine.stackSlots[execution.stackSlot] {
			t.Fatalf("execution %d retained stack slot %d", attempt, execution.stackSlot)
		}
		if _, err := execution.runBuiltin(thread, nil, nil, nil); err == nil || err.Error() != "execution.run: execution is closed" {
			t.Fatalf("run closed execution %d: %v", attempt, err)
		}
	}
}

func TestEmulatorDecodedInstructionCacheIsBounded(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	machine.decodedLimit = 3
	first := &x86asm.Inst{Len: 1}
	stale := &x86asm.Inst{Len: 2}
	third := &x86asm.Inst{Len: 3}
	replacement := &x86asm.Inst{Len: 4}
	fourth := &x86asm.Inst{Len: 5}

	machine.cacheDecodedInstruction(0x2000, first)
	machine.cacheDecodedInstruction(0x2020, stale)
	machine.cacheDecodedInstruction(0x2040, third)
	machine.invalidateDecodedCache(0x2020, 1)
	machine.cacheDecodedInstruction(0x2020, replacement)
	machine.cacheDecodedInstruction(0x2060, fourth)

	if got := len(machine.decoded); got != machine.decodedLimit {
		t.Fatalf("decoded entries = %d, want %d", got, machine.decodedLimit)
	}
	if machine.decoded[0x2000] != nil {
		t.Fatal("oldest decoded instruction was not evicted")
	}
	if machine.decoded[0x2020] != replacement {
		t.Fatal("stale ring entry evicted a replacement instruction")
	}
	if page := machine.decodedPages[2]; page == nil || page.instructions[0x20] != replacement {
		t.Fatal("dense decoded page does not reference the replacement instruction")
	}

	for attempt := 0; attempt < 12; attempt++ {
		machine.invalidateDecodedCache(0x2020, 1)
		machine.cacheDecodedInstruction(0x2020, &x86asm.Inst{Len: attempt + 1})
	}
	for address := uint32(0x3000); address < 0x3010; address++ {
		machine.cacheDecodedInstruction(address, &x86asm.Inst{Len: 1})
		if got := len(machine.decoded); got > machine.decodedLimit {
			t.Fatalf("decoded entries after stale-ring stress = %d, limit %d", got, machine.decodedLimit)
		}
	}
}

func TestEmulatorAcceleratesWideASCIICompare(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	prefix := []byte("\x8b\xff\x55\x8b\xec\x83\xec\x0c\x53\x8b\x5d\x0c\x56\x57\x8b\x3d\x00\x00\x00\x00\x8b\x45\x08\x66\x8b\x00\x66\x85\xc0\x75\x09\x66")
	if err := machine.addMapping("wide-compare", 0x2000, prefix, true, false, true); err != nil {
		t.Fatal(err)
	}
	strings := []byte("A\x00l\x00p\x00h\x00a\x00\x00\x00a\x00L\x00P\x00H\x00B\x00\x00\x00")
	if err := machine.addMapping("wide-strings", 0x3000, strings, true, false, false); err != nil {
		t.Fatal(err)
	}
	esp := emulatorStackTop - 16
	machine.registers[x86asm.ESP] = esp
	for address, value := range map[uint32]uint32{esp: 0x1234, esp + 4: 0x3000, esp + 8: 0x300c} {
		if err := machine.writeUint32(address, value); err != nil {
			t.Fatal(err)
		}
	}
	machine.eip = 0x2000
	accelerated, err := machine.accelerateWideASCIICompare(machine.eip)
	if err != nil {
		t.Fatal(err)
	}
	if !accelerated {
		t.Fatal("wide ASCII comparator was not recognized")
	}
	if got := machine.registers[x86asm.EAX]; got != 0xffffffff {
		t.Fatalf("comparison = %#x, want -1", got)
	}
	if machine.eip != 0x1234 || machine.registers[x86asm.ESP] != esp+12 {
		t.Fatalf("return state eip=%#x esp=%#x", machine.eip, machine.registers[x86asm.ESP])
	}
}

func TestEmulatorExecutionStartsAtHook(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	thread := &starlark.Thread{Name: "emulator-execution-hook-test"}
	callback := starlark.NewBuiltin("answer", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return starlark.MakeInt(0x12345678), nil
	})
	if _, err := machine.hookBuiltin(thread, nil, starlark.Tuple{callback}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeInt(0x2000)},
		{starlark.String("argc"), starlark.MakeInt(1)},
	}); err != nil {
		t.Fatal(err)
	}
	value, err := machine.spawnBuiltin(thread, nil, starlark.Tuple{starlark.MakeInt(0x2000)}, []starlark.Tuple{
		{starlark.String("args"), starlark.NewList([]starlark.Value{starlark.MakeInt(7)})},
	})
	if err != nil {
		t.Fatal(err)
	}
	resultValue, err := value.(*emulatorExecution).runBuiltin(thread, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0x12345678 {
		t.Fatalf("value = %#x, want %#x", got, uint32(0x12345678))
	}
}

func TestEmulatorVirtualModuleExport(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	thread := &starlark.Thread{Name: "emulator-module-test"}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "module.star", []byte("def callback(event):\n    return 0xf1234567\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	addressValue, err := machine.provideExportBuiltin(thread, nil, starlark.Tuple{globals["callback"]}, []starlark.Tuple{
		{starlark.String("module"), starlark.String("example")},
		{starlark.String("name"), starlark.String("Answer")},
		{starlark.String("argc"), starlark.MakeInt(0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, _ := addressValue.(starlark.Int).Uint64()
	if got := machine.resolveExport("example.dll", "answer", 0, 0); got != uint32(address) {
		t.Fatalf("resolved address = %#x, want %#x", got, address)
	}
	resultValue, err := machine.callAddress(thread, uint32(address), nil)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 0xf1234567 {
		t.Fatalf("eax = %#x, want full uint32 hook result", got)
	}
}

func TestEmulatorRelinksImportAfterModuleLoad(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if err := machine.addMapping("iat", 0x2000, make([]byte, 4), true, true, false); err != nil {
		t.Fatal(err)
	}
	machine.imports[emulatorImportBase] = emulatorImport{
		module: "dependency.dll",
		name:   "Answer",
		iat:    0x2000,
		target: emulatorImportBase,
	}
	machine.modules["dependency.dll"] = &emulatorModule{
		name:     "dependency.dll",
		exports:  map[string]emulatorModuleExport{"answer": {address: 0x12345678}},
		ordinals: make(map[uint32]emulatorModuleExport),
	}

	if err := machine.relinkImports(); err != nil {
		t.Fatal(err)
	}
	if got, err := machine.readUint32(0x2000); err != nil || got != 0x12345678 {
		t.Fatalf("IAT value = %#x, %v; want loaded export", got, err)
	}
}

func TestEmulatorX86BudgetTraceAndSnapshot(t *testing.T) {
	// jmp to self
	machine := newRawX86TestMachine(t, starlark.Bytes("\xeb\xfe"), []starlark.Tuple{
		{starlark.String("instruction_limit"), starlark.MakeInt(4)},
		{starlark.String("trace"), starlark.True},
	})
	cloneValue, err := machine.snapshotBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clone := cloneValue.(*emulatorX86)
	clone.registers[x86asm.EAX] = 99
	if machine.registers[x86asm.EAX] != 0 {
		t.Fatal("snapshot register mutation affected original")
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-budget-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "budget" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	trace := result.Values["trace"].(*starlark.List)
	if trace.Len() != 4 {
		t.Fatalf("trace length = %d, want 4", trace.Len())
	}
}

func TestEmulatorX86CheckpointRestoresMachineAndPluginState(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	addressValue, err := machine.allocateBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(4)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	address, _ := addressValue.(starlark.Int).Uint64()
	if err := machine.writeUint32(uint32(address), 0x12345678); err != nil {
		t.Fatal(err)
	}

	nested := starlark.NewList([]starlark.Value{starlark.String("before")})
	configuration := starlark.NewDict(1)
	if err := configuration.SetKey(starlark.String("fixed"), starlark.True); err != nil {
		t.Fatal(err)
	}
	configuration.Freeze()
	executionValue, err := machine.spawnBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(0x1000)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	execution := executionValue.(*emulatorExecution)
	execution.context.callFrames = []emulatorCallFrame{{site: 1, target: 2}}
	state := starlark.NewDict(2)
	if err := state.SetKey(starlark.String("nested"), nested); err != nil {
		t.Fatal(err)
	}
	if err := state.SetKey(starlark.String("configuration"), configuration); err != nil {
		t.Fatal(err)
	}
	plugin := newStarlarkRecord(starlark.StringDict{
		"install": starlark.NewBuiltin("install", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			return starlark.None, nil
		}),
		"name":  starlark.String("checkpoint test"),
		"state": state,
	})
	if _, err := machine.useBuiltin(&starlark.Thread{Name: "checkpoint-use"}, nil, starlark.Tuple{plugin}, nil); err != nil {
		t.Fatal(err)
	}

	checkpointValue, err := machine.checkpointBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := checkpointValue.(*emulatorCheckpoint)
	machine.registers[x86asm.EAX] = 99
	if err := machine.writeUint32(uint32(address), 0xaabbccdd); err != nil {
		t.Fatal(err)
	}
	if err := nested.Append(starlark.String("after")); err != nil {
		t.Fatal(err)
	}
	if err := state.SetKey(starlark.String("added"), starlark.True); err != nil {
		t.Fatal(err)
	}
	if _, err := execution.closeBuiltin(nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	execution.done = true
	execution.context.callFrames[0].site = 99

	if _, err := machine.restoreBuiltin(nil, nil, starlark.Tuple{checkpoint}, nil); err != nil {
		t.Fatal(err)
	}
	if got := machine.registers[x86asm.EAX]; got != 0 {
		t.Fatalf("restored eax = %d, want 0", got)
	}
	if got, err := machine.readUint32(uint32(address)); err != nil || got != 0x12345678 {
		t.Fatalf("restored memory = %#x, %v; want 0x12345678", got, err)
	}
	if nested.Len() != 1 || nested.Index(0) != starlark.String("before") {
		t.Fatalf("restored nested list = %s, want [\"before\"]", nested)
	}
	if _, found, err := state.Get(starlark.String("added")); err != nil || found {
		t.Fatalf("post-checkpoint dict entry survived restore: found=%t err=%v", found, err)
	}
	if execution.done || execution.closed || execution.machine != machine || !machine.executions[execution] || len(execution.context.callFrames) != 1 || execution.context.callFrames[0].site != 1 {
		t.Fatalf("suspended execution was not restored and rebound: %+v", execution)
	}

	// Checkpoints are reusable; a later probe must not mutate the saved state.
	machine.registers[x86asm.EAX] = 7
	if err := nested.Append(starlark.String("second")); err != nil {
		t.Fatal(err)
	}
	if _, err := machine.restoreBuiltin(nil, nil, starlark.Tuple{checkpoint}, nil); err != nil {
		t.Fatal(err)
	}
	if machine.registers[x86asm.EAX] != 0 || nested.Len() != 1 {
		t.Fatal("reused checkpoint did not restore its original state")
	}
}

func TestEmulatorX86SnapshotMethodsAndImportsAreIndependent(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	// Populate the method cache before cloning; cached builtins must not remain
	// bound to the source machine.
	if _, err := machine.Attr("set_register"); err != nil {
		t.Fatal(err)
	}
	machine.imports[0x2000] = emulatorImport{module: "source.dll", name: "Value", target: 0x2000}
	clone := machine.clone()
	setter, err := clone.Attr("set_register")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := starlark.Call(&starlark.Thread{Name: "snapshot-method"}, setter.(starlark.Callable), nil, []starlark.Tuple{
		{starlark.String("name"), starlark.String("eax")},
		{starlark.String("value"), starlark.MakeInt(42)},
	}); err != nil {
		t.Fatal(err)
	}
	if clone.registers[x86asm.EAX] != 42 || machine.registers[x86asm.EAX] != 0 {
		t.Fatal("snapshot method remained bound to the source machine")
	}
	delete(clone.imports, 0x2000)
	if _, ok := machine.imports[0x2000]; !ok {
		t.Fatal("snapshot import mutation affected source machine")
	}
}

func TestEmulatorX86MemoryWriteWatchIsBoundedAndRecordsIntersections(t *testing.T) {
	// mov eax,0x12345678; mov [0x60000000],eax;
	// mov eax,0xaabbccdd; mov [0x60000002],eax; ret
	code := starlark.Bytes("\xb8\x78\x56\x34\x12\xa3\x00\x00\x00\x60\xb8\xdd\xcc\xbb\xaa\xa3\x02\x00\x00\x60\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	if _, err := machine.allocateBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(8)}, nil); err != nil {
		t.Fatal(err)
	}
	watchValue, err := machine.watchMemoryBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(0x60000001)},
		{starlark.String("size"), starlark.MakeInt(4)},
		{starlark.String("limit"), starlark.MakeInt(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	watch, _ := watchValue.(starlark.Int).Uint64()
	if _, err := machine.run(&starlark.Thread{Name: "emulator-memory-watch-test"}); err != nil {
		t.Fatal(err)
	}
	writesValue, err := machine.memoryWritesBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(watch)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	writes := writesValue.(*starlarkRecord)
	if got := recordUint32(t, writes, "dropped"); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	entries := writes.Values["entries"].(*starlark.List)
	if entries.Len() != 1 {
		t.Fatalf("entries = %d, want 1", entries.Len())
	}
	entry := entries.Index(0).(*starlarkRecord)
	if got := recordUint32(t, entry, "eip"); got != 0x100f {
		t.Fatalf("writer eip = %#x, want 0x100f", got)
	}
	if got := recordUint32(t, entry, "address"); got != 0x60000002 {
		t.Fatalf("write address = %#x, want 0x60000002", got)
	}
	if got := string(entry.Values["before"].(starlark.Bytes)); got != "\x34\x12\x00" {
		t.Fatalf("before = %x, want 341200", got)
	}
	if got := string(entry.Values["after"].(starlark.Bytes)); got != "\xdd\xcc\xbb" {
		t.Fatalf("after = %x, want ddccbb", got)
	}

	cloneValue, err := machine.snapshotBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clone := cloneValue.(*emulatorX86)
	clone.memoryWatches[watch].entries[0].after[0] = 0
	if machine.memoryWatches[watch].entries[0].after[0] != 0xdd {
		t.Fatal("snapshot memory watch shares entry storage with original")
	}
}

func TestEmulatorX86CodeWatchIsBoundedAndSnapshotIndependent(t *testing.T) {
	// mov eax,0x12345678; mov [0x60000000],eax;
	// mov eax,0xaabbccdd; mov [0x60000002],eax; ret
	code := starlark.Bytes("\xb8\x78\x56\x34\x12\xa3\x00\x00\x00\x60\xb8\xdd\xcc\xbb\xaa\xa3\x02\x00\x00\x60\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	if _, err := machine.allocateBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(8)}, nil); err != nil {
		t.Fatal(err)
	}
	watchValue, err := machine.watchCodeBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(0x1005)},
		{starlark.String("size"), starlark.MakeInt(0xf)},
		{starlark.String("limit"), starlark.MakeInt(2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	watch, _ := watchValue.(starlark.Int).Uint64()
	if _, err := machine.run(&starlark.Thread{Name: "emulator-code-watch-test"}); err != nil {
		t.Fatal(err)
	}
	traceValue, err := machine.codeTraceBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(watch)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trace := traceValue.(*starlarkRecord)
	if got := recordUint32(t, trace, "dropped"); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	entries := trace.Values["entries"].(*starlark.List)
	if entries.Len() != 2 {
		t.Fatalf("entries = %d, want 2", entries.Len())
	}
	first := entries.Index(0).(*starlarkRecord)
	if got := recordUint32(t, first, "address"); got != 0x100a {
		t.Fatalf("first address = %#x, want 0x100a", got)
	}
	if got := recordString(t, first, "instruction"); got != "mov eax, 0xaabbccdd" {
		t.Fatalf("first instruction = %q", got)
	}
	firstRegisters := first.Values["registers"].(*starlarkRecord)
	if got := recordUint32(t, firstRegisters, "eax"); got != 0x12345678 {
		t.Fatalf("first eax = %#x, want 0x12345678", got)
	}
	if got := recordUint32(t, firstRegisters, "eip"); got != 0x100a {
		t.Fatalf("first eip = %#x, want 0x100a", got)
	}
	if got := recordUint32(t, firstRegisters, "esp"); got != recordUint32(t, first, "esp") {
		t.Fatalf("first register esp = %#x, want entry esp", got)
	}
	second := entries.Index(1).(*starlarkRecord)
	if got := recordUint32(t, second, "address"); got != 0x100f {
		t.Fatalf("second address = %#x, want 0x100f", got)
	}
	secondRegisters := second.Values["registers"].(*starlarkRecord)
	if got := recordUint32(t, secondRegisters, "eax"); got != 0xaabbccdd {
		t.Fatalf("second eax = %#x, want 0xaabbccdd", got)
	}

	cloneValue, err := machine.snapshotBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clone := cloneValue.(*emulatorX86)
	clone.codeWatches[watch].entries[0].instruction = "changed"
	if machine.codeWatches[watch].entries[0].instruction == "changed" {
		t.Fatal("snapshot code watch shares entry storage with original")
	}
}

func TestEmulatorX86AcceleratedRegionRecordsCodeWatch(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\x90\xc3"), nil)
	watchValue, err := machine.watchCodeBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(0x1000)},
		{starlark.String("size"), starlark.MakeInt(2)},
		{starlark.String("limit"), starlark.MakeInt(2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	watch, _ := watchValue.(starlark.Int).Uint64()
	machine.eip = 0x1000
	machine.regionAccelerations[0x1000] = emulatorRegionAcceleration{
		entry: 0x1000, start: 0x1000, end: 0x1002, maximumInstructions: 16,
	}
	consumed, accelerated, stop, detail, err := machine.accelerateRegisteredRegion(
		&starlark.Thread{Name: "accelerated-watch-test"},
		machine.regionAccelerations[0x1000],
		16,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !accelerated || consumed == 0 || stop != "return" || detail != "" {
		t.Fatalf("accelerated region = consumed %d, accelerated %t, stop %q, detail %q", consumed, accelerated, stop, detail)
	}
	trace := machine.codeWatches[watch]
	if len(trace.entries) != 2 || trace.entries[0].address != 0x1000 || trace.entries[1].address != 0x1001 {
		t.Fatalf("accelerated watch entries = %+v, want addresses 0x1000 and 0x1001", trace.entries)
	}
}

func TestEmulatorX86CodeWatchCapturesRegistersAndBoundedStack(t *testing.T) {
	// push 0x60000000; mov eax,0xaabbccdd; nop; ret
	machine := newRawX86TestMachine(t, starlark.Bytes("\x68\x00\x00\x00\x60\xb8\xdd\xcc\xbb\xaa\x90\xc3"), nil)
	if _, err := machine.allocateBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(4)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := machine.writeMemory(0x60000000, []byte("\x78\x56\x34\x12")); err != nil {
		t.Fatal(err)
	}
	capture := starlark.NewDict(3)
	for key, value := range map[string]starlark.Value{
		"base":        starlark.String("esp"),
		"dereference": starlark.MakeInt(1),
		"size":        starlark.MakeInt(4),
	} {
		if err := capture.SetKey(starlark.String(key), value); err != nil {
			t.Fatal(err)
		}
	}
	captures := starlark.NewDict(1)
	if err := captures.SetKey(starlark.String("pointed"), capture); err != nil {
		t.Fatal(err)
	}
	watchValue, err := machine.watchCodeBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(0x100a)},
		{starlark.String("size"), starlark.MakeInt(1)},
		{starlark.String("limit"), starlark.MakeInt(1)},
		{starlark.String("stack_bytes"), starlark.MakeInt(4)},
		{starlark.String("captures"), captures},
	})
	if err != nil {
		t.Fatal(err)
	}
	watch, _ := watchValue.(starlark.Int).Uint64()
	if _, err := machine.run(&starlark.Thread{Name: "emulator-code-watch-stack-test"}); err != nil {
		t.Fatal(err)
	}
	traceValue, err := machine.codeTraceBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(watch)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trace := traceValue.(*starlarkRecord)
	if got := recordUint32(t, trace, "stack_bytes"); got != 4 {
		t.Fatalf("stack bytes = %d, want 4", got)
	}
	entry := trace.Values["entries"].(*starlark.List).Index(0).(*starlarkRecord)
	if got := string(entry.Values["stack"].(starlark.Bytes)); got != "\x00\x00\x00\x60" {
		t.Fatalf("stack = %x, want 00000060", got)
	}
	registers := entry.Values["registers"].(*starlarkRecord)
	if got := recordUint32(t, registers, "eax"); got != 0xaabbccdd {
		t.Fatalf("eax = %#x, want 0xaabbccdd", got)
	}
	captured := entry.Values["captures"].(*starlarkRecord)
	if got := string(captured.Values["pointed"].(starlark.Bytes)); got != "\x78\x56\x34\x12" {
		t.Fatalf("pointed capture = %x, want 78563412", got)
	}
	cloneValue, err := machine.snapshotBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	clone := cloneValue.(*emulatorX86)
	clone.codeWatches[watch].entries[0].captures["pointed"][0] = 0
	if machine.codeWatches[watch].entries[0].captures["pointed"][0] != 0x78 {
		t.Fatal("snapshot code watch shares captured memory with original")
	}
}

func TestEmulatorX86SampledProfile(t *testing.T) {
	// nop; jmp back to nop
	machine := newRawX86TestMachine(t, starlark.Bytes("\x90\xeb\xfd"), []starlark.Tuple{
		{starlark.String("instruction_limit"), starlark.MakeInt(6)},
		{starlark.String("profile"), starlark.True},
		{starlark.String("profile_interval"), starlark.MakeInt(1)},
	})
	if _, err := machine.run(&starlark.Thread{Name: "emulator-profile-test"}); err != nil {
		t.Fatal(err)
	}
	profileValue, err := machine.profileBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := profileValue.(*starlarkRecord)
	if got := recordUint32(t, profile, "operations"); got != 6 {
		t.Fatalf("operations = %d, want 6", got)
	}
	entries := profile.Values["entries"].(*starlark.List)
	if entries.Len() != 2 {
		t.Fatalf("profile entries = %d, want 2", entries.Len())
	}
	first := entries.Index(0).(*starlarkRecord)
	if got := recordUint32(t, first, "address"); got != 0x1000 {
		t.Fatalf("first address = %#x, want 0x1000", got)
	}
	if got := recordString(t, first, "mapping"); got != "code" {
		t.Fatalf("first mapping = %q, want code", got)
	}
	if _, err := machine.profileBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("reset"), starlark.True}}); err != nil {
		t.Fatal(err)
	}
	clearedValue, err := machine.profileBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cleared := clearedValue.(*starlarkRecord)
	if got := recordUint32(t, cleared, "samples"); got != 0 {
		t.Fatalf("samples after reset = %d, want 0", got)
	}
}

func TestEmulatorX86SampledProfileRetainsLateHotspot(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), []starlark.Tuple{
		{starlark.String("profile"), starlark.True},
		{starlark.String("profile_interval"), starlark.MakeInt(1)},
		{starlark.String("profile_limit"), starlark.MakeInt(2)},
	})
	for _, address := range []uint32{0x10, 0x20, 0x30, 0x30, 0x30, 0x30} {
		machine.sampleProfile(address)
	}
	if len(machine.profileCounts) != 1 || machine.profileCounts[0x30] != 3 {
		t.Fatalf("profile counts = %#v, want late hotspot 0x30:3", machine.profileCounts)
	}
	if machine.profileDropped != 1 {
		t.Fatalf("dropped = %d, want 1", machine.profileDropped)
	}
}

func TestEmulatorPluginAllocationAndCString(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	bytesAddressValue, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("value"), starlark.Bytes("raw\xff\x00tail")},
		{starlark.String("name"), starlark.String("plugin-bytes")},
	})
	if err != nil {
		t.Fatal(err)
	}
	bytesAddress, _ := bytesAddressValue.(starlark.Int).Uint64()
	mappings := machine.mappingValues()
	var pluginMapping *starlarkRecord
	for index := 0; index < mappings.Len(); index++ {
		candidate := mappings.Index(index).(*starlarkRecord)
		if recordString(t, candidate, "name") == "plugin-bytes" {
			pluginMapping = candidate
			break
		}
	}
	if pluginMapping == nil {
		t.Fatal("plugin mapping is absent")
	}
	if pluginMapping.Values["writable"] != starlark.True || pluginMapping.Values["executable"] != starlark.False {
		t.Fatalf("plugin mapping permissions = writable %v executable %v", pluginMapping.Values["writable"], pluginMapping.Values["executable"])
	}
	raw, err := machine.readCBytesBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(bytesAddress)}, nil)
	if err != nil || raw != starlark.Bytes("raw\xff") {
		t.Fatalf("plugin bytes = %v, %v", raw, err)
	}
	bounded, err := machine.readCBytesBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(bytesAddress)}, []starlark.Tuple{
		{starlark.String("maximum"), starlark.MakeInt(4)},
		{starlark.String("require_terminator"), starlark.False},
	})
	if err != nil || bounded != starlark.Bytes("raw\xff") {
		t.Fatalf("bounded plugin bytes = %v, %v", bounded, err)
	}
	wideAddressValue, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("value"), starlark.Bytes("A\x00B\x00\x00\x00tail")},
		{starlark.String("name"), starlark.String("plugin-wide-bytes")},
	})
	if err != nil {
		t.Fatal(err)
	}
	wideAddress, _ := wideAddressValue.(starlark.Int).Uint64()
	wide, err := machine.readCBytesBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(wideAddress)}, []starlark.Tuple{
		{starlark.String("maximum"), starlark.MakeInt(8)},
		{starlark.String("unit_width"), starlark.MakeInt(2)},
	})
	if err != nil || wide != starlark.Bytes("A\x00B\x00") {
		t.Fatalf("wide plugin bytes = %v, %v", wide, err)
	}
	if _, err := machine.readCBytesBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(wideAddress)}, []starlark.Tuple{
		{starlark.String("maximum"), starlark.MakeInt(7)},
		{starlark.String("unit_width"), starlark.MakeInt(2)},
	}); err == nil {
		t.Fatal("read_cbytes accepted a partial code unit")
	}
	addressValue, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("value"), starlark.Bytes("h\x00i\x00\x00\x00")},
		{starlark.String("name"), starlark.String("plugin-string")},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, _ := addressValue.(starlark.Int).Uint64()
	text, err := machine.readCStringBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(address)}, []starlark.Tuple{
		{starlark.String("encoding"), starlark.String("utf16le")},
	})
	if err != nil || text != starlark.String("hi") {
		t.Fatalf("plugin string = %v, %v", text, err)
	}
}

func TestEmulatorProtectMakesGeneratedCodeExecutable(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	addressValue, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("value"), starlark.Bytes("\xb8\x2a\x00\x00\x00\xc3")},
		{starlark.String("name"), starlark.String("generated-code")},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, _ := addressValue.(starlark.Int).Uint64()
	before, err := machine.callBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(address)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := recordString(t, before.(*starlarkRecord), "reason"); got != "exception" {
		t.Fatalf("call before protect reason = %q, want exception", got)
	}
	previous, err := machine.protectBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(address)},
		{starlark.String("size"), starlark.MakeInt(6)},
		{starlark.String("readable"), starlark.True},
		{starlark.String("writable"), starlark.False},
		{starlark.String("executable"), starlark.True},
	})
	if err != nil {
		t.Fatal(err)
	}
	old := previous.(*starlark.List)
	if old.Len() != 1 || old.Index(0).(*starlarkRecord).Values["executable"] != starlark.False {
		t.Fatalf("previous protections = %v, want one non-executable mapping", old)
	}
	after, err := machine.callBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(address)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := after.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("call after protect reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 42 {
		t.Fatalf("generated code value = %d, want 42", got)
	}
}

func TestEmulatorProtectDoesNotChangeRestOfBackingMapping(t *testing.T) {
	code := starlark.Bytes("\xb8\x01\x00\x00\x00\xc3\xb8\x02\x00\x00\x00\xc3")
	machine := newRawX86TestMachine(t, code, nil)
	if _, err := machine.protectBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(0x1006)},
		{starlark.String("size"), starlark.MakeInt(6)},
		{starlark.String("executable"), starlark.False},
	}); err != nil {
		t.Fatal(err)
	}
	first, err := machine.callBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(0x1000)}, nil)
	if err != nil || recordString(t, first.(*starlarkRecord), "reason") != "return" {
		t.Fatalf("unprotected code did not return: %v, %v", first, err)
	}
	second, err := machine.callBuiltin(nil, nil, starlark.Tuple{starlark.MakeUint64(0x1006)}, nil)
	if err != nil || recordString(t, second.(*starlarkRecord), "reason") != "exception" {
		t.Fatalf("protected code did not fault: %v, %v", second, err)
	}
}

func TestEmulatorAllocateAtFixedAddress(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	value, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(0x7ffe0000)},
		{starlark.String("size"), starlark.MakeInt(0x1000)},
		{starlark.String("alignment"), starlark.MakeInt(0x1000)},
		{starlark.String("name"), starlark.String("shared-data")},
		{starlark.String("writable"), starlark.False},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, _ := value.(starlark.Int).Uint64()
	if address != 0x7ffe0000 {
		t.Fatalf("fixed allocation = %#x, want 0x7ffe0000", address)
	}
	if _, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(0x7ffe0800)},
		{starlark.String("size"), starlark.MakeInt(0x1000)},
	}); err == nil {
		t.Fatal("overlapping fixed allocation succeeded")
	}
}

func TestEmulatorIMULByteAccumulatorForm(t *testing.T) {
	for _, test := range []struct {
		name  string
		code  starlark.Bytes
		eax   uint32
		carry uint32
	}{
		{name: "fits", code: starlark.Bytes("\xb0\xfe\xb1\x03\xf6\xe9\x0f\x92\xc2\xc3"), eax: 0xfffa, carry: 0},
		{name: "overflows", code: starlark.Bytes("\xb0\x7f\xb1\x02\xf6\xe9\x0f\x92\xc2\xc3"), eax: 0x00fe, carry: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-imul-byte-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.eax {
				t.Fatalf("eax = %#x, want %#x", got, test.eax)
			}
			registers := result.Values["registers"].(*starlarkRecord)
			if got := recordUint32(t, registers, "edx") & 0xff; got != test.carry {
				t.Fatalf("carry byte = %d, want %d", got, test.carry)
			}
		})
	}
}

func TestEmulatorBitScanForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code starlark.Bytes
		eax  uint32
		zero uint32
	}{
		{name: "forward", code: starlark.Bytes("\xb8\x00\x01\x00\x00\x0f\xbc\xc8\x0f\x94\xc2\x89\xc8\xc3"), eax: 8, zero: 0},
		{name: "reverse", code: starlark.Bytes("\xb8\x00\x01\x00\x00\x0f\xbd\xc8\x0f\x94\xc2\x89\xc8\xc3"), eax: 8, zero: 0},
		{name: "zero-preserves-destination", code: starlark.Bytes("\xb9\x55\x00\x00\x00\x31\xc0\x0f\xbc\xc8\x0f\x94\xc2\x89\xc8\xc3"), eax: 0x55, zero: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			machine := newRawX86TestMachine(t, test.code, nil)
			resultValue, err := machine.run(&starlark.Thread{Name: "emulator-bit-scan-test"})
			if err != nil {
				t.Fatal(err)
			}
			result := resultValue.(*starlarkRecord)
			if got := recordString(t, result, "reason"); got != "return" {
				t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
			}
			if got := recordUint32(t, result, "value"); got != test.eax {
				t.Fatalf("eax = %#x, want %#x", got, test.eax)
			}
			registers := result.Values["registers"].(*starlarkRecord)
			if got := recordUint32(t, registers, "edx") & 0xff; got != test.zero {
				t.Fatalf("zero byte = %d, want %d", got, test.zero)
			}
		})
	}
}

func TestEmulatorProvideDataExport(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	iatValue, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("size"), starlark.MakeInt(4)},
		{starlark.String("name"), starlark.String("test-iat")},
	})
	if err != nil {
		t.Fatal(err)
	}
	iat, _ := iatValue.(starlark.Int).Uint64()
	machine.imports[emulatorImportBase] = emulatorImport{
		module: "runtime.dll",
		name:   "_state",
		iat:    uint32(iat),
		target: emulatorImportBase,
	}
	addressValue, err := machine.provideExportBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("module"), starlark.String("runtime.dll")},
		{starlark.String("name"), starlark.String("_state")},
		{starlark.String("value"), starlark.Bytes("\x01\x02\x03\x04")},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, ok := addressValue.(starlark.Int).Uint64()
	if !ok {
		t.Fatalf("data export address = %v", addressValue)
	}
	resolvedValue, err := machine.resolveExportBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("module"), starlark.String("RUNTIME")},
		{starlark.String("name"), starlark.String("_STATE")},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := resolvedValue.(starlark.Int).Uint64()
	if resolved != address {
		t.Fatalf("resolved data export = %#x, want %#x", resolved, address)
	}
	linked, err := machine.readUint32(uint32(iat))
	if err != nil || uint64(linked) != address {
		t.Fatalf("linked data export = %#x, %v, want %#x", linked, err, address)
	}
	if got, err := machine.readMemory(uint32(address), 4, 'r'); err != nil || string(got) != "\x01\x02\x03\x04" {
		t.Fatalf("data export = %x, %v", got, err)
	}
	if err := machine.writeMemory(uint32(address), []byte{4, 3, 2, 1}); err != nil {
		t.Fatalf("write data export: %v", err)
	}
}

func TestEmulatorImportHooksApplyToLaterModules(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	callback := starlark.NewBuiltin("late_api", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return starlark.MakeInt(7), nil
	})
	first := emulatorImport{
		module: "runtime.dll",
		name:   "LateAPI",
		iat:    0x2000,
		target: emulatorImportBase,
	}
	machine.imports[first.target] = first
	if _, err := machine.hookBuiltin(nil, nil, starlark.Tuple{callback}, []starlark.Tuple{
		{starlark.String("address"), starlark.MakeUint64(uint64(first.target))},
		{starlark.String("argc"), starlark.MakeInt(1)},
	}); err != nil {
		t.Fatal(err)
	}
	second := emulatorImport{
		module: "RUNTIME.DLL",
		name:   "lateapi",
		iat:    0x3000,
		target: emulatorImportBase + 16,
	}
	machine.imports[second.target] = second
	machine.applyHookRules(second.target, second)
	hook, ok := machine.hooks[second.target]
	if !ok {
		t.Fatal("late import did not inherit its symbolic hook")
	}
	if hook.argc != 1 || hook.convention != "stdcall" || hook.callback.Name() != callback.Name() {
		t.Fatalf("late import hook = %#v", hook)
	}
}

func TestEmulatorExecutionRunInstructionLimit(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xeb\xfe"), []starlark.Tuple{
		{starlark.String("instruction_limit"), starlark.MakeInt(100)},
	})
	executionValue, err := machine.spawnBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(0x1000)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	execution := executionValue.(*emulatorExecution)
	resultValue, err := execution.runBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("instruction_limit"), starlark.MakeInt(3)},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "budget" {
		t.Fatalf("execution reason = %q, want budget", got)
	}
	if got := recordUint32(t, result, "steps"); got != 3 {
		t.Fatalf("execution steps = %d, want 3", got)
	}
	if machine.instructionLimit != 100 {
		t.Fatalf("machine instruction limit = %d, want 100", machine.instructionLimit)
	}
}

func TestEmulatorCallDepthBudget(t *testing.T) {
	// call self
	machine := newRawX86TestMachine(t, starlark.Bytes("\xe8\xfb\xff\xff\xff"), []starlark.Tuple{
		{starlark.String("call_depth_limit"), starlark.MakeInt(3)},
	})
	resultValue, err := machine.run(&starlark.Thread{Name: "emulator-depth-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got, detail := recordString(t, result, "reason"), recordString(t, result, "detail"); got != "budget" || !strings.Contains(detail, "call depth limit reached at 0x") || !strings.Contains(detail, " calling 0x") {
		t.Fatalf("result = %s, %s", got, recordString(t, result, "detail"))
	}
}

func TestEmulatorConfigureTraceScopesInstructionCapture(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\x90\xc3"), nil)
	previousValue, err := machine.configureTraceBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("enabled"), starlark.True},
		{starlark.String("limit"), starlark.MakeInt(8)},
	})
	if err != nil {
		t.Fatal(err)
	}
	previous := previousValue.(*starlarkRecord)
	if previous.Values["enabled"] != starlark.False || previous.Values["limit"].String() != "4096" {
		t.Fatalf("previous trace configuration = %s", previous)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "scoped trace test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	trace := result.Values["trace"].(*starlark.List)
	if trace.Len() != 2 {
		t.Fatalf("trace length = %d, want 2", trace.Len())
	}
	if _, err := machine.configureTraceBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("enabled"), starlark.False},
		{starlark.String("limit"), starlark.MakeInt(4096)},
	}); err != nil {
		t.Fatal(err)
	}
	if machine.trace || len(machine.traceEntries) != 0 {
		t.Fatalf("trace remained enabled after restore")
	}
}

func TestEmulatorCallTracePreservesAcceleratedExecution(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xe8\x01\x00\x00\x00\xc3\xc3"), nil)
	if _, err := machine.configureCallTraceBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("enabled"), starlark.True},
		{starlark.String("limit"), starlark.MakeInt(8)},
		{starlark.String("start"), starlark.MakeInt(0x1000)},
		{starlark.String("size"), starlark.MakeInt(1)},
	}); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.run(&starlark.Thread{Name: "call trace test"})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	trace := result.Values["call_trace"].(*starlarkRecord)
	entries := trace.Values["entries"].(*starlark.List)
	if entries.Len() != 1 {
		t.Fatalf("call trace length = %d, want 1", entries.Len())
	}
	entry := entries.Index(0).(*starlarkRecord)
	if site, target := recordUint32(t, entry, "site"), recordUint32(t, entry, "target"); site != 0x1000 || target != 0x1006 {
		t.Fatalf("call edge = %#x -> %#x, want 0x1000 -> 0x1006", site, target)
	}
}

func TestCallFrameSummaryOrdersByFrequency(t *testing.T) {
	frames := []emulatorCallFrame{
		{site: 0x10, target: 0x20},
		{site: 0x30, target: 0x40},
		{site: 0x10, target: 0x20},
	}
	if got, want := callFrameSummary(frames, 2), "0x00000010->0x00000020:2,0x00000030->0x00000040:1"; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}

func TestEmulatorTypedMemoryAccess(t *testing.T) {
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	thread := &starlark.Thread{Name: "typed memory test"}
	addressValue, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("size"), starlark.MakeInt(16)},
		{starlark.String("name"), starlark.String("typed memory test")},
	})
	if err != nil {
		t.Fatal(err)
	}
	address, ok := addressValue.(starlark.Int).Uint64()
	if !ok {
		t.Fatalf("allocation address = %v", addressValue)
	}

	write, err := machine.Attr("write_i32le")
	if err != nil || write == nil {
		t.Fatalf("write_i32le = %v, %v", write, err)
	}
	if _, err := starlark.Call(thread, write.(starlark.Callable), starlark.Tuple{starlark.MakeUint64(address), starlark.MakeInt(-123)}, nil); err != nil {
		t.Fatal(err)
	}
	read, err := machine.Attr("read_i32le")
	if err != nil || read == nil {
		t.Fatalf("read_i32le = %v, %v", read, err)
	}
	value, err := starlark.Call(thread, read.(starlark.Callable), starlark.Tuple{starlark.MakeUint64(address)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value.String() != "-123" {
		t.Fatalf("typed memory value = %v, want -123", value)
	}
	if data, err := machine.readMemory(uint32(address), 4, 'r'); err != nil || !bytes.Equal(data, []byte{0x85, 0xff, 0xff, 0xff}) {
		t.Fatalf("raw memory = %x, %v", data, err)
	}
}

func BenchmarkEmulatorTypedMemoryU32LE(b *testing.B) {
	machine := newRawX86TestMachine(b, starlark.Bytes("\xc3"), nil)
	addressValue, err := machine.allocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("size"), starlark.MakeInt(16)},
		{starlark.String("name"), starlark.String("typed memory benchmark")},
	})
	if err != nil {
		b.Fatal(err)
	}
	address, _ := addressValue.(starlark.Int).Uint64()
	read, _ := machine.Attr("read_u32le")
	write, _ := machine.Attr("write_u32le")
	thread := &starlark.Thread{Name: "typed memory benchmark"}
	writeArgs := starlark.Tuple{starlark.MakeUint64(address), starlark.MakeUint64(0x12345678)}
	readArgs := starlark.Tuple{starlark.MakeUint64(address)}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := starlark.Call(thread, write.(starlark.Callable), writeArgs, nil); err != nil {
			b.Fatal(err)
		}
		if _, err := starlark.Call(thread, read.(starlark.Callable), readArgs, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func newRawX86TestMachine(t testing.TB, code starlark.Bytes, extra []starlark.Tuple) *emulatorX86 {
	t.Helper()
	kwargs := append([]starlark.Tuple{{starlark.String("code"), code}}, extra...)
	value, err := Builtin(nil, nil, nil, kwargs)
	if err != nil {
		t.Fatal(err)
	}
	return value.(*emulatorX86)
}

func recordString(t *testing.T, record *starlarkRecord, name string) string {
	t.Helper()
	value, ok := starlark.AsString(record.Values[name])
	if !ok {
		t.Fatalf("record.%s is not string", name)
	}
	return value
}

func recordUint32(t *testing.T, record *starlarkRecord, name string) uint32 {
	t.Helper()
	value, ok := record.Values[name].(starlark.Int)
	if !ok {
		t.Fatalf("record.%s is not int", name)
	}
	unsigned, ok := value.Uint64()
	if !ok || unsigned > 0xffffffff {
		t.Fatalf("record.%s does not fit uint32", name)
	}
	return uint32(unsigned)
}
