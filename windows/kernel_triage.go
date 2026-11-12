package windows

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// kernelTriageDumpBuiltin reads AMD64 PAGE/DU64 type-4 dumps. Offsets in the
// triage directory are file offsets, not virtual addresses. Secondary streams
// may follow SizeOfDump; they are not silently interpreted as captured RAM.
func kernelTriageDumpBuiltin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("kernel_triage_dump", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	header, err := kernelDumpHeaderBuiltin(thread, builtin, starlark.Tuple{file}, nil)
	if err != nil {
		return nil, err
	}
	fail := func(message string) (starlark.Value, error) {
		return nil, fmt.Errorf("kernel_triage_dump: %s", message)
	}
	if file.Size() < 8320 {
		return fail("truncated triage directory")
	}
	prefix, err := minidumpRead(file, 0, 8320)
	if err != nil {
		return nil, err
	}
	u32 := func(off int) uint64 { return uint64(binary.LittleEndian.Uint32(prefix[off:])) }
	u64 := func(off int) uint64 { return binary.LittleEndian.Uint64(prefix[off:]) }
	if u32(0x30) != 0x8664 || u32(0xf98) != 4 {
		return fail("expected AMD64 type-4 triage dump")
	}
	extent := u64(0xfa0)
	size := u32(8192 + 4)
	if size < 8320 || size > 64<<20 || extent < size || extent > uint64(file.Size()) {
		return fail("invalid or unavailable dump extent")
	}
	read := func(off, n uint64) ([]byte, error) {
		if off > size || n > size-off {
			return nil, fmt.Errorf("kernel_triage_dump: range %#x+%#x outside triage extent %#x", off, n, size)
		}
		return minidumpRead(file, off, n)
	}
	marker, err := read(u32(8192+8), 4)
	if err != nil {
		return nil, err
	}
	if string(marker) != "TRGD" {
		return fail("missing completed triage marker")
	}
	context, err := read(u32(8192+12), 1232)
	if err != nil {
		return nil, err
	}
	pc, sp, fp := minidumpRegisters(context, 9)
	stackOff, stackSize, stackBase := u32(8192+40), u32(8192+44), u64(8192+72)
	if stackSize > 1<<20 || stackBase+stackSize < stackBase {
		return fail("invalid stack range")
	}
	// Validate ranges without materializing memory payloads.
	slice := func(off, n uint64) (starfile.File, error) {
		if off > size || n > size-off {
			return nil, fmt.Errorf("kernel_triage_dump: file range outside triage extent")
		}
		return starfile.NewReader("kernel triage range", io.NewSectionReader(file, int64(off), int64(n))), nil
	}
	stack, err := slice(stackOff, stackSize)
	if err != nil {
		return nil, err
	}
	regions := []starlark.Value{}
	if stackSize != 0 {
		regions = append(regions, starfile.NewRecord(starlark.StringDict{"address": starlark.MakeUint64(stackBase), "file": stack}))
	}
	blocksOff, blocksCount := u32(8192+120), u32(8192+124)
	if blocksCount > 65536 || blocksOff > size || blocksCount > (size-blocksOff)/16 {
		return fail("invalid data-block table")
	}
	blocks, err := read(blocksOff, blocksCount*16)
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < blocksCount; i++ {
		b := blocks[i*16:]
		addr := binary.LittleEndian.Uint64(b)
		off, n := uint64(binary.LittleEndian.Uint32(b[8:])), uint64(binary.LittleEndian.Uint32(b[12:]))
		if addr+n < addr {
			return fail("overflowing virtual data-block range")
		}
		payload, e := slice(off, n)
		if e != nil {
			return nil, e
		}
		regions = append(regions, starfile.NewRecord(starlark.StringDict{"address": starlark.MakeUint64(addr), "file": payload}))
	}
	driversOff, driversCount := u32(8192+48), u32(8192+52)
	poolOff, poolSize := u32(8192+56), u32(8192+60)
	if driversCount > 4096 || driversOff > size || driversCount > (size-driversOff)/144 {
		return fail("invalid driver table")
	}
	if poolOff > size || poolSize > size-poolOff {
		return fail("invalid driver string pool")
	}
	drivers, err := read(driversOff, driversCount*144)
	if err != nil {
		return nil, err
	}
	modules := make([]starlark.Value, 0, driversCount)
	for i := uint64(0); i < driversCount; i++ {
		d := drivers[i*144:]
		nameOff := uint64(binary.LittleEndian.Uint32(d))
		if nameOff < poolOff || nameOff > poolOff+poolSize || poolOff+poolSize-nameOff < 4 {
			return fail("driver name outside string pool")
		}
		length, err := read(nameOff, 4)
		if err != nil {
			return nil, err
		}
		units := uint64(binary.LittleEndian.Uint32(length))
		if units > 32767 || (units+1)*2 > poolOff+poolSize-nameOff-4 {
			return fail("invalid driver name length")
		}
		raw, err := read(nameOff+4, (units+1)*2)
		if err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint16(raw[units*2:]) != 0 {
			return fail("unterminated driver name")
		}
		words := make([]uint16, units)
		for j := range words {
			words[j] = binary.LittleEndian.Uint16(raw[j*2:])
		}
		base, imageSize := binary.LittleEndian.Uint64(d[56:]), uint64(binary.LittleEndian.Uint32(d[72:]))
		if base+imageSize < base {
			return fail("overflowing driver image range")
		}
		modules = append(modules, starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(string(utf16.Decode(words))), "base": starlark.MakeUint64(base), "size": starlark.MakeUint64(imageSize),
			"checksum": starlark.MakeUint(uint(binary.LittleEndian.Uint32(d[128:]))), "timestamp": starlark.MakeUint(uint(binary.LittleEndian.Uint32(d[136:]))),
		}))
	}
	return starfile.NewRecord(starlark.StringDict{
		"header": header, "context": starlark.Bytes(context), "pc": starlark.MakeUint64(pc), "sp": starlark.MakeUint64(sp), "fp": starlark.MakeUint64(fp),
		"stack": stack, "stack_address": starlark.MakeUint64(stackBase), "regions": starlark.NewList(regions), "modules": starlark.NewList(modules),
	}), nil
}
