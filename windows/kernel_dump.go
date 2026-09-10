package windows

import (
	"encoding/binary"
	"fmt"
	"io"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// kernelDumpHeaderBuiltin reads the fixed AMD64 PAGE/DU64 header. The
// RequiredDumpSpace extent is useful for recovering a dump still in a pagefile;
// it is not proof that the body is complete or that its memory maps are valid.
func kernelDumpHeaderBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("kernel_dump_header", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	if file.Size() < 8192 {
		return nil, fmt.Errorf("kernel_dump_header: truncated PAGE/DU64 header")
	}
	header := make([]byte, 8192)
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, 8192), header); err != nil {
		return nil, fmt.Errorf("kernel_dump_header: %w", err)
	}
	if string(header[:8]) != "PAGEDU64" {
		return nil, fmt.Errorf("kernel_dump_header: expected PAGE/DU64 signature")
	}
	u32 := func(off int) starlark.Value { return starlark.MakeUint(uint(binary.LittleEndian.Uint32(header[off:]))) }
	u64 := func(off int) starlark.Value { return starlark.MakeUint64(binary.LittleEndian.Uint64(header[off:])) }
	parameters := make([]starlark.Value, 4)
	for i := range parameters {
		parameters[i] = u64(0x40 + i*8)
	}
	size := binary.LittleEndian.Uint64(header[0xfa0:])
	return starfile.NewRecord(starlark.StringDict{
		"major_version": u32(8), "minor_version": u32(12),
		"directory_table_base": u64(0x10), "pfn_database": u64(0x18),
		"loaded_module_list": u64(0x20), "active_process_head": u64(0x28),
		"machine": u32(0x30), "processor_count": u32(0x34),
		"bugcheck_code": u32(0x38), "bugcheck_parameters": starlark.NewList(parameters),
		"debugger_data_block": u64(0x80), "dump_type": u32(0xf98),
		"required_size": u64(0xfa0), "writer_status": u32(0x1048),
		"extent_available": starlark.Bool(size >= 8192 && size <= uint64(file.Size())),
	}), nil
}
