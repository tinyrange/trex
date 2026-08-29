package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

const (
	minidumpThreadList = 3
	minidumpModuleList = 4
	minidumpSystemInfo = 7
	minidumpMaxEntries = 1 << 20
	minidumpMaxStack   = 16 << 20
)

type minidumpLocation struct {
	size uint32
	rva  uint32
}

type minidumpFrame struct {
	address      uint64
	framePointer uint64
	stackAddress uint64
}

func minidumpBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("minidump", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	return parseMinidump(file)
}

func parseMinidump(file starfile.File) (starlark.Value, error) {
	header, err := minidumpRead(file, 0, 32)
	if err != nil {
		return nil, fmt.Errorf("minidump: read header: %w", err)
	}
	if string(header[:4]) != "MDMP" {
		return nil, fmt.Errorf("minidump: invalid signature")
	}
	count := uint64(binary.LittleEndian.Uint32(header[8:12]))
	directoryRVA := uint64(binary.LittleEndian.Uint32(header[12:16]))
	if count > minidumpMaxEntries || count*12 > uint64(file.Size()) {
		return nil, fmt.Errorf("minidump: invalid stream count %d", count)
	}
	directory, err := minidumpRead(file, directoryRVA, count*12)
	if err != nil {
		return nil, fmt.Errorf("minidump: read stream directory: %w", err)
	}
	streams := make(map[uint32]minidumpLocation)
	for index := uint64(0); index < count; index++ {
		offset := index * 12
		typ := binary.LittleEndian.Uint32(directory[offset : offset+4])
		streams[typ] = minidumpLocation{
			size: binary.LittleEndian.Uint32(directory[offset+4 : offset+8]),
			rva:  binary.LittleEndian.Uint32(directory[offset+8 : offset+12]),
		}
	}
	architecture := uint16(0xffff)
	if location, ok := streams[minidumpSystemInfo]; ok && location.size >= 2 {
		data, err := minidumpRead(file, uint64(location.rva), 2)
		if err != nil {
			return nil, fmt.Errorf("minidump: read system information: %w", err)
		}
		architecture = binary.LittleEndian.Uint16(data)
	}
	modules, err := minidumpModules(file, streams[minidumpModuleList])
	if err != nil {
		return nil, err
	}
	threads, err := minidumpThreads(file, streams[minidumpThreadList], architecture)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{
		"architecture": starlark.String(minidumpArchitectureName(architecture)),
		"flags":        starlark.MakeUint64(binary.LittleEndian.Uint64(header[24:32])),
		"modules":      starlark.NewList(modules),
		"threads":      starlark.NewList(threads),
		"time":         starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(header[20:24]))),
	}), nil
}

func minidumpModules(file starfile.File, location minidumpLocation) ([]starlark.Value, error) {
	if location.size == 0 {
		return nil, nil
	}
	header, err := minidumpRead(file, uint64(location.rva), 4)
	if err != nil {
		return nil, fmt.Errorf("minidump: read module count: %w", err)
	}
	count := uint64(binary.LittleEndian.Uint32(header))
	if count > minidumpMaxEntries || 4+count*108 > uint64(location.size) {
		return nil, fmt.Errorf("minidump: invalid module count %d", count)
	}
	data, err := minidumpRead(file, uint64(location.rva)+4, count*108)
	if err != nil {
		return nil, fmt.Errorf("minidump: read modules: %w", err)
	}
	modules := make([]starlark.Value, 0, count)
	for index := uint64(0); index < count; index++ {
		raw := data[index*108 : (index+1)*108]
		name, err := minidumpString(file, binary.LittleEndian.Uint32(raw[20:24]))
		if err != nil {
			return nil, fmt.Errorf("minidump: module %d name: %w", index, err)
		}
		modules = append(modules, starfile.NewRecord(starlark.StringDict{
			"base":      starlark.MakeUint64(binary.LittleEndian.Uint64(raw[0:8])),
			"checksum":  starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(raw[12:16]))),
			"name":      starlark.String(name),
			"size":      starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(raw[8:12]))),
			"timestamp": starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(raw[16:20]))),
		}))
	}
	return modules, nil
}

func minidumpThreads(file starfile.File, location minidumpLocation, architecture uint16) ([]starlark.Value, error) {
	if location.size == 0 {
		return nil, nil
	}
	header, err := minidumpRead(file, uint64(location.rva), 4)
	if err != nil {
		return nil, fmt.Errorf("minidump: read thread count: %w", err)
	}
	count := uint64(binary.LittleEndian.Uint32(header))
	if count > minidumpMaxEntries || 4+count*48 > uint64(location.size) {
		return nil, fmt.Errorf("minidump: invalid thread count %d", count)
	}
	data, err := minidumpRead(file, uint64(location.rva)+4, count*48)
	if err != nil {
		return nil, fmt.Errorf("minidump: read threads: %w", err)
	}
	threads := make([]starlark.Value, 0, count)
	for index := uint64(0); index < count; index++ {
		raw := data[index*48 : (index+1)*48]
		stackStart := binary.LittleEndian.Uint64(raw[24:32])
		stackLocation := minidumpLocation{size: binary.LittleEndian.Uint32(raw[32:36]), rva: binary.LittleEndian.Uint32(raw[36:40])}
		if stackLocation.size > minidumpMaxStack {
			return nil, fmt.Errorf("minidump: thread %d stack exceeds %d bytes", index, minidumpMaxStack)
		}
		stack, err := minidumpRead(file, uint64(stackLocation.rva), uint64(stackLocation.size))
		if err != nil {
			return nil, fmt.Errorf("minidump: thread %d stack: %w", index, err)
		}
		contextLocation := minidumpLocation{size: binary.LittleEndian.Uint32(raw[40:44]), rva: binary.LittleEndian.Uint32(raw[44:48])}
		context, err := minidumpRead(file, uint64(contextLocation.rva), uint64(contextLocation.size))
		if err != nil {
			return nil, fmt.Errorf("minidump: thread %d context: %w", index, err)
		}
		pc, sp, fp := minidumpRegisters(context, architecture)
		frames := minidumpFrames(stack, stackStart, pc, sp, fp, architecture)
		frameValues := make([]starlark.Value, len(frames))
		for frameIndex, frame := range frames {
			frameValues[frameIndex] = starfile.NewRecord(starlark.StringDict{
				"address":       starlark.MakeUint64(frame.address),
				"frame_pointer": starlark.MakeUint64(frame.framePointer),
				"stack_address": starlark.MakeUint64(frame.stackAddress),
			})
		}
		threads = append(threads, starfile.NewRecord(starlark.StringDict{
			"frame_pointer":       starlark.MakeUint64(fp),
			"frames":              starlark.NewList(frameValues),
			"id":                  starlark.MakeUint64(uint64(binary.LittleEndian.Uint32(raw[0:4]))),
			"instruction_pointer": starlark.MakeUint64(pc),
			"stack":               starlark.Bytes(stack),
			"stack_pointer":       starlark.MakeUint64(sp),
			"stack_start":         starlark.MakeUint64(stackStart),
			"teb":                 starlark.MakeUint64(binary.LittleEndian.Uint64(raw[16:24])),
		}))
	}
	return threads, nil
}

func minidumpFrames(stack []byte, stackStart, pc, sp, fp uint64, architecture uint16) []minidumpFrame {
	pointerSize := uint64(0)
	switch architecture {
	case 0: // PROCESSOR_ARCHITECTURE_INTEL
		pointerSize = 4
	case 9: // PROCESSOR_ARCHITECTURE_AMD64
		pointerSize = 8
	default:
		return nil
	}
	frames := make([]minidumpFrame, 0, 32)
	if pc != 0 {
		frames = append(frames, minidumpFrame{address: pc, framePointer: fp, stackAddress: sp})
	}
	if uint64(len(stack)) < pointerSize*2 {
		return frames
	}
	stackEnd := stackStart + uint64(len(stack))
	if stackEnd < stackStart {
		return frames
	}
	for len(frames) < 1024 && fp >= stackStart && fp <= stackEnd-pointerSize*2 {
		offset := fp - stackStart
		var callerFP, returnAddress uint64
		if pointerSize == 4 {
			callerFP = uint64(binary.LittleEndian.Uint32(stack[offset : offset+4]))
			returnAddress = uint64(binary.LittleEndian.Uint32(stack[offset+4 : offset+8]))
		} else {
			callerFP = binary.LittleEndian.Uint64(stack[offset : offset+8])
			returnAddress = binary.LittleEndian.Uint64(stack[offset+8 : offset+16])
		}
		if returnAddress == 0 {
			break
		}
		frames = append(frames, minidumpFrame{
			address:      returnAddress,
			framePointer: callerFP,
			stackAddress: fp + pointerSize,
		})
		if callerFP <= fp || callerFP < stackStart || callerFP > stackEnd-pointerSize*2 || callerFP%pointerSize != 0 {
			break
		}
		fp = callerFP
	}
	return frames
}

func minidumpRegisters(context []byte, architecture uint16) (pc, sp, fp uint64) {
	switch architecture {
	case 0: // PROCESSOR_ARCHITECTURE_INTEL
		if len(context) >= 200 {
			return uint64(binary.LittleEndian.Uint32(context[184:188])), uint64(binary.LittleEndian.Uint32(context[196:200])), uint64(binary.LittleEndian.Uint32(context[180:184]))
		}
	case 9: // PROCESSOR_ARCHITECTURE_AMD64
		if len(context) >= 256 {
			return binary.LittleEndian.Uint64(context[248:256]), binary.LittleEndian.Uint64(context[152:160]), binary.LittleEndian.Uint64(context[160:168])
		}
	}
	return 0, 0, 0
}

func minidumpString(file starfile.File, rva uint32) (string, error) {
	header, err := minidumpRead(file, uint64(rva), 4)
	if err != nil {
		return "", err
	}
	length := uint64(binary.LittleEndian.Uint32(header))
	if length > 1<<20 || length%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16 string length %d", length)
	}
	data, err := minidumpRead(file, uint64(rva)+4, length)
	if err != nil {
		return "", err
	}
	units := make([]uint16, len(data)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(data[index*2 : index*2+2])
	}
	return string(utf16.Decode(units)), nil
}

func minidumpRead(file starfile.File, offset, size uint64) ([]byte, error) {
	if offset > uint64(file.Size()) || size > uint64(file.Size())-offset || size > uint64(maxInt()) {
		return nil, fmt.Errorf("range %#x+%#x is outside the dump", offset, size)
	}
	data := make([]byte, int(size))
	if _, err := readFullAt(file, data, int64(offset)); err != nil {
		return nil, err
	}
	return data, nil
}

func minidumpArchitectureName(value uint16) string {
	switch value {
	case 0:
		return "i386"
	case 5:
		return "arm"
	case 9:
		return "amd64"
	case 12:
		return "arm64"
	default:
		return fmt.Sprintf("unknown-%d", value)
	}
}

func maxInt() int {
	return int(^uint(0) >> 1)
}
