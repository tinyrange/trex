package uefi

import (
	"encoding/binary"
	"hash/crc32"

	"github.com/tinyrange/trex/emulator/cpu"
)

type runtimeRange struct{ physical, virtual, size uint64 }
type runtimeMap []runtimeRange

func (mapping runtimeMap) convert(p uint64) (uint64, bool) {
	for _, r := range mapping {
		if p >= r.physical && p-r.physical < r.size {
			return r.virtual + p - r.physical, true
		}
	}
	return 0, false
}

func (f *Firmware) convertRuntimePointer(p uint64) (uint64, bool) {
	return f.virtualMap.convert(p)
}

func (f *Firmware) setVirtualAddressMap(a [10]uint64) (uint64, error) {
	return f.machine.setRuntimeMap(f.physical, &f.virtualMap, [4]uint64(a[:4]))
}

// setRuntimeMap is shared by native continuation and caller-owned firmware.
// Descriptor reads use the current virtual mapping; tables are updated through
// physical memory, before the new virtual mapping becomes authoritative.
func (m *Machine) setRuntimeMap(physical cpu.Memory, current *runtimeMap, a [4]uint64) (uint64, error) {
	if !m.exited || *current != nil || a[1] < 40 || a[1] > 4096 || a[0] == 0 || a[0] > 1<<20 || a[0]%a[1] != 0 || uint32(a[2]) != 1 {
		return invalidParameter, nil
	}
	data := m.get(a[3], a[0])
	if m.err != nil {
		return invalidParameter, m.err
	}
	ranges, status := parseRuntimeMap(data, a[1])
	if status != 0 {
		return status, nil
	}
	status, err := relocateRuntimeTables(physical, m.ramBase+0x500, m.systemTable, ranges)
	if status == 0 && err == nil {
		*current = ranges
	}
	return status, err
}

func parseRuntimeMap(data []byte, stride uint64) (runtimeMap, uint64) {
	var ranges runtimeMap
	for offset := uint64(0); offset < uint64(len(data)); offset += stride {
		d := data[offset:]
		p, v, pages, attr := binary.LittleEndian.Uint64(d[8:]), binary.LittleEndian.Uint64(d[16:]), binary.LittleEndian.Uint64(d[24:]), binary.LittleEndian.Uint64(d[32:])
		if attr>>63 == 0 {
			continue
		}
		if pages == 0 || pages > ^uint64(0)/4096 || p&4095 != 0 || v&4095 != 0 {
			return nil, invalidParameter
		}
		size := pages * 4096
		if p > ^uint64(0)-size || v > ^uint64(0)-size {
			return nil, invalidParameter
		}
		for _, r := range ranges {
			if p < r.physical+r.size && r.physical < p+size || v < r.virtual+r.size && r.virtual < v+size {
				return nil, invalidParameter
			}
		}
		ranges = append(ranges, runtimeRange{p, v, size})
	}
	return ranges, 0
}

func relocateRuntimeTables(physical cpu.Memory, runtimeAddress, systemAddress uint64, mapping runtimeMap) (uint64, error) {
	if runtimeAddress > ^uint64(0)-136 || systemAddress > ^uint64(0)-120 {
		return invalidParameter, nil
	}
	start := min(runtimeAddress, systemAddress)
	end := max(runtimeAddress+136, systemAddress+120)
	// Both tables live in the firmware's initial 64 KiB. Commit one bounded
	// span so cpu.Memory's all-or-nothing write contract covers both tables,
	// including implementations that reject a write after CheckMemory.
	if end-start > 16*page || runtimeAddress < systemAddress+120 && systemAddress < runtimeAddress+136 {
		return invalidParameter, nil
	}
	data := make([]byte, int(end-start))
	if err := physical.ReadMemory(start, data, cpu.Read); err != nil {
		return invalidParameter, err
	}
	runtime := data[runtimeAddress-start : runtimeAddress-start+136]
	system := data[systemAddress-start : systemAddress-start+120]
	for offset := 24; offset < 136; offset += 8 {
		p := binary.LittleEndian.Uint64(runtime[offset:])
		v, ok := mapping.convert(p)
		if !ok {
			return notFound, nil
		}
		binary.LittleEndian.PutUint64(runtime[offset:], v)
	}
	for _, offset := range []int{24, 88, 112} {
		p := binary.LittleEndian.Uint64(system[offset:])
		if p == 0 {
			continue
		}
		v, ok := mapping.convert(p)
		if !ok {
			return notFound, nil
		}
		binary.LittleEndian.PutUint64(system[offset:], v)
	}
	for _, b := range [][]byte{runtime, system} {
		binary.LittleEndian.PutUint32(b[16:], 0)
		binary.LittleEndian.PutUint32(b[16:], crc32.ChecksumIEEE(b))
	}
	if err := physical.CheckMemory(start, len(data), cpu.Write); err != nil {
		return invalidParameter, err
	}
	if err := physical.WriteMemory(start, data); err != nil {
		return invalidParameter, err
	}
	return 0, nil
}
