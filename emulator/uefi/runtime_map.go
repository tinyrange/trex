package uefi

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"hash/crc32"
)

func (f *Firmware) convertRuntimePointer(p uint64) (uint64, bool) {
	for _, r := range f.virtualMap {
		if p >= r.physical && p-r.physical < r.size {
			return r.virtual + p - r.physical, true
		}
	}
	return 0, false
}
func (f *Firmware) setVirtualAddressMap(a [10]uint64) (uint64, error) {
	m := f.machine
	if !m.exited || f.virtualMap != nil || a[1] < 40 || a[1] > 4096 || a[0] == 0 || a[0] > 1<<20 || a[0]%a[1] != 0 || uint32(a[2]) != 1 {
		return invalidParameter, nil
	}
	data := m.get(a[3], a[0])
	if m.err != nil {
		return invalidParameter, m.err
	}
	var ranges []runtimeRange
	for offset := uint64(0); offset < a[0]; offset += a[1] {
		d := data[offset:]
		p, v, pages, attr := binary.LittleEndian.Uint64(d[8:]), binary.LittleEndian.Uint64(d[16:]), binary.LittleEndian.Uint64(d[24:]), binary.LittleEndian.Uint64(d[32:])
		if attr>>63 == 0 {
			continue
		}
		if pages == 0 || pages > ^uint64(0)/4096 || p&4095 != 0 || v&4095 != 0 {
			return invalidParameter, nil
		}
		size := pages * 4096
		if p > ^uint64(0)-size || v > ^uint64(0)-size {
			return invalidParameter, nil
		}
		for _, r := range ranges {
			if p < r.physical+r.size && r.physical < p+size || v < r.virtual+r.size && r.virtual < v+size {
				return invalidParameter, nil
			}
		}
		ranges = append(ranges, runtimeRange{p, v, size})
	}
	convert := func(p uint64) (uint64, bool) {
		for _, r := range ranges {
			if p >= r.physical && p-r.physical < r.size {
				return r.virtual + p - r.physical, true
			}
		}
		return 0, false
	}
	runtime := make([]byte, 136)
	system := make([]byte, 120)
	if err := f.physical.ReadMemory(m.ramBase+0x500, runtime, cpu.Read); err != nil {
		return invalidParameter, err
	}
	if err := f.physical.ReadMemory(m.systemTable, system, cpu.Read); err != nil {
		return invalidParameter, err
	}
	for offset := 24; offset < 136; offset += 8 {
		p := binary.LittleEndian.Uint64(runtime[offset:])
		v, ok := convert(p)
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
		v, ok := convert(p)
		if !ok {
			return notFound, nil
		}
		binary.LittleEndian.PutUint64(system[offset:], v)
	}
	for _, b := range [][]byte{runtime, system} {
		binary.LittleEndian.PutUint32(b[16:], 0)
		binary.LittleEndian.PutUint32(b[16:], crc32.ChecksumIEEE(b))
	}
	if err := f.physical.CheckMemory(m.ramBase+0x500, len(runtime), cpu.Write); err != nil {
		return invalidParameter, err
	}
	if err := f.physical.CheckMemory(m.systemTable, len(system), cpu.Write); err != nil {
		return invalidParameter, err
	}
	if err := f.physical.WriteMemory(m.ramBase+0x500, runtime); err != nil {
		return invalidParameter, err
	}
	if err := f.physical.WriteMemory(m.systemTable, system); err != nil {
		return invalidParameter, err
	}
	f.virtualMap = ranges
	return 0, nil
}
