package r3000

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/channel"
)

const (
	ip24ARCSTrap = 0xbfc10000
	ip24ARCSBase = 0x80001000
	ip24Public   = 0x80
	ip24Private  = 0x120
	ip24Desc     = 0x200
	ip24Tree     = 0x280
	ip24SysID    = 0x300
	ip24ArgBase  = 0x88000000 + ip24RAMSize - 0x8000
)

type ip24ARCS struct {
	parameterBlock [0x3000]byte
	arguments      [0x8000]byte
	env            map[string]uint32
}

func makeIP24ARCS(args, env []string) (ip24ARCS, uint32, uint32, error) {
	a := ip24ARCS{env: make(map[string]uint32, len(env))}
	block := a.parameterBlock[:]
	put := func(offset int, value uint32) { binary.BigEndian.PutUint32(block[offset:], value) }
	put(0, 0x53435241) // ARCS system parameter block signature.
	put(4, 0x3c)
	put(8, 0x0001000a)
	put(0x1c, 37*4)
	put(0x20, ip24ARCSBase+ip24Public)
	put(0x24, 32*4)
	put(0x28, ip24ARCSBase+ip24Private)
	for i := range 37 {
		put(ip24Public+i*4, ip24ARCSTrap+uint32(i)*4)
	}
	for i := range 32 {
		put(ip24Private+i*4, ip24ARCSTrap+uint32(128+i)*4)
	}
	descriptors := [...]struct{ kind, base, pages uint32 }{
		{0, ip24RAMBase >> 12, 1},
		{1, (ip24RAMBase >> 12) + 1, 3},
		{3, (ip24RAMBase >> 12) + 4, (ip24RAMSize >> 12) - 4},
	}
	for i, d := range descriptors {
		p := ip24Desc + i*12
		put(p, d.kind)
		put(p+4, d.base)
		put(p+8, d.pages)
	}
	name := "SGI-IP22"
	put(ip24Tree+4, 0) // ARC system/root type.
	put(ip24Tree+0x18, uint32(len(name)))
	put(ip24Tree+0x1c, ip24ARCSBase+ip24Tree+0x20)
	copy(block[ip24Tree+0x20:], name)
	copy(block[ip24SysID:], "SGI")
	copy(block[ip24SysID+8:], "IP22")

	buffer := a.arguments[:]
	cursor := 0
	vector := func(values []string, environment bool) (uint32, error) {
		if len(values) >= (len(buffer)-cursor)/4 {
			return 0, fmt.Errorf("ip24: ARCS argument vector exceeds guest memory")
		}
		head := cursor
		cursor += (len(values) + 1) * 4
		for i, value := range values {
			if len(value) >= len(buffer)-cursor || strings.ContainsRune(value, 0) {
				return 0, fmt.Errorf("ip24: invalid or oversized ARCS argument")
			}
			address := uint32(ip24ArgBase + cursor)
			binary.BigEndian.PutUint32(buffer[head+i*4:], address)
			copy(buffer[cursor:], value)
			cursor += len(value) + 1
			if environment {
				key, _, ok := strings.Cut(value, "=")
				if !ok || key == "" {
					return 0, fmt.Errorf("ip24: invalid ARCS environment assignment %q", value)
				}
				a.env[key] = address + uint32(len(key)) + 1
			}
		}
		cursor = (cursor + 3) &^ 3
		return uint32(ip24ArgBase + head), nil
	}
	argv, err := vector(args, false)
	if err != nil {
		return a, 0, 0, err
	}
	envp, err := vector(env, true)
	return a, argv, envp, err
}

func (m *IP24) arcsRAM(address, size uint32) []byte {
	if address < 0x80000000 || address >= 0xc0000000 {
		return nil
	}
	return m.memory(uint64(address&0x1fffffff), uint64(size))
}

func (m *IP24) arcsString(address uint32) (string, bool) {
	data := m.arcsRAM(address, 1)
	if data == nil {
		return "", false
	}
	end := min(address&^0xfff+0x1000-address, uint32(4096))
	data = m.arcsRAM(address, end)
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return string(data[:i]), true
	}
	// A string can straddle two adjacent guest RAM pages.
	for i := end; i < 4096; i++ {
		last := m.arcsRAM(address+i, 1)
		if last == nil {
			break
		}
		if last[0] == 0 {
			return string(m.arcsRAM(address, i)), true
		}
	}
	return "", false
}

func (m *IP24) arcsCall(service uint32) (bool, error) {
	a0, a1, a2, a3 := uint32(m.cpu.gpr[4]), uint32(m.cpu.gpr[5]), uint32(m.cpu.gpr[6]), uint32(m.cpu.gpr[7])
	result := uint32(0)
	switch service {
	case 9, 11: // GetPeer, GetParent: the root has neither.
	case 10: // GetChild: a null component requests the root.
		if a0 == 0 {
			result = ip24ARCSBase + ip24Tree
		}
	case 17: // GetSystemId.
		result = ip24ARCSBase + ip24SysID
	case 18: // GetMemoryDescriptor.
		ptr := uint32(ip24ARCSBase + ip24Desc)
		switch a0 {
		case 0:
			result = ptr
		case ptr, ptr + 12:
			result = a0 + 12
		}
	case 21: // GetRelativeTime.
		result = uint32(m.cycles / ip24Clock)
	case 25, 27: // Read, Write.
		if service == 25 && a0 != 0 || service == 27 && a0 != 1 {
			result = 6 // EBADF.
			break
		}
		buffer, done := m.arcsRAM(a1, a2), m.arcsRAM(a3, 4)
		if buffer == nil || done == nil || a2 > 1<<20 {
			return false, fmt.Errorf("ip24 ARCS: invalid console buffer at %#x (%d bytes), count pointer %#x", a1, a2, a3)
		}
		stream := m.scc.ports[ip24SerialPort].stream
		var n int
		var err error
		if service == 25 {
			n, err = stream.ReadAvailable(buffer)
		} else {
			n, err = stream.WriteAvailable(buffer)
		}
		if err != nil {
			if err != channel.ErrWouldBlock {
				return false, err
			}
			result = 2 // EAGAIN.
		}
		binary.BigEndian.PutUint32(done, uint32(n))
	case 26: // GetReadStatus.
		if a0 != 0 {
			result = 6
		} else {
			result = 2
		}
	case 30: // GetEnvironmentVariable.
		key, ok := m.arcsString(a0)
		if !ok {
			return false, fmt.Errorf("ip24 ARCS: invalid environment name at %#x", a0)
		}
		result = m.arcs.env[key]
	case 34: // FlushAllCaches: coherent memory.
	case 129: // SGI private GetNvramTable.
		data := m.arcsRAM(a0, a1)
		if data == nil || a1 == 0 || a1 > 0x10000 {
			result = ^uint32(0)
		} else {
			clear(data)
		}
	default:
		return false, nil
	}
	m.cpu.gpr[2] = mipsWord(result)
	m.cpu.pc, m.cpu.next, m.cpu.delaySlot = m.cpu.gpr[31], m.cpu.gpr[31]+4, false
	return true, nil
}
