package power

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/scsi"
)

type srpDescriptor struct {
	address uint64
	size    uint32
}

// rpaLUN normalizes a single-level peripheral, flat, or PAPR logical-unit
// address to target/channel/LUN. Hierarchical and extended forms are explicit
// unsupported encodings, not aliases of the assigned device.
func rpaLUN(wire uint64) (uint64, bool) {
	if wire&0x0000ffffffffffff != 0 {
		return 0, false
	}
	w := uint16(wire >> 48)
	switch w >> 14 {
	case 0:
		if w>>8 != 0 {
			return 0, false
		}
		return uint64(w & 255), true
	case 1:
		return uint64(w & 0x3fff), true
	case 2:
		return uint64(w>>8&63)<<32 | uint64(w>>5&7)<<24 | uint64(w&31), true
	default:
		return 0, false
	}
}

// srpDescriptors decodes SRP16a direct and indirect descriptors. RPA selects
// its registered DMA window rather than an InfiniBand remote-memory key.
// Direct-descriptor count fields are unused (the native client supplies0).
func (m *Machine) srpDescriptors(q *commandResponseQueue, iu []byte, at int, format, count byte) ([]srpDescriptor, int, uint32, error) {
	decode := func(b []byte) srpDescriptor {
		return srpDescriptor{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint32(b[12:16])}
	}
	if format == 0 {
		return nil, at, 0, nil
	}
	if at > len(iu)-16 {
		return nil, at, 0, fmt.Errorf("power: truncated SRP descriptor")
	}
	if format == 1 {
		d := decode(iu[at:])
		if d.size > 1<<20 {
			return nil, at, 0, fmt.Errorf("power: SRP transfer exceeds1MiB")
		}
		return []srpDescriptor{d}, at + 16, d.size, nil
	}
	if format != 2 || at > len(iu)-20 {
		return nil, at, 0, fmt.Errorf("power: unsupported/truncated SRP descriptor format%x", format)
	}
	table := decode(iu[at:])
	total := binary.BigEndian.Uint32(iu[at+16 : at+20])
	inline := int(count) * 16
	if table.size%16 != 0 || table.size > 1<<20 || total > 1<<20 || inline > len(iu)-at-20 {
		return nil, at, 0, fmt.Errorf("power: invalid SRP indirect geometry")
	}
	var data []byte
	if uint32(inline) >= table.size {
		data = iu[at+20 : at+20+int(table.size)]
	} else {
		data = make([]byte, table.size)
		if err := m.ReadDMA(q.table, table.address, data, 0); err != nil {
			return nil, at, 0, err
		}
	}
	var desc []srpDescriptor
	var sum uint64
	for i := 0; i < len(data); i += 16 {
		d := decode(data[i:])
		sum += uint64(d.size)
		if sum > 1<<20 {
			return nil, at, 0, fmt.Errorf("power: indirect SRP transfer exceeds1MiB")
		}
		desc = append(desc, d)
	}
	if sum != uint64(total) {
		return nil, at, 0, fmt.Errorf("power: inconsistent SRP indirect data length")
	}
	return desc, at + 20 + inline, total, nil
}

func (m *Machine) rpaSCSI(q *commandResponseQueue, p *rpaEndpoint, iu []byte) ([]rpaWrite, []byte, *scsi.DiskCommand, error) {
	if !p.loggedIn || len(iu) < 48 {
		return nil, nil, nil, fmt.Errorf("power: SCSI command before login or truncated")
	}
	at := 48 + int(iu[31]&^3)
	if at > len(iu) {
		return nil, nil, nil, fmt.Errorf("power: truncated additional CDB")
	}
	out, at, outTotal, err := m.srpDescriptors(q, iu, at, iu[5]>>4, iu[6])
	if err != nil {
		return nil, nil, nil, err
	}
	in, _, inTotal, err := m.srpDescriptors(q, iu, at, iu[5]&15, iu[7])
	if err != nil {
		return nil, nil, nil, err
	}
	for _, d := range out {
		if _, err := m.dmaTable(q.table, d.address, int(d.size), 0, false); err != nil {
			return nil, nil, nil, err
		}
	}
	lun := binary.BigEndian.Uint64(iu[20:28])
	address, valid := rpaLUN(lun)
	assigned, _ := rpaLUN(p.lun)
	cdb := iu[32:48]
	var result scsi.Result
	var command *scsi.DiskCommand
	if cdb[0] == 0xa0 && (lun == 0 || lun == 0x0c10100000000000) {
		if cdb[2] > 2 {
			result = scsi.CheckCondition(5, 0x24, 0)
		} else {
			data := make([]byte, 16)
			binary.BigEndian.PutUint32(data, 8)
			binary.BigEndian.PutUint64(data[8:], p.lun)
			n := uint64(binary.BigEndian.Uint32(cdb[6:10]))
			result.Data = data[:min(n, uint64(len(data)))]
		}
	} else if !valid || address != assigned {
		if cdb[0] == 0x12 && cdb[1]&1 == 0 {
			data := make([]byte, 36)
			data[0] = 0x7f
			data[3], data[4] = 2, 31
			result.Data = data[:min(int(binary.BigEndian.Uint16(cdb[3:5])), len(data))]
		} else {
			result = scsi.CheckCondition(5, 0x25, 0)
		}
	} else {
		if p.isDisk {
			data := make([]byte, outTotal)
			at := 0
			for _, d := range out {
				if err := m.ReadDMA(q.table, d.address, data[at:at+int(d.size)], 0); err != nil {
					return nil, nil, nil, err
				}
				at += int(d.size)
			}
			command, err = p.disk.Prepare(0, cdb, data)
			if err == nil {
				result = command.Result()
			}
		} else {
			result, err = p.optical.Execute(cdb)
		}
		if err != nil {
			return nil, nil, nil, err
		}
	}
	var writes []rpaWrite
	remaining := result.Data
	for _, d := range in {
		n := min(len(remaining), int(d.size))
		if n > 0 {
			writes = append(writes, rpaWrite{d.address, remaining[:n]})
			remaining = remaining[n:]
		}
	}
	copied := len(result.Data) - len(remaining)
	reply := make([]byte, 36+len(result.Sense))
	reply[0] = 0xc1
	reply[19] = result.Status
	binary.BigEndian.PutUint32(reply[4:8], 1)
	copy(reply[8:16], iu[8:16])
	if result.Status == 0 {
		reply[1] = (iu[1] & 2) >> 1
	} else {
		reply[1] = (iu[1] & 4) >> 2
	}
	if uint32(copied) < inTotal {
		reply[18] |= 0x20
		binary.BigEndian.PutUint32(reply[24:28], inTotal-uint32(copied))
	} else if len(remaining) > 0 {
		reply[18] |= 0x10
		binary.BigEndian.PutUint32(reply[24:28], uint32(len(remaining)))
	}
	if outTotal > 0 && (command == nil || result.Status != 0) {
		reply[18] |= 8
		binary.BigEndian.PutUint32(reply[20:24], outTotal)
	}
	if len(result.Sense) > 0 {
		reply[18] |= 2
		binary.BigEndian.PutUint32(reply[28:32], uint32(len(result.Sense)))
		copy(reply[36:], result.Sense)
	}
	return writes, reply, command, nil
}
