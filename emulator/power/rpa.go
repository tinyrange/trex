package power

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/scsi"
)

// rpaEndpoint is an RPA SCSI RDMA Protocol peer. Its media is a portable
// block device; only protocol state is copied when a machine is checkpointed.
type rpaEndpoint struct {
	media           block.Device
	optical         scsi.Optical
	disk            scsi.Disk
	isDisk          bool
	lun             uint64
	unsupported     map[uint64]bool // explicitly unimplemented vendor MAD format/type pairs
	ready, loggedIn bool
}

// AttachCRQDisk assigns a direct-access logical unit backed by real abstract
// storage. Checkpoints copy protocol state only; callers snapshot disk bytes
// separately when creating independent executions.
func (m *Machine) AttachCRQDisk(unit uint64, media block.Device, config RPAOpticalConfig, identity scsi.DiskIdentity) error {
	q := m.crqs[unit]
	if q == nil || q.rpa != nil {
		return fmt.Errorf("power: CRQ%x missing or already assigned", unit)
	}
	if _, ok := rpaLUN(config.LUN); !ok {
		return fmt.Errorf("power: invalid disk LUN%016x", config.LUN)
	}
	disk, err := scsi.NewDisk(media, identity)
	if err != nil {
		return err
	}
	p := &rpaEndpoint{media: media, disk: disk, isDisk: true, lun: config.LUN, unsupported: make(map[uint64]bool)}
	for _, key := range config.UnsupportedMADs {
		p.unsupported[key] = true
	}
	q.rpa = p
	return nil
}

// RPAOpticalConfig assigns a wire-format LUN and optional vendor negotiation.
type RPAOpticalConfig struct {
	LUN             uint64
	UnsupportedMADs []uint64
}

// AttachCRQOptical assigns a read-only optical endpoint to a registered queue.
// UnsupportedMADs contains explicitly negotiated vendor MADs (format<<32 | type);
// unrelated unknown messages remain errors instead of receiving success replies.
func (m *Machine) AttachCRQOptical(unit uint64, media block.Device, config RPAOpticalConfig) error {
	q := m.crqs[unit]
	if q == nil {
		return fmt.Errorf("power: unknown CRQ %x", unit)
	}
	if q.rpa != nil {
		return fmt.Errorf("power: CRQ %x already has an endpoint", unit)
	}
	if _, ok := rpaLUN(config.LUN); !ok {
		return fmt.Errorf("power: unsupported optical LUN encoding %016x", config.LUN)
	}
	optical, err := scsi.NewOptical(media)
	if err != nil {
		return err
	}
	p := &rpaEndpoint{media: media, optical: optical, lun: config.LUN, unsupported: make(map[uint64]bool)}
	for _, key := range config.UnsupportedMADs {
		p.unsupported[key] = true
	}
	q.rpa = p
	return nil
}

// ChangeCRQOpticalMedia changes the disc without resetting the CRQ, SRP
// session, reservation or drive locks. The target reports unit attention.
func (m *Machine) ChangeCRQOpticalMedia(unit uint64, media block.Device) error {
	q := m.crqs[unit]
	if q == nil || q.rpa == nil || q.rpa.isDisk {
		return fmt.Errorf("power: CRQ%x has no optical endpoint", unit)
	}
	if err := q.rpa.optical.ChangeMedia(media); err != nil {
		return err
	}
	q.rpa.media = media
	return nil
}

type rpaWrite struct {
	address uint64
	data    []byte
}

// commitCRQ preflights the reply slot and every DMA destination before any
// bytes or protocol state change. The queue publication is the last write.
func (m *Machine) commitCRQ(q *commandResponseQueue, entry []byte, writes []rpaWrite) error {
	if err := m.preflightCRQ(q, entry, writes); err != nil {
		return err
	}
	writes = append(writes, rpaWrite{q.address + q.producer, entry})
	for _, w := range writes {
		if err := m.WriteDMA(q.table, w.address, w.data, 0); err != nil {
			return err
		}
	}
	q.producer = (q.producer + 16) % q.size
	return nil
}

func (m *Machine) preflightCRQ(q *commandResponseQueue, entry []byte, writes []rpaWrite) error {
	address := q.address + q.producer
	var old [16]byte
	if err := m.ReadDMA(q.table, address, old[:], 0); err != nil {
		return err
	}
	if old[0]&0x80 != 0 {
		return fmt.Errorf("power: CRQ full at %x", q.producer)
	}
	writes = append(writes, rpaWrite{address, entry})
	for _, w := range writes {
		if _, err := m.dmaTable(q.table, w.address, len(w.data), 0, true); err != nil {
			return err
		}
	}
	return nil
}

// ProcessCRQ handles a request against an assigned RPA endpoint. It reports
// whether it published a reply. Device interrupt notification remains backend
// policy; unknown requests return an error without modifying DMA memory.
func (m *Machine) ProcessCRQ(unit, high, low uint64) (bool, error) {
	q := m.crqs[unit]
	if q == nil || q.rpa == nil {
		return false, fmt.Errorf("power: CRQ %x has no storage endpoint", unit)
	}
	p := *q.rpa
	if high == 0xc001000000000000 && low == 0 {
		entry := make([]byte, 16)
		entry[0], entry[1] = 0xc0, 2
		if err := m.commitCRQ(q, entry, nil); err != nil {
			return false, err
		}
		p.ready = true
		*q.rpa = p
		return true, nil
	}
	if high>>56 != 0x80 || !p.ready {
		return false, fmt.Errorf("power: unsupported CRQ %016x/%016x", high, low)
	}
	format := uint8(high >> 48)
	size := int(high & 0xffff)
	if size < 16 || size > 256 || high&0x0000ffff00000000 != 0 {
		return false, fmt.Errorf("power: invalid RPA IU header %016x", high)
	}
	iu := make([]byte, size)
	if err := m.ReadDMA(q.table, low, iu, 0); err != nil {
		return false, err
	}
	tag := binary.BigEndian.Uint64(iu[8:16])
	var reply []byte
	var writes []rpaWrite
	var diskCommand *scsi.DiskCommand
	switch {
	case format == 2 || p.unsupported[uint64(format)<<32|uint64(binary.BigEndian.Uint32(iu))]:
		typ := binary.BigEndian.Uint32(iu)
		length := int(binary.BigEndian.Uint16(iu[6:8]))
		reply = append([]byte(nil), iu[:16]...)
		status := uint16(0)
		if p.unsupported[uint64(format)<<32|uint64(typ)] || typ == 8 {
			status = 0xf1 // optional fast-fail/vendor feature not supported
		} else if typ == 3 || typ == 5 {
			if size < 24 {
				return false, fmt.Errorf("power: truncated MAD %x", typ)
			}
			buffer := binary.BigEndian.Uint64(iu[16:24])
			data := make([]byte, length)
			if typ == 3 {
				info := make([]byte, 148)
				copy(info, "16.a")
				copy(info[8:104], "TinyRangeX")
				binary.BigEndian.PutUint32(info[104:108], 1)
				binary.BigEndian.PutUint32(info[108:112], 1)
				// RPA Linux-compatible peer profile, also used by standalone device
				// emulators; this does not require or launch a host/guest Linux OS.
				binary.BigEndian.PutUint32(info[112:116], 2)
				binary.BigEndian.PutUint32(info[116:120], 1<<20)
				copy(data, info)
			} else {
				if length < 68 {
					return false, fmt.Errorf("power: truncated RPA capabilities")
				}
				if err := m.ReadDMA(q.table, buffer, data, 0); err != nil {
					return false, err
				}
				binary.BigEndian.PutUint32(data, binary.BigEndian.Uint32(data)&4)
				for at := 68; at < len(data); {
					if len(data)-at < 8 {
						return false, fmt.Errorf("power: truncated capability header")
					}
					n := int(binary.BigEndian.Uint16(data[at+4 : at+6]))
					if n < 8 || n > len(data)-at {
						return false, fmt.Errorf("power: invalid capability length %d", n)
					}
					binary.BigEndian.PutUint16(data[at+6:at+8], 0)
					at += n
				}
			}
			writes = append(writes, rpaWrite{buffer, data})
			reply = append(reply, iu[16:24]...)
		} else {
			return false, fmt.Errorf("power: unsupported MAD format%x type%x", format, typ)
		}
		binary.BigEndian.PutUint16(reply[4:6], status)
	case format == 1 && iu[0] == 2:
		var err error
		writes, reply, diskCommand, err = m.rpaSCSI(q, &p, iu)
		if err != nil {
			return false, err
		}
	case format == 1 && iu[0] == 0:
		if size < 64 {
			return false, fmt.Errorf("power: truncated SRP login")
		}
		requested := binary.BigEndian.Uint32(iu[16:20])
		formats := binary.BigEndian.Uint16(iu[24:26]) & 6
		if requested < 64 || formats == 0 || iu[26]&3 != 0 {
			reply = make([]byte, 32)
			reply[0] = 0xc2
			reason := uint32(0x10002)
			if formats == 0 {
				reason = 0x10004
			} else if iu[26]&3 != 0 {
				reason = 0x10005
			}
			binary.BigEndian.PutUint32(reply[4:8], reason)
		} else {
			reply = make([]byte, 52)
			reply[0] = 0xc0
			binary.BigEndian.PutUint32(reply[4:8], 16)
			binary.BigEndian.PutUint32(reply[16:20], min(requested, 256))
			binary.BigEndian.PutUint32(reply[20:24], 256)
			binary.BigEndian.PutUint16(reply[24:26], formats)
			p.loggedIn = true
		}
		binary.BigEndian.PutUint64(reply[8:16], tag)
	default:
		return false, fmt.Errorf("power: unsupported RPA format%x opcode%x IU %x", format, iu[0], iu)
	}
	writes = append(writes, rpaWrite{low, reply})
	entry := make([]byte, 16)
	entry[0], entry[1] = 0x80, format
	binary.BigEndian.PutUint16(entry[6:8], uint16(len(reply)))
	binary.BigEndian.PutUint64(entry[8:16], tag)
	if diskCommand != nil {
		if err := m.preflightCRQ(q, entry, writes); err != nil {
			return false, err
		}
		if err := diskCommand.Complete(); err != nil {
			return false, err
		}
	}
	if err := m.commitCRQ(q, entry, writes); err != nil {
		return false, err
	}
	*q.rpa = p
	if format == 1 && iu[0] == 2 {
		m.Event("scsi", nil, fmt.Sprintf("CRQ %x LUN %016x CDB %x status%02x", unit, binary.BigEndian.Uint64(iu[20:28]), iu[32:48], reply[19]))
	}
	return true, nil
}
