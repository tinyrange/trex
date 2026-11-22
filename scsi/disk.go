package scsi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/block"
)

// DiskIdentity describes a virtual direct-access device's SCSI identity.
// Identity is transport policy; the target's storage semantics are generic.
type DiskIdentity struct{ Vendor, Product, Revision, Serial string }

// Disk implements bounded SBC commands over caller-owned block storage.
// Copying a Disk captures protocol state, but does not snapshot writable media.
type Disk struct {
	media             block.Device
	identity          DiskIdentity
	sense             [18]byte
	stopped, reserved bool
	owner             uint64
}

func NewDisk(media block.Device, identity DiskIdentity) (Disk, error) {
	if media == nil {
		return Disk{}, fmt.Errorf("scsi: disk requires block storage")
	}
	g := media.Geometry()
	if g.Size <= 0 || g.LogicalBlockSize == 0 || g.Size%int64(g.LogicalBlockSize) != 0 {
		return Disk{}, fmt.Errorf("scsi: disk requires complete logical sectors")
	}
	for _, field := range []struct {
		value string
		limit int
	}{{identity.Vendor, 8}, {identity.Product, 16}, {identity.Revision, 4}, {identity.Serial, 220}} {
		if len(field.value) > field.limit {
			return Disk{}, fmt.Errorf("scsi: disk identity field exceeds%d bytes", field.limit)
		}
		for _, b := range []byte(field.value) {
			if b < 32 || b > 126 {
				return Disk{}, fmt.Errorf("scsi: disk identity must be printable ASCII")
			}
		}
	}
	return Disk{media: media, identity: identity}, nil
}

// DiskCommand separates validation/read preparation from writes. A transport
// must preflight its completion and DMA destinations before calling Complete.
// The caller serializes commands against the target; Complete is single-use.
type DiskCommand struct {
	target                    *Disk
	next                      Disk
	result                    Result
	write                     []byte
	sameLength                int64
	offset                    int64
	flush, completed          bool
	verifyRead, verifyCompare bool
}

func (p *DiskCommand) Result() Result { return p.result }
func (p *DiskCommand) Complete() error {
	if p.completed {
		return fmt.Errorf("scsi: disk command already completed")
	}
	p.completed = true
	if p.sameLength > 0 {
		zero := true
		for _, b := range p.write {
			if b != 0 {
				zero = false
				break
			}
		}
		zeroer, canZero := p.next.media.(block.Zeroer)
		if zero && canZero && p.next.media.Capabilities().Zero {
			if err := zeroer.ZeroAt(p.offset, p.sameLength); err != nil {
				return err
			}
		} else {
			chunk := max(1, (64<<10)/len(p.write)) * len(p.write)
			data := bytes.Repeat(p.write, chunk/len(p.write))
			for done := int64(0); done < p.sameLength; {
				n := min(int64(len(data)), p.sameLength-done)
				written, err := p.next.media.(block.Writer).WriteAt(data[:n], p.offset+done)
				if err != nil {
					return err
				}
				if int64(written) != n {
					return io.ErrShortWrite
				}
				done += n
			}
		}
	} else if p.write != nil {
		n, err := p.next.media.(block.Writer).WriteAt(p.write, p.offset)
		if err != nil {
			return err
		}
		if n != len(p.write) {
			return io.ErrShortWrite
		}
	}
	if p.flush {
		if err := p.next.media.(block.Flusher).Flush(); err != nil {
			return err
		}
	}
	if p.verifyRead {
		// Read back the actual backing after the write. BYTCHK=0 checks
		// readability; BYTCHK=1 additionally compares every transferred byte.
		data := make([]byte, min(64<<10, len(p.write)))
		for done := 0; done < len(p.write); {
			n := min(len(data), len(p.write)-done)
			if _, err := block.ReadFullAt(p.next.media, data[:n], p.offset+int64(done)); err != nil {
				return fmt.Errorf("scsi: write verification read: %w", err)
			}
			if p.verifyCompare && !bytes.Equal(data[:n], p.write[done:done+n]) {
				return fmt.Errorf("scsi: write verification mismatch at byte%d", p.offset+int64(done))
			}
			done += n
		}
	}
	*p.target = p.next
	return nil
}
func (d *Disk) Execute(cdb, dataOut []byte) (Result, error) {
	p, err := d.Prepare(0, cdb, dataOut)
	if err != nil {
		return Result{}, err
	}
	if err = p.Complete(); err != nil {
		return Result{}, err
	}
	return p.Result(), nil
}

func (d *Disk) Prepare(initiator uint64, cdb, dataOut []byte) (*DiskCommand, error) {
	if len(cdb) < 6 {
		return nil, fmt.Errorf("scsi: truncated disk CDB")
	}
	need := 6
	switch cdb[0] >> 5 {
	case 1, 2:
		need = 10
	case 4:
		need = 16
	case 5:
		need = 12
	}
	if len(cdb) < need {
		return nil, fmt.Errorf("scsi: truncated disk CDB%02x", cdb[0])
	}
	p := &DiskCommand{target: d, next: *d}
	check := func(key, asc byte) (*DiskCommand, error) {
		p.result = CheckCondition(key, asc, 0)
		copy(p.next.sense[:], p.result.Sense)
		return p, nil
	}
	if d.reserved && d.owner != initiator && cdb[0] != 0x12 && cdb[0] != 3 && cdb[0] != 0x17 && cdb[0] != 0x57 {
		p.result.Status = 0x18
		return p, nil
	}
	if len(dataOut) > 0 && cdb[0] != 0x0a && cdb[0] != 0x2a && cdb[0] != 0x2e && cdb[0] != 0xaa && cdb[0] != 0x8a && cdb[0] != 0x93 {
		return nil, fmt.Errorf("scsi: unexpected disk data-out for CDB%02x", cdb[0])
	}
	g := d.media.Geometry()
	blocks := uint64(g.Size / int64(g.LogicalBlockSize))
	switch cdb[0] {
	case 0:
		if d.stopped {
			return check(2, 4)
		}
	case 3:
		if cdb[1]&1 != 0 {
			return check(5, 0x24)
		}
		b := d.sense
		if b[0] == 0 {
			b[0] = 0x70
			b[7] = 10
		}
		p.result.Data = allocation(b[:], uint32(cdb[4]))
		p.next.sense = [18]byte{}
	case 0x12:
		if cdb[1]&^byte(1) != 0 {
			return check(5, 0x24)
		}
		var data []byte
		if cdb[1]&1 == 0 {
			if cdb[2] != 0 {
				return check(5, 0x24)
			}
			data = make([]byte, 36)
			data[2] = 6
			data[3] = 2
			data[4] = 31
			for i := 8; i < 36; i++ {
				data[i] = ' '
			}
			copy(data[8:16], d.identity.Vendor)
			copy(data[16:32], d.identity.Product)
			copy(data[32:36], d.identity.Revision)
		} else {
			switch cdb[2] {
			case 0:
				data = []byte{0, 0, 0, 3, 0, 0x80, 0x83}
			case 0x80:
				data = append([]byte{0, 0x80, 0, byte(len(d.identity.Serial))}, []byte(d.identity.Serial)...)
			case 0x83:
				id := fmt.Sprintf("%-8s%s %s", d.identity.Vendor, d.identity.Product, d.identity.Serial)
				data = append([]byte{0, 0x83, 0, byte(4 + len(id)), 2, 1, 0, byte(len(id))}, []byte(id)...)
			default:
				// Only page00's advertised capabilities exist on this target.
				// An unadvertised vendor page is an invalid INQUIRY field, not
				// a successful empty capability structure.
				return check(5, 0x24)
			}
		}
		p.result.Data = allocation(data, uint32(binary.BigEndian.Uint16(cdb[3:5])))
	case 0x25:
		if binary.BigEndian.Uint32(cdb[2:6]) != 0 || cdb[8] != 0 {
			return check(5, 0x24)
		}
		data := make([]byte, 8)
		binary.BigEndian.PutUint32(data, uint32(min(blocks-1, 0xffffffff)))
		binary.BigEndian.PutUint32(data[4:], g.LogicalBlockSize)
		p.result.Data = data
	case 0x9e:
		if cdb[1] != 0x10 || binary.BigEndian.Uint64(cdb[2:10]) != 0 || cdb[14] != 0 {
			return check(5, 0x24)
		}
		data := make([]byte, 32)
		binary.BigEndian.PutUint64(data, blocks-1)
		binary.BigEndian.PutUint32(data[8:], g.LogicalBlockSize)
		p.result.Data = allocation(data, binary.BigEndian.Uint32(cdb[10:14]))
	case 0x1b:
		if cdb[1] != 0 || cdb[4]&^byte(1) != 0 {
			return check(5, 0x24)
		}
		p.next.stopped = cdb[4]&1 == 0
	case 0x1e:
		if cdb[4] > 1 {
			return check(5, 0x24)
		} // Nonremovable medium cannot be ejected.
	case 0x16, 0x17, 0x56, 0x57:
		for _, b := range cdb[1 : need-1] {
			if b != 0 {
				return check(5, 0x24)
			}
		}
		if cdb[0] == 0x16 || cdb[0] == 0x56 {
			p.next.reserved = true
			p.next.owner = initiator
		} else if d.reserved && d.owner == initiator {
			p.next.reserved = false
		}
	case 0x08, 0x0a, 0x28, 0x2a, 0x2e, 0xa8, 0xaa, 0x88, 0x8a:
		if d.stopped {
			return check(2, 4)
		}
		var lba, count uint64
		fua := false
		switch need {
		case 6:
			lba = uint64(cdb[1]&31)<<16 | uint64(binary.BigEndian.Uint16(cdb[2:4]))
			count = uint64(cdb[4])
			if count == 0 {
				count = 256
			}
		case 10, 12:
			allowed := byte(0x18)
			if cdb[0] == 0x2e {
				allowed = 0x12 // DPO and BYTCHK=0/1, without protection.
				p.verifyRead, p.verifyCompare = true, cdb[1]&2 != 0
			}
			if cdb[1]&^allowed != 0 {
				return check(5, 0x24)
			}
			fua = cdb[0] != 0x2e && cdb[1]&8 != 0
			lba = uint64(binary.BigEndian.Uint32(cdb[2:6]))
			if need == 10 {
				count = uint64(binary.BigEndian.Uint16(cdb[7:9]))
			} else {
				count = uint64(binary.BigEndian.Uint32(cdb[6:10]))
			}
		case 16:
			if cdb[1]&^byte(0x18) != 0 {
				return check(5, 0x24)
			}
			fua = cdb[1]&8 != 0
			lba = binary.BigEndian.Uint64(cdb[2:10])
			count = uint64(binary.BigEndian.Uint32(cdb[10:14]))
		}
		if lba > blocks || count > blocks-lba {
			return check(5, 0x21)
		}
		n := count * uint64(g.LogicalBlockSize)
		if n > 8<<20 {
			return nil, fmt.Errorf("scsi: disk transfer exceeds8MiB")
		}
		writing := cdb[0] == 0x0a || cdb[0] == 0x2a || cdb[0] == 0x2e || cdb[0] == 0xaa || cdb[0] == 0x8a
		if writing {
			if !gWritable(d.media) {
				return check(7, 0x27)
			}
			if uint64(len(dataOut)) != n {
				return check(5, 0x1a)
			}
			if fua {
				if _, ok := d.media.(block.Flusher); !ok || !d.media.Capabilities().Flush {
					return nil, fmt.Errorf("scsi: disk cannot honor FUA")
				}
				p.flush = true
			}
			p.offset = int64(lba * uint64(g.LogicalBlockSize))
			p.write = append([]byte{}, dataOut...)
		} else {
			if len(dataOut) != 0 {
				return check(5, 0x24)
			}
			p.result.Data = make([]byte, int(n))
			if _, err := block.ReadFullAt(d.media, p.result.Data, int64(lba*uint64(g.LogicalBlockSize))); err != nil {
				return nil, err
			}
		}
	case 0x93: // WRITE SAME(16): one pattern sector, actual repeated writes.
		if d.stopped {
			return check(2, 4)
		}
		if cdb[1]&^byte(1) != 0 {
			return check(5, 0x24)
		} // No protection, UNMAP, ANCHOR or obsolete address substitution.
		lba := binary.BigEndian.Uint64(cdb[2:10])
		count := uint64(binary.BigEndian.Uint32(cdb[10:14]))
		if lba >= blocks || count > blocks-lba {
			return check(5, 0x21)
		}
		if count == 0 {
			count = blocks - lba
		}
		if !gWritable(d.media) {
			return check(7, 0x27)
		}
		if cdb[1]&1 != 0 {
			if len(dataOut) != 0 {
				return check(5, 0x1a)
			}
			p.write = make([]byte, int(g.LogicalBlockSize))
		} else {
			if len(dataOut) != int(g.LogicalBlockSize) {
				return check(5, 0x1a)
			}
			p.write = bytes.Clone(dataOut)
		}
		p.offset = int64(lba * uint64(g.LogicalBlockSize))
		p.sameLength = int64(count * uint64(g.LogicalBlockSize))
	case 0x35, 0x91:
		if cdb[1] != 0 {
			return check(5, 0x24)
		}
		if _, ok := d.media.(block.Flusher); !ok || !d.media.Capabilities().Flush {
			return nil, fmt.Errorf("scsi: disk flush unsupported by backing")
		}
		p.flush = true
	case 0x1a, 0x5a:
		if cdb[1]&^byte(8) != 0 || cdb[2]>>6 != 0 || cdb[3] != 0 {
			return check(5, 0x24)
		}
		page := cdb[2] & 63
		var pages []byte
		for _, id := range []byte{1, 8, 0x0a} {
			if page != id && page != 63 {
				continue
			}
			size := 12
			if id == 8 {
				size = 20
			}
			b := make([]byte, size)
			b[0] = id
			b[1] = byte(size - 2)
			pages = append(pages, b...)
		}
		if len(pages) == 0 {
			return nil, fmt.Errorf("scsi: unsupported disk mode page%02x", page)
		}
		header := 4
		allocationLength := uint32(cdb[4])
		if need == 10 {
			header = 8
			allocationLength = uint32(binary.BigEndian.Uint16(cdb[7:9]))
		}
		data := make([]byte, header)
		wp := byte(0)
		if !gWritable(d.media) {
			wp = 0x80
		}
		if header == 4 {
			data[2] = wp
		} else {
			data[3] = wp
		}
		if cdb[1]&8 == 0 {
			b := make([]byte, 8)
			binary.BigEndian.PutUint32(b, uint32(min(blocks, 0xffffff)))
			b[0] = 0
			binary.BigEndian.PutUint32(b[4:], g.LogicalBlockSize)
			data = append(data, b...)
			if header == 4 {
				data[3] = 8
			} else {
				binary.BigEndian.PutUint16(data[6:], 8)
			}
		}
		data = append(data, pages...)
		if header == 4 {
			data[0] = byte(len(data) - 1)
		} else {
			binary.BigEndian.PutUint16(data, uint16(len(data)-2))
		}
		p.result.Data = allocation(data, allocationLength)
	default:
		return nil, fmt.Errorf("scsi: unsupported disk CDB%02x", cdb[0])
	}
	return p, nil
}
func gWritable(media block.Device) bool {
	_, ok := media.(block.Writer)
	return ok && media.Capabilities().Writable
}
