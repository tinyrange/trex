package irix

import "fmt"

// MIPS options and ABI flags are metadata, not permission to execute a codec.
type MIPSOption struct {
	Kind    byte
	Section uint16
	Info    uint32
}
type ABIFlags struct {
	ISALevel, ISARevision, GPRSize, CPR1Size, CPR2Size, FPABI byte
	ISAExtension, ASEs, Flags1, Flags2                        uint32
}

func (p *parser) mipsOptions(im *Image, offset, size uint64) error {
	key := [2]uint64{offset, size}
	if p.seenOptions[key] {
		return nil
	}
	if p.seenOptions == nil {
		p.seenOptions = map[[2]uint64]bool{}
	}
	p.seenOptions[key] = true
	for pos := uint64(0); pos < size; {
		if size-pos < 8 {
			return fmt.Errorf("irix ELF: truncated MIPS option")
		}
		b, err := p.read(offset+pos, 8)
		if err != nil {
			return err
		}
		n := uint64(b[1])
		if n < 8 || n > size-pos {
			return fmt.Errorf("irix ELF: invalid MIPS option size")
		}
		if err = p.budget(1); err != nil {
			return err
		}
		im.Options = append(im.Options, MIPSOption{b[0], p.order.Uint16(b[2:]), p.order.Uint32(b[4:])})
		if b[0] == 1 {
			width := uint64(24)
			if im.Class == 64 {
				width = 32
			}
			if n != width+8 {
				return fmt.Errorf("irix ELF: invalid MIPS reginfo option")
			}
			data, err := p.read(offset+pos+8, width)
			if err != nil {
				return err
			}
			if im.Class == 64 {
				im.GP = p.order.Uint64(data[24:])
			} else {
				im.GP = uint64(p.order.Uint32(data[20:]))
			}
		}
		pos += n
	}
	return nil
}
func (p *parser) abiFlags(im *Image, offset, size uint64) error {
	if size != 24 {
		return fmt.Errorf("irix ELF: invalid ABI flags size")
	}
	b, err := p.read(offset, size)
	if err != nil {
		return err
	}
	if p.order.Uint16(b) != 0 {
		return fmt.Errorf("irix ELF: unknown ABI flags version")
	}
	im.ABIFlags = &ABIFlags{b[2], b[3], b[4], b[5], b[6], b[7], p.order.Uint32(b[8:]), p.order.Uint32(b[12:]), p.order.Uint32(b[16:]), p.order.Uint32(b[20:])}
	return nil
}
