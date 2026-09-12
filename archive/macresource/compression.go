package macresource

import (
	"encoding/binary"
	"fmt"
	"io"

	starfile "github.com/tinyrange/trex/storage/star"
)

// DecodeCompressed decodes a Resource Manager compressed payload, including its
// 18-byte header. No resource code is executed. maximumBytes bounds both the
// stored input and decoded output. Format descriptions:
// https://formats.kaitai.io/compressed_resource/
// https://formats.kaitai.io/dcmp_0/ and https://formats.kaitai.io/dcmp_1/
// Extended literal integers additionally follow resource_dasm's System01
// research; the Kaitai descriptions omit multi-byte lengths. See
// LICENSE.compression for the research/decoder reference notices.
func DecodeCompressed(file starfile.File, maximumBytes int64) (starfile.File, error) {
	return decodeCompressed(file, maximumBytes, maximumBytes)
}
func decodeCompressed(file starfile.File, maximumStored, maximumDecoded int64) (starfile.File, error) {
	if maximumStored < 0 || maximumDecoded < 0 || file.Size() < 18 || file.Size() > maximumStored {
		return nil, fmt.Errorf("mac resource: compressed input outside size limit")
	}
	var h [18]byte
	if _, err := starfile.ReadFullAt(file, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if be.Uint32(h[:]) != 0xa89f6572 || be.Uint16(h[4:]) != 18 || h[7] != 1 {
		return nil, fmt.Errorf("mac resource: invalid compression header")
	}
	size := int64(be.Uint32(h[8:]))
	if size > maximumDecoded || size >= int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("mac resource: decoded size exceeds limit")
	}
	var id int16
	switch h[6] {
	case 8:
		id = int16(be.Uint16(h[14:]))
		if be.Uint16(h[16:]) != 0 {
			return nil, fmt.Errorf("mac resource: nonzero compression reserved field")
		}
	case 9:
		id = int16(be.Uint16(h[12:]))
	default:
		return nil, fmt.Errorf("mac resource: unsupported compression header type %d", h[6])
	}
	if !((h[6] == 8 && (id == 0 || id == 1)) || (h[6] == 9 && (id == 2 || id == 3))) {
		return nil, fmt.Errorf("mac resource: unsupported dcmp %d with header type %d", id, h[6])
	}
	b, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	d := resourceDecoder{input: b[18:], limit: int(size)}
	if id == 0 && size&1 != 0 {
		d.limit++
	} // Word-oriented codec pads an odd final byte.
	switch id {
	case 0, 1:
		err = d.tokens(id)
	case 2:
		err = d.tableWords(h[14:])
	case 3:
		err = d.instacomp()
	}
	if err != nil {
		return nil, fmt.Errorf("mac resource: dcmp %d at byte %d: %w", id, d.pos+18, err)
	}
	if len(d.output) < int(size) || len(d.output) > d.limit {
		return nil, fmt.Errorf("mac resource: decoded size %d, expected %d", len(d.output), size)
	}
	return &starfile.Bytes{Name: "decoded resource", Data: d.output[:size]}, nil
}

type resourceDecoder struct {
	input, output []byte
	pos, limit    int
	dictionary    [][]byte
}

func (d *resourceDecoder) take(n int) ([]byte, error) {
	if n < 0 || n > len(d.input)-d.pos {
		return nil, fmt.Errorf("need %d bytes, have %d: %w", n, len(d.input)-d.pos, io.ErrUnexpectedEOF)
	}
	b := d.input[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}
func (d *resourceDecoder) byte() (byte, error) {
	b, err := d.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}
func (d *resourceDecoder) integer() (int32, error) {
	b, err := d.byte()
	if err != nil {
		return 0, err
	}
	if b < 0x80 {
		return int32(b), nil
	}
	if b == 0xff {
		v, err := d.take(4)
		if err != nil {
			return 0, err
		}
		return int32(binary.BigEndian.Uint32(v)), nil
	}
	lo, err := d.byte()
	return (int32(b)<<8 | int32(lo)) - 0xc000, err
}
func (d *resourceDecoder) emit(b []byte) error {
	if len(b) > d.limit-len(d.output) {
		return fmt.Errorf("output exceeds declared size")
	}
	d.output = append(d.output, b...)
	return nil
}
func (d *resourceDecoder) word(v uint16) error {
	return d.emit([]byte{byte(v >> 8), byte(v)})
}
func (d *resourceDecoder) long(v uint32) error {
	return d.emit([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
func (d *resourceDecoder) literal(n int, store bool) error {
	if n < 0 || n > d.limit-len(d.output) {
		return fmt.Errorf("literal length exceeds declared size")
	}
	b, err := d.take(n)
	if err != nil {
		return err
	}
	if err := d.emit(b); err != nil {
		return err
	}
	if store {
		// The widest reference field is 16 bits plus a fixed dictionary bias.
		if len(d.dictionary) >= 65536+0xb0 {
			return fmt.Errorf("literal dictionary exceeds addressable range")
		}
		d.dictionary = append(d.dictionary, b)
	}
	return nil
}
func (d *resourceDecoder) reference(index int) error {
	if index < 0 || index >= len(d.dictionary) {
		return fmt.Errorf("dictionary index %d out of range", index)
	}
	return d.emit(d.dictionary[index])
}
func (d *resourceDecoder) tokens(id int16) error {
	for {
		start := d.pos
		tag, err := d.byte()
		if err != nil {
			return err
		}
		switch {
		case tag == 0xff:
			if d.pos != len(d.input) {
				return fmt.Errorf("trailing data after end marker")
			}
			return nil
		case tag == 0xfe:
			err = d.extended(id)
		case tag < 0x20:
			n := int(tag & 15)
			if id == 1 {
				n++
			} else {
				if n == 0 {
					var v int32
					v, err = d.integer()
					if err == nil && (v < 0 || int64(v)*2 > int64(d.limit-len(d.output))) {
						err = fmt.Errorf("word literal length exceeds declared size")
					}
					n = int(v)
				}
				n *= 2
			}
			if err == nil {
				err = d.literal(n, tag&16 != 0)
			}
		case id == 0 && tag <= 0x22:
			var v byte
			v, err = d.byte()
			index := int(v) + 0x28
			if tag == 0x21 {
				index += 0x100
			}
			if tag == 0x22 && err == nil {
				var lo byte
				lo, err = d.byte()
				index = int(v)<<8 | int(lo)
				index += 0x28
			}
			if err == nil {
				err = d.reference(index)
			}
		case id == 0 && tag < 0x4b:
			err = d.reference(int(tag) - 0x23)
		case id == 0:
			err = d.word(dcmp0Words[int(tag)-0x4b])
		case tag <= 0xcf:
			err = d.reference(int(tag) - 0x20)
		case tag <= 0xd1:
			var n int32
			n, err = d.integer()
			if err == nil {
				err = d.literal(int(n), tag == 0xd1)
			}
		case tag == 0xd2:
			var n byte
			n, err = d.byte()
			if err == nil {
				err = d.reference(int(n) + 0xb0)
			}
		case tag >= 0xd5:
			err = d.word(dcmp1Words[int(tag)-0xd5])
		default:
			err = fmt.Errorf("invalid token %02x", tag)
		}
		if err != nil {
			return fmt.Errorf("token %02x at %d after %d output bytes: %w", tag, start, len(d.output), err)
		}
	}
}

func (d *resourceDecoder) extended(id int16) error {
	tag, err := d.byte()
	if err != nil {
		return err
	}
	if id == 1 && tag != 2 {
		return fmt.Errorf("invalid extended token %02x", tag)
	}
	v, err := d.integer()
	if err != nil {
		return err
	}
	n, err := d.integer()
	if err != nil {
		return err
	}
	if n < 0 && tag != 1 {
		return fmt.Errorf("negative extended count")
	}
	remaining := d.limit - len(d.output)
	switch tag {
	case 1:
		// 68k jump veneers: BSR target; JMP (offset,A5). The target moves
		// back eight bytes per entry. A zero A5 delta supplies each offset
		// explicitly; otherwise offsets advance by the encoded delta.
		count, err := d.integer()
		if err != nil {
			return err
		}
		first, err := d.integer()
		if err != nil {
			return err
		}
		wordValue := func(x int32) bool { return x >= -32768 && x <= 65535 }
		if !wordValue(v) || !wordValue(n) || !wordValue(first) || count < 0 || (int64(count)+1)*8 > int64(remaining) {
			return fmt.Errorf("invalid jump veneer range")
		}
		target, a5 := uint16(v), uint16(first)
		for i := int32(0); i <= count; i++ {
			if i != 0 {
				target -= 8
				if n == 0 {
					value, err := d.integer()
					if err != nil {
						return err
					}
					if !wordValue(value) {
						return fmt.Errorf("A5 offset out of range")
					}
					a5 = uint16(value)
				} else {
					a5 += uint16(n)
				}
			}
			for _, word := range []uint16{0x6100, target, 0x4eed, a5} {
				if err := d.word(word); err != nil {
					return err
				}
			}
		}
	case 0:
		// The preceding literal contains the first address. Emit its trailer,
		// then the address/trailer pairs represented by this token.
		if v < 0 || v > 65535 || n == 0 || int64(n)*8+6 > int64(remaining) {
			return fmt.Errorf("invalid jump table range")
		}
		trailer := []byte{0x3f, 0x3c, byte(v >> 8), byte(v), 0xa9, 0xf0}
		if err := d.emit(trailer); err != nil {
			return err
		}
		var address int64
		for i := int32(0); i < n; i++ {
			x, err := d.integer()
			if err != nil {
				return err
			}
			if i == 0 {
				address = int64(x)
			} else {
				address += int64(x) - 6
			}
			if address < 0 || address > 65535 {
				return fmt.Errorf("jump address out of range")
			}
			if err := d.word(uint16(address)); err != nil {
				return err
			}
			if err := d.emit(trailer); err != nil {
				return err
			}
		}
	case 2, 3:
		width, max := int64(1), int32(255)
		if tag == 3 {
			width, max = 2, 65535
		}
		if v < 0 || v > max || (int64(n)+1)*width > int64(remaining) {
			return fmt.Errorf("invalid repetition range")
		}
		for i := int64(0); i <= int64(n); i++ {
			if tag == 3 {
				err = d.word(uint16(v))
			} else {
				err = d.emit([]byte{byte(v)})
			}
			if err != nil {
				return err
			}
		}
	case 4:
		if v < -32768 || v > 32767 || (int64(n)+1)*2 > int64(remaining) {
			return fmt.Errorf("invalid delta16 range")
		}
		value := uint16(v)
		if err := d.word(value); err != nil {
			return err
		}
		for i := int32(0); i < n; i++ {
			x, err := d.byte()
			if err != nil {
				return err
			}
			value += uint16(int8(x))
			if err := d.word(value); err != nil {
				return err
			}
		}
	case 6:
		if (int64(n)+1)*4 > int64(remaining) {
			return fmt.Errorf("invalid delta32 range")
		}
		value := uint32(v)
		if err := d.long(value); err != nil {
			return err
		}
		for i := int32(0); i < n; i++ {
			x, err := d.integer()
			if err != nil {
				return err
			}
			value += uint32(x)
			if err := d.long(value); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid extended token %02x", tag)
	}
	return nil
}

// These word dictionaries are constants of Apple's on-disk dcmp formats.
var dcmp0Words = [...]uint16{
	0x0000, 0x4eba, 0x0008, 0x4e75, 0x000c, 0x4ead, 0x2053, 0x2f0b, 0x6100, 0x0010, 0x7000, 0x2f00, 0x486e, 0x2050, 0x206e, 0x2f2e, 0xfffc, 0x48e7, 0x3f3c, 0x0004, 0xfff8, 0x2f0c, 0x2006, 0x4eed, 0x4e56, 0x2068, 0x4e5e, 0x0001, 0x588f, 0x4fef, 0x0002, 0x0018, 0x6000, 0xffff, 0x508f, 0x4e90, 0x0006, 0x266e, 0x0014, 0xfff4, 0x4cee, 0x000a, 0x000e, 0x41ee, 0x4cdf, 0x48c0, 0xfff0, 0x2d40, 0x0012, 0x302e, 0x7001, 0x2f28, 0x2054, 0x6700, 0x0020, 0x001c, 0x205f, 0x1800, 0x266f, 0x4878, 0x0016, 0x41fa, 0x303c, 0x2840, 0x7200, 0x286e, 0x200c, 0x6600, 0x206b, 0x2f07, 0x558f, 0x0028, 0xfffe, 0xffec, 0x22d8, 0x200b, 0x000f, 0x598f, 0x2f3c, 0xff00, 0x0118, 0x81e1, 0x4a00, 0x4eb0, 0xffe8, 0x48c7, 0x0003, 0x0022, 0x0007, 0x001a, 0x6706, 0x6708, 0x4ef9, 0x0024, 0x2078, 0x0800, 0x6604, 0x002a, 0x4ed0, 0x3028, 0x265f, 0x6704, 0x0030, 0x43ee, 0x3f00, 0x201f, 0x001e, 0xfff6, 0x202e, 0x42a7, 0x2007, 0xfffa, 0x6002, 0x3d40, 0x0c40, 0x6606, 0x0026, 0x2d48, 0x2f01, 0x70ff, 0x6004, 0x1880, 0x4a40, 0x0040, 0x002c, 0x2f08, 0x0011, 0xffe4, 0x2140, 0x2640, 0xfff2, 0x426e, 0x4eb9, 0x3d7c, 0x0038, 0x000d, 0x6006, 0x422e, 0x203c, 0x670c, 0x2d68, 0x6608, 0x4a2e, 0x4aae, 0x002e, 0x4840, 0x225f, 0x2200, 0x670a, 0x3007, 0x4267, 0x0032, 0x2028, 0x0009, 0x487a, 0x0200, 0x2f2b, 0x0005, 0x226e, 0x6602, 0xe580, 0x670e, 0x660a, 0x0050, 0x3e00, 0x660c, 0x2e00, 0xffee, 0x206d, 0x2040, 0xffe0, 0x5340, 0x6008, 0x0480, 0x0068, 0x0b7c, 0x4400, 0x41e8, 0x4841,
}
var dcmp1Words = [...]uint16{
	0x0000, 0x0001, 0x0002, 0x0003, 0x2e01, 0x3e01, 0x0101, 0x1e01, 0xffff, 0x0e01, 0x3100, 0x1112, 0x0107, 0x3332, 0x1239, 0xed10, 0x0127, 0x2322, 0x0137, 0x0706, 0x0117, 0x0123, 0x00ff, 0x002f, 0x070e, 0xfd3c, 0x0135, 0x0115, 0x0102, 0x0007, 0x003e, 0x05d5, 0x0201, 0x0607, 0x0708, 0x3001, 0x0133, 0x0010, 0x1716, 0x373e, 0x3637,
}
