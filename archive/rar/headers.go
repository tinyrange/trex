// Package rar reads RAR archive metadata and streams through portable readers.
package rar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"hash/crc32"
	"io"
	"math"
	"strings"
	"unicode/utf16"
)

type Header struct {
	Name                                string
	Offset, PackedSize, Size            int64
	Version, Method                     int
	Dictionary                          int64
	CRC                                 uint32
	HasCRC, Directory, Solid, Encrypted bool
}

// Headers validates each archive header and bounds every payload against source.
func Headers(source storage.Reader, maximum int) ([]Header, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("rar: invalid entry limit")
	}
	var sig [8]byte
	n, e := source.ReadAt(sig[:], 0)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if n >= 8 && string(sig[:]) == "Rar!\x1a\x07\x01\x00" {
		return headers5(source, maximum)
	}
	if n >= 7 && string(sig[:7]) == "Rar!\x1a\x07\x00" {
		return headers4(source, maximum)
	}
	return nil, fmt.Errorf("rar: invalid signature")
}
func headers4(r storage.Reader, maximum int) ([]Header, error) {
	var out []Header
	for off := int64(7); off < r.Size(); {
		var prefix [7]byte
		if _, e := r.ReadAt(prefix[:], off); e != nil {
			return nil, e
		}
		size := int(binary.LittleEndian.Uint16(prefix[5:]))
		flags := binary.LittleEndian.Uint16(prefix[3:])
		kind := prefix[2]
		if size < 7 || int64(size) > r.Size()-off {
			return nil, fmt.Errorf("rar: invalid header size")
		}
		h := make([]byte, size)
		if _, e := r.ReadAt(h, off); e != nil {
			return nil, e
		}
		if uint16(crc32.ChecksumIEEE(h[2:])) != binary.LittleEndian.Uint16(h) {
			return nil, fmt.Errorf("rar: header CRC at %d", off)
		}
		packed := uint64(0)
		if flags&0x8000 != 0 {
			if size < 11 {
				return nil, io.ErrUnexpectedEOF
			}
			packed = uint64(binary.LittleEndian.Uint32(h[7:]))
		}
		if kind == 0x73 && flags&0x80 != 0 {
			return nil, fmt.Errorf("rar: encrypted archive headers require password")
		}
		if kind == 0x74 {
			if size < 32 {
				return nil, io.ErrUnexpectedEOF
			}
			packed = uint64(binary.LittleEndian.Uint32(h[7:]))
			unpacked := uint64(binary.LittleEndian.Uint32(h[11:]))
			nameAt := 32
			if flags&0x100 != 0 {
				if size < 40 {
					return nil, io.ErrUnexpectedEOF
				}
				packed |= uint64(binary.LittleEndian.Uint32(h[32:])) << 32
				unpacked |= uint64(binary.LittleEndian.Uint32(h[36:])) << 32
				nameAt = 40
			}
			nameSize := int(binary.LittleEndian.Uint16(h[26:]))
			if nameSize > size-nameAt {
				return nil, io.ErrUnexpectedEOF
			}
			name := h[nameAt : nameAt+nameSize]
			var filename string
			if flags&0x200 != 0 {
				var e error
				filename, e = unicodeName(name)
				if e != nil {
					return nil, e
				}
			} else {
				filename = string(name)
			}
			if packed > math.MaxInt64 || unpacked > math.MaxInt64 {
				return nil, fmt.Errorf("rar: file size overflow")
			}
			if flags&3 != 0 {
				return nil, fmt.Errorf("rar: split member requires companion volume")
			}
			out = append(out, Header{Name: strings.ReplaceAll(filename, "\\", "/"), Offset: off + int64(size), PackedSize: int64(packed), Size: int64(unpacked), Version: int(h[24]), Method: int(h[25]) - 0x30, Dictionary: 0x10000 << ((flags >> 5) & 7), CRC: binary.LittleEndian.Uint32(h[16:]), HasCRC: true, Directory: flags&0xe0 == 0xe0, Solid: flags&0x10 != 0, Encrypted: flags&4 != 0})
			if len(out) > maximum {
				return nil, fmt.Errorf("rar: entry limit")
			}
		}
		off += int64(size)
		if packed > uint64(r.Size()-off) {
			return nil, io.ErrUnexpectedEOF
		}
		off += int64(packed)
		if kind == 0x7b {
			return out, nil
		}
	}
	return out, nil // RAR before 3.0 need not carry an end-of-archive block.
}

// RAR4 Unicode names combine a legacy spelling with a compact UTF-16 stream.
func unicodeName(raw []byte) (string, error) {
	cut := bytes.IndexByte(raw, 0)
	if cut < 0 {
		return string(raw), nil
	}
	old, code := raw[:cut], raw[cut+1:]
	if len(code) == 0 {
		return string(old), nil
	}
	high := uint16(code[0]) << 8
	code = code[1:]
	var out []uint16
	flags, bits := byte(0), 0
	take := func() (byte, error) {
		if len(code) == 0 {
			return 0, io.ErrUnexpectedEOF
		}
		b := code[0]
		code = code[1:]
		return b, nil
	}
	for len(code) > 0 {
		if bits == 0 {
			flags = code[0]
			code = code[1:]
			bits = 8
		}
		tag := flags >> 6
		flags <<= 2
		bits -= 2
		b, e := take()
		if e != nil {
			return "", e
		}
		switch tag {
		case 0:
			out = append(out, uint16(b))
		case 1:
			out = append(out, high|uint16(b))
		case 2:
			c, e := take()
			if e != nil {
				return "", e
			}
			out = append(out, uint16(b)|uint16(c)<<8)
		case 3:
			count := int(b&127) + 2
			corr := byte(0)
			if b&128 != 0 {
				corr, e = take()
				if e != nil {
					return "", e
				}
			}
			if count > len(old)-len(out) {
				return "", fmt.Errorf("rar: invalid Unicode name run")
			}
			for range count {
				v := uint16(old[len(out)])
				if b&128 != 0 {
					v = high | uint16(byte(v)+corr)
				}
				out = append(out, v)
			}
		}
	}
	return string(utf16.Decode(out)), nil
}

type cursor struct {
	b   []byte
	err error
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return make([]byte, n)
	}
	if n < 0 || n > len(c.b) {
		c.err = io.ErrUnexpectedEOF
		return make([]byte, n)
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}
func (c *cursor) v() uint64 {
	var v uint64
	for i := 0; i < 10; i++ {
		b := c.take(1)[0]
		if i == 9 && b > 1 {
			c.err = fmt.Errorf("rar: integer overflow")
			return 0
		}
		v |= uint64(b&127) << uint(i*7)
		if b&128 == 0 {
			return v
		}
	}
	c.err = fmt.Errorf("rar: integer overflow")
	return 0
}
func headers5(r storage.Reader, maximum int) ([]Header, error) {
	var out []Header
	for off := int64(8); off < r.Size(); {
		var pre [7]byte
		if _, e := r.ReadAt(pre[:], off); e != nil {
			return nil, e
		}
		c := cursor{b: pre[4:]}
		size := c.v()
		vn := 3 - len(c.b)
		if c.err != nil || size > 2<<20 || size < 2 || int64(size)+int64(4+vn) > r.Size()-off {
			return nil, fmt.Errorf("rar5: invalid header size")
		}
		h := make([]byte, 4+vn+int(size))
		if _, e := r.ReadAt(h, off); e != nil {
			return nil, e
		}
		if crc32.ChecksumIEEE(h[4:]) != binary.LittleEndian.Uint32(h) {
			return nil, fmt.Errorf("rar5: header CRC at %d", off)
		}
		c = cursor{b: h[4+vn:]}
		kind, flags := c.v(), c.v()
		extra, packed := uint64(0), uint64(0)
		if flags&1 != 0 {
			extra = c.v()
		}
		if flags&2 != 0 {
			packed = c.v()
		}
		if extra > uint64(len(c.b)) {
			return nil, fmt.Errorf("rar5: invalid extra area")
		}
		if kind == 4 {
			return nil, fmt.Errorf("rar5: encrypted headers require password")
		}
		if kind == 2 {
			f := c.v()
			size := c.v()
			c.v()
			if f&2 != 0 {
				c.take(4)
			}
			crc := uint32(0)
			if f&4 != 0 {
				crc = binary.LittleEndian.Uint32(c.take(4))
			}
			comp := c.v()
			c.v()
			namelen := c.v()
			if namelen > uint64(len(c.b)) {
				return nil, io.ErrUnexpectedEOF
			}
			name := string(c.take(int(namelen)))
			if flags&24 != 0 {
				return nil, fmt.Errorf("rar5: split member requires companion volume")
			}
			if f&8 != 0 || size > math.MaxInt64 || packed > math.MaxInt64 {
				return nil, fmt.Errorf("rar5: unknown or overflowing size")
			}
			dictionary := int64(128<<10) << ((comp >> 10) & 31)
			encrypted := false
			if extra > uint64(len(c.b)) {
				return nil, io.ErrUnexpectedEOF
			}
			ex := cursor{b: c.b[len(c.b)-int(extra):]}
			for len(ex.b) > 0 && ex.err == nil {
				n := ex.v()
				if n > uint64(len(ex.b)) {
					return nil, io.ErrUnexpectedEOF
				}
				record := cursor{b: ex.take(int(n))}
				typ := record.v()
				if typ == 1 {
					encrypted = true
				}
				if record.err != nil {
					return nil, record.err
				}
			}
			if ex.err != nil {
				return nil, ex.err
			}
			out = append(out, Header{Name: strings.ReplaceAll(name, "\\", "/"), Offset: off + int64(len(h)), PackedSize: int64(packed), Size: int64(size), Version: 50 + int(comp&63), Method: int((comp >> 7) & 7), Dictionary: dictionary, CRC: crc, HasCRC: f&4 != 0, Directory: f&1 != 0, Solid: comp&64 != 0, Encrypted: encrypted})
			if len(out) > maximum {
				return nil, fmt.Errorf("rar: entry limit")
			}
		}
		if c.err != nil {
			return nil, c.err
		}
		off += int64(len(h))
		if packed > uint64(r.Size()-off) {
			return nil, io.ErrUnexpectedEOF
		}
		off += int64(packed)
		if kind == 5 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("rar5: missing end of archive")
}
