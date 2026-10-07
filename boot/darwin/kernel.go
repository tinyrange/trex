// Package darwin implements portable Intel XNU direct-boot wire formats.
// No bootloader is executed and no kernel instructions are patched.
package darwin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"hash/adler32"
	"io"
	"strings"
)

const MaxKernelSize = 256 << 20
const kernelBase uint64 = 0xffffff8000000000

type Segment struct {
	Name                                string
	Address, Size, FileOffset, FileSize uint64
}
type Image struct {
	Data      []byte
	Entry     uint64 // physical 32-bit _pstart
	Segments  []Segment
	Symbols   map[string]uint64 // original virtual addresses for debugging
	Base, End uint64
}

func Open(r storage.Reader) (*Image, error) {
	if r == nil || r.Size() < 4 || r.Size() > MaxKernelSize {
		return nil, fmt.Errorf("darwin: invalid kernel size")
	}
	b := make([]byte, r.Size())
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, r.Size()), b); err != nil {
		return nil, err
	}
	for depth := 0; depth < 3; depth++ {
		if len(b) >= 8 && binary.BigEndian.Uint32(b) == 0xcafebabe {
			n := binary.BigEndian.Uint32(b[4:])
			if n == 0 || n > 32 || uint64(n)*20+8 > uint64(len(b)) {
				return nil, fmt.Errorf("darwin: invalid fat table")
			}
			var slice []byte
			for i := uint32(0); i < n; i++ {
				a := b[8+i*20 : 8+(i+1)*20]
				off, size := uint64(binary.BigEndian.Uint32(a[8:])), uint64(binary.BigEndian.Uint32(a[12:]))
				if off < 8+uint64(n)*20 || off > uint64(len(b)) || size > uint64(len(b))-off {
					return nil, fmt.Errorf("darwin: fat slice outside file")
				}
				if binary.BigEndian.Uint32(a) == 0x01000007 {
					if slice != nil {
						return nil, fmt.Errorf("darwin: duplicate amd64 slice")
					}
					slice = b[off : off+size]
				}
			}
			if slice == nil {
				return nil, fmt.Errorf("darwin: no amd64 slice")
			}
			b = slice
			continue
		}
		if len(b) >= 8 && string(b[:4]) == "comp" {
			if string(b[4:8]) != "lzss" || len(b) < 384 {
				return nil, fmt.Errorf("darwin: unsupported compressed cache")
			}
			size, packed := binary.BigEndian.Uint32(b[12:]), binary.BigEndian.Uint32(b[16:])
			if uint64(packed) != uint64(len(b)-384) {
				return nil, fmt.Errorf("darwin: packed length mismatch")
			}
			out, err := decodeLZSS(b[384:], int(size))
			if err != nil {
				return nil, err
			}
			if adler32.Checksum(out) != binary.BigEndian.Uint32(b[8:]) {
				return nil, fmt.Errorf("darwin: kernelcache Adler32 mismatch")
			}
			b = out
			continue
		}
		return parseMachO(b)
	}
	return nil, fmt.Errorf("darwin: kernel wrapper nesting limit")
}

// Original decoder for the wire format: LSB-first flags and 12-bit ring indices.
func decodeLZSS(src []byte, size int) ([]byte, error) {
	if size < 32 || size > MaxKernelSize {
		return nil, fmt.Errorf("darwin: decoded size outside bounds")
	}
	out := make([]byte, 0, size)
	var ring [4096]byte
	for i := range ring {
		ring[i] = ' '
	}
	r, pos := 4096-18, 0
	put := func(v byte) { out = append(out, v); ring[r] = v; r = (r + 1) & 4095 }
	for len(out) < size {
		if pos >= len(src) {
			return nil, io.ErrUnexpectedEOF
		}
		flags := src[pos]
		pos++
		for bit := 0; bit < 8 && len(out) < size; bit++ {
			if flags&(1<<bit) != 0 {
				if pos >= len(src) {
					return nil, io.ErrUnexpectedEOF
				}
				put(src[pos])
				pos++
			} else {
				if len(src)-pos < 2 {
					return nil, io.ErrUnexpectedEOF
				}
				a, c := int(src[pos]), int(src[pos+1])
				pos += 2
				index := a | ((c & 0xf0) << 4)
				count := (c & 15) + 3
				if count > size-len(out) {
					return nil, fmt.Errorf("darwin: LZSS match exceeds decoded size")
				}
				for j := 0; j < count; j++ {
					put(ring[(index+j)&4095])
				}
			}
		}
	}
	if pos != len(src) {
		return nil, fmt.Errorf("darwin: trailing compressed bytes")
	}
	return out, nil
}
func physical(v uint64) (uint64, error) {
	if v < 1<<32 {
		return v, nil
	}
	if v >= kernelBase && v < kernelBase+(1<<32) {
		return v - kernelBase, nil
	}
	return 0, fmt.Errorf("darwin: address %#x outside unslid kernel window", v)
}
func parseMachO(b []byte) (*Image, error) {
	u32, u64 := binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	if len(b) < 32 || u32(b) != 0xfeedfacf || u32(b[4:]) != 0x01000007 || u32(b[12:]) != 2 {
		return nil, fmt.Errorf("darwin: expected amd64 Mach-O executable")
	}
	n, cmdsize := u32(b[16:]), u32(b[20:])
	if n == 0 || n > 4096 || uint64(cmdsize) > uint64(len(b)-32) {
		return nil, fmt.Errorf("darwin: invalid load command bounds")
	}
	end, off := 32+int(cmdsize), 32
	img := &Image{Data: b, Base: 1 << 32, Symbols: map[string]uint64{}}
	var symtab []byte
	for i := uint32(0); i < n; i++ {
		if end-off < 8 {
			return nil, fmt.Errorf("darwin: truncated command")
		}
		c := b[off:end]
		sz := int(u32(c[4:]))
		if sz < 8 || sz%4 != 0 || sz > len(c) {
			return nil, fmt.Errorf("darwin: invalid command size")
		}
		c = c[:sz]
		switch u32(c) {
		case 0x19:
			if sz < 72 || uint64(u32(c[64:]))*80+72 != uint64(sz) {
				return nil, fmt.Errorf("darwin: malformed segment")
			}
			name := strings.TrimRight(string(c[8:24]), "\x00")
			va, vs, fo, fs := u64(c[24:]), u64(c[32:]), u64(c[40:]), u64(c[48:])
			if fo > uint64(len(b)) || fs > uint64(len(b))-fo || (vs != 0 && fs > vs) {
				return nil, fmt.Errorf("darwin: segment %s invalid file range %#x+%#x (VM size %#x, file size %#x)", name, fo, fs, vs, len(b))
			}
			if vs == 0 {
				break
			}
			pa, err := physical(va)
			if err != nil {
				return nil, err
			}
			if vs > MaxKernelSize || pa < 0x100000 || pa >= 1<<32 || vs > (1<<32)-pa {
				return nil, fmt.Errorf("darwin: invalid segment memory range")
			}
			for _, s := range img.Segments {
				if pa < s.Address+s.Size && s.Address < pa+vs {
					return nil, fmt.Errorf("darwin: overlapping segments")
				}
			}
			img.Segments = append(img.Segments, Segment{name, pa, vs, fo, fs})
			img.Base = min(img.Base, pa)
			img.End = max(img.End, pa+vs)
		case 5:
			if sz != 184 || u32(c[8:]) != 4 || u32(c[12:]) != 42 {
				return nil, fmt.Errorf("darwin: unsupported UNIXTHREAD state")
			}
			if img.Entry != 0 {
				return nil, fmt.Errorf("darwin: duplicate entry")
			}
			var err error
			img.Entry, err = physical(u64(c[144:]))
			if err != nil {
				return nil, err
			}
		case 2:
			if sz != 24 || symtab != nil {
				return nil, fmt.Errorf("darwin: invalid symtab command")
			}
			symtab = c
		}
		off += sz
	}
	if off != end || len(img.Segments) == 0 || img.End-img.Base > MaxKernelSize {
		return nil, fmt.Errorf("darwin: invalid kernel layout")
	}
	mapped := false
	for _, s := range img.Segments {
		if img.Entry >= s.Address && img.Entry < s.Address+s.FileSize {
			mapped = true
		}
	}
	if !mapped {
		return nil, fmt.Errorf("darwin: entry outside file-backed segments")
	}
	if symtab != nil {
		so, ns, st, ss := uint64(u32(symtab[8:])), uint64(u32(symtab[12:])), uint64(u32(symtab[16:])), uint64(u32(symtab[20:]))
		if so > uint64(len(b)) || ns > (uint64(len(b))-so)/16 || st > uint64(len(b)) || ss > uint64(len(b))-st {
			return nil, fmt.Errorf("darwin: symbol table out of bounds")
		}
		for i := uint64(0); i < ns; i++ {
			s := b[so+i*16 : so+(i+1)*16]
			index := uint64(u32(s))
			if index >= ss {
				return nil, fmt.Errorf("darwin: invalid symbol string")
			}
			if s[4]&0xe0 != 0 || s[4]&0xe == 0 {
				continue
			}
			str := b[st+index : st+ss]
			zero := bytes.IndexByte(str, 0)
			if zero < 0 {
				return nil, fmt.Errorf("darwin: unterminated symbol")
			}
			img.Symbols[string(str[:zero])] = u64(s[8:])
		}
	}
	return img, nil
}

// Load validates destinations before writing and clears each zero-fill tail.
func (i *Image) Load(ram []byte) error {
	if i.End > uint64(len(ram)) {
		return fmt.Errorf("darwin: kernel exceeds RAM")
	}
	// Image fields are exported for inspection; reject changed or fabricated
	// ranges atomically instead of panicking or partially modifying RAM.
	for _, s := range i.Segments {
		if s.Address > uint64(len(ram)) || s.Size > uint64(len(ram))-s.Address || s.FileSize > s.Size || s.FileOffset > uint64(len(i.Data)) || s.FileSize > uint64(len(i.Data))-s.FileOffset {
			return fmt.Errorf("darwin: invalid load range")
		}
	}
	for _, s := range i.Segments {
		clear(ram[s.Address : s.Address+s.Size])
		copy(ram[s.Address:s.Address+s.FileSize], i.Data[s.FileOffset:s.FileOffset+s.FileSize])
	}
	return nil
}
