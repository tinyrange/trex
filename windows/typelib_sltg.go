package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// SLTG stores type blocks in linked directory order, followed by a library
// block containing registration metadata and a shared name table. Only that
// metadata is decoded here; member signatures are outside the pe.typelibs API.
// Format reference: Wine dlls/oleaut32/typelib.h (SLTG_* structures).
type sltgReader struct {
	data []byte
	pos  int
	err  error
}

func (r *sltgReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.data)-r.pos {
		r.err = fmt.Errorf("truncated SLTG data at %#x (need %d bytes)", r.pos, n)
		return nil
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}
func (r *sltgReader) word() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}
func (r *sltgReader) dword() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}
func (r *sltgReader) text() string {
	n := r.word()
	if n == 0xffff {
		return ""
	}
	return string(r.take(int(n)))
}
func (r *sltgReader) guid() string {
	var raw [16]byte
	copy(raw[:], r.take(16))
	return windowsGUIDString(raw)
}

func parseSLTGTypeLib(data []byte) (msftTypeLib, error) {
	var lib msftTypeLib
	if len(data) < 0x24 || string(data[:4]) != "SLTG" {
		return lib, fmt.Errorf("invalid SLTG header")
	}
	n := int(binary.LittleEndian.Uint16(data[4:])) - 1
	if n < 1 {
		return lib, fmt.Errorf("empty SLTG block directory")
	}
	magic := 0x24 + n*8
	start := magic + 13 + (n-1)*11 + 9
	directoryEnd := start
	if start > len(data) || string(data[magic:magic+13]) != "\x01CompObj\x00dir\x00" {
		return lib, fmt.Errorf("invalid SLTG block directory")
	}
	order := int(binary.LittleEndian.Uint16(data[10:]))
	seen := make(map[int]bool)
	var blocks [][]byte
	var indices []string
	for order != 0 {
		if order > n || seen[order] {
			return lib, fmt.Errorf("invalid SLTG block chain at %d", order)
		}
		seen[order] = true
		entry := data[0x24+(order-1)*8:]
		length := int(binary.LittleEndian.Uint32(entry))
		if length < 0 || length > len(data)-start {
			return lib, fmt.Errorf("SLTG block %d exceeds input", order)
		}
		index := magic + int(binary.LittleEndian.Uint16(entry[4:]))
		if index >= directoryEnd {
			return lib, fmt.Errorf("SLTG index outside directory")
		}
		end := bytes.IndexByte(data[index:directoryEnd], 0)
		if end < 0 {
			return lib, fmt.Errorf("unterminated SLTG index")
		}
		indices = append(indices, string(data[index:index+end]))
		blocks = append(blocks, data[start:start+length])
		start += length
		order = int(binary.LittleEndian.Uint16(entry[6:]))
	}
	if len(blocks) != n {
		return lib, fmt.Errorf("incomplete SLTG block chain")
	}
	r := sltgReader{data: blocks[n-1]}
	if r.word() != 0x51cc {
		return lib, fmt.Errorf("invalid SLTG library block")
	}
	r.word()
	nameOffset := r.word()
	r.text()
	lib.description = r.text()
	r.text()  // Help file.
	r.dword() // Help context.
	lib.syskind = uint32(r.word())
	lib.language = uint32(r.word())
	// SLTG uses a neutral locale for localized libraries at registration time.
	if lib.language&0xfc00 == 0 {
		lib.lcid = lib.language
	}
	r.dword()
	lib.flags = uint32(r.word())
	lib.major, lib.minor = r.word(), r.word()
	lib.guid = r.guid()
	r.take(0x40)
	count := int(r.word())
	if r.err != nil {
		return lib, r.err
	}
	if count != n-1 {
		return lib, fmt.Errorf("SLTG type count %d does not match %d blocks", count, n-1)
	}
	names := make([]uint16, count)
	for i := 0; i < count; i++ {
		indexName := r.text()
		r.text()
		r.word()
		names[i] = r.word()
		r.take(int(r.word())) // Encoded help string.
		r.word()
		r.dword()
		r.word()
		guid := r.guid()
		r.word() // Kind is also stored in the type block header.
		if r.err != nil {
			return lib, r.err
		}
		if indexName != indices[i] {
			return lib, fmt.Errorf("SLTG type %d index mismatch", i)
		}
		block := blocks[i]
		if len(block) < 0x22 || binary.LittleEndian.Uint16(block) != 0x0501 {
			return lib, fmt.Errorf("invalid SLTG type block %d", i)
		}
		flags := uint32(block[0x1a]>>3) | uint32(block[0x1b])<<5
		kind := uint32(block[0x1d])
		if kind > 7 {
			return lib, fmt.Errorf("invalid SLTG type kind %d", kind)
		}
		if flags&msftTypeFlagDual != 0 {
			kind = msftTypeKindDispatch
		}
		lib.typeInfo = append(lib.typeInfo, msftTypeInfo{guid: guid, kind: kind, flags: flags})
	}
	table := int(r.dword())
	if r.err != nil {
		return lib, r.err
	}
	if table < 0 || table > len(r.data)-2 {
		return lib, fmt.Errorf("SLTG name table outside library")
	}
	switch binary.LittleEndian.Uint16(r.data[table:]) {
	case 0xffff:
	case 0x0200:
		table += 0x20
	default:
		return lib, fmt.Errorf("invalid SLTG name table header")
	}
	table += 0x218
	name := func(offset uint16) (string, error) {
		p := table + int(offset)
		if p >= len(r.data) {
			return "", fmt.Errorf("SLTG name outside table")
		}
		end := bytes.IndexByte(r.data[p:], 0)
		if end < 0 {
			return "", fmt.Errorf("unterminated SLTG name")
		}
		return string(r.data[p : p+end]), nil
	}
	var err error
	lib.name, err = name(nameOffset)
	if err != nil {
		return lib, err
	}
	if lib.description == "" {
		lib.description = lib.name
	}
	for i, offset := range names {
		lib.typeInfo[i].name, err = name(offset)
		if err != nil {
			return lib, err
		}
	}
	return lib, nil
}
