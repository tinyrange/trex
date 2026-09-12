// Package bff reads AIX by-name backup archives into portable file views.
package bff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path"
	"strings"

	"github.com/tinyrange/trex/archive/compressed"
	starfile "github.com/tinyrange/trex/storage/star"
)

const (
	headerUnit         = 8
	ordinaryMagic      = 60011
	packedMagic        = 60012
	volumeRecord       = 0
	endRecord          = 7
	extendedNameRecord = 11
	extendedNameOffset = 64
	volumeHeaderSize   = 72
	distributionBlock  = 1024
)

type Entry struct {
	Path, Kind                                           string
	Name                                                 []byte
	Offset                                               int64
	Inode, Mode, UID, GID                                uint32
	Links                                                uint16
	Accessed, Modified, Changed                          uint32
	DeviceMajor, DeviceMinor, SpecialMajor, SpecialMinor uint32
	Packed                                               bool
	Header, ACL, PCL, Stored, Data                       starfile.File
}

type Archive struct {
	Entries                         []Entry
	Date, PreviousDate, VolumeWords uint32
	Volume                          uint16
	Disk, Filesystem, User          []byte
	Header, Trailer                 starfile.File
}

// HeaderChecksum covers all declared header bytes, including padding. Its
// checksum word is treated as zero. This byte transform was independently
// derived from the original AIX 4.1.5 restbyname checksum routine and verified
// on 733 development-package headers and independent update packages.
func HeaderChecksum(header []byte) uint16 {
	var sum uint16
	for i, b := range header {
		if i != 4 && i != 5 {
			sum += uint16(uint32(b) << (b & 7))
		}
	}
	return sum
}

// Open validates a single-volume by-name archive with AIX extended name
// records. Stored data and security records stay borrowed; packed bodies are
// decoded in memory. No permissions, accounts or installer scripts are applied.
func Open(file starfile.File, maximumEntries int, maximumDecodedBytes int64) (*Archive, error) {
	if file.Size() < volumeHeaderSize || maximumEntries < 1 || maximumDecodedBytes < 0 {
		return nil, fmt.Errorf("bff: invalid input or limits")
	}
	slice := func(off, size int64) starfile.File { return &starfile.Slice{Base: file, Offset: off, Length: size} }
	read := func(off, size int64) ([]byte, error) {
		if off < 0 || size < 0 || off > file.Size() || size > file.Size()-off {
			return nil, fmt.Errorf("bff: range outside input at %d", off)
		}
		b := make([]byte, size)
		_, err := starfile.ReadFullAt(file, b, off)
		return b, err
	}
	le := binary.LittleEndian
	a := &Archive{}
	remaining := maximumDecodedBytes
	for off := int64(0); off < file.Size(); {
		short, err := read(off, headerUnit)
		if err != nil {
			return nil, err
		}
		length := int64(short[0]) * headerUnit
		if length < headerUnit {
			return nil, fmt.Errorf("bff: invalid header length at %d", off)
		}
		h, err := read(off, length)
		if err != nil {
			return nil, err
		}
		magic := le.Uint16(h[2:])
		if magic != ordinaryMagic && magic != packedMagic {
			return nil, fmt.Errorf("bff: invalid magic at %d", off)
		}
		if HeaderChecksum(h) != le.Uint16(h[4:]) {
			return nil, fmt.Errorf("bff: header checksum mismatch at %d", off)
		}
		kind := h[1]
		if off == 0 {
			if kind != volumeRecord || length != volumeHeaderSize || le.Uint16(h[68:]) != 100 {
				return nil, fmt.Errorf("bff: expected by-name volume header")
			}
			a.Volume = le.Uint16(h[6:])
			if a.Volume != 1 {
				return nil, fmt.Errorf("bff: continuation volume requires prior input")
			}
			a.Date, a.PreviousDate, a.VolumeWords = le.Uint32(h[8:]), le.Uint32(h[12:]), le.Uint32(h[16:])
			a.Disk = bytes.TrimRight(h[20:36], "\x00")
			a.Filesystem = bytes.TrimRight(h[36:52], "\x00")
			a.User = bytes.TrimRight(h[52:68], "\x00")
			a.Header = slice(0, length)
			off += length
			continue
		}
		if kind == endRecord {
			if length != headerUnit {
				return nil, fmt.Errorf("bff: invalid end record")
			}
			end := off + length
			trailing := file.Size() - end
			// Standalone distribution archives round their last physical block to
			// 1024 bytes. Those unused bytes can be nonzero; retain, never decode them.
			if trailing >= distributionBlock || (trailing != 0 && file.Size()%distributionBlock != 0) {
				return nil, fmt.Errorf("bff: unsupported data after end record")
			}
			a.Trailer = slice(end, trailing)
			return a, nil
		}
		if kind != extendedNameRecord {
			return nil, fmt.Errorf("bff: unsupported record type %d at %d", kind, off)
		}
		if length <= extendedNameOffset {
			return nil, fmt.Errorf("bff: short extended name header")
		}
		if len(a.Entries) >= maximumEntries {
			return nil, fmt.Errorf("bff: entry limit")
		}
		rawName := h[extendedNameOffset:]
		n := bytes.IndexByte(rawName, 0)
		if n <= 0 {
			return nil, fmt.Errorf("bff: missing terminated name")
		}
		name := string(rawName[:n])
		if strings.Contains(name, "\\") {
			return nil, fmt.Errorf("bff: unsupported backslash in path")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return nil, fmt.Errorf("bff: unsafe path %q", name)
			}
		}
		e := Entry{Path: path.Clean("/" + name), Name: bytes.Clone(rawName[:n]), Offset: off, Links: le.Uint16(h[6:]), Inode: le.Uint32(h[8:]), Mode: le.Uint32(h[12:]), UID: le.Uint32(h[16:]), GID: le.Uint32(h[20:]), Accessed: le.Uint32(h[28:]), Modified: le.Uint32(h[32:]), Changed: le.Uint32(h[36:]), DeviceMajor: le.Uint32(h[40:]), DeviceMinor: le.Uint32(h[44:]), SpecialMajor: le.Uint32(h[48:]), SpecialMinor: le.Uint32(h[52:]), Packed: magic == packedMagic, Header: slice(off, length)}
		switch e.Mode & 0170000 {
		case 0100000:
			e.Kind = "file"
		case 0040000:
			e.Kind = "directory"
		case 0120000:
			e.Kind = "symlink"
		case 0020000:
			e.Kind = "character"
		case 0060000:
			e.Kind = "block"
		case 0010000:
			e.Kind = "fifo"
		case 0140000:
			e.Kind = "socket"
		default:
			return nil, fmt.Errorf("bff: unsupported file mode %#o", e.Mode)
		}
		logical, stored := int64(le.Uint32(h[24:])), int64(le.Uint32(h[56:]))
		sec := off + length
		sizes, err := read(sec, 8)
		if err != nil {
			return nil, err
		}
		acl, pcl := int64(le.Uint32(sizes))*8, int64(le.Uint32(sizes[4:]))*8
		pos := sec + 8
		for i, size := range []int64{acl, pcl} {
			if size > file.Size()-pos {
				return nil, fmt.Errorf("bff: security record outside input")
			}
			if size != 0 {
				prefix, err := read(pos, 4)
				if err != nil {
					return nil, err
				}
				actual := int64(le.Uint32(prefix))
				if actual < 4 || actual > size || (actual+7)/8*8 != size {
					return nil, fmt.Errorf("bff: inconsistent security record length")
				}
			}
			if i == 0 {
				e.ACL = slice(pos, size)
			} else {
				e.PCL = slice(pos, size)
			}
			pos += size
		}
		if stored > file.Size()-pos {
			return nil, fmt.Errorf("bff: stored payload outside input")
		}
		e.Stored = slice(pos, stored)
		if e.Packed {
			if logical > remaining {
				return nil, fmt.Errorf("bff: decoded byte limit")
			}
			decoded, err := compressed.OpenPackBody(e.Stored, uint32(logical), remaining)
			if err != nil {
				return nil, fmt.Errorf("bff: %s: %w", e.Path, err)
			}
			e.Data = decoded
			remaining -= logical
		} else {
			if logical != stored {
				return nil, fmt.Errorf("bff: inconsistent uncompressed size for %s", e.Path)
			}
			e.Data = e.Stored
		}
		a.Entries = append(a.Entries, e)
		off = (pos + stored + 7) / 8 * 8
		if off > file.Size() {
			return nil, fmt.Errorf("bff: missing payload alignment")
		}
	}
	return nil, fmt.Errorf("bff: missing end record")
}
