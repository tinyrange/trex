// Package cpio indexes ASCII and Cray binary CPIO archives without extracting their payloads.
package cpio

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() { auto.Register("cpio", 20, Open) }

// Open accepts newc (070701), checksum newc (070702), odc (070707),
// and the UNICOS Cray binary format (19 big-endian 64-bit words).
// Concatenated archives are applied in order; later paths replace earlier ones.
// Hardlinks share data within a trailer-delimited archive. Symlinks and device
// nodes are metadata only and are never followed or instantiated.
func Open(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
	if !archiveMagic(prefix) {
		return nil, auto.ErrNoMatch
	}
	entries, err := Read(source, options.MaxEntries)
	if err != nil {
		return nil, err
	}
	return auto.Tree(entries, options)
}

// Read indexes the flat archive directly, retaining borrowed payloads and Unix
// metadata. Later duplicate paths replace earlier ones; archive identifies the
// trailer-delimited hardlink namespace. No directory adapter is constructed.
func Read(source storage.Reader, limit int) ([]auto.Entry, error) {
	if source == nil || source.Size() < 0 {
		return nil, fmt.Errorf("cpio: invalid source")
	}
	if limit <= 0 {
		limit = 100000
	}
	size := source.Size()
	var pos int64
	var entries []auto.Entry
	latest := map[string]int{}
	type linkKey struct{ dev, minor, ino uint64 }
	type linkGroup struct {
		members []int
		data    storage.Reader
	}
	links := map[linkKey]*linkGroup{}
	finish := func() {
		for _, g := range links {
			if g.data != nil {
				for _, i := range g.members {
					entries[i].Reader = g.data
				}
			}
		}
		links = map[linkKey]*linkGroup{}
	}
	metadata := metadataReader{source: source, size: size}
	read := metadata.read
	prefix, err := read(0, min(int64(8), size))
	if err != nil {
		return nil, err
	}
	if !archiveMagic(prefix) {
		return nil, auto.ErrNoMatch
	}
	count := 0
	var archive uint64
	afterTrailer := false
	for pos < size {
		signature, err := read(pos, min(int64(8), size-pos))
		if err != nil {
			return nil, err
		}
		cray := crayMagic(signature)
		if !archiveMagic(signature) {
			if signature[0] == 0 {
				padding, err := read(pos, min(int64(metadataBuffer), size-pos))
				if err != nil {
					return nil, err
				}
				n := 0
				for n < len(padding) && padding[n] == 0 {
					n++
				}
				// Keep seven bytes: a Cray signature begins with six zeros.
				if n == len(padding) && pos+int64(n) == size {
					break
				}
				pos += int64(max(1, n-7))
				continue
			}
			// Old cpio writers can leave arbitrary bytes in the final output
			// block. Only a recognized next header starts a concatenated archive.
			if afterTrailer {
				break
			}
			return nil, fmt.Errorf("cpio: invalid header at %d", pos)
		}
		afterTrailer = false
		sig := "cray"
		headerSize := int64(152)
		if !cray {
			sig = string(signature[:6])
			headerSize = 110
			if sig == "070707" {
				headerSize = 76
			}
		}
		h, err := read(pos, headerSize)
		if err != nil {
			return nil, err
		}
		var fields [19]uint64
		if cray {
			for i := range fields {
				fields[i] = binary.BigEndian.Uint64(h[i*8 : i*8+8])
			}
		} else if sig == "070707" {
			h = h[6:]
			at := 0
			for index, width := range [...]int{6, 6, 6, 6, 6, 6, 6, 11, 6, 11} {
				v, e := number(h[at:at+width], 8)
				if e != nil {
					return nil, e
				}
				fields[index] = v
				at += width
			}
		} else {
			h = h[6:]
			for at := 0; at < len(h); at += 8 {
				v, e := number(h[at:at+8], 16)
				if e != nil {
					return nil, e
				}
				fields[at/8] = v
			}
		}
		var ino, mode, uid, gid, nlink, mtime, length, dev, minor, rdev, rminor, namesize, check uint64
		if cray {
			dev, ino, mode, uid, gid, nlink, rdev = fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7]
			mtime, namesize, length = fields[16], fields[17], fields[18]
		} else if sig == "070707" {
			dev, ino, mode, uid, gid, nlink, rdev, mtime, namesize, length = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8], fields[9]
		} else {
			ino, mode, uid, gid, nlink, mtime, length, dev, minor, rdev, rminor, namesize, check = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8], fields[9], fields[10], fields[11], fields[12]
			if sig == "070701" && check != 0 {
				return nil, fmt.Errorf("cpio: nonzero newc checksum")
			}
		}
		if namesize == 0 || namesize > 65536 {
			return nil, fmt.Errorf("cpio: invalid name size")
		}
		nameBytes, err := read(pos+headerSize, int64(namesize))
		if err != nil {
			return nil, err
		}
		end := bytes.IndexByte(nameBytes, 0)
		if end <= 0 || len(bytes.Trim(nameBytes[end:], "\x00")) != 0 {
			return nil, fmt.Errorf("cpio: invalid name terminator")
		}
		name := string(nameBytes[:end])
		dataOffset := pos + headerSize + int64(namesize)
		if !cray && sig != "070707" {
			dataOffset = (dataOffset + 3) &^ 3
		}
		if dataOffset > size || length > uint64(size-dataOffset) {
			return nil, fmt.Errorf("cpio: truncated payload %q", name)
		}
		pos = dataOffset + int64(length)
		if !cray && sig != "070707" {
			pos = (pos + 3) &^ 3
		}
		if pos > size {
			return nil, fmt.Errorf("cpio: truncated alignment padding")
		}
		if name == "TRAILER!!!" {
			if length != 0 || check != 0 {
				return nil, fmt.Errorf("cpio: invalid trailer")
			}
			finish()
			archive++
			afterTrailer = true
			continue
		}
		count++
		if count > limit {
			return nil, fmt.Errorf("cpio: entry limit %d at %q (offset %d): %w", limit, name, dataOffset, auto.ErrLimit)
		}
		if strings.HasPrefix(name, "/") {
			return nil, fmt.Errorf("cpio: absolute path")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return nil, fmt.Errorf("cpio: parent path component")
			}
		}
		name = path.Clean(name)
		if name == "." {
			if mode&0170000 != 0040000 || length != 0 {
				return nil, fmt.Errorf("cpio: invalid root entry")
			}
			continue
		}
		entry := auto.Entry{Name: name, Attributes: map[string]any{"archive": archive, "mode": mode, "uid": uid, "gid": gid, "mtime": mtime, "inode": ino, "nlink": nlink, "device": dev, "device_minor": minor, "rdev": rdev, "rdev_minor": rminor}}
		var reader storage.Reader = io.NewSectionReader(source, dataOffset, int64(length))
		if sig == "070702" {
			reader = &checkedReader{Reader: reader, want: uint32(check)}
		}
		kind := mode & 0170000
		// UNICOS uses 0130000 for symbolic links; retain its original mode.
		if cray && kind == 0130000 {
			kind = 0120000
		}
		switch kind {
		case 0100000:
			entry.Kind = "file"
			entry.Reader = reader
		case 0040000:
			entry.Kind = "directory"
		case 0120000:
			if length > 65536 {
				return nil, auto.ErrLimit
			}
			target, e := read(dataOffset, int64(length))
			if e != nil {
				return nil, e
			}
			if sig == "070702" {
				var sum uint32
				for _, b := range target {
					sum += uint32(b)
				}
				if sum != uint32(check) {
					return nil, fmt.Errorf("cpio: checksum mismatch for symlink %q", name)
				}
			}
			entry.Kind = "symlink"
			entry.Attributes["target"] = string(target)
		case 0020000, 0060000, 0010000, 0140000:
			entry.Kind = "special"
		default:
			return nil, fmt.Errorf("cpio: unsupported mode %#o for %q at %d", mode, name, dataOffset)
		}
		if entry.Kind != "file" && entry.Kind != "symlink" && (length != 0 || check != 0) {
			return nil, fmt.Errorf("cpio: nonempty special entry")
		}
		if entry.Kind == "file" && nlink > 1 {
			key := linkKey{dev, minor, ino}
			g := links[key]
			if g == nil {
				g = &linkGroup{}
				links[key] = g
			}
			if length > 0 {
				g.data = reader
			}
			g.members = append(g.members, len(entries))
		}
		latest[name] = len(entries)
		entries = append(entries, entry)
	}
	finish()
	selected := entries[:0]
	for i, e := range entries {
		if latest[e.Name] == i {
			selected = append(selected, e)
		}
	}
	clear(entries[len(selected):])
	return selected, nil
}

func crayMagic(b []byte) bool {
	return len(b) >= 8 && binary.BigEndian.Uint64(b[:8]) == 070707
}
func archiveMagic(b []byte) bool {
	return crayMagic(b) || len(b) >= 6 && magic(string(b[:6]))
}
func magic(s string) bool { return s == "070701" || s == "070702" || s == "070707" }
func number(b []byte, base int) (uint64, error) {
	// CPIO fields have at most eleven octal or eight hexadecimal digits, so
	// validated input cannot overflow uint64. Reject signs and spaces.
	var value uint64
	for _, c := range b {
		var digit byte
		switch {
		case c >= '0' && c <= '9':
			digit = c - '0'
		case c >= 'a' && c <= 'f':
			digit = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			digit = c - 'A' + 10
		default:
			return 0, fmt.Errorf("cpio: invalid numeric field")
		}
		if int(digit) >= base {
			return 0, fmt.Errorf("cpio: invalid numeric field")
		}
		value = value*uint64(base) + uint64(digit)
	}
	return value, nil
}

type checkedReader struct {
	storage.Reader
	want uint32
	once sync.Once
	err  error
}

func (r *checkedReader) ReadAt(p []byte, off int64) (int, error) {
	r.once.Do(func() {
		var sum uint32
		b := make([]byte, 32768)
		for pos := int64(0); pos < r.Size(); {
			n := min(int64(len(b)), r.Size()-pos)
			if _, r.err = io.ReadFull(io.NewSectionReader(r.Reader, pos, n), b[:n]); r.err != nil {
				return
			}
			for _, c := range b[:n] {
				sum += uint32(c)
			}
			pos += n
		}
		if sum != r.want {
			r.err = fmt.Errorf("cpio: checksum mismatch")
		}
	})
	if r.err != nil {
		return 0, r.err
	}
	return r.Reader.ReadAt(p, off)
}
