// Package cpio indexes ASCII CPIO archives without extracting their payloads.
package cpio

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() { auto.Register("cpio", 20, Open) }

// Open accepts newc (070701), checksum newc (070702), and odc (070707).
// Concatenated archives are applied in order; later paths replace earlier ones.
// Hardlinks share data within a trailer-delimited archive. Symlinks and device
// nodes are metadata only and are never followed or instantiated.
func Open(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
	if len(prefix) < 6 || !magic(string(prefix[:6])) {
		return nil, auto.ErrNoMatch
	}
	limit := options.MaxEntries
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
	read := func(off, n int64) ([]byte, error) {
		if off < 0 || n < 0 || off > size || n > size-off {
			return nil, io.ErrUnexpectedEOF
		}
		b := make([]byte, n)
		_, err := io.ReadFull(io.NewSectionReader(source, off, n), b)
		return b, err
	}
	count := 0
	for pos < size {
		// Never reread header bytes: compressed portable readers may have to replay
		// the entire stream for a backward read, even one of only a few bytes.
		first, err := read(pos, 1)
		if err != nil {
			return nil, err
		}
		if first[0] == 0 {
			pos++
			continue
		}
		rest, err := read(pos+1, 5)
		if err != nil {
			return nil, err
		}
		sig := string(append(first, rest...))
		if !magic(sig) {
			return nil, fmt.Errorf("cpio: invalid header at %d", pos)
		}
		headerSize := int64(110)
		if sig == "070707" {
			headerSize = 76
		}
		h, err := read(pos+6, headerSize-6)
		if err != nil {
			return nil, err
		}
		var fields []uint64
		if sig == "070707" {
			at := 0
			for _, width := range []int{6, 6, 6, 6, 6, 6, 6, 11, 6, 11} {
				v, e := number(h[at:at+width], 8)
				if e != nil {
					return nil, e
				}
				fields = append(fields, v)
				at += width
			}
		} else {
			for at := 0; at < len(h); at += 8 {
				v, e := number(h[at:at+8], 16)
				if e != nil {
					return nil, e
				}
				fields = append(fields, v)
			}
		}
		var ino, mode, uid, gid, nlink, mtime, length, dev, minor, rdev, rminor, namesize, check uint64
		if sig == "070707" {
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
		if sig != "070707" {
			dataOffset = (dataOffset + 3) &^ 3
		}
		if dataOffset > size || length > uint64(size-dataOffset) {
			return nil, fmt.Errorf("cpio: truncated payload %q", name)
		}
		pos = dataOffset + int64(length)
		if sig != "070707" {
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
			continue
		}
		count++
		if count > limit {
			return nil, auto.ErrLimit
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
		entry := auto.Entry{Name: name, Attributes: map[string]any{"mode": mode, "uid": uid, "gid": gid, "mtime": mtime, "inode": ino, "nlink": nlink, "device": dev, "device_minor": minor, "rdev": rdev, "rdev_minor": rminor}}
		var reader storage.Reader = io.NewSectionReader(source, dataOffset, int64(length))
		if sig == "070702" {
			reader = &checkedReader{Reader: reader, want: uint32(check)}
		}
		switch mode & 0170000 {
		case 0100000:
			entry.Kind = "file"
			entry.Reader = reader
		case 0040000:
			entry.Kind = "directory"
		case 0120000:
			if length > 65536 {
				return nil, auto.ErrLimit
			}
			target, e := io.ReadAll(io.NewSectionReader(reader, 0, int64(length)))
			if e != nil {
				return nil, e
			}
			entry.Kind = "symlink"
			entry.Attributes["target"] = string(target)
		case 0020000, 0060000, 0010000, 0140000:
			entry.Kind = "special"
		default:
			return nil, fmt.Errorf("cpio: unsupported mode %#o", mode)
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
	var selected []auto.Entry
	for i, e := range entries {
		if latest[e.Name] == i {
			selected = append(selected, e)
		}
	}
	return auto.Tree(selected, options)
}

func magic(s string) bool { return s == "070701" || s == "070702" || s == "070707" }
func number(b []byte, base int) (uint64, error) {
	// ParseUint accepts a leading +; ASCII CPIO numeric fields do not.
	for _, c := range b {
		if !(c >= '0' && c <= '7' || base == 16 && (c >= '8' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
			return 0, fmt.Errorf("cpio: invalid numeric field")
		}
	}
	return strconv.ParseUint(string(b), base, 64)
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
