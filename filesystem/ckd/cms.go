package ckd

import (
	"bytes"
	"fmt"
)

// CMS enhanced disk format (EDF) minidisks on CKD volumes. A minidisk is a
// cylinder-aligned extent whose tracks hold fixed-size block records (record
// numbers 1..N per track; record zero excluded). Block n (1-based) lives on
// minidisk track (n-1)/N, record (n-1)%N+1. Block 3 holds the CMS1 label; the
// directory is itself a fixed-format file of 64-byte FSTs whose first entry
// describes the directory. Layout decoded from z/VM 4.4 ADCD media.

var cmsLabelMagic = []byte{0xc3, 0xd4, 0xe2, 0xf1} // "CMS1"

type CMSLabel struct {
	ID                          string
	BlockSize, DirectoryOrigin  uint32
	Cylinders, MaximumCylinders uint32
	Blocks, UsedBlocks          uint32
	FSTSize, FSTsPerBlock       uint32
	Created                     string // YYMMDDHHMMSS from packed BCD
	Flags                       byte
	Raw                         []byte
}

// CMSFile is one directory entry. Date is YYMMDDHHMMSS from the packed BCD
// field at offset 54; Century preserves byte 60 without interpretation.
// DataBlocks preserves the stored count; content length is derived from
// Records and the pointer tree instead.
type CMSFile struct {
	Name, Type, Mode             string
	RecordFormat, Flags, Century byte
	RecordLength                 uint32
	Origin, DataBlocks, Records  uint32
	Levels, PointerSize          byte
	Date                         string
	FST                          []byte
}

type CMSMinidisk struct {
	Disk           *Disk
	OriginTrack    uint32
	BlocksPerTrack uint32
	Label          CMSLabel
}

func bcd(b []byte) (string, error) {
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		if x>>4 > 9 || x&15 > 9 {
			return "", fmt.Errorf("cms: invalid packed date %x", b)
		}
		out = append(out, '0'+x>>4, '0'+x&15)
	}
	return string(out), nil
}

// OpenCMS reads the CMS1 label of the minidisk starting at cylinder. Blocks per
// track are the block-sized records on the minidisk's first track. extent, when
// nonzero, is the minidisk size in cylinders from an authoritative source such
// as the CP directory; the label must then fit within it. Without it, a label is
// trusted for its own size, which overlapping or stale labels can violate.
func OpenCMS(d *Disk, cylinder, extent uint32) (*CMSMinidisk, error) {
	origin := cylinder * d.Heads
	rs, err := d.Track(origin)
	if err != nil {
		return nil, err
	}
	var label []byte
	for _, r := range rs {
		if r.Number == 3 && len(r.Key) == 0 && len(r.Data) >= 64 && bytes.Equal(r.Data[:4], cmsLabelMagic) {
			label = r.Data
		}
	}
	if label == nil {
		return nil, fmt.Errorf("cms: no CMS1 label at cylinder %d", cylinder)
	}
	l := CMSLabel{ID: Identifier(label[4:10]), BlockSize: be.Uint32(label[12:]), DirectoryOrigin: be.Uint32(label[16:]),
		Cylinders: be.Uint32(label[20:]), MaximumCylinders: be.Uint32(label[24:]), Blocks: be.Uint32(label[28:]), UsedBlocks: be.Uint32(label[32:]),
		FSTSize: be.Uint32(label[36:]), FSTsPerBlock: be.Uint32(label[40:]), Flags: label[50], Raw: append([]byte(nil), label...)}
	if l.Created, err = bcd(label[44:50]); err != nil {
		return nil, err
	}
	switch l.BlockSize {
	case 512, 1024, 2048, 4096:
	default:
		return nil, fmt.Errorf("cms: unsupported block size %d", l.BlockSize)
	}
	if int(l.BlockSize) != len(label) || l.FSTSize != 64 || l.FSTsPerBlock != l.BlockSize/64 {
		return nil, fmt.Errorf("cms: unsupported label geometry %d/%d/%d", len(label), l.FSTSize, l.FSTsPerBlock)
	}
	m := &CMSMinidisk{Disk: d, OriginTrack: origin, Label: l}
	for i, r := range rs {
		if i > 0 && r.Number != byte(i) {
			return nil, fmt.Errorf("cms: track %d record %d out of sequence", origin, r.Number)
		}
		if r.Number > 0 {
			if len(r.Data) != int(l.BlockSize) || len(r.Key) != 0 {
				return nil, fmt.Errorf("cms: track %d record %d is not a %d-byte block", origin, r.Number, l.BlockSize)
			}
			m.BlocksPerTrack++
		}
	}
	if m.BlocksPerTrack < 3 || uint64(l.Blocks) > uint64(l.Cylinders)*uint64(d.Heads)*uint64(m.BlocksPerTrack) || l.DirectoryOrigin < 4 || l.DirectoryOrigin > l.Blocks || l.UsedBlocks > l.Blocks {
		return nil, fmt.Errorf("cms: label geometry does not fit minidisk")
	}
	if extent != 0 && (l.Cylinders > extent || uint64(cylinder)+uint64(extent) > 65536) {
		return nil, fmt.Errorf("cms: %d formatted cylinders exceed %d-cylinder extent", l.Cylinders, extent)
	}
	return m, nil
}

// Block returns an owned copy of block n.
func (m *CMSMinidisk) Block(n uint32) ([]byte, error) {
	if n == 0 || n > m.Label.Blocks {
		return nil, fmt.Errorf("cms: block %d outside minidisk of %d blocks", n, m.Label.Blocks)
	}
	t := m.OriginTrack + (n-1)/m.BlocksPerTrack
	rec := byte((n-1)%m.BlocksPerTrack + 1)
	rs, err := m.Disk.Track(t)
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		if r.Number == rec {
			if len(r.Data) != int(m.Label.BlockSize) || len(r.Key) != 0 {
				return nil, fmt.Errorf("cms: block %d has %d bytes", n, len(r.Data))
			}
			return r.Data, nil
		}
	}
	return nil, fmt.Errorf("cms: block %d missing from track %d", n, t)
}

func parseFST(b []byte) (CMSFile, error) {
	f := CMSFile{Name: Identifier(b[:8]), Type: Identifier(b[8:16]), Mode: Identifier(b[24:26]), RecordFormat: b[30], Flags: b[31],
		RecordLength: be.Uint32(b[32:]), Origin: be.Uint32(b[40:]), DataBlocks: be.Uint32(b[44:]), Records: be.Uint32(b[48:]),
		Levels: b[52], PointerSize: b[53], Century: b[60], FST: append([]byte(nil), b...)}
	var err error
	if f.Date, err = bcd(b[54:60]); err != nil {
		return f, err
	}
	switch {
	case f.RecordFormat == 0xc6 && f.PointerSize == 4: // F
	case f.RecordFormat == 0xe5 && f.PointerSize == 12: // V
	default:
		return f, fmt.Errorf("cms: %s %s: unsupported record format %02x with %d-byte pointers", f.Name, f.Type, f.RecordFormat, f.PointerSize)
	}
	if f.RecordLength == 0 || f.RecordLength > 65535 || f.Levels > 8 {
		return f, fmt.Errorf("cms: %s %s: invalid record length %d or %d levels", f.Name, f.Type, f.RecordLength, f.Levels)
	}
	return f, nil
}

// Files reads the directory through its own FST. The first two entries
// (the directory and allocation map) are returned like any other file.
func (m *CMSMinidisk) Files(limit int) ([]CMSFile, error) {
	return m.FilesAt(m.Label.DirectoryOrigin, limit)
}

// FilesAt reads a directory whose first block is origin, for inspecting the
// alternate directory copy rather than the one the label selects.
func (m *CMSMinidisk) FilesAt(origin uint32, limit int) ([]CMSFile, error) {
	b, err := m.Block(origin)
	if err != nil {
		return nil, err
	}
	dir, err := parseFST(b[:64])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(b[:8], []byte{0, 0, 0, 1, 0, 0, 0, 0}) || dir.Type != "DIRECTOR" || dir.RecordFormat != 0xc6 || dir.RecordLength != 64 {
		return nil, fmt.Errorf("cms: directory block does not begin with its own FST")
	}
	if int(dir.Records) > limit {
		return nil, fmt.Errorf("cms: %d directory entries exceed limit %d", dir.Records, limit)
	}
	data, err := m.Content(dir, int64(dir.Records)*64)
	if err != nil {
		return nil, fmt.Errorf("cms directory: %w", err)
	}
	// Directory data blocks are listed in pointer order; the first must be the
	// label's directory origin.
	if !bytes.Equal(data[:64], b[:64]) {
		return nil, fmt.Errorf("cms: directory origin is not the directory's first block")
	}
	out := make([]CMSFile, 0, dir.Records)
	for i := 0; i < int(dir.Records); i++ {
		f, err := parseFST(data[64*i : 64*i+64])
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// Content returns the logical stored bytes of f, bounded by maximumBytes.
// Fixed files are Records*RecordLength bytes with unallocated (zero) pointers
// (at any level) read as zero blocks. Variable files are the verbatim stream of 2-byte length
// prefixed records through record Records; every pointer's last-record number
// and first-record displacement is checked against the stream.
func (m *CMSMinidisk) Content(f CMSFile, maximumBytes int64) ([]byte, error) {
	bs := int64(m.Label.BlockSize)
	if f.RecordFormat == 0xc6 {
		size := int64(f.Records) * int64(f.RecordLength)
		if size > maximumBytes {
			return nil, fmt.Errorf("cms: %s %s: %d bytes exceed limit", f.Name, f.Type, size)
		}
		blocks := (size + bs - 1) / bs
		out := make([]byte, 0, blocks*bs)
		err := m.walkFixed(f.Origin, int(f.Levels), &blocks, &out)
		if err != nil {
			return nil, fmt.Errorf("cms: %s %s: %w", f.Name, f.Type, err)
		}
		if blocks != 0 {
			return nil, fmt.Errorf("cms: %s %s: pointer tree ends %d blocks early", f.Name, f.Type, blocks)
		}
		return out[:size], nil
	}
	v := &variableWalk{m: m, f: f, limit: maximumBytes}
	if f.Records == 0 {
		return []byte{}, nil
	}
	if err := v.walk(f.Origin, int(f.Levels), f.Records, 0); err != nil {
		return nil, fmt.Errorf("cms: %s %s: %w", f.Name, f.Type, err)
	}
	if v.records != f.Records || v.need != 0 {
		return nil, fmt.Errorf("cms: %s %s: stream ends after %d of %d records", f.Name, f.Type, v.records, f.Records)
	}
	return v.out, nil
}

func (m *CMSMinidisk) walkFixed(block uint32, level int, remaining *int64, out *[]byte) error {
	if *remaining == 0 {
		return nil
	}
	if block == 0 {
		// An unallocated pointer at level L stands for (blocksize/4)^L zero
		// data blocks, bounded by the blocks the file still needs.
		span := int64(1)
		for i := 0; i < level && span < *remaining; i++ {
			span *= int64(m.Label.BlockSize / 4)
		}
		span = min(span, *remaining)
		*out = append(*out, make([]byte, span*int64(m.Label.BlockSize))...)
		*remaining -= span
		return nil
	}
	b, err := m.Block(block)
	if err != nil {
		return err
	}
	if level == 0 {
		*out = append(*out, b...)
		*remaining--
		return nil
	}
	for i := 0; i+4 <= len(b) && *remaining > 0; i += 4 {
		if err := m.walkFixed(be.Uint32(b[i:]), level-1, remaining, out); err != nil {
			return err
		}
	}
	return nil
}

type variableWalk struct {
	m       *CMSMinidisk
	f       CMSFile
	limit   int64
	out     []byte
	records uint32 // records begun so far
	need    int    // bytes still owed to the current length prefix or record
	header  bool   // need counts length-prefix bytes
	prefix  []byte
}

func (v *variableWalk) done() bool { return v.records == v.f.Records && v.need == 0 }

// walk follows a variable-file pointer tree. Each 12-byte entry names a block,
// the number of the last record that begins in it (or its subtree), and, for
// data blocks, the displacement of the first record beginning in it
// (0xffffffff when none does; the end of data in a final block where none
// does). Upper entries carry 0, or 0xffffffff for a subtree in which no record
// begins. Data block zero is an unallocated zero block.
func (v *variableWalk) walk(block uint32, level int, last, displacement uint32) error {
	var b []byte
	var err error
	if block == 0 && level == 0 {
		// Unallocated data blocks are all zero; they occur inside long records.
		b = make([]byte, v.m.Label.BlockSize)
	} else if b, err = v.m.Block(block); err != nil {
		return err
	}
	if level == 0 {
		return v.data(b, last, displacement)
	}
	for i := 0; i+12 <= len(b) && !v.done(); i += 12 {
		child, childLast, childDisp := be.Uint32(b[i:]), be.Uint32(b[i+4:]), be.Uint32(b[i+8:])
		if (child == 0 && level > 1) || childLast < v.records || childLast > v.f.Records {
			return fmt.Errorf("invalid pointer %d/%d/%d after record %d", child, childLast, childDisp, v.records)
		}
		// An upper pointer's displacement is 0xffffffff when no record begins
		// anywhere in its subtree, otherwise 0.
		if level > 1 && !((childDisp == 0xffffffff && childLast == v.records) || (childDisp == 0 && childLast > v.records)) {
			return fmt.Errorf("upper pointer %d/%d/%d inconsistent after record %d", child, childLast, int32(childDisp), v.records)
		}
		if err := v.walk(child, level-1, childLast, childDisp); err != nil {
			return err
		}
		if v.records != childLast {
			return fmt.Errorf("subtree ends at record %d, pointer says %d", v.records, childLast)
		}
	}
	return nil
}

// data consumes one block. A record begins where its length prefix begins.
func (v *variableWalk) data(b []byte, last, displacement uint32) error {
	pos, first := 0, -1
	for pos < len(b) && !v.done() {
		if v.need == 0 {
			if v.records == v.f.Records {
				break
			}
			if first < 0 {
				first = pos
			}
			v.records++
			v.header, v.need, v.prefix = true, 2, v.prefix[:0]
		}
		n := min(v.need, len(b)-pos)
		if int64(len(v.out)+n) > v.limit {
			return fmt.Errorf("content exceeds limit")
		}
		v.out = append(v.out, b[pos:pos+n]...)
		if v.header {
			v.prefix = append(v.prefix, b[pos:pos+n]...)
		}
		pos += n
		v.need -= n
		if v.need == 0 && v.header {
			length := int(be.Uint16(v.prefix))
			if length == 0 || length > int(v.f.RecordLength) {
				return fmt.Errorf("record %d length %d exceeds LRECL %d", v.records, length, v.f.RecordLength)
			}
			v.header, v.need = false, length
		}
	}
	// Displacement 0xffffffff marks a block in which no record begins, except
	// that a final such block records where the data ends instead.
	if (first < 0 && displacement != 0xffffffff && !(v.done() && uint32(pos) == displacement)) || (first >= 0 && uint32(first) != displacement) {
		return fmt.Errorf("first record begins at %d, pointer says %d", first, int32(displacement))
	}
	if v.records != last {
		return fmt.Errorf("block ends after record %d, pointer says %d", v.records, last)
	}
	return nil
}
