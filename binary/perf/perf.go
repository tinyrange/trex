package perf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"

	"github.com/tinyrange/trex/storage"
)

// Format references (Linux v6.11): include/uapi/linux/perf_event.h,
// tools/perf/util/header.h and tools/lib/perf/include/perf/event.h.
const supportedSamples = SampleIP | SampleTID | SampleTime | SampleAddress | SampleID | SampleCPU | SamplePeriod | SampleStreamID | SampleIdentifier
const identitySamples = SampleTID | SampleTime | SampleID | SampleStreamID | SampleCPU | SampleIdentifier

var le = binary.LittleEndian

type section struct{ offset, size uint64 }
type parser struct {
	r       storage.Reader
	size    uint64
	spans   []section
	strings int
	options Options
	result  *File
}

func (p *parser) read(offset uint64, b []byte) error {
	if offset > p.size || uint64(len(b)) > p.size-offset {
		return fmt.Errorf("perf: read outside input at %#x", offset)
	}
	n, err := p.r.ReadAt(b, int64(offset))
	if n != len(b) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("perf: read at %#x: %w", offset, err)
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("perf: read at %#x: %w", offset, err)
	}
	return nil
}

func getSection(b []byte) section { return section{le.Uint64(b), le.Uint64(b[8:])} }

func (p *parser) reserve(s section) error {
	if s.offset > p.size || s.size > p.size-s.offset {
		return fmt.Errorf("perf: section outside input at %#x size %#x", s.offset, s.size)
	}
	if s.size == 0 {
		return nil
	}
	for _, old := range p.spans {
		if s.offset < old.offset+old.size && old.offset < s.offset+s.size {
			return fmt.Errorf("perf: overlapping sections at %#x and %#x", s.offset, old.offset)
		}
	}
	p.spans = append(p.spans, s)
	return nil
}

// Open reads a completed regular perf.data file. Fixed-width IP sampling fields
// and homogeneous attribute layouts are supported. Unsupported sample fields,
// byte orders, pipe/auxiliary/compressed streams fail explicitly. Metadata
// feature payloads are extent-checked but not interpreted. No symbols are read
// from the host, and record order is preserved through byte offsets.
func Open(r storage.Reader, options Options) (*File, error) {
	if options.MaximumRecords == 0 {
		options.MaximumRecords = 1000000
	}
	if options.MaximumSamples == 0 {
		options.MaximumSamples = 1000000
	}
	if options.MaximumStringBytes == 0 {
		options.MaximumStringBytes = 1 << 20
	}
	if options.MaximumRecords < 1 || options.MaximumRecords > 10000000 || options.MaximumSamples < 1 || options.MaximumSamples > 10000000 || options.MaximumStringBytes < 1 || options.MaximumStringBytes > 64<<20 {
		return nil, fmt.Errorf("perf: limits must be positive; records/samples at most 10000000 and strings at most 64 MiB")
	}
	if r == nil || r.Size() < 104 {
		return nil, fmt.Errorf("perf: truncated PERFILE2 header")
	}
	p := &parser{r: r, size: uint64(r.Size()), options: options, result: &File{LittleEndian: true, UnknownRecords: make(map[uint32]uint64)}}
	var h [104]byte
	if err := p.read(0, h[:]); err != nil {
		return nil, err
	}
	if string(h[:8]) != "PERFILE2" || le.Uint64(h[8:]) != 104 {
		return nil, fmt.Errorf("perf: expected little-endian regular PERFILE2 header (104 bytes); pipe and other byte orders are unsupported")
	}
	attrSize := le.Uint64(h[16:])
	attrs, data, eventTypes := getSection(h[24:]), getSection(h[40:]), getSection(h[56:])
	if attrSize < 80 || attrSize > 4096 || attrs.size == 0 || attrs.size%attrSize != 0 || attrs.size/attrSize > 4096 {
		return nil, fmt.Errorf("perf: invalid or over-limit attribute table")
	}
	if data.size == 0 {
		return nil, fmt.Errorf("perf: empty/unfinalized data section")
	}
	for _, s := range []section{{0, 104}, attrs, data, eventTypes} {
		if err := p.reserve(s); err != nil {
			return nil, err
		}
	}
	// Feature descriptors follow the data section, one per set bit. Reject
	// container variants whose event stream is not represented by data alone.
	features := 0
	for i := 0; i < 4; i++ {
		mask := le.Uint64(h[72+i*8:])
		if i == 0 && mask&((1<<18)|(1<<24)|(1<<27)) != 0 {
			return nil, fmt.Errorf("perf: AUX, directory and compressed captures are unsupported")
		}
		features += bits.OnesCount64(mask)
	}
	if features != 0 {
		table := section{data.offset + data.size, uint64(features * 16)}
		if err := p.reserve(table); err != nil {
			return nil, err
		}
		b := make([]byte, features*16)
		if err := p.read(table.offset, b); err != nil {
			return nil, err
		}
		for i := 0; i < features; i++ {
			if err := p.reserve(getSection(b[i*16:])); err != nil {
				return nil, err
			}
		}
	}
	if err := p.attributes(attrs, int(attrSize)); err != nil {
		return nil, err
	}
	if err := p.records(data); err != nil {
		return nil, err
	}
	return p.result, nil
}

func (p *parser) attributes(table section, size int) error {
	row := make([]byte, size)
	ids := make(map[uint64]bool)
	totalIDs := uint64(0)
	for off := table.offset; off < table.offset+table.size; off += uint64(size) {
		if err := p.read(off, row); err != nil {
			return err
		}
		a := Attribute{Type: le.Uint32(row), Size: le.Uint32(row[4:]), Config: le.Uint64(row[8:]), SamplePeriod: le.Uint64(row[16:]), SampleType: le.Uint64(row[24:]), ReadFormat: le.Uint64(row[32:]), Flags: le.Uint64(row[40:])}
		if a.Size < 64 || uint64(a.Size) != uint64(size-16) {
			return fmt.Errorf("perf: unsupported attribute size at %#x", off)
		}
		if a.SampleType&^supportedSamples != 0 {
			return fmt.Errorf("perf: unsupported sample_type %#x", a.SampleType)
		}
		a.SampleIDAll, a.UseClockID = a.Flags&(1<<18) != 0, a.Flags&(1<<25) != 0
		if a.UseClockID && a.Size < 96 {
			return fmt.Errorf("perf: clock_id missing from attribute")
		}
		if a.Size >= 96 {
			a.ClockID = int32(le.Uint32(row[92:]))
		}
		if len(p.result.Attributes) != 0 {
			first := p.result.Attributes[0]
			if a.SampleType != first.SampleType || a.SampleIDAll != first.SampleIDAll || a.UseClockID != first.UseClockID || a.UseClockID && a.ClockID != first.ClockID {
				return fmt.Errorf("perf: heterogeneous sample layouts or clock domains are unsupported")
			}
		}
		idSection := getSection(row[size-16:])
		if idSection.size%8 != 0 || idSection.size/8 > 1000000-totalIDs {
			return fmt.Errorf("perf: invalid or over-limit event IDs")
		}
		totalIDs += idSection.size / 8
		if err := p.reserve(idSection); err != nil {
			return err
		}
		idBytes := make([]byte, int(idSection.size))
		if err := p.read(idSection.offset, idBytes); err != nil {
			return err
		}
		for i := 0; i < len(idBytes); i += 8 {
			id := le.Uint64(idBytes[i:])
			if ids[id] {
				return fmt.Errorf("perf: duplicate event ID %d", id)
			}
			ids[id] = true
			a.IDs = append(a.IDs, id)
		}
		p.result.Attributes = append(p.result.Attributes, a)
	}
	return nil
}

func parseFields(b []byte, mask uint64, trailer bool) (Fields, error) {
	f := Fields{Present: mask}
	if len(b) != bits.OnesCount64(mask)*8 {
		return f, fmt.Errorf("perf: sample payload size %d does not match sample_type %#x", len(b), mask)
	}
	next := func() uint64 { v := le.Uint64(b); b = b[8:]; return v }
	if !trailer && mask&SampleIdentifier != 0 {
		f.Identifier = next()
	}
	if mask&SampleIP != 0 {
		f.IP = next()
	}
	if mask&SampleTID != 0 {
		f.PID, f.TID = le.Uint32(b), le.Uint32(b[4:])
		b = b[8:]
	}
	if mask&SampleTime != 0 {
		f.Time = next()
	}
	if mask&SampleAddress != 0 {
		f.Address = next()
	}
	if mask&SampleID != 0 {
		f.ID = next()
	}
	if mask&SampleStreamID != 0 {
		f.StreamID = next()
	}
	if mask&SampleCPU != 0 {
		f.CPU = le.Uint32(b)
		b = b[8:]
	}
	if mask&SamplePeriod != 0 {
		f.Period = next()
	}
	if trailer && mask&SampleIdentifier != 0 {
		f.Identifier = next()
	}
	if mask&(SampleID|SampleIdentifier) == SampleID|SampleIdentifier && f.ID != f.Identifier {
		return f, fmt.Errorf("perf: conflicting sample ID and identifier")
	}
	return f, nil
}

func (p *parser) name(b []byte) (string, error) {
	end := bytes.IndexByte(b, 0)
	if end < 0 {
		return "", fmt.Errorf("perf: unterminated record string")
	}
	if end > p.options.MaximumStringBytes-p.strings {
		return "", fmt.Errorf("perf: string byte limit exceeded")
	}
	p.strings += end
	return string(b[:end]), nil
}

func (p *parser) records(data section) error {
	a := p.result.Attributes[0]
	trailerMask := uint64(0)
	if a.SampleIDAll {
		trailerMask = a.SampleType & identitySamples
	}
	trailerBytes := bits.OnesCount64(trailerMask) * 8
	var header [8]byte
	buffer := make([]byte, 65535-8)
	for off := data.offset; off < data.offset+data.size; {
		if p.result.Records >= uint64(p.options.MaximumRecords) {
			return fmt.Errorf("perf: record limit exceeded")
		}
		if data.offset+data.size-off < 8 {
			return fmt.Errorf("perf: truncated record header at %#x", off)
		}
		if err := p.read(off, header[:]); err != nil {
			return err
		}
		kind, misc, size := le.Uint32(header[:]), le.Uint16(header[4:]), int(le.Uint16(header[6:]))
		if size < 8 || uint64(size) > data.offset+data.size-off {
			return fmt.Errorf("perf: invalid record extent at %#x", off)
		}
		body := buffer[:size-8]
		if err := p.read(off+8, body); err != nil {
			return err
		}
		p.result.Records++
		if kind == 9 {
			if len(p.result.Samples) >= p.options.MaximumSamples {
				return fmt.Errorf("perf: sample limit exceeded")
			}
			fields, err := parseFields(body, a.SampleType, false)
			if err != nil {
				return fmt.Errorf("record %#x: %w", off, err)
			}
			p.result.Samples = append(p.result.Samples, Sample{Offset: off, Misc: misc, Fields: fields})
		} else {
			if err := p.record(kind, misc, off, body, trailerMask, trailerBytes); err != nil {
				return fmt.Errorf("record %#x: %w", off, err)
			}
		}
		off += uint64(size)
	}
	return nil
}

func (p *parser) record(kind uint32, misc uint16, offset uint64, body []byte, trailerMask uint64, trailerBytes int) error {
	switch kind {
	case 11, 12, 21, 64, 66, 70, 71, 72, 81:
		return fmt.Errorf("perf: unsupported auxiliary/compressed/stream-layout record kind %d", kind)
	case 1, 2, 3, 10, 13:
	default:
		p.result.UnknownRecords[kind]++
		return nil
	}
	if len(body) < trailerBytes {
		return fmt.Errorf("perf: truncated sample_id trailer")
	}
	identity, err := parseFields(body[len(body)-trailerBytes:], trailerMask, true)
	if err != nil {
		return err
	}
	body = body[:len(body)-trailerBytes]
	switch kind {
	case 1, 10:
		fixed := 32
		if kind == 10 {
			fixed = 64
		}
		if len(body) < fixed+1 {
			return fmt.Errorf("perf: truncated mmap record")
		}
		m := Mapping{Offset: offset, Misc: misc, Type: kind, PID: le.Uint32(body), TID: le.Uint32(body[4:]), Address: le.Uint64(body[8:]), Length: le.Uint64(body[16:]), PageOffset: le.Uint64(body[24:]), SampleID: identity}
		if m.Length > ^uint64(0)-m.Address || m.Length > ^uint64(0)-m.PageOffset {
			return fmt.Errorf("perf: overflowing mmap range")
		}
		if kind == 10 {
			if misc&(1<<14) != 0 {
				n := int(body[32])
				if n > 20 {
					return fmt.Errorf("perf: invalid mmap2 build ID length")
				}
				m.BuildID = bytes.Clone(body[36 : 36+n])
			} else {
				m.Major, m.Minor, m.Inode, m.InodeGeneration = le.Uint32(body[32:]), le.Uint32(body[36:]), le.Uint64(body[40:]), le.Uint64(body[48:])
			}
			m.Prot, m.Flags = le.Uint32(body[56:]), le.Uint32(body[60:])
		}
		m.Filename, err = p.name(body[fixed:])
		if err != nil {
			return err
		}
		p.result.Mappings = append(p.result.Mappings, m)
	case 3:
		if len(body) < 9 {
			return fmt.Errorf("perf: truncated comm record")
		}
		name, err := p.name(body[8:])
		if err != nil {
			return err
		}
		p.result.Comms = append(p.result.Comms, Comm{Offset: offset, Misc: misc, PID: le.Uint32(body), TID: le.Uint32(body[4:]), Name: name, SampleID: identity})
	case 2, 13:
		want := 16
		if kind == 13 {
			want = 8
		}
		if len(body) != want {
			return fmt.Errorf("perf: invalid lost record size")
		}
		l := LostRecord{Offset: offset, Misc: misc, Type: kind, SampleID: identity}
		if kind == 2 {
			l.ID, l.Count = le.Uint64(body), le.Uint64(body[8:])
		} else {
			l.Count = le.Uint64(body)
		}
		if l.Count > ^uint64(0)-p.result.TotalLost {
			return fmt.Errorf("perf: lost count overflow")
		}
		p.result.TotalLost += l.Count
		p.result.Lost = append(p.result.Lost, l)
	}
	return nil
}
