// Package hunk decodes Amiga object-unit libraries into borrowed file views.
// It does not link code, apply relocations, or allocate uninitialised sections.
package hunk

import (
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
)

const (
	UnitTag    = 999
	NameTag    = 1000
	CodeTag    = 1001
	DataTag    = 1002
	BSSTag     = 1003
	Reloc32Tag = 1004
	Reloc16Tag = 1005
	Reloc8Tag  = 1006
	ExtTag     = 1007
	SymbolTag  = 1008
	DebugTag   = 1009
	EndTag     = 1010
	HeaderTag  = 1011
	PPCCodeTag = 1257
	Reloc26Tag = 1260
)

// Record retains the complete encoded block, including tags and terminators.
// Payload is the uninterpreted name, code, data, or debug bytes, when present.
type Record struct {
	Tag, Flags   uint32
	Offset       int64
	Raw, Payload starfile.File
	MemorySize   int64
	Symbols      []Symbol
	Relocations  []Relocation
}
type Symbol struct {
	Kind    uint8
	Name    starfile.File // longword-padded original bytes
	Value   uint32        // definition value, or COMMON allocation size
	Offsets starfile.File // big-endian uint32 offsets, without the count
}
type Relocation struct {
	Target  uint32
	Offsets starfile.File // big-endian uint32 offsets
}
type Unit struct {
	Name, Raw starfile.File
	Records   []Record
}
type Archive struct {
	Units  []Unit
	Header *LoadHeader
}

// LoadHeader declares allocation sizes, not stored payload lengths. The sole
// Units element of a load module holds its records; it has an empty name.
type LoadHeader struct {
	Raw                    starfile.File
	Libraries              []starfile.File
	TableSize, First, Last uint32
	Sizes                  []int64
}

type reader struct {
	f    starfile.File
	p    int64
	left int
	err  error
}

func (r *reader) fail(message string) {
	if r.err == nil {
		r.err = fmt.Errorf("hunk at %#x: %s", r.p, message)
	}
}
func (r *reader) item() {
	if r.left == 0 {
		r.fail("metadata limit")
	} else {
		r.left--
	}
}
func (r *reader) take(n int64) starfile.File {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > r.f.Size()-r.p {
		r.fail("truncated record")
		return nil
	}
	v := &starfile.Slice{Base: r.f, Offset: r.p, Length: n}
	r.p += n
	return v
}
func (r *reader) word() uint32 {
	if r.err != nil {
		return 0
	}
	var b [4]byte
	if _, err := starfile.ReadFullAt(r.f, b[:], r.p); err != nil {
		r.err = fmt.Errorf("hunk at %#x: %w", r.p, err)
		return 0
	}
	r.p += 4
	return binary.BigEndian.Uint32(b[:])
}
func (r *reader) string() starfile.File { return r.take(int64(r.word()) * 4) }

// OpenObjects reads concatenated HUNK_UNIT objects. maximumRecords bounds all
// blocks, symbols and relocation groups together. Payload sizes are bounded by
// the input itself and remain views, including names and offset tables.
// Load modules, indexed libraries and overlays are rejected
// until their distinct layouts have been implemented.
func OpenObjects(file starfile.File, maximumRecords int) (*Archive, error) {
	return open(file, maximumRecords, false)
}

// OpenLoad reads one non-overlaid HUNK_HEADER load module without executing it.
// Extended memory attributes and compact relocations are explicitly rejected.
func OpenLoad(file starfile.File, maximumRecords int) (*Archive, error) {
	return open(file, maximumRecords, true)
}

func open(file starfile.File, maximumRecords int, load bool) (*Archive, error) {
	if maximumRecords < 1 {
		return nil, fmt.Errorf("hunk: invalid metadata limit")
	}
	r := reader{f: file, left: maximumRecords}
	a := &Archive{}
	if load {
		r.item()
		if r.word() != HeaderTag {
			return nil, fmt.Errorf("hunk: expected HUNK_HEADER")
		}
		h := &LoadHeader{}
		for r.err == nil {
			n := r.word()
			if n == 0 {
				break
			}
			r.item()
			h.Libraries = append(h.Libraries, r.take(int64(n)*4))
		}
		h.TableSize, h.First, h.Last = r.word(), r.word(), r.word()
		if h.TableSize == 0 || h.First > h.Last || h.Last >= h.TableSize {
			r.fail("invalid load hunk range")
		}
		if r.err == nil {
			for i := uint64(h.First); i <= uint64(h.Last) && r.err == nil; i++ {
				r.item()
				n := r.word()
				if n&0xc0000000 != 0 {
					r.fail("unsupported load memory attributes")
					break
				}
				h.Sizes = append(h.Sizes, int64(n)*4)
			}
		}
		if r.err != nil {
			return nil, r.err
		}
		h.Raw = &starfile.Slice{Base: file, Length: r.p}
		a.Header = h
		a.Units = []Unit{{Name: &starfile.Slice{Base: file, Length: 0}}}
	}
	unitStart := int64(0)
	active := false
	sections := 0
	pendingName := false
	for r.p < file.Size() && r.err == nil {
		r.item()
		start := r.p
		rawTag := r.word()
		rec := Record{Tag: rawTag & 0x3fffffff, Flags: rawTag & 0xc0000000, Offset: start}
		if rec.Tag == UnitTag {
			if load {
				r.fail("object unit inside load module")
				break
			}
			if rec.Flags != 0 || active || pendingName {
				r.fail("unit starts inside unfinished section")
				break
			}
			if len(a.Units) > 0 {
				if sections == 0 {
					r.fail("unit has no sections")
					break
				}
				a.Units[len(a.Units)-1].Raw = &starfile.Slice{Base: file, Offset: unitStart, Length: start - unitStart}
			}
			unitStart, sections = start, 0
			rec.Payload = r.string()
			a.Units = append(a.Units, Unit{Name: rec.Payload})
		} else if len(a.Units) == 0 {
			r.fail("expected HUNK_UNIT")
			break
		} else {
			switch rec.Tag {
			case NameTag:
				if active || pendingName {
					r.fail("misplaced section name")
					break
				}
				pendingName = true
				rec.Payload = r.string()
			case CodeTag, DataTag, BSSTag, PPCCodeTag:
				if active {
					r.fail("section missing HUNK_END")
					break
				}
				active, pendingName = true, false
				sections++
				rec.MemorySize = int64(r.word()) * 4
				if load && (sections > len(a.Header.Sizes) || rec.MemorySize > a.Header.Sizes[sections-1]) {
					r.fail("section exceeds load allocation table")
					break
				}
				if rec.Tag != BSSTag {
					rec.Payload = r.take(rec.MemorySize)
				}
			case Reloc32Tag, Reloc16Tag, Reloc8Tag, 1015, 1016, 1017, Reloc26Tag:
				if load && rec.Tag != Reloc32Tag {
					r.fail("unsupported load relocation encoding")
					break
				}
				if !active {
					r.fail("relocations outside section")
					break
				}
				for r.err == nil {
					n := r.word()
					if n == 0 {
						break
					}
					r.item()
					target := r.word()
					offsets := r.take(int64(n) * 4)
					rec.Relocations = append(rec.Relocations, Relocation{Target: target, Offsets: offsets})
				}
			case ExtTag, SymbolTag:
				if load && rec.Tag == ExtTag {
					r.fail("external symbols in load module")
					break
				}
				if !active {
					r.fail("symbols outside section")
					break
				}
				for r.err == nil {
					d := r.word()
					if d == 0 {
						break
					}
					r.item()
					s := Symbol{Kind: uint8(d >> 24), Name: r.take(int64(d&0xffffff) * 4)}
					if rec.Tag == SymbolTag && s.Kind != 0 {
						r.fail("typed HUNK_SYMBOL entry")
						break
					}
					switch s.Kind {
					case 0, 1, 2, 3:
						s.Value = r.word()
					case 129, 130, 131, 132, 133, 134, 135, 229:
						if s.Kind == 130 {
							s.Value = r.word()
						}
						s.Offsets = r.take(int64(r.word()) * 4)
					default:
						r.fail(fmt.Sprintf("unsupported external symbol type %d", s.Kind))
					}
					rec.Symbols = append(rec.Symbols, s)
				}
			case DebugTag:
				if !active {
					r.fail("debug outside section")
					break
				}
				rec.Payload = r.string()
			case EndTag:
				if !active {
					r.fail("end outside section")
					break
				}
				active = false
			default:
				r.fail(fmt.Sprintf("unsupported record %d", rec.Tag))
			}
		}
		if r.err == nil {
			rec.Raw = &starfile.Slice{Base: file, Offset: start, Length: r.p - start}
			u := &a.Units[len(a.Units)-1]
			u.Records = append(u.Records, rec)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(a.Units) == 0 || active || pendingName || sections == 0 {
		return nil, fmt.Errorf("hunk: incomplete object unit")
	}
	if load && sections != len(a.Header.Sizes) {
		return nil, fmt.Errorf("hunk: load section count mismatch")
	}
	a.Units[len(a.Units)-1].Raw = &starfile.Slice{Base: file, Offset: unitStart, Length: r.p - unitStart}
	return a, nil
}
