package ckd

import (
	"bytes"
	"fmt"
)

// Object decks are 80-byte card images. Cards beginning X'02' carry a type in
// columns 2-4: ESD (external symbols: up to three 16-byte items of name, type,
// 24-bit address, flags and 24-bit length or ID; numbered consecutively from
// the ESDID in columns 15-16, LD items excepted), TXT (24-bit address in
// columns 6-8, byte count 11-12, ESDID 15-16, data from column 17, usually
// through column 72 but through 80 in decks without sequence numbers), RLD
// (relocation items: relocation and position ESDIDs, flags and a 24-bit
// address; flag bit X'01' means the next item on the same card reuses both
// ESDIDs), END
// (entry address 6-8 and ESDID 15-16, optional symbolic entry 17-24), XSD
// (one extended item: item type 13-14, ESDID 15-16, four words from column 17
// of which the first is the total name length and the second the 1-based
// offset of this card's name piece, then the piece; long names span cards)
// and SYM.
// Other cards (CMS loader cards such as LDT, and control statements) are kept
// raw. These layouts follow IBM's published object module format.

var (
	ebcdicESD = []byte{0xc5, 0xe2, 0xc4}
	ebcdicTXT = []byte{0xe3, 0xe7, 0xe3}
	ebcdicRLD = []byte{0xd9, 0xd3, 0xc4}
	ebcdicEND = []byte{0xc5, 0xd5, 0xc4}
	ebcdicSYM = []byte{0xe2, 0xe8, 0xd4}
	ebcdicXSD = []byte{0xe7, 0xe2, 0xc4}
)

type ObjectSymbol struct {
	Module  int
	Name    string
	RawName []byte
	Type    byte
	// ID is the ESDID; LD (type 1) items have none and refer to Owner.
	ID, Owner      uint16
	Address, Value uint32 // Value is the length (SD/PC/CM) or owning ID (LD)
	Flags          byte
	// Extended items come from XSD cards: Kind is the item type in columns
	// 13-14 and Words the four words before the name, kept uninterpreted.
	Extended bool
	Kind     uint16
	Words    [4]uint32
}

type ObjectText struct {
	Module  int // index of the object module (END cards seen before it)
	ID      uint16
	Address uint32
	Data    []byte
}

type ObjectRelocation struct {
	Relocation, Position uint16
	Flags                byte
	Address              uint32
}

type ObjectDeck struct {
	Symbols     []ObjectSymbol
	Texts       []ObjectText
	Relocations []ObjectRelocation
	// Ends holds each END card's entry address, ESDID and symbolic name.
	Ends    []ObjectEnd
	Others  [][]byte // SYM and non-object cards, unchanged
	modules int
}

type ObjectEnd struct {
	Address uint32
	ID      uint16
	Name    string
}

func u24(b []byte) uint32 { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }

// ParseObjectDeck decodes F 80 card content. Every TXT ESDID and every RLD
// ESDID must name a symbol defined earlier by an ESD card.
func ParseObjectDeck(data []byte, maxCards int) (*ObjectDeck, error) {
	if len(data)%80 != 0 {
		return nil, fmt.Errorf("object deck: content is not whole 80-byte cards")
	}
	if len(data)/80 > maxCards {
		return nil, fmt.Errorf("object deck: %d cards exceed limit", len(data)/80)
	}
	d := &ObjectDeck{}
	ids := map[uint16]bool{}
	pending := map[uint16]int{} // XSD items whose names are incomplete
	for c := 0; c < len(data); c += 80 {
		card := data[c : c+80]
		if card[0] != 0x02 {
			d.Others = append(d.Others, card)
			continue
		}
		kind := card[1:4]
		count := int(be.Uint16(card[10:12]))
		switch {
		case bytes.Equal(kind, ebcdicESD):
			if count%16 != 0 || count > 48 {
				return nil, fmt.Errorf("object deck: card %d: ESD byte count %d", c/80+1, count)
			}
			next := be.Uint16(card[14:16])
			for i := 0; i < count; i += 16 {
				it := card[16+i : 32+i]
				s := ObjectSymbol{Module: d.modules, Name: Identifier(it[:8]), RawName: append([]byte(nil), it[:8]...), Type: it[8], Address: u24(it[9:12]), Flags: it[12], Value: u24(it[13:16])}
				if s.Type&0x0f == 0x01 { // LD: label definition, no ESDID of its own
					s.Owner = uint16(s.Value)
				} else {
					s.ID = next
					ids[next] = true
					next++
				}
				d.Symbols = append(d.Symbols, s)
			}
		case bytes.Equal(kind, ebcdicXSD):
			// Extended ESD: one item whose long name may span cards. Word 0 is
			// the total name length, word 1 this piece's 1-based offset; the
			// byte count is 16 plus the piece length.
			if count < 16 || count > 64 {
				return nil, fmt.Errorf("object deck: card %d: XSD byte count %d", c/80+1, count)
			}
			id := be.Uint16(card[14:16])
			total, offset := int(be.Uint32(card[16:])), int(be.Uint32(card[20:]))
			piece := card[32 : 16+count]
			if i, ok := pending[id]; ok {
				sym := &d.Symbols[i]
				if offset != len(sym.RawName)+1 || len(sym.RawName)+len(piece) > total {
					return nil, fmt.Errorf("object deck: card %d: XSD name piece out of order", c/80+1)
				}
				sym.RawName = append(sym.RawName, piece...)
			} else {
				if offset != 1 || len(piece) > total {
					return nil, fmt.Errorf("object deck: card %d: XSD name does not start at offset 1", c/80+1)
				}
				sym := ObjectSymbol{Module: d.modules, Extended: true, Kind: be.Uint16(card[12:14]), ID: id, RawName: append([]byte(nil), piece...)}
				for k := range sym.Words {
					sym.Words[k] = be.Uint32(card[16+4*k:])
				}
				pending[id] = len(d.Symbols)
				d.Symbols = append(d.Symbols, sym)
				ids[id] = true
			}
			if i := pending[id]; len(d.Symbols[i].RawName) == total {
				d.Symbols[i].Name = Identifier(d.Symbols[i].RawName)
				delete(pending, id)
			}
		case bytes.Equal(kind, ebcdicTXT):
			// Normally at most 56 bytes (columns 17-72); decks without sequence
			// numbers may use columns 73-80 too.
			if count > 64 {
				return nil, fmt.Errorf("object deck: card %d: TXT byte count %d", c/80+1, count)
			}
			t := ObjectText{Module: d.modules, ID: be.Uint16(card[14:16]), Address: u24(card[5:8]), Data: card[16 : 16+count]}
			if !ids[t.ID] {
				return nil, fmt.Errorf("object deck: card %d: TXT for undefined ESDID %d", c/80+1, t.ID)
			}
			d.Texts = append(d.Texts, t)
		case bytes.Equal(kind, ebcdicRLD):
			if count > 64 {
				return nil, fmt.Errorf("object deck: card %d: RLD byte count %d", c/80+1, count)
			}
			items := card[16 : 16+count]
			// Pointer omission applies within a card; a continuation flag on a
			// card's last item is ignored.
			var r, p uint16
			reuse := false
			for i := 0; i < len(items); {
				if !reuse {
					if i+8 > len(items) {
						return nil, fmt.Errorf("object deck: card %d: truncated RLD item", c/80+1)
					}
					r, p = be.Uint16(items[i:]), be.Uint16(items[i+2:])
					i += 4
				} else if i+4 > len(items) {
					return nil, fmt.Errorf("object deck: card %d: truncated RLD item", c/80+1)
				}
				x := ObjectRelocation{Relocation: r, Position: p, Flags: items[i], Address: u24(items[i+1 : i+4])}
				// Relocation ESDID zero is permitted for some address constant
				// kinds; the position must be a defined section.
				if !ids[p] || (r != 0 && !ids[r]) {
					return nil, fmt.Errorf("object deck: card %d: RLD for undefined ESDIDs %d/%d", c/80+1, r, p)
				}
				d.Relocations = append(d.Relocations, x)
				reuse = x.Flags&0x01 != 0
				i += 4
			}
		case bytes.Equal(kind, ebcdicEND):
			d.Ends = append(d.Ends, ObjectEnd{Address: u24(card[5:8]), ID: be.Uint16(card[14:16]), Name: Identifier(card[16:24])})
			// A deck may hold several object modules; ESDIDs restart.
			ids = map[uint16]bool{}
			d.modules++
		case bytes.Equal(kind, ebcdicSYM):
			d.Others = append(d.Others, card)
		default:
			d.Others = append(d.Others, card)
		}
	}
	if len(pending) != 0 {
		return nil, fmt.Errorf("object deck: XSD name incomplete at end of deck")
	}
	return d, nil
}

// ObjectSection is a control section assembled from its TXT cards.
type ObjectSection struct {
	Module int
	Symbol ObjectSymbol
	Data   []byte
}

// Sections assembles SD, PC and CM sections (type nibble 0, 4, 5, 0xD) from TXT
// data, zero-filling gaps. A section is sized by its ESD length or, when that
// is zero, by its furthest TXT data; TXT beyond a nonzero length is an error.
func (d *ObjectDeck) Sections(maxBytes int) ([]ObjectSection, error) {
	type key struct {
		module int
		id     uint16
	}
	index := map[key]int{}
	var out []ObjectSection
	for _, s := range d.Symbols {
		if s.Extended {
			continue // XSD lengths are not interpreted
		}
		switch s.Type & 0x0f {
		case 0x0, 0x4, 0x5, 0xd:
			index[key{s.Module, s.ID}] = len(out)
			out = append(out, ObjectSection{Module: s.Module, Symbol: s})
		}
	}
	total := 0
	for _, t := range d.Texts {
		i, ok := index[key{t.Module, t.ID}]
		if !ok {
			continue // text for an XD/ER item is not section content
		}
		s := &out[i]
		if t.Address < s.Symbol.Address {
			return nil, fmt.Errorf("object deck: TXT at %x precedes section %s at %x", t.Address, s.Symbol.Name, s.Symbol.Address)
		}
		off := int(t.Address - s.Symbol.Address)
		end := off + len(t.Data)
		if s.Symbol.Value != 0 && end > int(s.Symbol.Value) {
			return nil, fmt.Errorf("object deck: TXT beyond section %s length %x", s.Symbol.Name, s.Symbol.Value)
		}
		if end > len(s.Data) {
			total += end - len(s.Data)
			if total > maxBytes {
				return nil, fmt.Errorf("object deck: sections exceed limit")
			}
			s.Data = append(s.Data, make([]byte, end-len(s.Data))...)
		}
		copy(s.Data[off:], t.Data)
	}
	for i := range out {
		if n := int(out[i].Symbol.Value); n > len(out[i].Data) {
			total += n - len(out[i].Data)
			if total > maxBytes {
				return nil, fmt.Errorf("object deck: sections exceed limit")
			}
			out[i].Data = append(out[i].Data, make([]byte, n-len(out[i].Data))...)
		}
	}
	return out, nil
}
