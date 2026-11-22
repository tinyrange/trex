package binary

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
	"golang.org/x/arch/ppc64/ppc64asm"
)

// PowerPCRange selects bytes of a census source.
type PowerPCRange struct {
	Offset int64
	Size   int64
}

// PowerPCUnknown summarizes words that the decoder rejects, grouped by primary
// and (where the primary opcode defines one) extended opcode field.
type PowerPCUnknown struct {
	Key     string   `json:"key"`
	Count   int64    `json:"count"`
	Words   []uint32 `json:"words"`
	Offsets []int64  `json:"offsets"`
}

// PowerPCCensus is a read-only opcode histogram. It does not prove that the
// selected ranges are code; callers choose ranges from independent evidence.
type PowerPCCensus struct {
	Words    int64            `json:"words"`
	Zero     int64            `json:"zero"`
	Decoded  int64            `json:"decoded"`
	Mnemonic map[string]int64 `json:"mnemonics"`
	SPR      map[string]int64 `json:"spr"`
	// Absolute counts absolute branch and call targets (64-bit sign
	// extended) by 64 KiB page, keyed by the page's hexadecimal address.
	Absolute map[string]int64  `json:"absolute"`
	Unknown  []*PowerPCUnknown `json:"unknown"`
}

// PowerPCExtendedKey returns the "primary/extended" grouping used for
// undecodable words. Primary opcodes without a single extended field use "-".
func PowerPCExtendedKey(word uint32) string {
	po := word >> 26
	switch po {
	case 4, 19, 31, 59, 60, 63:
		return fmt.Sprintf("%d/%d", po, (word>>1)&0x3ff)
	case 30:
		return fmt.Sprintf("%d/%d", po, (word>>1)&0xf)
	case 57, 58, 61, 62:
		return fmt.Sprintf("%d/%d", po, word&3)
	}
	return fmt.Sprintf("%d/-", po)
}

// PowerPCCensusRanges decodes every aligned word of the selected ranges and
// merges mnemonic, SPR-access and unknown-encoding counts. samples bounds the
// distinct words and offsets kept per unknown key; total bounds the bytes read.
//
// With flow, each range is treated as one procedure whose entry is its first
// nonzero word: only words reachable by fallthrough and in-range direct
// branches and calls are counted. A rejected word ends its path, so embedded tables and
// strings after unconditional transfers are not mistaken for instructions.
func PowerPCCensusRanges(source storage.Reader, ranges []PowerPCRange, order string, samples int, total int64, flow bool) (*PowerPCCensus, error) {
	var bo binary.ByteOrder
	switch order {
	case "big":
		bo = binary.BigEndian
	case "little":
		bo = binary.LittleEndian
	default:
		return nil, fmt.Errorf("powerpc: byte_order must be big or little")
	}
	if samples < 0 || samples > 64 || total < 0 {
		return nil, fmt.Errorf("powerpc: invalid census budget")
	}
	var sum int64
	for _, r := range ranges {
		if r.Offset < 0 || r.Size < 0 || r.Offset > source.Size() || r.Size > source.Size()-r.Offset || r.Offset%4 != 0 || r.Size%4 != 0 {
			return nil, fmt.Errorf("powerpc: invalid census range %#x+%#x", r.Offset, r.Size)
		}
		sum += r.Size
		if sum > total {
			return nil, fmt.Errorf("powerpc: census byte budget")
		}
	}
	c := &PowerPCCensus{Mnemonic: map[string]int64{}, SPR: map[string]int64{}, Absolute: map[string]int64{}, Unknown: []*PowerPCUnknown{}}
	unknown := map[string]*PowerPCUnknown{}
	visit := func(word uint32, data []byte, at int64) (ppc64asm.Inst, bool) {
		c.Words++
		if word == 0 {
			c.Zero++
			return ppc64asm.Inst{}, false
		}
		inst, err := ppc64asm.Decode(data, bo)
		if err != nil || inst.Op == 0 {
			key := PowerPCExtendedKey(word)
			u := unknown[key]
			if u == nil {
				u = &PowerPCUnknown{Key: key}
				unknown[key] = u
			}
			u.Count++
			if len(u.Offsets) < samples {
				u.Offsets = append(u.Offsets, at)
			}
			if len(u.Words) < samples && !containsWord(u.Words, word) {
				u.Words = append(u.Words, word)
			}
			return ppc64asm.Inst{}, false
		}
		c.Decoded++
		if po := word >> 26; po == 18 && word&2 != 0 {
			target := uint64(int64(int32(word&0x03fffffc<<6) >> 6))
			c.Absolute[fmt.Sprintf("%016x", target&^0xffff)]++
		} else if po == 16 && word&2 != 0 {
			target := uint64(int64(int16(word & 0xfffc)))
			c.Absolute[fmt.Sprintf("%016x", target&^0xffff)]++
		}
		op := inst.Op.String()
		c.Mnemonic[op]++
		for _, arg := range inst.Args {
			if spr, ok := arg.(ppc64asm.SpReg); ok {
				c.SPR[fmt.Sprintf("%s %d", op, int(spr))]++
			}
		}
		return inst, true
	}
	if flow {
		for _, r := range ranges {
			if r.Size > 1<<22 {
				return nil, fmt.Errorf("powerpc: flow range larger than 4MiB")
			}
			data := make([]byte, r.Size)
			if got, err := source.ReadAt(data, r.Offset); int64(got) != r.Size {
				if err == nil || err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return nil, err
			}
			entry := 0
			for entry+4 <= len(data) && bo.Uint32(data[entry:]) == 0 {
				entry += 4
			}
			seen := make([]bool, len(data)/4)
			work := []int{entry}
			for len(work) > 0 {
				pos := work[len(work)-1]
				work = work[:len(work)-1]
				for pos >= 0 && pos+4 <= len(data) && !seen[pos/4] {
					seen[pos/4] = true
					word := bo.Uint32(data[pos:])
					inst, ok := visit(word, data[pos:min(pos+8, len(data))], r.Offset+int64(pos))
					if !ok {
						break
					}
					next, more, target, branch := powerPCSuccessors(word, pos, inst.Len)
					if branch && target >= 0 && target < len(data) {
						work = append(work, target)
					}
					if !more {
						break
					}
					pos = next
				}
			}
		}
	} else {
		if err := powerPCLinear(source, ranges, bo, visit); err != nil {
			return nil, err
		}
	}
	for _, u := range unknown {
		c.Unknown = append(c.Unknown, u)
	}
	sort.Slice(c.Unknown, func(i, j int) bool {
		if c.Unknown[i].Count != c.Unknown[j].Count {
			return c.Unknown[i].Count > c.Unknown[j].Count
		}
		return c.Unknown[i].Key < c.Unknown[j].Key
	})
	return c, nil
}

// powerPCSuccessors classifies direct control flow from a decoded word at pos.
// It returns the fallthrough position and whether it is reachable, plus an
// in-range relative branch or call target. Calls also fall through; absolute
// branches leave the range.
func powerPCSuccessors(word uint32, pos, length int) (next int, more bool, target int, branch bool) {
	next, more, target = pos+length, true, -1
	po := word >> 26
	aa, lk := word&2 != 0, word&1 != 0
	unconditional := (word>>21)&0x14 == 0x14
	switch po {
	case 18: // b
		if !aa {
			target, branch = pos+int(int32(word&0x03fffffc<<6)>>6), true
		}
		more = lk
	case 16: // bc
		if !aa {
			target, branch = pos+int(int32(word&0xfffc<<16)>>16), true
		}
		more = !unconditional || lk
	case 19:
		switch (word >> 1) & 0x3ff {
		case 16, 528, 560: // bclr, bcctr, bctar
			more = !unconditional || lk
		case 18, 274, 82: // rfid, hrfid, rfscv
			more = false
		}
	}
	return
}

func powerPCLinear(source storage.Reader, ranges []PowerPCRange, bo binary.ByteOrder, visit func(uint32, []byte, int64) (ppc64asm.Inst, bool)) error {
	buf := make([]byte, 1<<20)
	for _, r := range ranges {
		for done := int64(0); done < r.Size; {
			n := int(min(int64(len(buf)), r.Size-done))
			got, err := source.ReadAt(buf[:n], r.Offset+done)
			if got != n {
				if err == nil || err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return err
			}
			for pos := 0; pos+4 <= n; pos += 4 {
				// Prefixed instructions are counted by their prefix word only;
				// the suffix is decoded independently, matching a linear sweep.
				visit(bo.Uint32(buf[pos:]), buf[pos:min(pos+8, n)], r.Offset+done+int64(pos))
			}
			done += int64(n)
		}
	}
	return nil
}

func containsWord(words []uint32, word uint32) bool {
	for _, w := range words {
		if w == word {
			return true
		}
	}
	return false
}
