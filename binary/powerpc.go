package binary

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/tinyrange/trex/storage"
	"golang.org/x/arch/ppc64/ppc64asm"
)

type PowerPCOperand struct {
	Kind  string `json:"kind"`
	Text  string `json:"text"`
	Value int64  `json:"value"`
}
type PowerPCInstruction struct {
	Offset    int64            `json:"offset"`
	Address   uint64           `json:"address"`
	Length    int              `json:"length"`
	Word      uint32           `json:"word"`
	Opcode    string           `json:"opcode"`
	Text      string           `json:"text"`
	Arguments []PowerPCOperand `json:"arguments"`
	Target    *uint64          `json:"target,omitempty"`
	Error     string           `json:"error,omitempty"`
}

// PowerPCInstructions inspects a bounded range without executing it. Address is
// the address of the first selected byte, independent of its source offset.
// Unknown encodings are reported and stepped over by four bytes; this is not
// evidence that the selected range is code. Prefixed instructions consume eight.
// Targets use 64-bit address arithmetic, including sign-extended absolute labels;
// GNU display text retains the upstream decoder's 32-bit absolute label spelling.
func PowerPCInstructions(source storage.Reader, offset, size int64, address uint64, order string, maximum int) ([]PowerPCInstruction, error) {
	if offset < 0 || size < 0 || offset > source.Size() || size > source.Size()-offset || offset%4 != 0 || size%4 != 0 || size > 65536 || maximum < 1 || maximum > 16384 || uint64(size) > math.MaxUint64-address {
		return nil, fmt.Errorf("powerpc: invalid range, alignment, address or budget")
	}
	var bo binary.ByteOrder
	switch order {
	case "big":
		bo = binary.BigEndian
	case "little":
		bo = binary.LittleEndian
	default:
		return nil, fmt.Errorf("powerpc: byte_order must be big or little")
	}
	data := make([]byte, int(size))
	if len(data) > 0 {
		n, err := source.ReadAt(data, offset)
		if err != nil && !(err == io.EOF && n == len(data)) {
			return nil, err
		}
		if n != len(data) {
			return nil, io.ErrUnexpectedEOF
		}
	}
	records := make([]PowerPCInstruction, 0, min(int(size/4), maximum))
	for pos := 0; pos < len(data); {
		if len(records) >= maximum {
			return nil, fmt.Errorf("powerpc: instruction budget")
		}
		rec := PowerPCInstruction{Offset: offset + int64(pos), Address: address + uint64(pos), Length: 4, Word: bo.Uint32(data[pos:])}
		inst, err := ppc64asm.Decode(data[pos:min(pos+8, len(data))], bo)
		if err == nil && inst.Op == 0 {
			err = fmt.Errorf("unknown encoding")
		}
		if err != nil {
			rec.Error = err.Error()
			rec.Text = fmt.Sprintf(".long 0x%08x", rec.Word)
		} else {
			rec.Length = inst.Len
			rec.Opcode = inst.Op.String()
			rec.Text = ppc64asm.GNUSyntax(inst, rec.Address)
			for _, arg := range inst.Args {
				if arg == nil {
					break
				}
				a := PowerPCOperand{Text: arg.String()}
				switch v := arg.(type) {
				case ppc64asm.Reg:
					a.Kind = "register"
					a.Value = int64(v)
				case ppc64asm.CondReg:
					a.Kind = "condition_register"
					a.Value = int64(v)
				case ppc64asm.SpReg:
					a.Kind = "special_register"
					a.Value = int64(v)
				case ppc64asm.Imm:
					a.Kind = "immediate"
					a.Value = int64(v)
				case ppc64asm.Offset:
					a.Kind = "offset"
					a.Value = int64(v)
				case ppc64asm.PCRel:
					a.Kind = "relative"
					a.Value = int64(v)
					target := rec.Address + uint64(v)
					rec.Target = &target
				case ppc64asm.Label:
					a.Kind = "absolute"
					// Absolute branch displacements are sign-extended in 64-bit mode.
					a.Value = int64(int32(v))
					target := uint64(a.Value)
					rec.Target = &target
				default:
					a.Kind = "unknown"
				}
				rec.Arguments = append(rec.Arguments, a)
			}
		}
		records = append(records, rec)
		pos += rec.Length
	}
	return records, nil
}
