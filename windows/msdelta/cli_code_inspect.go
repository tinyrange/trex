package msdelta

import (
	"bytes"
	"fmt"
	"math/bits"
	"strings"
	"unicode/utf16"
)

// CLIInspection is a read-only metadata/IL view, not a verifier or decompiler.
// Rows use ECMA-335 table/column order; coded indexes are expanded to tokens.
// Heap string and blob columns are decoded, other columns remain uint32.
type CLIInspection struct {
	EntryPoint uint32
	Rows       []CLIRow
	Methods    []CLIMethod
	Strings    map[uint32]string
}
type CLIRow struct {
	Token   uint32
	Columns []any
}
type CLIMethod struct {
	Token        uint32
	Name         string
	Instructions []CLIInstruction
}
type CLIInstruction struct {
	Offset  int
	Opcode  uint16
	Operand []byte
	Token   uint32
}

// InspectCLI reads bounded CLI metadata and selected IL method bodies. method
// is a case-sensitive name substring (empty selects all). It never executes IL.
func InspectCLI(source []byte, method string) (*CLIInspection, error) {
	if len(source) > 32<<20 {
		return nil, fmt.Errorf("CLI input exceeds 32 MiB")
	}
	pe, err := parsePELayout(source)
	if err != nil {
		return nil, err
	}
	m, err := parseCLIMetadata(source, pe)
	if err != nil {
		return nil, err
	}
	cor, _ := pe.rawOffset(pe.directories[14].rva)
	out := &CLIInspection{EntryPoint: get32(source, cor+20), Strings: map[uint32]string{}}
	heap := func(id int) []byte { s := m.Streams[id]; return source[int(s.Offset) : int(s.Offset)+int(s.Size)] }
	strHeap, blobHeap, us := heap(0), heap(2), heap(1)
	readString := func(index uint32) (string, error) {
		if index == 0 {
			return "", nil
		}
		if uint64(index) >= uint64(len(strHeap)) {
			return "", fmt.Errorf("CLI string index out of range")
		}
		b := strHeap[index:]
		n := bytes.IndexByte(b, 0)
		if n < 0 {
			return "", fmt.Errorf("unterminated CLI string")
		}
		return string(b[:n]), nil
	}
	readBlob := func(index uint32) ([]byte, error) {
		if index == 0 {
			return nil, nil
		}
		if uint64(index) >= uint64(len(blobHeap)) {
			return nil, fmt.Errorf("CLI blob index out of range")
		}
		b := blobHeap[index:]
		n, w := cliCompressed(b)
		if w == 0 || uint64(n) > uint64(len(b)-w) {
			return nil, fmt.Errorf("invalid CLI blob")
		}
		return bytes.Clone(b[w : w+int(n)]), nil
	}
	for p := 1; p < len(us); {
		if us[p] == 0 {
			p++
			continue
		}
		n, w := cliCompressed(us[p:])
		if w == 0 || n == 0 || uint64(n) > uint64(len(us)-p-w) || n%2 != 1 {
			return nil, fmt.Errorf("invalid CLI user string at %d", p)
		}
		b := us[p+w : p+w+int(n)-1]
		units := make([]uint16, len(b)/2)
		for i := range units {
			units[i] = get16(b, i*2)
		}
		out.Strings[0x70000000|uint32(p)] = string(utf16.Decode(units))
		p += w + int(n)
	}
	total, instructions, decoded := 0, 0, 0
	for table, count := range m.Rows {
		total += int(count)
		if total > 100000 {
			return nil, fmt.Errorf("CLI row limit exceeded")
		}
		for row := 0; row < int(count); row++ {
			token := uint32(table)<<24 | uint32(row+1)
			off := m.tableOffsets[table] + row*m.rowSizes[table]
			cols := []any{}
			for _, kind := range m.columns(table) {
				width := m.columnWidth(kind)
				v := uint32(get16(source, off))
				if width == 4 {
					v = get32(source, off)
				}
				off += width
				var value any = v
				switch {
				case kind == cliStrings:
					value, err = readString(v)
				case kind == cliBlob:
					value, err = readBlob(v)
				case kind < 64:
					if v != 0 {
						value = uint32(kind)<<24 | v
					}
				case kind >= 64 && kind <= cliTypeOrMethodDef:
					tables := cliCodedTables[kind-64]
					shift := bits.Len(uint(len(tables) - 1))
					tag := int(v & uint32((1<<shift)-1))
					index := v >> shift
					if index != 0 {
						if tag >= len(tables) || tables[tag] < 0 || index > m.Rows[tables[tag]] {
							return nil, fmt.Errorf("invalid CLI coded index")
						}
						value = uint32(tables[tag])<<24 | index
					} else {
						value = uint32(0)
					}
				}
				if err != nil {
					return nil, err
				}
				switch v := value.(type) {
				case string:
					decoded += len(v)
				case []byte:
					decoded += len(v)
				}
				if decoded > 64<<20 {
					return nil, fmt.Errorf("CLI decoded heap limit exceeded")
				}
				cols = append(cols, value)
			}
			out.Rows = append(out.Rows, CLIRow{token, cols})
			if table == 6 {
				name := cols[3].(string)
				rva := cols[0].(uint32)
				// Native/runtime methods have no IL body to inspect.
				if rva == 0 || cols[1].(uint32)&3 != 0 || !strings.Contains(name, method) {
					continue
				}
				start, end, ok := cliMethodCode(source, pe, rva)
				if !ok {
					return nil, fmt.Errorf("invalid CLI method body %#x", token)
				}
				code, err := inspectCLIInstructions(source[start:end])
				if err != nil {
					return nil, fmt.Errorf("method %#x: %w", token, err)
				}
				instructions += len(code)
				if instructions > 1000000 {
					return nil, fmt.Errorf("CLI instruction limit exceeded")
				}
				out.Methods = append(out.Methods, CLIMethod{token, name, code})
			}
		}
	}
	return out, nil
}

func inspectCLIInstructions(code []byte) ([]CLIInstruction, error) {
	out := []CLIInstruction{}
	for p := 0; p < len(code); {
		start := p
		op := uint16(code[p])
		p++
		if op == 0xfe {
			if p == len(code) {
				return nil, fmt.Errorf("truncated CLI opcode")
			}
			op = 0xfe00 | uint16(code[p])
			p++
		}
		if !validInspectCLIOpcode(op) {
			return nil, fmt.Errorf("unknown CLI opcode %#x at %d", op, start)
		}
		if len(out) >= 1000000 {
			return nil, fmt.Errorf("CLI instruction limit exceeded")
		}
		width := cliOperand(op)
		if op == 0xfe19 {
			width = 1
		} // no. prefix flags
		token := uint32(0)
		if width == cliOperandToken {
			width = 4
			if len(code)-p < 4 {
				return nil, fmt.Errorf("truncated CLI token")
			}
			token = get32(code, p)
		}
		if width == cliOperandSwitch {
			if len(code)-p < 4 {
				return nil, fmt.Errorf("truncated CLI switch")
			}
			n := get32(code, p)
			if uint64(n) > uint64((len(code)-p-4)/4) {
				return nil, fmt.Errorf("CLI switch exceeds body")
			}
			width = 4 + int(n)*4
		}
		if width > len(code)-p {
			return nil, fmt.Errorf("truncated CLI operand")
		}
		out = append(out, CLIInstruction{start, op, bytes.Clone(code[p : p+width]), token})
		p += width
	}
	return out, nil
}

// Reserved encodings must not silently consume zero operand bytes.
func validInspectCLIOpcode(op uint16) bool {
	return op <= 0x23 || (op >= 0x25 && op <= 0x76) ||
		(op >= 0x79 && op <= 0xa5) || (op >= 0xb3 && op <= 0xba) ||
		op == 0xc2 || op == 0xc3 || op == 0xc6 || (op >= 0xd0 && op <= 0xe0) ||
		(op >= 0xfe00 && op <= 0xfe07) || (op >= 0xfe09 && op <= 0xfe0f) ||
		(op >= 0xfe11 && op <= 0xfe1a) || (op >= 0xfe1c && op <= 0xfe1e)
}
