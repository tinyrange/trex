package etl

import "fmt"

// ExtendedData is serialized EVENT_HEADER extended information. Data aliases
// the event buffer, like Payload. Stack addresses are values, never live host
// pointers. Unknown types remain opaque rather than becoming user payload.
type ExtendedData struct {
	Type        uint16
	Linkage     uint16
	Data        []byte
	MatchID     uint64
	PointerSize uint8
	Stack       []uint64
}

// The on-disk form has an eight-byte header followed by inline DataSize bytes,
// padded to eight bytes. It does not contain the in-memory DataPtr field.
func eventExtensions(b []byte) ([]ExtendedData, int, error) {
	var items []ExtendedData
	offset := 0
	for {
		if len(items) >= 128 || len(b)-offset < 8 {
			return nil, 0, fmt.Errorf("invalid or excessive extended-event chain")
		}
		h := b[offset:]
		size := int(le.Uint16(h[6:8]))
		if size > len(h)-8 {
			return nil, 0, fmt.Errorf("extended-event data exceeds record")
		}
		extent := (8 + size + 7) &^ 7
		if extent > len(h) {
			return nil, 0, fmt.Errorf("extended-event alignment exceeds record")
		}
		item := ExtendedData{Type: le.Uint16(h[2:4]), Linkage: le.Uint16(h[4:6]), Data: h[8 : 8+size]}
		if item.Type == 5 || item.Type == 6 {
			width := 4
			if item.Type == 6 {
				width = 8
			}
			if size < 8 || (size-8)%width != 0 {
				return nil, 0, fmt.Errorf("invalid extended stack-trace length")
			}
			item.PointerSize = uint8(width)
			item.MatchID = le.Uint64(item.Data[:8])
			for off := 8; off < size; off += width {
				address := uint64(le.Uint32(item.Data[off : off+4]))
				if width == 8 {
					address = le.Uint64(item.Data[off : off+8])
				}
				item.Stack = append(item.Stack, address)
			}
		}
		items = append(items, item)
		offset += extent
		if item.Linkage&1 == 0 {
			return items, offset, nil
		}
	}
}
