package etl

import "fmt"

// messageRecord reads the 0x9000 TraceMessage (WPP) framing. Optional fields
// follow TRACE_MESSAGE_* bit order from the Windows SDK's evntrace.h.
func messageRecord(b []byte) (Event, int, error) {
	e := Event{Group: 0xff, PID: 0xffffffff, TID: 0xffffffff, Marker: 0x9000}
	n := int(le.Uint16(b))
	flags := le.Uint16(b[6:])
	e.EventID, e.MessageFlags = le.Uint16(b[4:]), flags
	if n < 8 || n > len(b) || flags & ^uint16(0xef) != 0 || flags&6 == 6 || flags&0xc0 == 0xc0 {
		return e, 0, fmt.Errorf("invalid TraceMessage length or flags %#x", flags)
	}
	hdr := 8
	if flags&1 != 0 {
		hdr += 4
	}
	identity := hdr
	if flags&2 != 0 {
		hdr += 16
	}
	if flags&4 != 0 {
		hdr += 4
	}
	timestamp := hdr
	if flags&8 != 0 {
		hdr += 8
	}
	system := hdr
	if flags&32 != 0 {
		hdr += 8
	}
	if n < hdr {
		return e, 0, fmt.Errorf("truncated TraceMessage optional fields")
	}
	if flags&2 != 0 {
		copy(e.ProviderID[:], b[identity:identity+16])
	}
	if flags&8 != 0 {
		e.Timestamp = le.Uint64(b[timestamp:])
	}
	if flags&32 != 0 {
		e.TID = le.Uint32(b[system:])
		e.PID = le.Uint32(b[system+4:])
	}
	e.Payload = b[hdr:n]
	return e, n, nil
}
