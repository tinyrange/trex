// Package etl reads uncompressed sequential Windows kernel ETW log files.
// It does not use Windows APIs, host tools, or third-party parser libraries.
// See FORMAT.md for supported formats, provenance and limitations.
package etl

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

var le = binary.LittleEndian

const bufferHeaderSize = 72

// Limits bound allocations and work on untrusted traces. Zero selects defaults.
type Limits struct {
	MaxBytes  int64
	MaxEvents int
}

func (l Limits) defaults() Limits {
	if l.MaxBytes == 0 {
		l.MaxBytes = 1 << 30
	}
	if l.MaxEvents == 0 {
		l.MaxEvents = 4_000_000
	}
	return l
}

// Header is the finalized TRACE_LOGFILE_HEADER. Times are Windows FILETIME;
// event timestamps use Clock (1=QPC, 2=FILETIME). QPCFrequency also scales I/O times.
type Header struct {
	BufferSize         uint32 `json:"buffer_size"`
	Processors         uint32 `json:"processors"`
	PointerSize        uint32 `json:"pointer_size"`
	BuffersWritten     uint32 `json:"buffers_written"`
	EventsLost         uint32 `json:"events_lost"`
	BuffersLost        uint32 `json:"buffers_lost"`
	LossFlaggedBuffers uint32 `json:"loss_flagged_buffers"`
	BootTime           uint64 `json:"boot_filetime"`
	StartTime          uint64 `json:"start_filetime"`
	EndTime            uint64 `json:"end_filetime"`
	QPCFrequency       uint64 `json:"qpc_frequency"`
	Clock              uint32 `json:"clock"`
	StartTick          uint64 `json:"start_tick"`
}

// Event payload aliases the current buffer: the callback must copy retained data.
// Group is 0xff for non-kernel records. Unsupported payloads can still be counted.
type Event struct {
	Offset     int64
	Timestamp  uint64
	CPU        uint16
	HeaderType byte
	Group      byte
	Opcode     byte
	Version    uint16
	PID, TID   uint32
	Payload    []byte
}

// Walk validates framing and visits events in file order (NOT timestamp order).
// It fails rather than silently treating truncated/compressed/circular logs as complete.
func Walk(ctx context.Context, r io.ReaderAt, size int64, limits Limits, visit func(Event) error) (Header, error) {
	var h Header
	l := limits.defaults()
	if size < bufferHeaderSize || size > l.MaxBytes || l.MaxEvents <= 0 {
		return h, fmt.Errorf("ETL: invalid size or limits: %d bytes", size)
	}
	var prefix [bufferHeaderSize]byte
	var buf []byte
	count, buffers := 0, uint32(0)
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return h, err
		}
		if _, err := r.ReadAt(prefix[:], off); err != nil {
			return h, fmt.Errorf("ETL buffer at %#x: %w", off, err)
		}
		n, end := int64(le.Uint32(prefix[0:])), int64(le.Uint32(prefix[48:]))
		flags := le.Uint16(prefix[52:])
		if n < bufferHeaderSize || n > 1<<20 || n > size-off || end < bufferHeaderSize || end > n {
			return h, fmt.Errorf("ETL buffer at %#x: invalid size %d / filled %d", off, n, end)
		}
		if flags&0x40 != 0 {
			return h, fmt.Errorf("ETL buffer at %#x: compressed buffers unsupported", off)
		}
		if flags&6 != 0 {
			h.LossFlaggedBuffers++
		}
		if cap(buf) < int(n) {
			buf = make([]byte, n)
		} else {
			buf = buf[:n]
		}
		if _, err := r.ReadAt(buf, off); err != nil {
			return h, err
		}
		cpu := le.Uint16(prefix[40:])
		for pos := int64(bufferHeaderSize); pos < end; {
			if count%4096 == 0 {
				if err := ctx.Err(); err != nil {
					return h, err
				}
			}
			if end-pos < 4 {
				return h, fmt.Errorf("ETL record at %#x: short marker", off+pos)
			}
			b := buf[pos:end]
			// Flushed buffers can end in all-0xff alignment padding.
			if le.Uint32(b) == 0xffffffff {
				for _, v := range b {
					if v != 0xff {
						return h, fmt.Errorf("ETL: non-padding after terminator at %#x", off+pos)
					}
				}
				break
			}
			e, nrec, err := record(b)
			if err != nil {
				return h, fmt.Errorf("ETL record at %#x: %w", off+pos, err)
			}
			e.Offset, e.CPU = off+pos, cpu
			if count == 0 {
				if e.Group != 0 || e.Opcode != 0 {
					return h, fmt.Errorf("ETL: first record is not TRACE_LOGFILE_HEADER")
				}
				loss := h.LossFlaggedBuffers
				h, err = logfileHeader(e)
				h.LossFlaggedBuffers = loss
				if err != nil {
					return h, err
				}
				if h.BufferSize != uint32(n) {
					return h, fmt.Errorf("ETL: inconsistent buffer size")
				}
			}
			count++
			if count > l.MaxEvents {
				return h, fmt.Errorf("ETL: event limit %d exceeded", l.MaxEvents)
			}
			if visit != nil {
				if err := visit(e); err != nil {
					return h, err
				}
			}
			pos += int64((nrec + 7) &^ 7)
			if pos > end {
				return h, fmt.Errorf("ETL: record alignment exceeds filled buffer")
			}
		}
		off += n
		buffers++
	}
	if count == 0 || h.EndTime == 0 || h.EndTime < h.StartTime || buffers != h.BuffersWritten {
		return h, fmt.Errorf("ETL: unfinalized or truncated log (%d buffers, header says %d)", buffers, h.BuffersWritten)
	}
	return h, nil
}

func record(b []byte) (Event, int, error) {
	var e Event
	if len(b) < 8 || b[3] != 0xc0 {
		return e, 0, fmt.Errorf("unsupported marker")
	}
	e.HeaderType = b[2]
	e.Group = 0xff
	e.PID = 0xffffffff
	e.TID = 0xffffffff
	n, hdr := int(le.Uint16(b)), 0
	switch b[2] {
	case 1, 2, 3, 4, 0x10, 0x11:
		n = int(le.Uint16(b[4:]))
		e.Version = uint16(b[0])
		e.Group = b[7]
		e.Opcode = b[6]
		switch b[2] {
		case 1, 2:
			hdr = 32
		case 3, 4:
			hdr = 24
		default:
			hdr = 16
		}
		// Extended kernel headers are not enabled by this recorder. Reject instead
		// of interpreting extension bytes as payload fields.
		if b[1] != 0 {
			return e, 0, fmt.Errorf("extended kernel header %#x unsupported", le.Uint16(b))
		}
		if n < hdr || n > len(b) {
			return e, 0, fmt.Errorf("invalid kernel record length %d", n)
		}
		if hdr >= 24 {
			e.TID = le.Uint32(b[8:])
			e.PID = le.Uint32(b[12:])
			e.Timestamp = le.Uint64(b[16:])
		} else {
			e.Timestamp = le.Uint64(b[8:])
		}
	case 0x0a, 0x14:
		hdr = 48
		if n < hdr || n > len(b) {
			return e, 0, fmt.Errorf("invalid classic record length")
		}
		e.Opcode = b[4]
		e.Version = le.Uint16(b[6:])
		e.TID = le.Uint32(b[8:])
		e.PID = le.Uint32(b[12:])
		e.Timestamp = le.Uint64(b[16:])
	case 0x12, 0x13:
		hdr = 80
		if n < hdr || n > len(b) {
			return e, 0, fmt.Errorf("invalid event-header record length")
		}
		e.Opcode = b[45]
		e.Version = uint16(b[42])
		e.TID = le.Uint32(b[8:])
		e.PID = le.Uint32(b[12:])
		e.Timestamp = le.Uint64(b[16:])
	default:
		return e, 0, fmt.Errorf("unsupported header type %#x", b[2])
	}
	e.Payload = b[hdr:n]
	return e, n, nil
}

func logfileHeader(e Event) (Header, error) {
	var h Header
	b := e.Payload
	if len(b) < 56 {
		return h, fmt.Errorf("ETL: short logfile header")
	}
	h.PointerSize = le.Uint32(b[44:])
	if h.PointerSize != 4 && h.PointerSize != 8 {
		return h, fmt.Errorf("ETL: invalid pointer size")
	}
	tail := 240
	if h.PointerSize == 8 {
		tail += 8
	}
	if len(b) < tail+32 {
		return h, fmt.Errorf("ETL: short logfile clock fields")
	}
	h.BufferSize = le.Uint32(b)
	h.Processors = le.Uint32(b[12:])
	h.EndTime = le.Uint64(b[16:])
	h.BuffersWritten = le.Uint32(b[36:])
	h.EventsLost = le.Uint32(b[48:])
	h.BootTime = le.Uint64(b[tail:])
	h.QPCFrequency = le.Uint64(b[tail+8:])
	h.StartTime = le.Uint64(b[tail+16:])
	h.Clock = le.Uint32(b[tail+24:])
	h.BuffersLost = le.Uint32(b[tail+28:])
	h.StartTick = e.Timestamp
	if le.Uint32(b[32:])&3 != 1 {
		return h, fmt.Errorf("ETL: only sequential logs supported")
	}
	if h.Processors == 0 || h.Processors > 4096 || h.QPCFrequency == 0 || h.QPCFrequency > 1_000_000_000_000 {
		return h, fmt.Errorf("ETL: invalid CPU count or clock frequency")
	}
	if h.Clock != 1 && h.Clock != 2 {
		return h, fmt.Errorf("ETL: unsupported clock %d", h.Clock)
	}
	return h, nil
}
