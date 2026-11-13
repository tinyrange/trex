package s390

import (
	"bytes"
	"strings"
)

// Distributed function terminal (DFT) file transfer, as IND$FILE uses it.
// The host sends file-transfer requests as WRITE STRUCTURED FIELD with
// structured field X'D0'; the terminal answers each with an inbound
// structured field (AID X'88') that the host reads after attention. The
// display advertises the facility in its query reply (DDM, X'95').
//
// A display attached to a remote terminal (a tn3270 client observing it)
// passes the requests through and returns the client's replies; otherwise
// the requests go to the display's Transfer, if one is set up, and are
// refused when none is.

// DFT request and reply codes.
const (
	dftOpen       = 0x0012
	dftClose      = 0x4112
	dftSetCursor  = 0x4511
	dftGet        = 0x4611
	dftInsert     = 0x4711
	dftDataInsert = 0x4704

	dftBuffer = 4096 // INLIM and OUTLIM advertised in the query reply
)

// Transfer is one IND$FILE transfer handled by the display itself: an
// upload (the host GETs Upload) or a download (the host inserts data,
// collected in Download). Done is set by the host's closing message, whose
// text is Message; Failed reports a message other than TRANS03.
type Transfer struct {
	Upload   []byte
	Download bytes.Buffer
	Message  string
	Done     bool
	Failed   bool
	// Records counts data records exchanged.
	Records int

	pos     int
	recnum  uint32
	message bool
}

// SetTransfer prepares the display to answer the host's next IND$FILE
// requests (nil removes it).
func (t *Console3270) SetTransfer(x *Transfer) { t.transfer = x }

// TransferState returns the display's transfer, if any.
func (t *Console3270) TransferState() *Transfer { return t.transfer }

// dft handles one D0 structured field from the host and returns the
// inbound reply (AID first), or nil when the request takes none.
func (t *Console3270) dft(sf []byte) []byte {
	if len(sf) < 5 {
		return nil
	}
	req := int(sf[3])<<8 | int(sf[4])
	x := t.transfer
	reply := func(b ...byte) []byte {
		out := []byte{AIDStructuredField, 0, 0}
		out = append(out, b...)
		n := len(out) - 1
		out[1], out[2] = byte(n>>8), byte(n)
		return out
	}
	abort := func() []byte { return reply(0xd0, byte(req>>8), 0x08, 0x69, 0x04, 0x01, 0x00) }
	recnum := func() []byte {
		r := x.recnum
		x.recnum++
		return []byte{0x63, 0x06, byte(r >> 24), byte(r >> 16), byte(r >> 8), byte(r)}
	}
	switch req {
	case dftOpen:
		if x == nil || x.Done {
			return abort()
		}
		var name string
		switch len(sf) {
		case 35:
			name = string(sf[28:35])
		case 41:
			name = string(sf[34:41])
		default:
			return abort()
		}
		x.message = strings.TrimRight(name, " ") == "FT:MSG"
		x.recnum = 1
		return reply(0xd0, 0x00, 0x09)
	case dftClose:
		return reply(0xd0, 0x41, 0x09)
	case dftSetCursor, dftInsert:
		return nil
	case dftDataInsert:
		if x == nil || len(sf) < 10 {
			return abort()
		}
		n := int(sf[8])<<8 | int(sf[9]) - 5
		if n < 0 || 10+n > len(sf) {
			return abort()
		}
		data := sf[10 : 10+n]
		ack := reply(append([]byte{0xd0, 0x47, 0x05}, recnum()...)...)
		if x.message {
			text := string(data)
			if i := strings.IndexByte(text, '$'); i >= 0 {
				text = text[:i]
			}
			x.Message, x.Done = strings.TrimSpace(text), true
			x.Failed = !strings.HasPrefix(text, "TRANS03")
		} else {
			x.Download.Write(data)
			x.Records++
		}
		return ack
	case dftGet:
		if x == nil {
			return abort()
		}
		if x.pos >= len(x.Upload) {
			return reply(0xd0, 0x46, 0x08, 0x69, 0x04, 0x22, 0x00)
		}
		chunk := x.Upload[x.pos:min(len(x.Upload), x.pos+dftBuffer-27)]
		x.pos += len(chunk)
		x.Records++
		out := append([]byte{0xd0, 0x46, 0x05}, recnum()...)
		out = append(out, 0xc0, 0x80, 0x61, byte((len(chunk)+5)>>8), byte(len(chunk)+5))
		return reply(append(out, chunk...)...)
	}
	return abort()
}

// AIDStructuredField identifies an inbound structured field.
const AIDStructuredField = 0x88

// presentInbound queues an inbound structured field for the host's next
// read and presents attention.
func (t *Console3270) presentInbound(rec []byte) {
	t.inboundSF = append([]byte(nil), rec...)
	t.aid = AIDStructuredField
	if t.css != nil {
		t.css.Unsolicited(t.devno, usAttention)
	}
}

// Remote reports whether a remote terminal (a tn3270 client) mirrors the
// display, in which case that terminal answers file-transfer requests.
func (t *Console3270) Remote() bool { return len(t.observers) > 0 }
