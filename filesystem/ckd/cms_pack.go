package ckd

import (
	"bytes"
	"fmt"
)

// CMS packed files (COPYFILE PACK) are usually F 1024 files; some are
// variable-format files whose records hold the same stream. The stream
// begins with X'0001', X'40', the original record format (F or V in EBCDIC)
// and its 4-byte LRECL, followed by codes:
//
//	X'00'-X'77'               n+1 blanks (X'40')
//	X'78' n                   n+1 blanks
//	X'79' nn                  nn+1 blanks (16-bit count)
//	X'7A' n c                 n+1 copies of byte c
//	X'7B' nn c                nn+1 copies of byte c (16-bit count)
//	X'7C' n                   n+1 blanks ending a variable record
//	X'7E' n c                 n+1 copies of c ending a variable record
//	X'80'-X'F7'               (code&X'7F')+1 literal bytes
//	X'F8' n                   n+1 literal bytes
//	X'F9' nn                  nn+1 literal bytes (16-bit count)
//	X'FC' n                   n+1 literal bytes ending a variable record
//	X'FD' nn                  nn+1 literal bytes ending a variable record
//	X'FF'                     end of data; the rest of the final container
//	                          record is blank or repeats the stream 1024
//	                          bytes earlier (the packer's chunk buffer)
//
// Other codes (X'7D', X'7F', X'FA'-X'FB', X'FE') have
// not been observed and are rejected.
//
// Fixed output is the concatenation of whole records. Variable output uses
// the same 2-byte length-prefixed stream as CMSMinidisk.Content. Decoded from
// z/VM 4.4 ADCD media; packed and unpacked copies of the same files agree.

var cmsPackMagic = []byte{0x00, 0x01, 0x40}

type CMSUnpacked struct {
	RecordFormat byte
	RecordLength uint32
	Records      int
	// MaximumRecord is the longest variable record decoded.
	MaximumRecord int
	Data          []byte
}

// IsCMSPacked reports whether content begins with a packed-file header.
func IsCMSPacked(b []byte) bool {
	return len(b) >= 8 && bytes.Equal(b[:3], cmsPackMagic) && (b[3] == 0xc6 || b[3] == 0xe5)
}

// UnpackCMS decodes packed content, bounding the decoded size by maximumBytes.
func UnpackCMS(b []byte, maximumBytes int) (*CMSUnpacked, error) {
	starts := make([]int, 0, len(b)/1024+1)
	for p := 0; p < len(b); p += 1024 {
		starts = append(starts, p)
	}
	return unpackCMS(b, starts, maximumBytes)
}

// UnpackCMSRecords decodes a packed stream held in container records of any
// length, such as the records of a variable-format packed file.
func UnpackCMSRecords(records [][]byte, maximumBytes int) (*CMSUnpacked, error) {
	starts := make([]int, len(records))
	var b []byte
	for i, r := range records {
		starts[i] = len(b)
		b = append(b, r...)
	}
	return unpackCMS(b, starts, maximumBytes)
}

// unpackCMS decodes b, whose container records begin at starts.
func unpackCMS(b []byte, starts []int, maximumBytes int) (*CMSUnpacked, error) {
	if !IsCMSPacked(b) {
		return nil, fmt.Errorf("cms unpack: not a packed file")
	}
	u := &CMSUnpacked{RecordFormat: b[3], RecordLength: be.Uint32(b[4:8])}
	if u.RecordLength == 0 || u.RecordLength > 65535 {
		return nil, fmt.Errorf("cms unpack: invalid LRECL %d", u.RecordLength)
	}
	variable := u.RecordFormat == 0xe5
	var out, record []byte
	emit := func(p []byte) error {
		record = append(record, p...)
		// A variable record is written with a 2-byte length prefix.
		pending := len(record)
		if variable {
			pending += 2
		}
		if len(out)+pending > maximumBytes {
			return fmt.Errorf("cms unpack: decoded content exceeds limit")
		}
		if !variable {
			for len(record) >= int(u.RecordLength) {
				out = append(out, record[:u.RecordLength]...)
				record = record[u.RecordLength:]
				u.Records++
			}
		} else if len(record) > int(u.RecordLength) {
			return fmt.Errorf("cms unpack: record %d exceeds LRECL %d", u.Records+1, u.RecordLength)
		}
		return nil
	}
	endRecord := func() {
		u.MaximumRecord = max(u.MaximumRecord, len(record))
		out = append(out, byte(len(record)>>8), byte(len(record)))
		out = append(out, record...)
		record = record[:0]
		u.Records++
	}
	blanks := bytes.Repeat([]byte{0x40}, 256)
	for i := 8; ; {
		if i >= len(b) {
			return nil, fmt.Errorf("cms unpack: missing end marker")
		}
		c := b[i]
		var err error
		switch {
		case c == 0xff:
			// The rest of the final container record is the pack buffer: blank
			// when fresh, otherwise the previous record's bytes left in place.
			k := len(starts) - 1
			if i < starts[k] {
				return nil, fmt.Errorf("cms unpack: end marker before the final container record")
			}
			tail := b[i+1:]
			// The packer fills 1024-byte chunks even inside larger container
			// records, so leftover bytes repeat the stream 1024 bytes earlier.
			stale := i+1 >= 1024 && bytes.Equal(tail, b[i+1-1024:len(b)-1024])
			if !stale && !bytes.Equal(tail, blanks128(len(tail))) {
				return nil, fmt.Errorf("cms unpack: data after end marker is neither padding nor the previous record")
			}
			if len(record) != 0 {
				return nil, fmt.Errorf("cms unpack: stream ends inside a record")
			}
			u.Data = out
			if u.Data == nil {
				u.Data = []byte{}
			}
			return u, nil
		case c == 0x7a:
			if i+3 > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated repeat")
			}
			err = emit(bytes.Repeat([]byte{b[i+2]}, int(b[i+1])+1))
			i += 3
		case c == 0x7b:
			if i+4 > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated long repeat")
			}
			err = emit(bytes.Repeat([]byte{b[i+3]}, int(be.Uint16(b[i+1:]))+1))
			i += 4
		case c == 0x7e:
			if !variable || i+3 > len(b) {
				return nil, fmt.Errorf("cms unpack: unexpected or truncated final repeat")
			}
			if err = emit(bytes.Repeat([]byte{b[i+2]}, int(b[i+1])+1)); err == nil {
				endRecord()
			}
			i += 3
		case c < 0x78:
			err = emit(blanks[:int(c)+1])
			i++
		case c == 0x78:
			if i+2 > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated blank run")
			}
			err = emit(blanks[:int(b[i+1])+1])
			i += 2
		case c == 0x79:
			if i+3 > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated long blank run")
			}
			err = emit(bytes.Repeat([]byte{0x40}, int(be.Uint16(b[i+1:]))+1))
			i += 3
		case c == 0x7c:
			if !variable || i+2 > len(b) {
				return nil, fmt.Errorf("cms unpack: unexpected or truncated final blanks")
			}
			if err = emit(blanks[:int(b[i+1])+1]); err == nil {
				endRecord()
			}
			i += 2
		case c < 0x80:
			return nil, fmt.Errorf("cms unpack: unsupported code %02x at %d", c, i)
		case c == 0xf8:
			if i+2 > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated long literal")
			}
			n := int(b[i+1]) + 1
			if i+2+n > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated long literal")
			}
			err = emit(b[i+2 : i+2+n])
			i += 2 + n
		case c == 0xf9:
			if i+3 > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated long literal")
			}
			n := int(be.Uint16(b[i+1:])) + 1
			if i+3+n > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated long literal")
			}
			err = emit(b[i+3 : i+3+n])
			i += 3 + n
		case c == 0xfd:
			if !variable || i+3 > len(b) {
				return nil, fmt.Errorf("cms unpack: unexpected or truncated long final literal")
			}
			n := int(be.Uint16(b[i+1:])) + 1
			if i+3+n > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated long final literal")
			}
			if err = emit(b[i+3 : i+3+n]); err == nil {
				endRecord()
			}
			i += 3 + n
		case c >= 0xfa && c != 0xfc:
			return nil, fmt.Errorf("cms unpack: unsupported code %02x at %d", c, i)
		case c < 0xf8:
			n := int(c&0x7f) + 1
			if i+1+n > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated literal")
			}
			err = emit(b[i+1 : i+1+n])
			i += 1 + n
		case c == 0xfc:
			if !variable || i+2 > len(b) {
				return nil, fmt.Errorf("cms unpack: unexpected end-of-record code")
			}
			n := int(b[i+1]) + 1
			if i+2+n > len(b) {
				return nil, fmt.Errorf("cms unpack: truncated final literal")
			}
			if err = emit(b[i+2 : i+2+n]); err == nil {
				endRecord()
			}
			i += 2 + n
		default:
			return nil, fmt.Errorf("cms unpack: unsupported code %02x at %d", c, i)
		}
		if err != nil {
			return nil, err
		}
	}
}

func blanks128(n int) []byte { return bytes.Repeat([]byte{0x40}, n) }
