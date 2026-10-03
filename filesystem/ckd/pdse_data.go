package ckd

import (
	"bytes"
	"fmt"

	"github.com/tinyrange/trex/storage"
)

// OpenPDSEData resolves the observed six-byte record frames in a PDSE data
// member. It returns payload bytes without frame headers and retains every
// record length (including zero lengths). The independent 4004 descriptor,
// not allocation slack or an apparent marker in payload, establishes EOF.
func OpenPDSEData(source storage.Reader, info []byte, recordFormat byte, recordLength uint16, maxRecords int) (*Content, []uint32, error) {
	bad := func(s string) (*Content, []uint32, error) { return nil, nil, fmt.Errorf("PDSE data: %s", s) }
	if maxRecords <= 0 || len(info) != 85 || info[0] != 1 {
		return bad("invalid limits or member descriptor")
	}
	if recordFormat != 0x80 && recordFormat != 0x90 && recordFormat != 0x40 && recordFormat != 0x50 {
		return bad("unsupported record format")
	}
	count := uint64(be.Uint32(info[48:]))
	length := be.Uint64(info[28:])
	pages := uint64(be.Uint32(info[56:]))
	if count > uint64(maxRecords) || count != uint64(be.Uint32(info[64:])) || pages*4096 != uint64(source.Size()) || (pages > 0 && uint64(be.Uint32(info[52:]))+1 != pages) || length > uint64(source.Size()) || count*6 > uint64(source.Size())-length {
		return bad("inconsistent counts or record budget exceeded")
	}
	out := &Content{source: source}
	sizes := make([]uint32, 0, int(count))
	var pos int64
	var largest uint32
	for i := uint64(0); i < count; i++ {
		var header [6]byte
		if _, err := source.ReadAt(header[:], pos); err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(header[:4], []byte{0xc3, 0, 0, 0}) {
			return bad("unsupported record frame")
		}
		n := uint32(be.Uint16(header[4:]))
		if int64(n) > source.Size()-pos-6 {
			return bad("record outside allocation")
		}
		if recordFormat&0xc0 == 0x80 {
			if recordLength == 0 || n != uint32(recordLength) {
				return bad("fixed record length mismatch")
			}
		} else if recordLength < 4 || n > uint32(recordLength-4) {
			return bad("variable record exceeds LRECL")
		}
		if n > largest {
			largest = n
		}
		sizes = append(sizes, n)
		if n > 0 {
			out.spans = append(out.spans, span{pos + 6, int64(n), out.size})
		}
		out.size += int64(n)
		pos += 6 + int64(n)
	}
	if uint64(out.size) != length || largest != be.Uint32(info[60:]) {
		return bad("logical size or maximum record length mismatch")
	}
	return out, sizes, nil
}

// DataMembers reads fixed or variable PDSE data libraries without converting
// EBCDIC or inventing newline separators. RecordLengths preserves boundaries.
func (ds *Dataset) DataMembers(maxMembers int) ([]PDSEMember, error) {
	if ds.SMSFlags&0x0a != 8 || maxMembers <= 0 {
		return nil, fmt.Errorf("IGW: not a PDSE data library")
	}
	pages, err := ds.OpenPages(4096)
	if err != nil {
		return nil, err
	}
	g, err := OpenIGW(pages)
	if err != nil {
		return nil, err
	}
	return g.pdseMembers(maxMembers, ds.RecordFormat, ds.RecordLength)
}
