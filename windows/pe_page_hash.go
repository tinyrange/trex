package windows

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
)

// Page-hash wire conventions were cross-checked against the Apache-2.0
// licensed SAS Relic format reference (lib/authenticode/{structs,pedigest}.go).
// This implementation uses trex's validated PE ranges and DER constructors.
var spcPageHashV2OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 3, 2}

func pePageHashImageData(hashes []byte) []byte {
	classID := []byte{0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 0x05, 0xa2, 0x17, 0xda, 0x8e, 0x60, 0xd6}
	serialized := signingSet(signingAttribute(spcPageHashV2OID, signingTLV(4, hashes)))
	moniker := signingTLV(0xa1, append(signingTLV(4, classID), signingTLV(4, serialized)...))
	return signingSequence([]byte{3, 1, 0}, signingTLV(0xa0, moniker))
}

// pePageHashes hashes mapped image pages, not the certificate or overlay.
// Offsets in the table are file offsets. Header exclusions are omitted rather
// than zeroed, so a normal first page hashes 4096-12 bytes. Section tails are
// zero-padded; the final entry records the last raw section end with a zero hash.
func pePageHashes(data []byte) ([]byte, error) {
	ranges, err := authenticodePERanges(data)
	if err != nil {
		return nil, err
	}
	pe := int(binary.LittleEndian.Uint32(data[0x3c:]))
	headerSize := int(binary.LittleEndian.Uint32(data[pe+24+60:]))
	pageSize := 4096
	switch binary.LittleEndian.Uint16(data[pe+4:]) {
	case 0x184, 0x284, 0x200:
		pageSize = 8192
	}
	zero := make([]byte, pageSize)
	var result []byte
	add := func(offset int, digest []byte) {
		result = binary.LittleEndian.AppendUint32(result, uint32(offset))
		result = append(result, digest...)
	}
	for at := 0; at < headerSize; at += pageSize {
		end := min(at+pageSize, headerSize)
		h := sha256.New()
		for _, r := range ranges {
			if r.offset >= headerSize {
				break
			}
			start, stop := max(at, r.offset), min(end, r.offset+r.size)
			if start < stop {
				h.Write(data[start:stop])
			}
		}
		h.Write(zero[:pageSize-(end-at)])
		add(at, h.Sum(nil))
	}
	last := headerSize
	for _, r := range ranges {
		if r.offset < headerSize {
			continue
		}
		for at := r.offset; at < r.offset+r.size; at += pageSize {
			end := min(at+pageSize, r.offset+r.size)
			h := sha256.New()
			h.Write(data[at:end])
			h.Write(zero[:pageSize-(end-at)])
			add(at, h.Sum(nil))
			last = end
		}
	}
	add(last, make([]byte, sha256.Size))
	return result, nil
}
