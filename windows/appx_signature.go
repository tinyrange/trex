package windows

// Bounded APPX/MSIX Authenticode integrity. All parsing and hashing use the
// supplied immutable bytes, never a host trust store, filesystem, or tool.
import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"go.starlark.net/starlark"
)

var appxSIPOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 30}
var appxSIPUUID = []byte{0x4b, 0xdf, 0xc5, 0x0a, 0x07, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0, 0x9f, 0xd1}

type appxSIPInfo struct {
	Version       int
	UUID          []byte
	A, B, C, D, E int
}

type appxHashParts struct {
	hashes    map[string][]byte
	signature []byte
}

// Supports single-disk, comment-free ZIP/ZIP64 with a final signature local
// record and final signature directory entry. Other layouts fail closed.
// ZIP64 entry sizes/offsets are deliberately excluded by the 64 MiB bound.
func appxPackageHashes(data []byte) (*appxHashParts, error) {
	bad := func(detail string) (*appxHashParts, error) {
		return nil, fmt.Errorf("unsupported or malformed APPX ZIP layout: %s", detail)
	}
	if len(data) < 22 || len(data) > 64<<20 {
		return bad("size")
	}
	le := binary.LittleEndian
	end := len(data) - 22
	if le.Uint32(data[end:]) != 0x06054b50 || le.Uint16(data[end+20:]) != 0 || le.Uint16(data[end+4:]) != 0 || le.Uint16(data[end+6:]) != 0 {
		return bad("end record")
	}
	count := uint64(le.Uint16(data[end+10:]))
	cdSize := uint64(le.Uint32(data[end+12:]))
	cdOffset := uint64(le.Uint32(data[end+16:]))
	tail := end
	is64 := count == 0xffff || cdSize == 0xffffffff || cdOffset == 0xffffffff
	if is64 {
		if end < 76 || le.Uint32(data[end-20:]) != 0x07064b50 || le.Uint32(data[end-16:]) != 0 || le.Uint32(data[end-4:]) != 1 {
			return bad("ZIP64 locator")
		}
		z64 := end - 76
		if le.Uint64(data[end-12:]) != uint64(z64) || le.Uint32(data[z64:]) != 0x06064b50 || le.Uint64(data[z64+4:]) != 44 || le.Uint32(data[z64+16:]) != 0 || le.Uint32(data[z64+20:]) != 0 {
			return bad("ZIP64 end record")
		}
		count = le.Uint64(data[z64+32:])
		cdSize = le.Uint64(data[z64+40:])
		cdOffset = le.Uint64(data[z64+48:])
		if le.Uint64(data[z64+24:]) != count {
			return bad("ZIP64 counts")
		}
		tail = z64
	} else if le.Uint16(data[end+8:]) != uint16(count) {
		return bad("disk counts")
	}
	if count < 3 || count > 4096 || cdOffset > uint64(tail) || cdSize != uint64(tail)-cdOffset {
		return bad("central bounds")
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(reader.File) != int(count) {
		return bad("ZIP reader")
	}
	files := map[string]*zip.File{}
	cursor := int(cdOffset)
	signatureCD, signatureLocal := -1, -1
	previousEnd := 0
	for i, f := range reader.File {
		if cursor > tail-46 || le.Uint32(data[cursor:]) != 0x02014b50 {
			return bad("central header")
		}
		nameLen, extraLen, commentLen := int(le.Uint16(data[cursor+28:])), int(le.Uint16(data[cursor+30:])), int(le.Uint16(data[cursor+32:]))
		length := 46 + nameLen + extraLen + commentLen
		if length > tail-cursor || commentLen != 0 || le.Uint16(data[cursor+34:]) != 0 || le.Uint32(data[cursor+20:]) == 0xffffffff || le.Uint32(data[cursor+24:]) == 0xffffffff {
			return bad("central entry bounds")
		}
		name := string(data[cursor+46 : cursor+46+nameLen])
		if name != f.Name || name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "\x00") || files[strings.ToLower(name)] != nil {
			return bad("entry name")
		}
		for _, part := range strings.Split(name, "/") {
			if part == "." || part == ".." || part == "" {
				return bad("entry path")
			}
		}
		local := uint64(le.Uint32(data[cursor+42:]))
		if local != uint64(previousEnd) || local > cdOffset || cdOffset-local < 30 {
			return bad("local sequence")
		}
		l := int(local)
		if le.Uint32(data[l:]) != 0x04034b50 || le.Uint16(data[l+6:]) != f.Flags || le.Uint16(data[l+8:]) != f.Method || f.Flags & ^uint16(0x808) != 0 {
			return bad("local header flags")
		}
		ln, extra := int(le.Uint16(data[l+26:])), int(le.Uint16(data[l+28:]))
		offset := l + 30 + ln + extra
		if offset > int(cdOffset) || ln != nameLen || string(data[l+30:l+30+ln]) != name || f.CompressedSize64 > cdOffset-uint64(offset) {
			return bad("local data bounds")
		}
		actual, err := f.DataOffset()
		if err != nil || actual != int64(offset) {
			return bad("data offset")
		}
		finish := offset + int(f.CompressedSize64)
		if f.Flags&8 != 0 {
			if finish > int(cdOffset)-12 {
				return bad("data descriptor bounds")
			}
			if le.Uint32(data[finish:]) == 0x08074b50 {
				finish += 4
			}
			if is64 && le.Uint16(data[l+4:]) == 45 {
				if finish > int(cdOffset)-20 || le.Uint32(data[finish:]) != f.CRC32 || le.Uint64(data[finish+4:]) != f.CompressedSize64 || le.Uint64(data[finish+12:]) != f.UncompressedSize64 {
					return bad("ZIP64 data descriptor")
				}
				finish += 20
			} else {
				if finish > int(cdOffset)-12 || le.Uint32(data[finish:]) != f.CRC32 || uint64(le.Uint32(data[finish+4:])) != f.CompressedSize64 || uint64(le.Uint32(data[finish+8:])) != f.UncompressedSize64 {
					return bad("data descriptor")
				}
				finish += 12
			}
		} else if le.Uint32(data[l+14:]) != f.CRC32 || uint64(le.Uint32(data[l+18:])) != f.CompressedSize64 || uint64(le.Uint32(data[l+22:])) != f.UncompressedSize64 {
			return bad("local sizes")
		}
		if name == "AppxSignature.p7x" {
			if i != len(reader.File)-1 {
				return bad("signature order")
			}
			signatureCD, signatureLocal = cursor, l
		}
		files[strings.ToLower(name)] = f
		previousEnd = finish
		cursor += length
	}
	if cursor != tail || previousEnd != int(cdOffset) || signatureCD < 0 || signatureLocal < 0 {
		return bad("record coverage")
	}
	readPart := func(name string, limit uint64) ([]byte, error) {
		f := files[strings.ToLower(name)]
		if f == nil || f.UncompressedSize64 > limit {
			return nil, fmt.Errorf("missing or oversized APPX footprint %s", name)
		}
		stream, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer stream.Close()
		value, err := io.ReadAll(io.LimitReader(stream, int64(limit)+1))
		if err != nil || uint64(len(value)) != f.UncompressedSize64 {
			return nil, fmt.Errorf("invalid APPX footprint %s: %v", name, err)
		}
		return value, nil
	}
	hashes := map[string][]byte{}
	add := func(name string, value []byte) { hash := sha256.Sum256(value); hashes[name] = hash[:] }
	add("AXPC", data[:signatureLocal])
	directory := append([]byte(nil), data[int(cdOffset):signatureCD]...)
	newSize := len(directory)
	if is64 {
		z64 := append([]byte(nil), data[tail:end-20]...)
		le.PutUint64(z64[24:], count-1)
		le.PutUint64(z64[32:], count-1)
		le.PutUint64(z64[40:], uint64(newSize))
		le.PutUint64(z64[48:], uint64(signatureLocal))
		directory = append(directory, z64...)
		locator := append([]byte(nil), data[end-20:end]...)
		le.PutUint64(locator[8:], uint64(signatureLocal+newSize))
		directory = append(directory, locator...)
	}
	eocd := append([]byte(nil), data[end:]...)
	if le.Uint16(eocd[8:]) != 0xffff {
		le.PutUint16(eocd[8:], uint16(count-1))
	}
	if le.Uint16(eocd[10:]) != 0xffff {
		le.PutUint16(eocd[10:], uint16(count-1))
	}
	if le.Uint32(eocd[12:]) != 0xffffffff {
		le.PutUint32(eocd[12:], uint32(newSize))
	}
	if le.Uint32(eocd[16:]) != 0xffffffff {
		le.PutUint32(eocd[16:], uint32(signatureLocal))
	}
	directory = append(directory, eocd...)
	add("AXCD", directory)
	for code, name := range map[string]string{"AXCT": "[Content_Types].xml", "AXBM": "AppxBlockMap.xml", "AXCI": "AppxMetadata/CodeIntegrity.cat"} {
		if code == "AXCI" && files[strings.ToLower(name)] == nil {
			continue
		}
		value, err := readPart(name, 16<<20)
		if err != nil {
			return nil, err
		}
		add(code, value)
	}
	signature, err := readPart("AppxSignature.p7x", 4<<20)
	if err != nil {
		return nil, err
	}
	return &appxHashParts{hashes: hashes, signature: signature}, nil
}

func verifyAppxIntegrity(data []byte) (*verifiedPEIntegrity, error) {
	parts, err := appxPackageHashes(data)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(parts.signature, []byte("PKCX")) {
		return nil, fmt.Errorf("invalid APPX signature magic")
	}
	var outer signatureContent
	if err := signatureDER(parts.signature[4:], &outer); err != nil {
		return nil, err
	}
	if !outer.Type.Equal(pkcs7SignedDataOID) {
		return nil, fmt.Errorf("APPX signature is not SignedData")
	}
	var sd signatureSignedData
	if err := signatureDER(outer.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	if sd.Version != 1 || !sd.Content.Type.Equal(spcIndirectOID) {
		return nil, fmt.Errorf("unsupported APPX SignedData")
	}
	var indirect signatureIndirect
	if err := signatureDER(sd.Content.Content.Bytes, &indirect); err != nil {
		return nil, err
	}
	if !indirect.Data.Type.Equal(appxSIPOID) || !signatureAlgorithm(indirect.Digest.Algorithm, sha256OID) {
		return nil, fmt.Errorf("unsupported APPX SIP or digest")
	}
	var sip appxSIPInfo
	if err := signatureDER(indirect.Data.Value.FullBytes, &sip); err != nil {
		return nil, err
	}
	if sip.Version != 0x01010000 || !bytes.Equal(sip.UUID, appxSIPUUID) || sip.A != 0 || sip.B != 0 || sip.C != 0 || sip.D != 0 || sip.E != 0 {
		return nil, fmt.Errorf("unsupported APPX SIP identity")
	}
	digests := indirect.Digest.Value
	if len(digests) != 4+36*len(parts.hashes) || !bytes.HasPrefix(digests, []byte("APPX")) {
		return nil, fmt.Errorf("invalid APPX digest table")
	}
	seen := map[string]bool{}
	for offset := 4; offset < len(digests); offset += 36 {
		name := string(digests[offset : offset+4])
		expected, ok := parts.hashes[name]
		if !ok || seen[name] || !bytes.Equal(expected, digests[offset+4:offset+36]) {
			return nil, fmt.Errorf("APPX %s digest mismatch or duplicate", name)
		}
		seen[name] = true
	}
	var content asn1.RawValue
	if err := signatureDER(sd.Content.Content.Bytes, &content); err != nil {
		return nil, err
	}
	return verifySignedContent(sd, spcIndirectOID, content.Bytes)
}

func appxSignatureBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("appx_signature", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 64<<20)
	if err != nil {
		return nil, err
	}
	result, err := verifyAppxIntegrity(data)
	if err != nil {
		return nil, fmt.Errorf("appx_signature: %w", err)
	}
	return signatureIntegrityRecord(result, "appx_signature")
}
