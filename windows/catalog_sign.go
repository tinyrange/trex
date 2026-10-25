package windows

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

var (
	catalogCTLOID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}
	catalogUsageOID      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 1, 1}
	catalogMemberOID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 1, 2}
	catalogNameValueOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 1}
	catalogMemberInfoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 2}
	catalogFlatFileOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 25}
)

func catalogUTF16(value string, order binary.ByteOrder, terminate bool) []byte {
	words := utf16.Encode([]rune(value))
	if terminate {
		words = append(words, 0)
	}
	result := make([]byte, len(words)*2)
	for i, word := range words {
		order.PutUint16(result[2*i:], word)
	}
	return result
}

func catalogNameValue(name, value string) []byte {
	return signingSequence(signingTLV(0x1e, catalogUTF16(name, binary.BigEndian, false)),
		[]byte{2, 4, 0x10, 1, 0, 1}, // authenticated UTF-16 attribute, CRYPTCAT_ATTR_*.
		signingTLV(4, catalogUTF16(value, binary.LittleEndian, true)))
}

// Catalog subject tags use the uppercase hash in NUL-terminated UTF-16LE.
// The CTL v1 member attribute carries the actual SHA-256 digest. See
// docs/pe-signing.md for the wire format and supported file kinds.
func catalogMember(name string, data []byte, osAttributes string) ([]byte, error) {
	digest, err := windowsCatalogHash(data, "sha256")
	if err != nil {
		return nil, err
	}
	guid := "{DE351A42-8E59-11D0-8C47-00C04FC295EE}"
	typed := signingSequence(signingOID(catalogFlatFileOID), signingTLV(0xa2,
		signingTLV(0x80, catalogUTF16("<<<Obsolete>>>", binary.BigEndian, false))))
	if _, err := authenticodePERanges(data); err == nil {
		guid = "{43C9A1E0-8DA0-11CF-8736-00AA00A485EB}"
		typed = signingSequence(signingOID(spcPEImageOID), signingSequence([]byte{3, 1, 0},
			signingTLV(0xa0, signingTLV(0xa2, signingTLV(0x80, catalogUTF16("<<<Obsolete>>>", binary.BigEndian, false))))))
	}
	indirect := signingSequence(typed, signingSequence(signingAlgorithm(sha256OID), signingTLV(4, digest)))
	attrs := [][]byte{
		signingAttribute(spcIndirectOID, indirect),
		signingAttribute(catalogMemberInfoOID, signingSequence(signingTLV(0x1e, catalogUTF16(guid, binary.BigEndian, false)), []byte{2, 2, 2, 0})),
		signingAttribute(catalogNameValueOID, catalogNameValue("File", name)),
	}
	if osAttributes != "" {
		attrs = append(attrs, signingAttribute(catalogNameValueOID, catalogNameValue("OSAttr", osAttributes)))
	}
	tag := catalogUTF16(strings.ToUpper(hex.EncodeToString(digest)), binary.LittleEndian, true)
	return signingSequence(signingTLV(4, tag), signingSet(attrs...)), nil
}

func catalogSignBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var members *starlark.Dict
	var identity *peSigningIdentity
	var createdAt int64
	var osAttributes string
	if err := starlark.UnpackArgs("catalog_sign", args, kwargs, "members", &members, "identity", &identity, "created_at", &createdAt, "os_attributes?", &osAttributes); err != nil {
		return nil, err
	}
	if err := identity.validate(); err != nil {
		return nil, err
	}
	if members.Len() == 0 || members.Len() > 4096 {
		return nil, fmt.Errorf("catalog_sign: expected 1 to 4096 members")
	}
	if createdAt < 0 || createdAt > 253402300799 {
		return nil, fmt.Errorf("catalog_sign: invalid creation time (Unix seconds)")
	}
	if len(osAttributes) > 4096 || strings.ContainsRune(osAttributes, 0) || !utf8.ValidString(osAttributes) {
		return nil, fmt.Errorf("catalog_sign: invalid OS attributes")
	}
	names := make([]string, 0, members.Len())
	values := make(map[string]starlark.Value, members.Len())
	for _, item := range members.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok || name == "" || len(name) > 255 || strings.ContainsAny(name, "\\/:\x00") || name == "." || name == ".." || !utf8.ValidString(name) {
			return nil, fmt.Errorf("catalog_sign: member name must be a simple filename")
		}
		name = strings.ToLower(name)
		if _, exists := values[name]; exists {
			return nil, fmt.Errorf("catalog_sign: duplicate member name %q", name)
		}
		names = append(names, name)
		values[name] = item[1]
	}
	sort.Strings(names)
	entries := make([][]byte, 0, len(names))
	remaining := int64(256 << 20)
	for _, name := range names {
		limit := min(remaining, 64<<20)
		data, err := bytesForBinaryValueLimited(values[name], limit)
		if err != nil {
			return nil, fmt.Errorf("catalog_sign %q: %w", name, err)
		}
		remaining -= int64(len(data))
		entry, err := catalogMember(name, data, osAttributes)
		if err != nil {
			return nil, fmt.Errorf("catalog_sign %q: %w", name, err)
		}
		entries = append(entries, entry)
	}
	entrySequence := signingSequence(entries...)
	identifier := sha256.Sum256(entrySequence)
	update, err := asn1.Marshal(time.Unix(createdAt, 0).UTC())
	if err != nil {
		return nil, err
	}
	parts := [][]byte{signingSequence(signingOID(catalogUsageOID)), signingTLV(4, identifier[:16]), update,
		signingAlgorithm(catalogMemberOID), entrySequence}
	if osAttributes != "" {
		parts = append(parts, signingTLV(0xa0, signingSequence(signingSequence(signingOID(catalogNameValueOID), signingTLV(4, catalogNameValue("OSAttr", osAttributes))))))
	}
	result, err := signPKCS7Content(signingSequence(parts...), catalogCTLOID, identity)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(result), nil
}
