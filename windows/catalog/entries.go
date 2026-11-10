package catalog

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

// Entry is one ordered CTL member. Subject is the encoded subject identifier;
// Digest is the lookup digest (indirect-data digest in v1). Attributes preserve
// their order and multiplicity. Neither membership nor Hint is a trust verdict.
type Entry struct {
	Subject    []byte
	Digest     []byte
	Attributes []Attribute
}

// ParseEntries returns member attributes, not catalog-level or signer
// attributes. Version is 1 for SPC indirect data, 2 for subject digests.
// All returned byte slices are independent of the caller's input.
func ParseEntries(data []byte) (version int, result []Entry, err error) {
	return parseEntries(data, "")
}

// ParseEntriesWithNameValue projects named SPC member attributes after full
// member validation, preserving order and multiplicity. Nonmatching members
// are omitted, but malformed unselected attributes still fail the entire parse.
// Returned bytes are independently owned, as with ParseEntries.
func ParseEntriesWithNameValue(data []byte, name string) (int, []Entry, error) {
	if name == "" {
		return 0, nil, fmt.Errorf("empty catalog member attribute name")
	}
	return parseEntries(data, strings.ToLower(name))
}

func parseEntries(data []byte, filter string) (version int, result []Entry, err error) {
	ctl, err := catalogCTL(data)
	if err != nil {
		return 0, nil, err
	}
	entries, v2, err := catalogEntries(ctl)
	if err != nil {
		return 0, nil, err
	}
	version = 1
	if v2 {
		version = 2
	}
	if filter == "" {
		result = make([]Entry, 0, len(entries))
	}
	for _, raw := range entries {
		fields, err := catalogSequence(raw)
		if err != nil || len(fields) != 2 || fields[0].Class != 0 || fields[0].Tag != 4 || fields[1].Class != 0 || fields[1].Tag != 17 {
			return 0, nil, fmt.Errorf("invalid CTL entry")
		}
		digest, err := catalogEntryDigest(fields, v2)
		if err != nil {
			return 0, nil, err
		}
		var entry Entry
		attrs, err := catalogParts(fields[1].Bytes)
		if err != nil {
			return 0, nil, err
		}
		for _, rawAttr := range attrs {
			parts, err := catalogSequence(rawAttr)
			if err != nil || len(parts) != 2 || parts[1].Class != 0 || parts[1].Tag != 17 || !parts[1].IsCompound {
				return 0, nil, fmt.Errorf("invalid CTL member attribute")
			}
			var oid asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(parts[0].FullBytes, &oid)
			if err != nil || len(rest) != 0 {
				return 0, nil, fmt.Errorf("invalid CTL member attribute OID")
			}
			values, err := catalogParts(parts[1].Bytes)
			if err != nil || len(values) == 0 {
				return 0, nil, fmt.Errorf("empty CTL member attribute values")
			}
			attributeOID := oid.String()
			for _, value := range values {
				attr := Attribute{OID: attributeOID, Value: value.FullBytes}
				if attr.OID == "1.3.6.1.4.1.311.12.2.1" {
					attr, err = catalogNameValueView(value.FullBytes)
					if err != nil {
						return 0, nil, err
					}
					attr.OID = attributeOID
				}
				if filter != "" && (!attr.NameValue || strings.ToLower(attr.Name) != filter) {
					continue
				}
				attr.Value = append([]byte(nil), attr.Value...)
				entry.Attributes = append(entry.Attributes, attr)
			}
		}
		if filter != "" && len(entry.Attributes) == 0 {
			continue
		}
		entry.Subject = append([]byte(nil), fields[0].Bytes...)
		entry.Digest = digest
		result = append(result, entry)
	}
	return version, result, nil
}
