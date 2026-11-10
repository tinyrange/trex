// Package catalog reads Windows catalog membership without making signature or trust decisions.
package catalog

import (
	"encoding/asn1"
	"fmt"
)

func catalogParts(data []byte) ([]asn1.RawValue, error) {
	var result []asn1.RawValue
	// Reuse the reflection destination; appended RawValues retain their own
	// slice headers, not this temporary struct.
	var item asn1.RawValue
	for len(data) != 0 {
		if len(result) >= 1000000 {
			return nil, fmt.Errorf("too many catalog elements")
		}
		rest, err := asn1.Unmarshal(data, &item)
		if err != nil {
			return nil, err
		}
		if result == nil && len(rest) != 0 {
			// Most CTL fields and attributes are pairs. Avoid allocating and
			// immediately growing a one-element slice, without overallocating
			// the equally common singleton wrappers.
			result = make([]asn1.RawValue, 0, 2)
		}
		result = append(result, item)
		data = rest
	}
	return result, nil
}
func catalogSequence(v asn1.RawValue) ([]asn1.RawValue, error) {
	if v.Class != 0 || v.Tag != 16 || !v.IsCompound {
		return nil, fmt.Errorf("expected catalog sequence")
	}
	return catalogParts(v.Bytes)
}
func catalogOID(v asn1.RawValue, oid string) bool {
	var value asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(v.FullBytes, &value)
	return err == nil && len(rest) == 0 && value.String() == oid
}

// catalogCTL unwraps the bounded SignedData catalog, not signer attributes.
func catalogCTL(data []byte) ([]asn1.RawValue, error) {
	if len(data) > 64<<20 {
		return nil, fmt.Errorf("catalog exceeds 64 MiB")
	}
	top, err := catalogParts(data)
	if err != nil || len(top) != 1 {
		return nil, fmt.Errorf("invalid catalog ContentInfo: %v", err)
	}
	ci, err := catalogSequence(top[0])
	if err != nil || len(ci) != 2 || !catalogOID(ci[0], "1.2.840.113549.1.7.2") || ci[1].Class != 2 || ci[1].Tag != 0 {
		return nil, fmt.Errorf("expected SignedData")
	}
	wrapper, err := catalogParts(ci[1].Bytes)
	if err != nil || len(wrapper) != 1 {
		return nil, fmt.Errorf("invalid SignedData wrapper")
	}
	signed, err := catalogSequence(wrapper[0])
	if err != nil || len(signed) < 3 {
		return nil, fmt.Errorf("invalid SignedData")
	}
	content, err := catalogSequence(signed[2])
	if err != nil || len(content) != 2 || !catalogOID(content[0], "1.3.6.1.4.1.311.10.1") || content[1].Class != 2 || content[1].Tag != 0 {
		return nil, fmt.Errorf("expected CTL content")
	}
	payload, err := catalogParts(content[1].Bytes)
	if err != nil || len(payload) != 1 {
		return nil, fmt.Errorf("invalid CTL wrapper")
	}
	if payload[0].Class == 0 && payload[0].Tag == 4 {
		payload, err = catalogParts(payload[0].Bytes)
		if err != nil || len(payload) != 1 {
			return nil, fmt.Errorf("invalid encapsulated CTL")
		}
	}
	ctl, err := catalogSequence(payload[0])
	if err != nil {
		return nil, err
	}
	return ctl, nil
}

// ParseIndex returns CTL member digests, not digest-sized attributes or
// certificate values. It supports v1 indirect data and v2 subject identifiers.
// It does not verify the SignedData signature or establish publisher trust.
func ParseIndex(data []byte) ([][]byte, error) {
	ctl, err := catalogCTL(data)
	if err != nil {
		return nil, err
	}
	entries, v2, err := catalogEntries(ctl)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		fields, err := catalogSequence(entry)
		if err != nil || len(fields) != 2 || fields[0].Class != 0 || fields[0].Tag != 4 || fields[1].Class != 0 || fields[1].Tag != 17 {
			return nil, fmt.Errorf("invalid CTL entry")
		}
		digest, err := catalogEntryDigest(fields, v2)
		if err != nil {
			return nil, err
		}
		result = append(result, digest)
	}
	return result, nil
}

// catalogEntries validates the CTL header and bounds the member sequence.
func catalogEntries(ctl []asn1.RawValue) ([]asn1.RawValue, bool, error) {
	i := 0
	if i < len(ctl) && ctl[i].Tag == 2 {
		i++
	} // version
	if i >= len(ctl) || ctl[i].Tag != 16 {
		return nil, false, fmt.Errorf("missing CTL usage")
	}
	i++
	if i < len(ctl) && ctl[i].Tag == 4 {
		i++
	} // list identifier
	if i < len(ctl) && ctl[i].Tag == 2 {
		i++
	} // sequence number
	if i >= len(ctl) || (ctl[i].Tag != 23 && ctl[i].Tag != 24) {
		return nil, false, fmt.Errorf("missing CTL update time")
	}
	i++
	if i < len(ctl) && (ctl[i].Tag == 23 || ctl[i].Tag == 24) {
		i++
	}
	if i >= len(ctl) {
		return nil, false, fmt.Errorf("missing CTL algorithm")
	}
	algorithm, err := catalogSequence(ctl[i])
	i++
	if err != nil || len(algorithm) < 1 {
		return nil, false, fmt.Errorf("invalid CTL algorithm")
	}
	v2 := catalogOID(algorithm[0], "1.3.6.1.4.1.311.12.1.3")
	if !v2 && !catalogOID(algorithm[0], "1.3.6.1.4.1.311.12.1.2") {
		return nil, false, fmt.Errorf("unsupported CTL subject algorithm")
	}
	if i == len(ctl) {
		return nil, v2, nil
	}
	if ctl[i].Class == 2 {
		if i != len(ctl)-1 || ctl[i].Tag != 0 || !ctl[i].IsCompound {
			return nil, false, fmt.Errorf("invalid CTL extensions")
		}
		return nil, v2, nil
	}
	if len(ctl) > i+2 || len(ctl) == i+2 && (ctl[i+1].Class != 2 || ctl[i+1].Tag != 0 || !ctl[i+1].IsCompound) {
		return nil, false, fmt.Errorf("unexpected fields after CTL entries")
	}
	entries, err := catalogSequence(ctl[i])
	if err != nil {
		return nil, false, err
	}
	return entries, v2, nil
}

func catalogEntryDigest(fields []asn1.RawValue, v2 bool) ([]byte, error) {
	digest := fields[0].Bytes
	if !v2 {
		attrs, err := catalogParts(fields[1].Bytes)
		if err != nil {
			return nil, err
		}
		digest = nil
		for _, attr := range attrs {
			parts, err := catalogSequence(attr)
			if err != nil || len(parts) != 2 {
				return nil, fmt.Errorf("invalid CTL attribute")
			}
			if !catalogOID(parts[0], "1.3.6.1.4.1.311.2.1.4") {
				continue
			}
			if parts[1].Class != 0 || parts[1].Tag != 17 {
				return nil, fmt.Errorf("invalid indirect-data values")
			}
			values, err := catalogParts(parts[1].Bytes)
			if err != nil || len(values) != 1 {
				return nil, fmt.Errorf("invalid indirect-data value")
			}
			indirect, err := catalogSequence(values[0])
			if err != nil || len(indirect) != 2 {
				return nil, fmt.Errorf("invalid indirect data")
			}
			info, err := catalogSequence(indirect[1])
			if err != nil || len(info) != 2 || info[1].Class != 0 || info[1].Tag != 4 {
				return nil, fmt.Errorf("invalid digest info")
			}
			digest = info[1].Bytes
			break
		}
	}
	if len(digest) != 20 && len(digest) != 32 {
		return nil, fmt.Errorf("unsupported CTL digest length %d", len(digest))
	}
	return append([]byte(nil), digest...), nil
}
