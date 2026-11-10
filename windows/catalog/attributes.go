package catalog

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Attribute preserves one ordered, catalog-level CTL extension. NameValue
// marks the SPC_NAME_VALUE encoding exposed by CryptCATEnumerateCatAttr.
// Unknown OIDs remain opaque; parsing is not a signature or trust decision.
type Attribute struct {
	OID       string
	Critical  bool
	NameValue bool
	Name      string
	Flags     uint32
	Value     []byte
}

func catalogBMP(value asn1.RawValue) (string, error) {
	if value.Class != 0 || value.Tag != 30 || value.IsCompound || len(value.Bytes)%2 != 0 {
		return "", fmt.Errorf("invalid catalog attribute BMPString")
	}
	units := make([]uint16, len(value.Bytes)/2)
	for i := range units {
		units[i] = binary.BigEndian.Uint16(value.Bytes[i*2:])
		// BMPString excludes surrogate code points. NUL cannot be represented
		// in the null-terminated Win32 reference-tag contract.
		if units[i] == 0 || units[i] >= 0xd800 && units[i] <= 0xdfff {
			return "", fmt.Errorf("invalid catalog attribute name code point")
		}
	}
	if len(units) == 0 {
		return "", fmt.Errorf("empty catalog attribute name")
	}
	return string(utf16.Decode(units)), nil
}

// ParseAttributes reads only the global CTL extensions, never member or signer
// attributes. Name/value payload bytes and flags are preserved without value
// normalization, duplicate coalescing, or invented defaults.
func ParseAttributes(data []byte) ([]Attribute, error) {
	if _, err := ParseIndex(data); err != nil {
		return nil, err
	}
	ctl, err := catalogCTL(data)
	if err != nil {
		return nil, err
	}
	last := ctl[len(ctl)-1]
	if last.Class != 2 {
		return []Attribute{}, nil
	}
	explicit, err := catalogParts(last.Bytes)
	if err != nil || len(explicit) != 1 {
		return nil, fmt.Errorf("invalid CTL extensions wrapper")
	}
	extensions, err := catalogSequence(explicit[0])
	if err != nil {
		return nil, err
	}
	result := make([]Attribute, 0, len(extensions))
	for _, extension := range extensions {
		fields, err := catalogSequence(extension)
		if err != nil || (len(fields) != 2 && len(fields) != 3) {
			return nil, fmt.Errorf("invalid catalog extension")
		}
		var oid asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(fields[0].FullBytes, &oid)
		if err != nil || len(rest) != 0 {
			return nil, fmt.Errorf("invalid catalog extension OID")
		}
		attr := Attribute{OID: oid.String()}
		if len(fields) == 3 {
			rest, err = asn1.Unmarshal(fields[1].FullBytes, &attr.Critical)
			if err != nil || len(rest) != 0 {
				return nil, fmt.Errorf("invalid catalog extension critical flag")
			}
		}
		payload := fields[len(fields)-1]
		if payload.Class != 0 || payload.Tag != 4 || payload.IsCompound {
			return nil, fmt.Errorf("invalid catalog extension payload")
		}
		attr.Value = append([]byte(nil), payload.Bytes...)
		if attr.OID == "1.3.6.1.4.1.311.12.2.1" {
			decoded, err := catalogNameValue(payload.Bytes)
			if err != nil {
				return nil, err
			}
			decoded.OID, decoded.Critical = attr.OID, attr.Critical
			attr = decoded
		}
		result = append(result, attr)
	}
	return result, nil
}

func catalogNameValue(data []byte) (Attribute, error) {
	attr, err := catalogNameValueView(data)
	if err != nil {
		return Attribute{}, err
	}
	attr.Value = append([]byte(nil), attr.Value...)
	return attr, nil
}

// Borrow payload bytes only inside a parse. Public results clone selected data.
func catalogNameValueView(data []byte) (Attribute, error) {
	var attr Attribute
	values, err := catalogParts(data)
	if err != nil || len(values) != 1 {
		return Attribute{}, fmt.Errorf("invalid catalog name/value wrapper")
	}
	parts, err := catalogSequence(values[0])
	if err != nil || len(parts) != 3 {
		return Attribute{}, fmt.Errorf("invalid catalog name/value attribute")
	}
	attr.Name, err = catalogBMP(parts[0])
	if err != nil {
		return Attribute{}, err
	}
	var flags int64
	rest, err := asn1.Unmarshal(parts[1].FullBytes, &flags)
	if err != nil || len(rest) != 0 || flags < 0 || flags > 0xffffffff {
		return Attribute{}, fmt.Errorf("invalid catalog attribute flags")
	}
	if parts[2].Class != 0 || parts[2].Tag != 4 || parts[2].IsCompound {
		return Attribute{}, fmt.Errorf("invalid catalog attribute value")
	}
	attr.NameValue = true
	attr.Flags = uint32(flags)
	attr.Value = parts[2].Bytes
	return attr, nil
}
