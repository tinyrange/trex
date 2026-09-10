package pri

import (
	"fmt"
	"unicode/utf16"
)

const (
	SchemaType         = "[mrm_hschema]  \x00"
	ExtendedSchemaType = "[mrm_hschemaex] "
	NamesType          = "[def_hnames]   \x00"
	ExtendedNamesType  = "[def_hnamesx]  \x00"
)

// Schema contains the identifiers and hierarchical names from a schema section.
// Version records are preserved without assigning unverified field meanings.
type Schema struct {
	Identifiers [2]string
	Versions    [][20]byte
	Names       *Names
}

func ParseSchema(section Section) (*Schema, error) {
	payload, err := section.Payload()
	if err != nil {
		return nil, err
	}
	header := 8
	nameType := NamesType
	switch string(section.Type[:]) {
	case SchemaType:
	case ExtendedSchemaType:
		header = 24
	default:
		return nil, fmt.Errorf("pri: unsupported schema section type")
	}
	if len(payload) < header {
		return nil, fmt.Errorf("pri: truncated schema header")
	}
	if header == 24 {
		nameType = string(payload[8:24])
	}
	if nameType != NamesType && nameType != ExtendedNamesType {
		return nil, fmt.Errorf("pri: unsupported hierarchical-name type %q", nameType)
	}
	versions := int(le.Uint16(payload))
	lengths := [2]int{int(le.Uint16(payload[2:])), int(le.Uint16(payload[4:]))}
	if versions < 1 || lengths[0] < 2 || lengths[1] < 2 {
		return nil, fmt.Errorf("pri: invalid schema counts")
	}
	end := header + 20*versions + 2*lengths[0] + 2*lengths[1]
	aligned := (end + 3) &^ 3
	if aligned > len(payload) {
		return nil, fmt.Errorf("pri: truncated schema identifiers/versions")
	}
	s := &Schema{Versions: make([][20]byte, versions)}
	off := header
	for i := range s.Versions {
		copy(s.Versions[i][:], payload[off:off+20])
		off += 20
	}
	for i, length := range lengths {
		units := make([]uint16, length)
		for j := range units {
			units[j] = le.Uint16(payload[off+2*j:])
		}
		off += 2 * length
		if units[length-1] != 0 {
			return nil, fmt.Errorf("pri: unterminated schema identifier")
		}
		units = units[:length-1]
		for j := 0; j < len(units); j++ {
			u := units[j]
			if u == 0 {
				return nil, fmt.Errorf("pri: embedded NUL in schema identifier")
			}
			if u >= 0xd800 && u <= 0xdbff {
				if j+1 >= len(units) || units[j+1] < 0xdc00 || units[j+1] > 0xdfff {
					return nil, fmt.Errorf("pri: invalid identifier surrogate")
				}
				j++
			} else if u >= 0xdc00 && u <= 0xdfff {
				return nil, fmt.Errorf("pri: invalid identifier surrogate")
			}
		}
		s.Identifiers[i] = string(utf16.Decode(units))
	}
	s.Names, err = ParseNames(payload[aligned:], nameType == ExtendedNamesType)
	if err != nil {
		return nil, err
	}
	return s, nil
}
