package uup

import (
	"encoding/xml"
	"fmt"
)

// The public streaming decoder and buffered token decoder share this typed
// reader. encoding/xml still owns namespace/element-balance validation. Unknown
// subtrees are skipped as by DecodeElement, never mistaken for direct children.
// Attribute strings may borrow a buffered document; converters detach the few
// strings which survive numeric/hash conversion.
func cixChildren(d *xml.Decoder, visit func(xml.StartElement) error) error {
	for {
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case xml.StartElement:
			if err := visit(token); err != nil {
				return err
			}
		case xml.EndElement:
			return nil
		}
	}
}
func decodeCIXLocation(d *xml.Decoder, start xml.StartElement, out *rawCIXLocation) error {
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "id":
			out.ID = a.Value
		case "path":
			out.Path = a.Value
		case "flags":
			out.Flags = a.Value
		}
	}
	return d.Skip()
}
func decodeCIXHash(d *xml.Decoder, start xml.StartElement, out *rawCIXHash) error {
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "alg":
			out.Algorithm = a.Value
		case "value":
			out.Value = a.Value
		}
	}
	return d.Skip()
}
func decodeCIXFile(d *xml.Decoder, start xml.StartElement, out *rawCIXFile) error {
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "id":
			out.ID = a.Value
		case "name":
			out.Name = a.Value
		case "length":
			out.Length = a.Value
		case "time":
			out.Time = a.Value
		case "attr":
			out.Attr = a.Value
		}
	}
	return cixChildren(d, func(start xml.StartElement) error {
		switch start.Name.Local {
		case "Hash":
			return decodeCIXHash(d, start, &out.Hash)
		case "Delta":
			return decodeCIXDelta(d, start, &out.Delta)
		default:
			return d.Skip()
		}
	})
}
func decodeCIXDelta(d *xml.Decoder, _ xml.StartElement, out *rawCIXDelta) error {
	return cixChildren(d, func(start xml.StartElement) error {
		switch start.Name.Local {
		case "Source":
			if len(out.Sources) >= defaultCIXMaximumSourcesPerFile {
				return fmt.Errorf("uup CIX: source count exceeds %d", defaultCIXMaximumSourcesPerFile)
			}
			var source rawCIXSource
			if err := decodeCIXSource(d, start, &source); err != nil {
				return err
			}
			out.Sources = append(out.Sources, source)
		case "Basis":
			if len(out.Bases) >= defaultCIXMaximumSourcesPerFile {
				return fmt.Errorf("uup CIX: basis count exceeds %d", defaultCIXMaximumSourcesPerFile)
			}
			var basis rawCIXBasis
			if err := decodeCIXBasis(d, start, &basis); err != nil {
				return err
			}
			out.Bases = append(out.Bases, basis)
		default:
			return d.Skip()
		}
		return nil
	})
}
func decodeCIXSource(d *xml.Decoder, start xml.StartElement, out *rawCIXSource) error {
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "type":
			out.Type = a.Value
		case "name":
			out.Name = a.Value
		case "offset":
			out.Offset = a.Value
		case "length":
			out.Length = a.Value
		}
	}
	return cixChildren(d, func(start xml.StartElement) error {
		if start.Name.Local == "Hash" {
			return decodeCIXHash(d, start, &out.Hash)
		}
		return d.Skip()
	})
}
func decodeCIXBasis(d *xml.Decoder, start xml.StartElement, out *rawCIXBasis) error {
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "file":
			out.File = a.Value
		case "length":
			out.Length = a.Value
		}
	}
	return cixChildren(d, func(start xml.StartElement) error {
		if start.Name.Local == "Hash" {
			return decodeCIXHash(d, start, &out.Hash)
		}
		return d.Skip()
	})
}
