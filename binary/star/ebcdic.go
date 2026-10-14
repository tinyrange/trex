package star

import (
	"golang.org/x/text/encoding/charmap"
	"unicode"
)

// Explicit IBM037 rendering is not CCSID detection. Controls terminate runs;
// minimum counts characters (one per source byte), not UTF-8 output bytes.
func scanIBM037Strings(data []byte, minimum int) []string {
	var out []string
	for offset := 0; offset < len(data); {
		start := offset
		for offset < len(data) {
			r := charmap.CodePage037.DecodeByte(data[offset])
			if !unicode.IsPrint(r) && r != '\t' {
				break
			}
			offset++
		}
		if offset-start >= minimum {
			text, _ := charmap.CodePage037.NewDecoder().String(string(data[start:offset]))
			out = append(out, text)
		}
		offset++
	}
	return out
}
