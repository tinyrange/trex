// Package xmltoken provides a raw-token reader for bounded, already buffered
// XML. Common ASCII tokens borrow immutable source strings; all other syntax
// is parsed by encoding/xml. Namespace and element-balance validation remains
// with the consumer (normally xml.NewTokenDecoder).
package xmltoken

import (
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Reader has encoding/xml.RawToken semantics, not Decoder.Token semantics.
// It must not be shared between goroutines. Tokens do not alias mutable buffers.
type Reader struct {
	source     string
	offset     int
	pending    xml.EndElement
	hasPending bool
	err        error
	decoded    bool
}

// New owns a string copy of data. decoded permits UTF-16/unicode declarations
// only when the caller has already converted the actual bytes to UTF-8.
// No input-size limit is imposed here: callers must bound the buffered input.
func New(data []byte, decoded bool) *Reader { return &Reader{source: string(data), decoded: decoded} }

// Token returns a raw token, for use as xml.NewTokenDecoder's input.
func (r *Reader) Token() (xml.Token, error) { return r.RawToken() }

func space(c byte) bool        { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
func initial(c byte) bool      { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' }
func continuation(c byte) bool { return initial(c) || c >= '0' && c <= '9' || c == '-' || c == '.' }

// name recognizes the conservative ASCII subset. Unsupported names are left
// to the standard parser, including all Unicode and unusual colon placements.
func name(s string, i int) (xml.Name, int, bool) {
	start := i
	if i == len(s) || !initial(s[i]) {
		return xml.Name{}, i, false
	}
	i++
	colon := -1
	for i < len(s) {
		if continuation(s[i]) {
			i++
			continue
		}
		if s[i] == ':' && colon < 0 && i+1 < len(s) && initial(s[i+1]) {
			colon = i
			i += 2
			continue
		}
		break
	}
	if colon < 0 {
		return xml.Name{Local: s[start:i]}, i, true
	}
	return xml.Name{Space: s[start:colon], Local: s[colon+1 : i]}, i, true
}

func (r *Reader) RawToken() (xml.Token, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.hasPending {
		r.hasPending = false
		return r.pending, nil
	}
	s, start := r.source, r.offset
	if start == len(s) {
		return nil, io.EOF
	}
	if s[start] != '<' {
		i := start
		for i < len(s) && s[i] != '<' {
			c := s[i]
			if c == '&' || c == ']' || c >= 0x80 || c < 0x20 && c != '\n' && c != '\t' && c != '\r' {
				return r.standard()
			}
			i++
		}
		r.offset = i
		text := []byte(s[start:i])
		if strings.IndexByte(s[start:i], '\r') >= 0 {
			used := 0
			for j := 0; j < len(text); j++ {
				c := text[j]
				if c == '\r' {
					c = '\n'
					if j+1 < len(text) && text[j+1] == '\n' {
						j++
					}
				}
				text[used] = c
				used++
			}
			text = text[:used]
		}
		return xml.CharData(text), nil
	}
	i := start + 1
	end := i < len(s) && s[i] == '/'
	if end {
		i++
	}
	n, i, ok := name(s, i)
	if !ok {
		return r.standard()
	}
	if end {
		for i < len(s) && space(s[i]) {
			i++
		}
		if i == len(s) || s[i] != '>' {
			return r.standard()
		}
		r.offset = i + 1
		return xml.EndElement{Name: n}, nil
	}
	var local [8]xml.Attr
	attrs := local[:0]
	for {
		before := i
		for i < len(s) && space(s[i]) {
			i++
		}
		if i == len(s) {
			return r.standard()
		}
		if s[i] == '>' {
			r.offset = i + 1
			return xml.StartElement{Name: n, Attr: slices.Clone(attrs)}, nil
		}
		if s[i] == '/' && i+1 < len(s) && s[i+1] == '>' {
			r.offset = i + 2
			r.pending = xml.EndElement{Name: n}
			r.hasPending = true
			return xml.StartElement{Name: n, Attr: slices.Clone(attrs)}, nil
		}
		if before == i {
			return r.standard()
		}
		a, next, ok := name(s, i)
		if !ok {
			return r.standard()
		}
		i = next
		for i < len(s) && space(s[i]) {
			i++
		}
		if i == len(s) || s[i] != '=' {
			return r.standard()
		}
		i++
		for i < len(s) && space(s[i]) {
			i++
		}
		if i == len(s) || s[i] != '\'' && s[i] != '"' {
			return r.standard()
		}
		quote := s[i]
		i++
		value := i
		transform := false
		for i < len(s) && s[i] != quote {
			c := s[i]
			if c >= 0x80 || c == '<' || c < 0x20 && !space(c) {
				return r.standard()
			}
			transform = transform || c == '&' || c == '\r'
			i++
		}
		if i == len(s) {
			return r.standard()
		}
		text := s[value:i]
		if transform {
			var ok bool
			text, ok = attributeText(text)
			if !ok {
				return r.standard()
			}
		}
		attrs = append(attrs, xml.Attr{Name: a, Value: text})
		i++
	}
}

// RawToken has no namespace/balance state. A single standard token can thus
// be consumed at a token boundary. Its only deferred token is the matching end
// of a self-closing start tag, which we preserve explicitly. CharsetReader may
// only be the identity transform, so InputOffset stays in source coordinates.
func (r *Reader) standard() (xml.Token, error) {
	d := xml.NewDecoder(strings.NewReader(r.source[r.offset:]))
	if r.decoded {
		d.CharsetReader = func(label string, in io.Reader) (io.Reader, error) {
			switch strings.ToLower(strings.ReplaceAll(label, "-", "")) {
			case "utf8", "utf16", "unicode":
				return in, nil
			default:
				return nil, fmt.Errorf("unsupported declared encoding %q", label)
			}
		}
	}
	t, err := d.RawToken()
	if err != nil {
		r.err = err
		return t, err
	}
	r.offset += int(d.InputOffset())
	if start, ok := t.(xml.StartElement); ok && r.offset >= 2 && r.source[r.offset-2:r.offset] == "/>" {
		end := start.End()
		r.pending = end
		r.hasPending = true
	}
	return t, nil
}

// Preserve the standard raw-token normalization for ASCII attribute content.
// Numeric/custom references and non-ASCII syntax remain delegated to encoding/xml.
func attributeText(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\r':
			b.WriteByte('\n')
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
		case '&':
			switch {
			case strings.HasPrefix(s[i:], "&amp;"):
				b.WriteByte('&')
				i += 4
			case strings.HasPrefix(s[i:], "&lt;"):
				b.WriteByte('<')
				i += 3
			case strings.HasPrefix(s[i:], "&gt;"):
				b.WriteByte('>')
				i += 3
			case strings.HasPrefix(s[i:], "&quot;"):
				b.WriteByte('"')
				i += 5
			case strings.HasPrefix(s[i:], "&apos;"):
				b.WriteByte('\'')
				i += 5
			default:
				return "", false
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}
