// Package plist reads bounded Apple XML 1.0 and binary bplist00 property lists.
// Binary markers/trailer semantics follow Apple's CF-635.21 CFBinaryPList.c;
// this is an independent implementation, not a copy of that source.
package plist

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/tinyrange/trex/storage"
)

const MaxBytes = 64 << 20
const maxNodes = 100000
const maxDepth = 128

type Date struct{ time.Time }
type budget struct{ nodes, bytes int }

func (b *budget) use(depth, size int) error {
	b.nodes++
	b.bytes += size
	if depth > maxDepth || b.nodes > maxNodes || b.bytes > MaxBytes {
		return fmt.Errorf("plist: decoded value limit")
	}
	return nil
}

// Open returns maps with string keys, []any arrays, []byte data, strings,
// int64, float64, bool, Date, or nil (binary null only). It never follows URLs.
func Open(r storage.Reader) (any, error) {
	if r == nil || r.Size() < 1 || r.Size() > MaxBytes {
		return nil, fmt.Errorf("plist: input size limit")
	}
	raw := make([]byte, int(r.Size()))
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, r.Size()), raw); err != nil {
		return nil, err
	}
	return Decode(raw)
}
func Decode(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return nil, fmt.Errorf("plist: input size limit")
	}
	if bytes.HasPrefix(raw, []byte("bplist00")) {
		return decodeBinary(raw)
	}
	p := xmlParser{d: xml.NewDecoder(bytes.NewReader(raw))}
	start, err := p.nextStart()
	if err != nil || start.Name.Local != "plist" || start.Name.Space != "" {
		return nil, fmt.Errorf("plist: expected XML plist root")
	}
	token, err := p.nextContent()
	child, ok := token.(xml.StartElement)
	if err != nil || !ok {
		return nil, fmt.Errorf("plist: expected one root value")
	}
	value, err := p.value(child, 0)
	if err != nil {
		return nil, err
	}
	token, err = p.nextContent()
	end, ok := token.(xml.EndElement)
	if err != nil || !ok || end.Name.Local != "plist" {
		return nil, fmt.Errorf("plist: multiple root values")
	}
	if _, err = p.nextContent(); err != io.EOF {
		return nil, fmt.Errorf("plist: trailing XML content")
	}
	return value, nil
}

type xmlParser struct {
	d      *xml.Decoder
	budget budget
}

func (p *xmlParser) nextContent() (xml.Token, error) {
	for {
		t, e := p.d.Token()
		if e != nil {
			return nil, e
		}
		switch v := t.(type) {
		case xml.Comment, xml.ProcInst, xml.Directive:
			continue
		case xml.CharData:
			if strings.TrimSpace(string(v)) != "" {
				return nil, fmt.Errorf("plist: unexpected text")
			}
			continue
		default:
			return t, nil
		}
	}
}
func (p *xmlParser) nextStart() (xml.StartElement, error) {
	t, e := p.nextContent()
	s, ok := t.(xml.StartElement)
	if e != nil {
		return s, e
	}
	if !ok {
		return s, fmt.Errorf("plist: expected element")
	}
	return s, nil
}
func (p *xmlParser) text(s xml.StartElement) (string, error) {
	var buf strings.Builder
	for {
		t, e := p.d.Token()
		if e != nil {
			return "", e
		}
		switch v := t.(type) {
		case xml.CharData:
			if buf.Len()+len(v) > MaxBytes {
				return "", fmt.Errorf("plist: text size limit")
			}
			buf.Write(v)
		case xml.Comment:
			continue
		case xml.EndElement:
			if v.Name != s.Name {
				return "", fmt.Errorf("plist: mismatched element")
			}
			return buf.String(), nil
		default:
			return "", fmt.Errorf("plist: scalar contains element")
		}
	}
}
func (p *xmlParser) value(s xml.StartElement, depth int) (any, error) {
	if e := p.budget.use(depth, 0); e != nil {
		return nil, e
	}
	if s.Name.Space != "" {
		return nil, fmt.Errorf("plist: namespaced element")
	}
	switch s.Name.Local {
	case "array", "dict":
		array := []any{}
		dict := map[string]any{}
		for {
			t, e := p.nextContent()
			if e != nil {
				return nil, e
			}
			if end, ok := t.(xml.EndElement); ok {
				if end.Name != s.Name {
					return nil, fmt.Errorf("plist: mismatched container")
				}
				if s.Name.Local == "dict" {
					return dict, nil
				}
				return array, nil
			}
			child, ok := t.(xml.StartElement)
			if !ok {
				return nil, fmt.Errorf("plist: expected value")
			}
			if s.Name.Local == "array" {
				v, e := p.value(child, depth+1)
				if e != nil {
					return nil, e
				}
				array = append(array, v)
				continue
			}
			if child.Name.Local != "key" || child.Name.Space != "" {
				return nil, fmt.Errorf("plist: expected dictionary key")
			}
			key, e := p.text(child)
			if e != nil {
				return nil, e
			}
			if e = p.budget.use(depth+1, len(key)); e != nil {
				return nil, e
			}
			if _, ok := dict[key]; ok {
				return nil, fmt.Errorf("plist: duplicate key %q", key)
			}
			next, e := p.nextStart()
			if e != nil {
				return nil, e
			}
			v, e := p.value(next, depth+1)
			if e != nil {
				return nil, e
			}
			dict[key] = v
		}
	default:
		text, e := p.text(s)
		if e != nil {
			return nil, e
		}
		if e = p.budget.use(depth, len(text)); e != nil {
			return nil, e
		}
		switch s.Name.Local {
		case "string":
			return text, nil
		case "integer":
			return strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		case "real":
			v, e := strconv.ParseFloat(strings.TrimSpace(text), 64)
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, fmt.Errorf("plist: nonfinite real")
			}
			return v, e
		case "data":
			return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
		case "date":
			v, e := time.Parse(time.RFC3339Nano, strings.TrimSpace(text))
			return Date{v}, e
		case "true", "false":
			if strings.TrimSpace(text) != "" {
				return nil, fmt.Errorf("plist: boolean text")
			}
			return s.Name.Local == "true", nil
		default:
			return nil, fmt.Errorf("plist: unsupported XML value %s", s.Name.Local)
		}
	}
}

type binaryParser struct {
	raw     []byte
	offsets []uint64
	end     uint64
	refSize int
	active  map[uint64]bool
	budget  budget
}

func sized(raw []byte) uint64 {
	var v uint64
	for _, b := range raw {
		v = v<<8 | uint64(b)
	}
	return v
}
func decodeBinary(raw []byte) (any, error) {
	if len(raw) < 40 {
		return nil, fmt.Errorf("plist: truncated binary trailer")
	}
	t := raw[len(raw)-32:]
	width, refs := int(t[6]), int(t[7])
	n, top, table := sized(t[8:16]), sized(t[16:24]), sized(t[24:])
	if width < 1 || width > 8 || refs < 1 || refs > 8 || n == 0 || n > maxNodes || top >= n || table < 8 || table > uint64(len(raw)-32) || n > uint64(len(raw)-32)/uint64(width) || n*uint64(width) != uint64(len(raw)-32)-table {
		return nil, fmt.Errorf("plist: binary table bounds")
	}
	p := binaryParser{raw: raw, end: table, refSize: refs, active: map[uint64]bool{}}
	p.offsets = make([]uint64, int(n))
	for i := range p.offsets {
		off := sized(raw[int(table)+i*width : int(table)+(i+1)*width])
		if off < 8 || off >= table {
			return nil, fmt.Errorf("plist: object offset bounds")
		}
		p.offsets[i] = off
	}
	return p.value(top, 0)
}
func (p *binaryParser) span(off, n uint64) ([]byte, error) {
	if off > p.end || n > p.end-off {
		return nil, fmt.Errorf("plist: object extent bounds")
	}
	return p.raw[off : off+n], nil
}
func (p *binaryParser) count(off uint64, marker byte) (uint64, uint64, error) {
	if marker&15 != 15 {
		return uint64(marker & 15), off + 1, nil
	}
	b, e := p.span(off+1, 1)
	if e != nil {
		return 0, 0, e
	}
	if b[0]>>4 != 1 || b[0]&15 > 3 {
		return 0, 0, fmt.Errorf("plist: invalid extended length")
	}
	width := uint64(1) << uint(b[0]&15)
	data, e := p.span(off+2, width)
	if e != nil {
		return 0, 0, e
	}
	return sized(data), off + 2 + width, nil
}
func (p *binaryParser) ref(off uint64) (uint64, error) {
	data, e := p.span(off, uint64(p.refSize))
	if e != nil {
		return 0, e
	}
	id := sized(data)
	if id >= uint64(len(p.offsets)) {
		return 0, fmt.Errorf("plist: object reference bounds")
	}
	return id, nil
}
func (p *binaryParser) value(id uint64, depth int) (any, error) {
	if e := p.budget.use(depth, 0); e != nil {
		return nil, e
	}
	if p.active[id] {
		return nil, fmt.Errorf("plist: cyclic object graph")
	}
	p.active[id] = true
	defer delete(p.active, id)
	off := p.offsets[id]
	m := p.raw[off]
	switch m >> 4 {
	case 0:
		switch m {
		case 0:
			return nil, nil
		case 8:
			return false, nil
		case 9:
			return true, nil
		}
		return nil, fmt.Errorf("plist: unsupported simple marker")
	case 1:
		if m&15 > 3 {
			return nil, fmt.Errorf("plist: integer wider than int64")
		}
		data, e := p.span(off+1, uint64(1)<<uint(m&15))
		if e != nil {
			return nil, e
		}
		return int64(sized(data)), nil
	case 2, 3:
		width := uint64(1) << uint(m&15)
		if (m>>4 == 3 && m != 0x33) || (m>>4 == 2 && width != 4 && width != 8) {
			return nil, fmt.Errorf("plist: invalid real/date width")
		}
		data, e := p.span(off+1, width)
		if e != nil {
			return nil, e
		}
		v := math.Float64frombits(sized(data))
		if width == 4 {
			v = float64(math.Float32frombits(uint32(sized(data))))
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("plist: nonfinite real/date")
		}
		if m>>4 == 3 {
			if v < -63113904000 || v >= 252423993600 {
				return nil, fmt.Errorf("plist: date range")
			}
			seconds, fraction := math.Modf(v)
			return Date{time.Unix(978307200+int64(seconds), int64(fraction*1e9)).UTC()}, nil
		}
		return v, nil
	case 4, 5, 6:
		n, start, e := p.count(off, m)
		if e != nil {
			return nil, e
		}
		width := uint64(1)
		if m>>4 == 6 {
			width = 2
		}
		if n > MaxBytes/width {
			return nil, fmt.Errorf("plist: scalar length bounds")
		}
		data, e := p.span(start, n*width)
		if e != nil {
			return nil, e
		}
		if e = p.budget.use(depth, int(n*width)); e != nil {
			return nil, e
		}
		if m>>4 == 4 {
			return append([]byte(nil), data...), nil
		}
		if m>>4 == 5 {
			for _, b := range data {
				if b > 127 {
					return nil, fmt.Errorf("plist: non-ASCII marker5 string")
				}
			}
			return string(data), nil
		}
		units := make([]uint16, int(n))
		for i := range units {
			units[i] = binary.BigEndian.Uint16(data[i*2:])
		}
		decodedBytes := 0
		for i, u := range units {
			if u >= 0xd800 && u <= 0xdbff {
				decodedBytes += 4
				if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
					return nil, fmt.Errorf("plist: unpaired UTF16 surrogate")
				}
			} else if u >= 0xdc00 && u <= 0xdfff {
				if i == 0 || units[i-1] < 0xd800 || units[i-1] > 0xdbff {
					return nil, fmt.Errorf("plist: unpaired UTF16 surrogate")
				}
			} else if u < 0x80 {
				decodedBytes++
			} else if u < 0x800 {
				decodedBytes += 2
			} else {
				decodedBytes += 3
			}
		}
		// Count UTF8 expansion before allocating the decoded string.
		if extra := decodedBytes - len(data); extra > 0 {
			if e := p.budget.use(depth, extra); e != nil {
				return nil, e
			}
		}
		return string(utf16.Decode(units)), nil
	case 10, 13:
		n, start, e := p.count(off, m)
		if e != nil {
			return nil, e
		}
		mult := uint64(1)
		if m>>4 == 13 {
			mult = 2
		}
		if n > uint64(maxNodes-p.budget.nodes)/mult || start > p.end || n*mult*uint64(p.refSize) > p.end-start {
			return nil, fmt.Errorf("plist: container length bounds")
		}
		if m>>4 == 10 {
			out := make([]any, int(n))
			for i := range out {
				ref, e := p.ref(start + uint64(i*p.refSize))
				if e != nil {
					return nil, e
				}
				out[i], e = p.value(ref, depth+1)
				if e != nil {
					return nil, e
				}
			}
			return out, nil
		}
		out := map[string]any{}
		for i := uint64(0); i < n; i++ {
			ref, e := p.ref(start + i*uint64(p.refSize))
			if e != nil {
				return nil, e
			}
			key, e := p.value(ref, depth+1)
			if e != nil {
				return nil, e
			}
			s, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("plist: dictionary key not string")
			}
			if _, ok := out[s]; ok {
				return nil, fmt.Errorf("plist: duplicate key %q", s)
			}
			ref, e = p.ref(start + (n+i)*uint64(p.refSize))
			if e != nil {
				return nil, e
			}
			out[s], e = p.value(ref, depth+1)
			if e != nil {
				return nil, e
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("plist: unsupported binary marker %#x", m)
	}
}

// EncodeXML emits deterministic XML1.0, preserving data and scalar types.
func EncodeXML(value any) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">")
	e := xml.NewEncoder(&limitWriter{out: &out, count: out.Len()})
	b := budget{}
	if err := encode(e, value, &b, 0); err != nil {
		return nil, err
	}
	if err := e.Flush(); err != nil {
		return nil, err
	}
	out.WriteString("</plist>\n")
	if out.Len() > MaxBytes {
		return nil, fmt.Errorf("plist: encoded size limit")
	}
	return out.Bytes(), nil
}
func encode(e *xml.Encoder, v any, b *budget, depth int) error {
	if err := b.use(depth, 0); err != nil {
		return err
	}
	scalar := func(tag, text string) error {
		if err := b.use(depth, len(text)); err != nil {
			return err
		}
		if !utf8.ValidString(text) {
			return fmt.Errorf("plist: invalid UTF8")
		}
		for _, r := range text {
			if r != 9 && r != 10 && r != 13 && (r < 32 || r == 0xfffe || r == 0xffff) {
				return fmt.Errorf("plist: invalid XML character")
			}
		}
		return e.EncodeElement(text, xml.StartElement{Name: xml.Name{Local: tag}})
	}
	container := func(tag string, emit func() error) error {
		s := xml.StartElement{Name: xml.Name{Local: tag}}
		if err := e.EncodeToken(s); err != nil {
			return err
		}
		if err := emit(); err != nil {
			return err
		}
		return e.EncodeToken(s.End())
	}
	switch x := v.(type) {
	case string:
		return scalar("string", x)
	case []byte:
		if len(x) > MaxBytes/4*3 || base64.StdEncoding.EncodedLen(len(x)) > MaxBytes-b.bytes {
			return fmt.Errorf("plist: data size limit")
		}
		return scalar("data", base64.StdEncoding.EncodeToString(x))
	case bool:
		if x {
			return scalar("true", "")
		}
		return scalar("false", "")
	case int64:
		return scalar("integer", strconv.FormatInt(x, 10))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("plist: nonfinite real")
		}
		return scalar("real", strconv.FormatFloat(x, 'g', -1, 64))
	case Date:
		return scalar("date", x.UTC().Format(time.RFC3339Nano))
	case []any:
		if len(x) > maxNodes-b.nodes {
			return fmt.Errorf("plist: encoded node limit")
		}
		return container("array", func() error {
			for _, item := range x {
				if err := encode(e, item, b, depth+1); err != nil {
					return err
				}
			}
			return nil
		})
	case map[string]any:
		if len(x) > (maxNodes-b.nodes)/2 {
			return fmt.Errorf("plist: encoded node limit")
		}
		return container("dict", func() error {
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := scalar("key", k); err != nil {
					return err
				}
				if err := encode(e, x[k], b, depth+1); err != nil {
					return err
				}
			}
			return nil
		})
	default:
		return fmt.Errorf("plist: cannot encode %T as XML1.0", v)
	}
}

type limitWriter struct {
	out   *bytes.Buffer
	count int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if len(p) > MaxBytes-w.count {
		return 0, fmt.Errorf("plist: encoded size limit")
	}
	n, e := w.out.Write(p)
	w.count += n
	return n, e
}
