// Package udif reads XML-backed, single-segment Apple disk images lazily.
// Layout facts follow the published UDIF/BLKX declarations in libdmg-hfsplus;
// this reader and its fixtures are independent implementations.
package udif

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

const MaxMetadata = 16 << 20
const MaxChunk = 64 << 20

// Table describes a logical disk range; Raw retains the complete BLKX record.
type Table struct {
	Name                                 string
	Offset, Size                         int64
	Raw                                  []byte
	ChecksumType, ChecksumBits, Checksum uint32
}
type run struct {
	kind                        uint32
	start, size, offset, length int64
}

// Image exposes the complete logical disk, plus original container metadata.
// Unsupported chunk codecs, overlapping/gapped maps and segmented images fail.
type Image struct {
	source                               storage.Reader
	size, dataOffset, dataLength         int64
	runs                                 []run
	Tables                               []Table
	XML, Trailer                         storage.Reader
	cache                                *bytecache.Cache
	checksumType, checksumBits, checksum uint32
}

func (d *Image) Size() int64 { return d.size }
func read(r storage.Reader, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > r.Size() || n > r.Size()-off {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	_, err := io.ReadFull(io.NewSectionReader(r, off, n), b)
	return b, err
}
func rangeOK(off, n uint64, size int64) bool {
	return size >= 0 && off <= uint64(size) && n <= uint64(size)-off
}
func Open(source storage.Reader) (*Image, error) {
	if source == nil || source.Size() < 512 {
		return nil, fmt.Errorf("udif: missing trailer")
	}
	h, err := read(source, source.Size()-512, 512)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if string(h[:4]) != "koly" || be.Uint32(h[4:]) != 4 || be.Uint32(h[8:]) != 512 {
		return nil, fmt.Errorf("udif: invalid v4 trailer")
	}
	if be.Uint64(h[16:]) != 0 || be.Uint32(h[56:]) > 1 || be.Uint32(h[60:]) > 1 {
		return nil, fmt.Errorf("udif: segmented image unsupported")
	}
	dataOff, dataLen := be.Uint64(h[24:]), be.Uint64(h[32:])
	xmlOff, xmlLen := be.Uint64(h[216:]), be.Uint64(h[224:])
	sectors := be.Uint64(h[492:])
	if !rangeOK(dataOff, dataLen, source.Size()-512) || !rangeOK(xmlOff, xmlLen, source.Size()-512) || xmlLen == 0 || xmlLen > MaxMetadata || sectors == 0 || sectors > math.MaxInt64/512 {
		return nil, fmt.Errorf("udif: invalid data/XML/logical size bounds")
	}
	if dataOff+dataLen > xmlOff {
		return nil, fmt.Errorf("udif: data fork overlaps XML")
	}
	d := &Image{source: source, size: int64(sectors) * 512, dataOffset: int64(dataOff), dataLength: int64(dataLen),
		XML: io.NewSectionReader(source, int64(xmlOff), int64(xmlLen)), Trailer: io.NewSectionReader(source, source.Size()-512, 512), cache: bytecache.New(MaxChunk),
		checksumType: be.Uint32(h[80:]), checksumBits: be.Uint32(h[84:]), checksum: be.Uint32(h[88:])}
	metadata, err := read(d.XML, 0, int64(xmlLen))
	if err != nil {
		return nil, err
	}
	root, err := parseXML(metadata)
	if err != nil {
		return nil, fmt.Errorf("udif: plist: %w", err)
	}
	if root.name != "plist" || len(root.children) != 1 {
		return nil, fmt.Errorf("udif: invalid plist root")
	}
	maps := root.children[0].value("resource-fork").value("blkx")
	if maps.name != "array" || len(maps.children) == 0 {
		return nil, fmt.Errorf("udif: missing blkx array")
	}
	for _, item := range maps.children {
		blob := item.value("Data")
		if blob.name != "data" {
			return nil, fmt.Errorf("udif: missing blkx data")
		}
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(blob.text), ""))
		if err != nil {
			return nil, fmt.Errorf("udif: blkx base64: %w", err)
		}
		if len(raw) < 204 || string(raw[:4]) != "mish" || be.Uint32(raw[4:]) != 1 {
			return nil, fmt.Errorf("udif: invalid blkx header")
		}
		count := be.Uint32(raw[200:])
		if count == 0 || uint64(count)*40 != uint64(len(raw)-204) {
			return nil, fmt.Errorf("udif: invalid blkx run count")
		}
		first, length, dataStart := be.Uint64(raw[8:]), be.Uint64(raw[16:]), be.Uint64(raw[24:])
		if first > sectors || length > sectors-first || length == 0 || dataStart > dataLen {
			return nil, fmt.Errorf("udif: blkx bounds")
		}
		table := Table{Name: item.value("Name").text, Offset: int64(first) * 512, Size: int64(length) * 512, Raw: raw,
			ChecksumType: be.Uint32(raw[64:]), ChecksumBits: be.Uint32(raw[68:]), Checksum: be.Uint32(raw[72:])}
		d.Tables = append(d.Tables, table)
		var covered uint64
		for i := uint32(0); i < count; i++ {
			p := raw[204+int(i)*40:]
			kind := be.Uint32(p)
			start, size, off, packed := be.Uint64(p[8:]), be.Uint64(p[16:]), be.Uint64(p[24:]), be.Uint64(p[32:])
			if kind == 0xffffffff {
				if i != count-1 || size != 0 {
					return nil, fmt.Errorf("udif: invalid terminator")
				}
				continue
			}
			if i == count-1 {
				return nil, fmt.Errorf("udif: missing terminator")
			}
			if kind == 0x7ffffffe {
				continue
			}
			if start != covered || size == 0 || size > length-covered {
				return nil, fmt.Errorf("udif: noncontiguous blkx runs")
			}
			covered += size
			switch kind {
			case 0, 2:
				if packed != 0 {
					return nil, fmt.Errorf("udif: zero run has stored bytes")
				}
			case 1:
				if packed != size*512 {
					return nil, fmt.Errorf("udif: raw run length mismatch")
				}
			case 0x80000005, 0x80000006:
				if size*512 > MaxChunk || packed == 0 || packed > MaxChunk {
					return nil, fmt.Errorf("udif: chunk bounds exceeded")
				}
			default:
				return nil, fmt.Errorf("udif: unsupported chunk codec %#x", kind)
			}
			if kind != 0 && kind != 2 && !rangeOK(off, packed, int64(dataLen-dataStart)) {
				return nil, fmt.Errorf("udif: stored run outside data fork")
			}
			d.runs = append(d.runs, run{kind, int64(first+start) * 512, int64(size) * 512, int64(dataOff + dataStart + off), int64(packed)})
		}
		if covered != length {
			return nil, fmt.Errorf("udif: incomplete blkx range")
		}
	}
	sort.Slice(d.runs, func(i, j int) bool { return d.runs[i].start < d.runs[j].start })
	var end int64
	for _, r := range d.runs {
		if r.start != end {
			return nil, fmt.Errorf("udif: overlapping or gapped block maps")
		}
		end += r.size
	}
	if end != d.size {
		return nil, fmt.Errorf("udif: incomplete disk map")
	}
	return d, nil
}
func (d *Image) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("udif: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= d.size {
		return 0, io.EOF
	}
	wanted := len(p)
	p = p[:min(int64(len(p)), d.size-off)]
	done := 0
	i := sort.Search(len(d.runs), func(i int) bool { return d.runs[i].start+d.runs[i].size > off })
	for len(p) > 0 {
		r := d.runs[i]
		skip := off - r.start
		n := min(int64(len(p)), r.size-skip)
		switch r.kind {
		case 0, 2:
			clear(p[:n])
		case 1:
			if _, err := io.ReadFull(io.NewSectionReader(d.source, r.offset+skip, n), p[:n]); err != nil {
				return done, err
			}
		default:
			data, err := d.cache.Get(bytecache.Key{Index: i}, func() ([]byte, error) {
				packed, err := read(d.source, r.offset, r.length)
				if err != nil {
					return nil, err
				}
				input := bytes.NewReader(packed)
				var decoded io.Reader
				var close func() error
				if r.kind == 0x80000005 {
					z, err := zlib.NewReader(input)
					if err != nil {
						return nil, err
					}
					decoded = z
					close = z.Close
				} else {
					decoded = bzip2.NewReader(input)
				}
				data, err := io.ReadAll(io.LimitReader(decoded, r.size+1))
				if close != nil {
					close()
				}
				if err != nil {
					return nil, err
				}
				if int64(len(data)) != r.size || input.Len() != 0 {
					return nil, fmt.Errorf("udif: decoded chunk length/trailing data mismatch")
				}
				return data, nil
			})
			if err != nil {
				return done, fmt.Errorf("udif: chunk %d: %w", i, err)
			}
			copy(p[:n], data[skip:skip+n])
		}
		done += int(n)
		off += n
		p = p[n:]
		i++
	}
	if done != wanted {
		return done, io.EOF
	}
	return done, nil
}

// Verify reads all stored bytes and logical table ranges and checks CRC32s when
// declared. It does not claim to authenticate an Apple code-signing signature.
func (d *Image) Verify() error {
	check := func(r io.Reader, kind, bits, want uint32) error {
		if kind == 0 {
			_, err := io.Copy(io.Discard, r)
			return err
		}
		if kind != 2 || bits != 32 {
			return fmt.Errorf("udif: unsupported checksum %d/%d", kind, bits)
		}
		h := crc32.NewIEEE()
		if _, err := io.Copy(h, r); err != nil {
			return err
		}
		if h.Sum32() != want {
			return fmt.Errorf("udif: CRC32 mismatch")
		}
		return nil
	}
	if err := check(io.NewSectionReader(d.source, d.dataOffset, d.dataLength), d.checksumType, d.checksumBits, d.checksum); err != nil {
		return err
	}
	var sums []byte
	for _, t := range d.Tables {
		// BLOCK_IGNORE (2) reserves sectors but contributes no bytes to the
		// BLKX checksum. It is distinct from explicit zero-fill (0).
		var readers []io.Reader
		first := sort.Search(len(d.runs), func(i int) bool { return d.runs[i].start >= t.Offset })
		for i := first; i < len(d.runs) && d.runs[i].start < t.Offset+t.Size; i++ {
			r := d.runs[i]
			if r.kind != 2 {
				readers = append(readers, io.NewSectionReader(d, r.start, r.size))
			}
		}
		if err := check(io.MultiReader(readers...), t.ChecksumType, t.ChecksumBits, t.Checksum); err != nil {
			return fmt.Errorf("udif: %s: %w", t.Name, err)
		}
		if t.ChecksumType == 2 {
			sums = binary.BigEndian.AppendUint32(sums, t.Checksum)
		}
	}
	trailer, err := read(d.Trailer, 352, 12)
	if err != nil {
		return err
	}
	return check(bytes.NewReader(sums), binary.BigEndian.Uint32(trailer), binary.BigEndian.Uint32(trailer[4:]), binary.BigEndian.Uint32(trailer[8:]))
}

// XML is bounded in bytes, nodes and depth. No external entities are resolved.
type xmlNode struct {
	name, text string
	children   []*xmlNode
}

func (n *xmlNode) value(key string) *xmlNode {
	if n != nil && n.name == "dict" {
		for i := 0; i+1 < len(n.children); i += 2 {
			if n.children[i].name == "key" && n.children[i].text == key {
				return n.children[i+1]
			}
		}
	}
	return &xmlNode{}
}
func parseXML(data []byte) (*xmlNode, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var root *xmlNode
	var stack []*xmlNode
	count := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			count++
			if len(stack) >= 64 || count > 1000000 {
				return nil, fmt.Errorf("XML limits exceeded")
			}
			n := &xmlNode{name: t.Name.Local}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("multiple XML roots")
				}
				root = n
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, n)
			}
			stack = append(stack, n)
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(t)
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, fmt.Errorf("incomplete XML")
	}
	return root, nil
}
