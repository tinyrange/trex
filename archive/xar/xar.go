// Package xar indexes XAR v1 installer archives and exposes borrowed members.
// Format facts follow the Apple open-source xar header and XML TOC definitions.
package xar

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/tinyrange/trex/archive/bzip2"
	"github.com/tinyrange/trex/storage"
)

const MaxTOC = 16 << 20
const MaxMember = 64 << 30

type checksum struct {
	Style  string `xml:"style,attr"`
	Value  string `xml:",chardata"`
	Offset int64  `xml:"offset"`
	Size   int64  `xml:"size"`
}
type dataRecord struct {
	Offset   int64 `xml:"offset"`
	Length   int64 `xml:"length"`
	Size     int64 `xml:"size"`
	Encoding struct {
		Style string `xml:"style,attr"`
	} `xml:"encoding"`
	Archived  checksum `xml:"archived-checksum"`
	Extracted checksum `xml:"extracted-checksum"`
}
type fileRecord struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
	Type struct {
		Value string `xml:",chardata"`
		Link  string `xml:"link,attr"`
	} `xml:"type"`
	Link     string       `xml:"link"`
	Mode     string       `xml:"mode"`
	UID      uint64       `xml:"uid"`
	GID      uint64       `xml:"gid"`
	Data     *dataRecord  `xml:"data"`
	Children []fileRecord `xml:"file"`
}

// Entry retains Unix metadata; symlinks are never followed. Raw denotes the
// archived member bytes, Data the decoded byte source. Checksums are verified
// explicitly by Verify, without requiring whole-member reads during listing.
type Entry struct {
	Path, ID, Kind, Target, Encoding string
	Mode, UID, GID                   uint64
	Raw, Data                        storage.Reader
	archived, extracted              checksum
}
type Archive struct {
	Entries []Entry
	TOC     []byte
	Heap    storage.Reader
}

func sum(style string) (hash.Hash, error) {
	switch strings.ToLower(style) {
	case "sha1":
		return sha1.New(), nil
	case "md5":
		return md5.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("xar: unsupported checksum %q", style)
	}
}
func check(r storage.Reader, c checksum) error {
	if c.Style == "" || c.Style == "none" {
		n, err := io.Copy(io.Discard, io.NewSectionReader(r, 0, r.Size()))
		if err == nil && n != r.Size() {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	h, err := sum(c.Style)
	if err != nil {
		return err
	}
	expected, err := hex.DecodeString(strings.TrimSpace(c.Value))
	if err != nil || len(expected) != h.Size() {
		return fmt.Errorf("xar: invalid checksum value")
	}
	n, err := io.Copy(h, io.NewSectionReader(r, 0, r.Size()))
	if err != nil {
		return err
	}
	if n != r.Size() {
		return io.ErrUnexpectedEOF
	}
	if !bytes.Equal(expected, h.Sum(nil)) {
		return fmt.Errorf("xar: %s checksum mismatch", c.Style)
	}
	return nil
}
func (e *Entry) Verify() error {
	if e.Raw != nil {
		if err := check(e.Raw, e.archived); err != nil {
			return fmt.Errorf("xar: %s archived: %w", e.Path, err)
		}
	}
	if e.Data != nil {
		if stream, ok := e.Data.(interface{ validateEmpty() error }); ok && e.Data.Size() == 0 {
			if err := stream.validateEmpty(); err != nil {
				return err
			}
		}
		if err := check(e.Data, e.extracted); err != nil {
			return fmt.Errorf("xar: %s extracted: %w", e.Path, err)
		}
	}
	return nil
}
func Open(source storage.Reader, maximumEntries int) (*Archive, error) {
	if source == nil || source.Size() < 28 || maximumEntries <= 0 {
		return nil, fmt.Errorf("xar: invalid source/entry limit")
	}
	var h [28]byte
	if _, err := io.ReadFull(io.NewSectionReader(source, 0, 28), h[:]); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	header := int64(be.Uint16(h[4:]))
	packed := be.Uint64(h[8:])
	expanded := be.Uint64(h[16:])
	algorithm := be.Uint32(h[24:])
	if string(h[:4]) != "xar!" || header < 28 || be.Uint16(h[6:]) != 1 || packed == 0 || packed > MaxTOC || expanded == 0 || expanded > MaxTOC || header > source.Size() || packed > uint64(source.Size()-header) {
		return nil, fmt.Errorf("xar: invalid v1 header/TOC bounds")
	}
	compressed := make([]byte, packed)
	if _, err := io.ReadFull(io.NewSectionReader(source, header, int64(packed)), compressed); err != nil {
		return nil, err
	}
	input := bytes.NewReader(compressed)
	z, err := zlib.NewReader(input)
	if err != nil {
		return nil, err
	}
	toc, err := io.ReadAll(io.LimitReader(z, int64(expanded)+1))
	z.Close()
	if err != nil {
		return nil, err
	}
	if uint64(len(toc)) != expanded || input.Len() != 0 {
		return nil, fmt.Errorf("xar: TOC length/trailing bytes mismatch")
	}
	// Bound recursive XML decoding before constructing records. Entity expansion
	// and external resources are not enabled by encoding/xml.
	dec := xml.NewDecoder(bytes.NewReader(toc))
	depth, nodes := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
			nodes++
			if depth > 128 || nodes > 1000000 {
				return nil, fmt.Errorf("xar: XML limits exceeded")
			}
		case xml.EndElement:
			depth--
		}
	}
	var doc struct {
		XMLName xml.Name `xml:"xar"`
		TOC     struct {
			Checksum checksum     `xml:"checksum"`
			Files    []fileRecord `xml:"file"`
		} `xml:"toc"`
	}
	if err := xml.Unmarshal(toc, &doc); err != nil {
		return nil, fmt.Errorf("xar: XML: %w", err)
	}
	heapOff := header + int64(packed)
	heap := io.NewSectionReader(source, heapOff, source.Size()-heapOff)
	c := doc.TOC.Checksum
	if algorithm != 0 {
		style := ""
		switch algorithm {
		case 1:
			style = "sha1"
		case 2:
			style = "md5"
		default:
			return nil, fmt.Errorf("xar: unsupported TOC checksum algorithm %d", algorithm)
		}
		h, err := sum(style)
		if err != nil {
			return nil, err
		}
		if c.Style != style || c.Offset < 0 || c.Size != int64(h.Size()) || c.Offset > heap.Size() || c.Size > heap.Size()-c.Offset {
			return nil, fmt.Errorf("xar: TOC checksum bounds/type")
		}
		expected := make([]byte, h.Size())
		if _, err = heap.ReadAt(expected, c.Offset); err != nil {
			return nil, err
		}
		h.Write(compressed)
		if !bytes.Equal(h.Sum(nil), expected) {
			return nil, fmt.Errorf("xar: TOC checksum mismatch")
		}
	} else if c.Style != "" && c.Style != "none" {
		return nil, fmt.Errorf("xar: unexpected TOC checksum")
	}
	archive := &Archive{TOC: toc, Heap: heap}
	ids := map[string]int{}
	names := map[string]bool{}
	var walk func([]fileRecord, string) error
	walk = func(files []fileRecord, base string) error {
		for _, f := range files {
			if len(archive.Entries) >= maximumEntries {
				return fmt.Errorf("xar: entry limit exceeded")
			}
			if f.Name == "" || f.Name == "." || f.Name == ".." || strings.ContainsAny(f.Name, "/\x00") {
				return fmt.Errorf("xar: unsafe component %q", f.Name)
			}
			name := path.Join(base, f.Name)
			if names[name] || f.ID == "" {
				return fmt.Errorf("xar: duplicate path/missing ID")
			}
			names[name] = true
			if _, exists := ids[f.ID]; exists {
				return fmt.Errorf("xar: duplicate ID")
			}
			e := Entry{Path: name, ID: f.ID, Kind: f.Type.Value, Target: f.Link, UID: f.UID, GID: f.GID}
			if f.Mode != "" {
				v, err := strconv.ParseUint(f.Mode, 8, 32)
				if err != nil {
					return fmt.Errorf("xar: invalid mode")
				}
				e.Mode = v
			}
			if f.Data != nil {
				d := f.Data
				if d.Offset < 0 || d.Length < 0 || d.Size < 0 || d.Size > MaxMember || d.Offset > heap.Size() || d.Length > heap.Size()-d.Offset {
					return fmt.Errorf("xar: %s data bounds", name)
				}
				e.Raw = io.NewSectionReader(heap, d.Offset, d.Length)
				e.Encoding = d.Encoding.Style
				e.archived = d.Archived
				e.extracted = d.Extracted
				switch e.Encoding {
				case "", "application/octet-stream":
					if d.Length != d.Size {
						return fmt.Errorf("xar: stored length mismatch")
					}
					e.Data = e.Raw
				case "application/x-gzip":
					e.Data = &zlibFile{source: e.Raw, size: d.Size, offset: -1}
				case "application/x-bzip2":
					e.Data = &sizedReader{Reader: bzip2.NewReader(e.Raw, d.Size), size: d.Size}
				default:
					return fmt.Errorf("xar: unsupported encoding %q", e.Encoding)
				}
			}
			switch e.Kind {
			case "file":
				if e.Data == nil {
					return fmt.Errorf("xar: missing file data")
				}
			case "directory":
				if e.Data != nil {
					return fmt.Errorf("xar: directory has data")
				}
			case "symlink":
				if e.Data != nil {
					return fmt.Errorf("xar: symlink has data")
				}
			case "hardlink":
				e.Target = f.Type.Link
			default:
				return fmt.Errorf("xar: unsupported entry type %q", e.Kind)
			}
			ids[e.ID] = len(archive.Entries)
			archive.Entries = append(archive.Entries, e)
			if len(f.Children) > 0 {
				if e.Kind != "directory" {
					return fmt.Errorf("xar: children under non-directory")
				}
				if err := walk(f.Children, name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(doc.TOC.Files, ""); err != nil {
		return nil, err
	}
	for i := range archive.Entries {
		e := &archive.Entries[i]
		if e.Kind == "hardlink" {
			index, ok := ids[e.Target]
			if !ok || archive.Entries[index].Kind != "file" {
				return nil, fmt.Errorf("xar: unresolved hardlink")
			}
			target := archive.Entries[index]
			e.Data = target.Data
			e.Raw = target.Raw
			e.Target = target.Path
			e.archived = target.archived
			e.extracted = target.extracted
		}
	}
	return archive, nil
}

type sizedReader struct {
	storage.Reader
	size int64
}

func (s *sizedReader) Size() int64 { return s.size }
func (s *sizedReader) validateEmpty() error {
	var extra [1]byte
	n, err := s.Reader.ReadAt(extra[:], s.size)
	if n != 0 || err != io.EOF || s.Reader.Size() != s.size {
		return fmt.Errorf("xar: bzip2 declared size mismatch: %v", err)
	}
	return nil
}
func (s *sizedReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("xar: negative decoded offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= s.size {
		return 0, io.EOF
	}
	wanted := len(p)
	p = p[:min(int64(len(p)), s.size-off)]
	n, err := s.Reader.ReadAt(p, off)
	if err != nil && err != io.EOF {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	if off+int64(n) == s.size {
		if err := s.validateEmpty(); err != nil {
			return n, err
		}
	}
	if n < wanted {
		return n, io.EOF
	}
	return n, nil
}

// zlibFile uses declared size with a bounded look-behind window. Listing is
// metadata-only, forward scans reuse decoder state, backwards reads replay.
type zlibFile struct {
	source      storage.Reader
	size        int64
	mu          sync.Mutex
	input       *bufio.Reader
	decoder     io.ReadCloser
	offset      int64
	cache       []byte
	cacheOffset int64
}

func (f *zlibFile) Size() int64 { return f.size }
func (f *zlibFile) validateEmpty() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.reset(); err != nil {
		return err
	}
	return f.finish()
}
func (f *zlibFile) finish() error {
	var extra [1]byte
	n, err := f.decoder.Read(extra[:])
	if n != 0 || err != io.EOF {
		return fmt.Errorf("xar: zlib size/checksum mismatch: %v", err)
	}
	if _, err := f.input.ReadByte(); err != io.EOF {
		return fmt.Errorf("xar: trailing compressed data")
	}
	return nil
}
func (f *zlibFile) reset() error {
	if f.decoder != nil {
		f.decoder.Close()
	}
	f.input = bufio.NewReader(io.NewSectionReader(f.source, 0, f.source.Size()))
	z, err := zlib.NewReader(f.input)
	if err != nil {
		return err
	}
	f.decoder = z
	f.offset = 0
	f.cache = f.cache[:0]
	return nil
}
func (f *zlibFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if off < 0 {
		return 0, fmt.Errorf("xar: negative decoded offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	p = p[:min(int64(len(p)), f.size-off)]
	if off >= f.cacheOffset && off+int64(len(p)) <= f.cacheOffset+int64(len(f.cache)) {
		copy(p, f.cache[off-f.cacheOffset:])
		if len(p) < wanted {
			return len(p), io.EOF
		}
		return len(p), nil
	}
	if f.decoder == nil || off < f.offset {
		if err := f.reset(); err != nil {
			return 0, err
		}
	}
	if off > f.offset {
		n, err := io.CopyN(io.Discard, f.decoder, off-f.offset)
		f.offset += n
		if err != nil {
			return 0, err
		}
	}
	n, err := io.ReadFull(f.decoder, p)
	f.offset += int64(n)
	if err != nil {
		return n, fmt.Errorf("xar: truncated zlib member: %w", err)
	}
	if f.offset == f.size {
		if err := f.finish(); err != nil {
			return n, err
		}
	}
	if len(p) <= 1<<20 {
		f.cache = append(f.cache[:0], p...)
		f.cacheOffset = off
	} else {
		f.cache = append(f.cache[:0], p[len(p)-(1<<20):]...)
		f.cacheOffset = f.offset - int64(len(f.cache))
	}
	if n < wanted {
		return n, io.EOF
	}
	return n, nil
}
