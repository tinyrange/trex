package appx

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
)

// MSIX's writer emits Z_FULL_FLUSH after each 64KiB decoded block. The
// block map's compressed sizes therefore form a random-access index, unlike
// arbitrary ZIP deflate streams. See microsoft/msix-packaging,
// src/msix/pack/DeflateStream.cpp. No code is copied from that implementation.
// Hashes authenticate bytes against the map, NOT the publisher.
type indexedBlock struct {
	offset, size int64
	hash         [sha256.Size]byte
}
type indexedFile struct {
	source io.ReaderAt
	blocks []indexedBlock
	size   int64
	mu     sync.Mutex
	cached int
	data   []byte
}

// Invalid/absent indexes retain the ordinary ZIP reader. VerifyBlockMap still
// rejects invalid maps; this optional optimization never replaces verification.
func (a *Archive) indexBlocks(entries map[string]*Entry) {
	f := a.zipFiles["appxblockmap.xml"]
	if f == nil || f.UncompressedSize64 > maxManifest {
		return
	}
	r, err := f.Open()
	if err != nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r, maxManifest+1))
	r.Close()
	if err != nil || len(data) > maxManifest {
		return
	}
	var doc struct {
		XMLName xml.Name
		Method  string `xml:"HashMethod,attr"`
		Files   []struct {
			Name   string `xml:"Name,attr"`
			Size   uint64 `xml:"Size,attr"`
			Blocks []struct {
				Hash string `xml:"Hash,attr"`
				Size uint64 `xml:"Size,attr"`
			} `xml:"Block"`
		} `xml:"File"`
	}
	if xml.Unmarshal(data, &doc) != nil || doc.XMLName != (xml.Name{Space: blockMapNamespace, Local: "BlockMap"}) || doc.Method != "http://www.w3.org/2001/04/xmlenc#sha256" {
		return
	}
	seen := map[string]bool{}
	pending := map[*Entry]*indexedFile{}
	for _, file := range doc.Files {
		key := strings.ToLower(strings.ReplaceAll(file.Name, `\`, "/"))
		if seen[key] {
			return
		}
		seen[key] = true
		z := a.zipFiles[key]
		if z == nil || z.CompressedSize64 > math.MaxInt64 || z.Method != zip.Deflate || file.Size != z.UncompressedSize64 || file.Size == 0 || uint64(len(file.Blocks)) != (file.Size+blockSize-1)/blockSize {
			continue
		}
		blocks := make([]indexedBlock, 0, len(file.Blocks))
		offset := uint64(0)
		valid := true
		for _, b := range file.Blocks {
			hash, err := base64.StdEncoding.Strict().DecodeString(b.Hash)
			if err != nil || len(hash) != sha256.Size || b.Size == 0 || offset > z.CompressedSize64 || b.Size > z.CompressedSize64-offset || b.Size > 1<<20 {
				valid = false
				break
			}
			item := indexedBlock{offset: int64(offset), size: int64(b.Size)}
			copy(item.hash[:], hash)
			blocks = append(blocks, item)
			offset += b.Size
		}
		if !valid {
			continue
		}
		// ZIP readers bound the raw member. No offset can address another entry.
		raw, err := z.OpenRaw()
		if err != nil {
			continue
		}
		source, ok := raw.(io.ReaderAt)
		if !ok {
			continue
		}
		pending[entries[key]] = &indexedFile{source: source, blocks: blocks, size: int64(file.Size), cached: -1}
	}
	for entry, index := range pending {
		entry.index = index
	}
}

func (f *indexedFile) readAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("appx: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for n < len(p) && off < f.size {
		block := int(off / blockSize)
		if f.cached != block {
			b := f.blocks[block]
			// A nonfinal full-flush boundary is byte aligned but lacks BFINAL.
			// Append an empty final stored block to finish this independent stream.
			stream := flate.NewReader(io.MultiReader(io.NewSectionReader(f.source, b.offset, b.size), bytes.NewReader([]byte{1, 0, 0, 255, 255})))
			decoded := make([]byte, min(int64(blockSize), f.size-int64(block)*blockSize))
			_, err := io.ReadFull(stream, decoded)
			if err == nil {
				var extra [1]byte
				count, end := stream.Read(extra[:])
				if count != 0 || end != io.EOF {
					err = fmt.Errorf("invalid block ending: %v", end)
				}
			}
			stream.Close()
			if err != nil {
				return n, fmt.Errorf("appx: compressed block %d: %w", block, err)
			}
			if sha256.Sum256(decoded) != b.hash {
				return n, fmt.Errorf("appx: block hash mismatch at %d", block)
			}
			f.data = decoded
			f.cached = block
		}
		count := copy(p[n:], f.data[off%blockSize:])
		n += count
		off += int64(count)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (e *Entry) ReadAt(p []byte, off int64) (int, error) {
	if e.index == nil {
		return e.Entry.ReadAt(p, off)
	}
	// Preserve complete-read CRC validation as well as per-block hashes.
	if off == 0 && int64(len(p)) >= e.Size() {
		if err := e.Verify(); err != nil {
			return 0, err
		}
	}
	return e.index.readAt(p, off)
}
