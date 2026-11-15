package ckd

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"runtime"
	"sync"

	"github.com/tinyrange/trex/storage"
)

// CKDZ is trex's compact CKD volume format, for volumes built rather than
// exchanged. Tracks are stored as record lists (no padding; a count field
// that names the physical track and all-zero keys and data are flags),
// identical encoded tracks are stored once, and tracks are packed into
// chunks of about 1 MiB compressed with deflate at the highest level, so
// redundancy between neighbouring tracks is used too. It reads as the
// equivalent CKD_P370 image, like a CKD_C370 image does.
//
// Layout (little endian): "CKDZ\x00\x01\x00\x00", the 512-byte CKD_P370
// device header of the volume, the track count (u32) and chunk count
// (u32); per chunk its file offset (u64), stored length (u32) and decoded
// length (u32); per track its chunk (u32, 0xFFFFFFFF for a null track:
// record zero and an end-of-file record one) and offset in the chunk's
// decoded bytes (u32); then the chunks (raw deflate).
//
// An encoded track is: record count (uvarint), then per record a flag byte
// (1: the count field's CCHH is not the track's, 4 bytes follow; 2: the
// data is all zero; 4: the key is all zero), the record number, the key
// length, the data length (uvarint), the CCHH if flagged, the key unless
// zero and the data unless zero.
const ckdzMagic = "CKDZ\x00\x01\x00\x00"

const (
	ckdzCCHH     = 1
	ckdzZeroData = 2
	ckdzZeroKey  = 4
	ckdzNull     = 0xffffffff
	ckdzChunk    = 1 << 20
)

// IsCKDZ reports whether the bytes begin a CKDZ image.
func IsCKDZ(p []byte) bool { return len(p) >= 8 && string(p[:8]) == ckdzMagic }

func encodeTrack(buf []byte, t, heads uint32, recs []Record) []byte {
	cc, hh := uint16(t/heads), uint16(t%heads)
	buf = binary.AppendUvarint(buf, uint64(len(recs)))
	for _, r := range recs {
		var f byte
		if r.Cylinder != cc || r.Head != hh {
			f |= ckdzCCHH
		}
		if allZero(r.Data) {
			f |= ckdzZeroData
		}
		if len(r.Key) > 0 && allZero(r.Key) {
			f |= ckdzZeroKey
		}
		buf = append(buf, f, r.Number, byte(len(r.Key)))
		buf = binary.AppendUvarint(buf, uint64(len(r.Data)))
		if f&ckdzCCHH != 0 {
			buf = binary.BigEndian.AppendUint16(buf, r.Cylinder)
			buf = binary.BigEndian.AppendUint16(buf, r.Head)
		}
		if f&ckdzZeroKey == 0 {
			buf = append(buf, r.Key...)
		}
		if f&ckdzZeroData == 0 {
			buf = append(buf, r.Data...)
		}
	}
	return buf
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// CKDZImage is a CKDZ image built in memory.
type CKDZImage struct {
	data  []byte
	Held  uint32 // tracks with content
	Dedup uint32 // held tracks stored as a copy of an earlier one
}

func (c *CKDZImage) Size() int64 { return int64(len(c.data)) }
func (c *CKDZImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(c.data)) {
		return 0, fmt.Errorf("ckdz image: offset outside image")
	}
	n := copy(p, c.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// WriteCKDZ builds a CKDZ image of the tracks. header is the volume's
// 512-byte CKD_P370 device header.
func WriteCKDZ(set TrackSet, header []byte, heads uint32) (*CKDZImage, error) {
	if len(header) < 512 || string(header[:8]) != "CKD_P370" {
		return nil, fmt.Errorf("ckdz write: a CKD_P370 device header is required")
	}
	n := set.Tracks()
	img := &CKDZImage{}
	type entry struct{ chunk, offset uint32 }
	entries := make([]entry, n)
	seen := map[uint64][]uint32{} // hash -> tracks with that encoding
	encoded := map[uint32][]byte{}
	var chunks [][]byte // decoded chunk contents
	var cur []byte
	for t := uint32(0); t < n; t++ {
		if !set.Holds(t) {
			entries[t] = entry{ckdzNull, 0}
			continue
		}
		recs, err := set.Track(t)
		if err != nil {
			return nil, fmt.Errorf("ckdz write: track %d: %w", t, err)
		}
		img.Held++
		enc := encodeTrack(nil, t, heads, recs)
		h := fnv.New64a()
		h.Write(enc)
		key := h.Sum64()
		dup := false
		for _, o := range seen[key] {
			if bytes.Equal(encoded[o], enc) {
				entries[t] = entries[o]
				img.Dedup++
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		seen[key] = append(seen[key], t)
		encoded[t] = enc
		if len(cur)+len(enc) > ckdzChunk && len(cur) > 0 {
			chunks = append(chunks, cur)
			cur = nil
		}
		entries[t] = entry{uint32(len(chunks)), uint32(len(cur))}
		cur = append(cur, enc...)
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	// Compress the chunks in parallel.
	stored := make([][]byte, len(chunks))
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	var ferr error
	var mu sync.Mutex
	for i := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			var b bytes.Buffer
			w, err := flate.NewWriter(&b, flate.BestCompression)
			if err == nil {
				_, err = w.Write(chunks[i])
			}
			if err == nil {
				err = w.Close()
			}
			if err != nil {
				mu.Lock()
				ferr = err
				mu.Unlock()
				return
			}
			stored[i] = b.Bytes()
		}(i)
	}
	wg.Wait()
	if ferr != nil {
		return nil, ferr
	}
	head := []byte(ckdzMagic)
	head = append(head, header[:512]...)
	head[8+17], head[8+18], head[8+19] = 0, 0, 0 // one file holds every cylinder
	head = binary.LittleEndian.AppendUint32(head, n)
	head = binary.LittleEndian.AppendUint32(head, uint32(len(chunks)))
	pos := uint64(len(head) + 16*len(chunks) + 8*int(n))
	for i := range chunks {
		head = binary.LittleEndian.AppendUint64(head, pos)
		head = binary.LittleEndian.AppendUint32(head, uint32(len(stored[i])))
		head = binary.LittleEndian.AppendUint32(head, uint32(len(chunks[i])))
		pos += uint64(len(stored[i]))
	}
	for _, e := range entries {
		head = binary.LittleEndian.AppendUint32(head, e.chunk)
		head = binary.LittleEndian.AppendUint32(head, e.offset)
	}
	for _, s := range stored {
		head = append(head, s...)
	}
	img.data = head
	return img, nil
}

// CKDZ exposes a CKDZ image as the equivalent CKD_P370 image: its device
// header followed by every track padded to the track size. Decoded chunks
// are cached (a few at a time).
type CKDZ struct {
	source    storage.Reader
	header    [512]byte
	trackSize int64
	heads     uint32
	tracks    uint32
	chunks    []ckdzChunkRef
	entries   []uint32 // chunk, offset per track

	mu    sync.Mutex
	cache map[uint32][]byte
	order []uint32
	track int64
	buf   []byte
}

type ckdzChunkRef struct {
	off           uint64
	stored, plain uint32
}

// OpenCKDZ validates a CKDZ image's tables.
func OpenCKDZ(source storage.Reader) (*CKDZ, error) {
	var h [528]byte
	if _, err := io.ReadFull(io.NewSectionReader(source, 0, int64(len(h))), h[:]); err != nil {
		return nil, fmt.Errorf("ckdz header: %w", err)
	}
	if !IsCKDZ(h[:]) {
		return nil, fmt.Errorf("ckdz: not a CKDZ image")
	}
	c := &CKDZ{source: source, cache: map[uint32][]byte{}, track: -1}
	copy(c.header[:], h[8:520])
	c.heads, c.trackSize = le.Uint32(c.header[8:12]), int64(le.Uint32(c.header[12:16]))
	if c.heads == 0 || c.heads > 256 || c.trackSize < 29 || c.trackSize > 1<<20 {
		return nil, fmt.Errorf("ckdz: invalid geometry")
	}
	c.tracks = le.Uint32(h[520:524])
	nchunks := le.Uint32(h[524:528])
	if c.tracks == 0 || c.tracks > 1<<24 || nchunks > c.tracks || c.tracks%c.heads != 0 {
		return nil, fmt.Errorf("ckdz: invalid track or chunk count")
	}
	tab := make([]byte, 16*int(nchunks)+8*int(c.tracks))
	if _, err := io.ReadFull(io.NewSectionReader(source, 528, int64(len(tab))), tab); err != nil {
		return nil, fmt.Errorf("ckdz tables: %w", err)
	}
	for i := uint32(0); i < nchunks; i++ {
		e := tab[16*i:]
		r := ckdzChunkRef{le.Uint64(e), le.Uint32(e[8:]), le.Uint32(e[12:])}
		if r.off+uint64(r.stored) > uint64(source.Size()) || r.plain > 64<<20 {
			return nil, fmt.Errorf("ckdz: chunk %d outside image", i)
		}
		c.chunks = append(c.chunks, r)
	}
	c.entries = make([]uint32, 2*c.tracks)
	for t := uint32(0); t < c.tracks; t++ {
		e := tab[16*int(nchunks)+8*int(t):]
		ch, off := le.Uint32(e), le.Uint32(e[4:])
		if ch != ckdzNull && (ch >= nchunks || off >= c.chunks[ch].plain) {
			return nil, fmt.Errorf("ckdz: track %d outside its chunk", t)
		}
		c.entries[2*t], c.entries[2*t+1] = ch, off
	}
	copy(c.header[:8], "CKD_P370")
	return c, nil
}

func (c *CKDZ) Size() int64    { return 512 + int64(c.tracks)*c.trackSize }
func (c *CKDZ) Tracks() uint32 { return c.tracks }
func (c *CKDZ) chunk(i uint32) ([]byte, error) {
	if b, ok := c.cache[i]; ok {
		return b, nil
	}
	r := c.chunks[i]
	raw := make([]byte, r.stored)
	if _, err := io.ReadFull(io.NewSectionReader(c.source, int64(r.off), int64(r.stored)), raw); err != nil {
		return nil, fmt.Errorf("ckdz chunk %d: %w", i, err)
	}
	plain := make([]byte, r.plain)
	z := flate.NewReader(bytes.NewReader(raw))
	if _, err := io.ReadFull(z, plain); err != nil {
		return nil, fmt.Errorf("ckdz chunk %d: %w", i, err)
	}
	if len(c.order) >= 4 {
		delete(c.cache, c.order[0])
		c.order = c.order[1:]
	}
	c.cache[i] = plain
	c.order = append(c.order, i)
	return plain, nil
}

// load returns track t's padded CKD_P370 image (valid until the next load).
func (c *CKDZ) load(t uint32) ([]byte, error) {
	if int64(t) == c.track {
		return c.buf, nil
	}
	if c.buf == nil {
		c.buf = make([]byte, c.trackSize)
	}
	c.track = -1
	clear(c.buf)
	cc, hh := uint16(t/c.heads), uint16(t%c.heads)
	b := c.buf
	be.PutUint16(b[1:], cc)
	be.PutUint16(b[3:], hh)
	p := 5
	put := func(rc, rh uint16, n byte, key, data []byte, zk, zd bool, kl int, dl int) error {
		if p+8+kl+dl+8 > len(b) {
			return fmt.Errorf("ckdz track %d: records exceed the track size", t)
		}
		be.PutUint16(b[p:], rc)
		be.PutUint16(b[p+2:], rh)
		b[p+4], b[p+5] = n, byte(kl)
		be.PutUint16(b[p+6:], uint16(dl))
		p += 8
		if !zk {
			copy(b[p:], key)
		}
		p += kl
		if !zd {
			copy(b[p:], data)
		}
		p += dl
		return nil
	}
	ch, off := c.entries[2*t], c.entries[2*t+1]
	if ch == ckdzNull {
		put(cc, hh, 0, nil, make([]byte, 8), true, true, 0, 8)
		put(cc, hh, 1, nil, nil, true, true, 0, 0)
	} else {
		plain, err := c.chunk(ch)
		if err != nil {
			return nil, err
		}
		s := plain[off:]
		count, k := binary.Uvarint(s)
		if k <= 0 || count > 256 {
			return nil, fmt.Errorf("ckdz track %d: invalid record count", t)
		}
		s = s[k:]
		for i := uint64(0); i < count; i++ {
			if len(s) < 3 {
				return nil, fmt.Errorf("ckdz track %d: truncated record", t)
			}
			f, n, kl := s[0], s[1], int(s[2])
			dl, k := binary.Uvarint(s[3:])
			if k <= 0 || dl > 0xffff {
				return nil, fmt.Errorf("ckdz track %d: invalid data length", t)
			}
			s = s[3+k:]
			rc, rh := cc, hh
			if f&ckdzCCHH != 0 {
				if len(s) < 4 {
					return nil, fmt.Errorf("ckdz track %d: truncated count", t)
				}
				rc, rh = be.Uint16(s), be.Uint16(s[2:])
				s = s[4:]
			}
			var key, data []byte
			if f&ckdzZeroKey == 0 {
				if len(s) < kl {
					return nil, fmt.Errorf("ckdz track %d: truncated key", t)
				}
				key, s = s[:kl], s[kl:]
			}
			if f&ckdzZeroData == 0 {
				if len(s) < int(dl) {
					return nil, fmt.Errorf("ckdz track %d: truncated data", t)
				}
				data, s = s[:dl], s[dl:]
			}
			if err := put(rc, rh, n, key, data, f&ckdzZeroKey != 0, f&ckdzZeroData != 0, kl, int(dl)); err != nil {
				return nil, err
			}
		}
	}
	copy(b[p:], []byte{255, 255, 255, 255, 255, 255, 255, 255})
	c.track = int64(t)
	return c.buf, nil
}

func (c *CKDZ) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ckdz: negative offset")
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= c.Size() {
			return n, io.EOF
		}
		if pos < 512 {
			n += copy(p[n:], c.header[pos:])
			continue
		}
		t := (pos - 512) / c.trackSize
		c.mu.Lock()
		b, err := c.load(uint32(t))
		if err == nil {
			n += copy(p[n:], b[(pos-512)%c.trackSize:])
		}
		c.mu.Unlock()
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
