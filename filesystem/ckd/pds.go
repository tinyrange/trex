package ckd

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
)

type Member struct {
	Name     string
	Track    uint32
	Record   byte
	Alias    bool
	UserData []byte
}

// Members returns a traditional PDS directory. PDSE/HFS are intentionally not
// interpreted as PDS directories; their allocated tracks remain fully readable.
func (ds *Dataset) Members(maxMembers int) ([]Member, error) {
	if !ds.IsPDS() {
		return nil, fmt.Errorf("ckd: %s is not a traditional PDS", ds.Name)
	}
	if maxMembers <= 0 {
		return nil, fmt.Errorf("ckd: invalid member limit")
	}
	var out []Member
	names := map[string]bool{}
	for t := uint32(0); t < ds.Tracks(); t++ {
		rs, e := ds.Track(t)
		if e != nil {
			return nil, e
		}
		for _, r := range rs {
			if r.Number == 0 {
				continue
			}
			members, end, e := DirectoryBlock(r.Data)
			if e != nil {
				return nil, fmt.Errorf("ckd PDS %s: %w", ds.Name, e)
			}
			for _, m := range members {
				if len(out) >= maxMembers {
					return nil, fmt.Errorf("ckd: member limit exceeded")
				}
				if names[m.Name] || m.Name == "" || m.Name == "." || m.Name == ".." || m.Track >= ds.Tracks() || m.Record == 0 {
					return nil, fmt.Errorf("ckd: invalid PDS member %q", m.Name)
				}
				names[m.Name] = true
				out = append(out, m)
			}
			if end {
				return out, nil
			}
		}
	}
	return nil, fmt.Errorf("ckd: PDS directory has no end marker")
}

// DirectoryBlock decodes one 256-byte PDS directory record (IBM DFSMS Using
// Data Sets, PDS directory). User data is retained without guessing its format.
func DirectoryBlock(b []byte) ([]Member, bool, error) {
	if len(b) != 256 {
		return nil, false, fmt.Errorf("directory block length %d, want 256", len(b))
	}
	used := int(be.Uint16(b[:2]))
	if used < 2 || used > 256 {
		return nil, false, fmt.Errorf("invalid directory used count %d", used)
	}
	var out []Member
	for p := 2; p < used; {
		if p+8 > used {
			return nil, false, fmt.Errorf("truncated directory name")
		}
		if bytes.Equal(b[p:p+8], bytes.Repeat([]byte{255}, 8)) {
			return out, true, nil
		}
		if p+12 > used {
			return nil, false, fmt.Errorf("truncated directory entry")
		}
		length := 12 + 2*int(b[p+11]&31)
		if p+length > used {
			return nil, false, fmt.Errorf("directory user data outside block")
		}
		m := Member{Name: Identifier(b[p : p+8]), Track: uint32(be.Uint16(b[p+8 : p+10])), Record: b[p+10], Alias: b[p+11]&128 != 0, UserData: bytes.Clone(b[p+12 : p+length])}
		out = append(out, m)
		p += length
	}
	return out, false, nil
}

type span struct{ offset, length, start int64 }
type Content struct {
	source storage.Reader
	spans  []span
	size   int64
}

func (c *Content) Size() int64 { return c.size }
func (c *Content) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ckd: negative read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= c.size {
		return 0, io.EOF
	}
	done := 0
	i := sort.Search(len(c.spans), func(i int) bool { return c.spans[i].start+c.spans[i].length > off })
	for i < len(c.spans) && done < len(p) {
		s := c.spans[i]
		n := min(int64(len(p)-done), s.start+s.length-off)
		var got int
		var e error
		if s.offset == -1 { // Explicit sparse extent.
			clear(p[done : done+int(n)])
			got = int(n)
		} else {
			got, e = c.source.ReadAt(p[done:done+int(n)], s.offset+off-s.start)
		}
		done += got
		off += int64(got)
		if e != nil && !(e == io.EOF && got == int(n)) {
			return done, e
		}
		if got != int(n) {
			return done, io.ErrUnexpectedEOF
		}
		i++
	}
	if done < len(p) {
		return done, io.EOF
	}
	return done, nil
}

// Content reads data fields through the first zero-length EOF record. Blocks
// retain their bytes (including BDW/RDW for variable formats); there is no text
// conversion. PDS members start at their directory TTR. Other organizations
// must use raw allocated tracks rather than being mistaken for sequential data.
func (ds *Dataset) Content(member *Member, maxRecords int) (*Content, error) {
	if maxRecords <= 0 {
		return nil, fmt.Errorf("ckd: invalid record limit")
	}
	t := uint32(0)
	number := byte(1)
	if member != nil {
		if !ds.IsPDS() {
			return nil, fmt.Errorf("ckd: member on non-PDS")
		}
		t = member.Track
		number = member.Record
	} else if ds.Organization != 0x4000 || ds.SMSFlags&0x0e != 0 || ds.Flags&0x84 != 0 {
		return nil, fmt.Errorf("ckd: logical content requires PS or a PDS member")
	}
	c := &Content{source: ds.Disk.Source}
	started := false
	for ; t < ds.Tracks(); t++ {
		rs, e := ds.Track(t)
		if e != nil {
			return nil, e
		}
		for _, r := range rs {
			if r.Number == 0 {
				continue
			}
			if !started {
				if r.Number != number {
					continue
				}
				started = true
			}
			if len(r.Data) == 0 {
				return c, nil
			}
			if len(c.spans) >= maxRecords {
				return nil, fmt.Errorf("ckd: content record limit exceeded")
			}
			c.spans = append(c.spans, span{r.Offset + 8 + int64(len(r.Key)), int64(len(r.Data)), c.size})
			c.size += int64(len(r.Data))
		}
		if !started {
			return nil, fmt.Errorf("ckd: content start record not found")
		}
	}
	return nil, fmt.Errorf("ckd: missing EOF within allocated extents of %s", ds.Name)
}

// Allocation exposes every byte of every allocated track, including keys,
// count fields, deleted records and padding. Extents are in dataset order.
func (ds *Dataset) Allocation() storage.Reader {
	c := &Content{source: ds.Disk.Source}
	for _, e := range ds.Extents {
		n := int64(e.Last-e.First+1) * int64(ds.Disk.TrackSize)
		c.spans = append(c.spans, span{512 + int64(e.First)*int64(ds.Disk.TrackSize), n, c.size})
		c.size += n
	}
	return c
}
