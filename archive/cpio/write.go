package cpio

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	"math"
	"path"
)

// Build emits deterministic newc suitable for the Linux initramfs loader.
// Payloads are borrowed lazy readers; headers and padding alone are retained.
// Hardlink groups contain data only in their final record, as Linux expects.
func Build(input []unixfs.Entry) (storage.Reader, error) {
	entries, err := unixfs.Normalize(input)
	if err != nil {
		return nil, err
	}
	ids := map[string]uint32{}
	groups := map[string][]int{}
	canonical := map[string]unixfs.Entry{}
	for i, e := range entries {
		if e.Path == "TRAILER!!!" {
			return nil, fmt.Errorf("cpio: reserved trailer name")
		}
		if !e.Hardlink {
			ids[e.Path] = uint32(i + 1)
			canonical[e.Path] = e
		}
	}
	for i, e := range entries {
		key := e.Path
		if e.Hardlink {
			key = e.Target
		}
		groups[key] = append(groups[key], i)
	}
	directoryLinks := map[string]uint32{}
	for _, e := range entries {
		if e.Path != "." && e.Mode&0170000 == unixfs.Directory {
			directoryLinks[path.Dir(e.Path)]++
		}
	}
	var ranges []storage.Range
	add := func(r storage.Reader) { ranges = append(ranges, storage.Range{Source: r, Length: r.Size()}) }
	record := func(name string, e unixfs.Entry, id, links uint32, payload storage.Reader) error {
		size := int64(0)
		if payload != nil {
			size = payload.Size()
		}
		if size < 0 || size > math.MaxUint32 || len(name)+1 > 65536 {
			return fmt.Errorf("cpio: entry too large %q", name)
		}
		var h bytes.Buffer
		h.WriteString("070701")
		for _, v := range []uint32{id, e.Mode, e.UID, e.GID, links, e.Mtime, uint32(size), 0, 0, e.Major, e.Minor, uint32(len(name) + 1), 0} {
			fmt.Fprintf(&h, "%08x", v)
		}
		h.WriteString(name)
		h.WriteByte(0)
		for h.Len()%4 != 0 {
			h.WriteByte(0)
		}
		add(bytes.NewReader(h.Bytes()))
		if payload != nil {
			add(payload)
		}
		add(unixfs.Zero((-size) & 3))
		return nil
	}
	for i, e := range entries {
		key := e.Path
		if e.Hardlink {
			key = e.Target
		}
		c := canonical[key]
		group := groups[key]
		var data storage.Reader
		switch e.Mode & 0170000 {
		case unixfs.Regular:
			if i == group[len(group)-1] {
				data = c.Data
			}
		case unixfs.Symlink:
			data = bytes.NewReader([]byte(e.Target))
		}
		links := uint32(len(group))
		if e.Mode&0170000 == unixfs.Directory {
			links = 2 + directoryLinks[e.Path]
		}
		if err := record(e.Path, c, ids[key], links, data); err != nil {
			return nil, err
		}
	}
	if err := record("TRAILER!!!", unixfs.Entry{}, 0, 1, nil); err != nil {
		return nil, err
	}
	return storage.Compose(ranges...)
}
