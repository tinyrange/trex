package zfs

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	"io"
	"sort"
	"strconv"
	"strings"
)

func init() {
	auto.Register("zfs", 35, func(prefix []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(prefix) < 16448 || prefix[16384] != 1 || le.Uint32(prefix[16388:]) != 0 || !strings.Contains(string(prefix[16384:16448]), "version") {
			return nil, auto.ErrNoMatch
		}
		return Open(r, o)
	})
}

// Open reads a single-vdev image. Dataset heads are directories; snapshots are
// not substituted for the live tree. Unsupported pool features return errors.
func Open(r storage.Reader, o auto.Options) (auto.View, error) {
	if r.Size() < 512<<10 {
		return nil, auto.ErrNoMatch
	}
	// All supported labels use the XDR nvlist encoding at byte 16384.
	label, err := read(r, 16384, 64)
	if err != nil {
		return nil, err
	}
	if label[0] != 1 || le.Uint32(label[4:]) != 0 || !strings.Contains(string(label), "version") {
		return nil, auto.ErrNoMatch
	}
	p := &pool{source: r, maximum: o.MaxEntries, depth: o.MaxDepth, cache: map[string][]byte{}}
	if p.maximum <= 0 {
		p.maximum = 100000
	}
	if p.depth <= 0 {
		p.depth = 32
	}
	type uber struct {
		txg uint64
		bp  pointer
	}
	var choices []uber
	for _, base := range []int64{0, 256 << 10} {
		ring, err := read(r, base+(128<<10), 128<<10)
		if err != nil {
			return nil, err
		}
		for at := 0; at+1024 <= len(ring); at += 1024 {
			var bo binary.ByteOrder = le
			if le.Uint64(ring[at:]) != 0xbab10c {
				bo = be
				if be.Uint64(ring[at:]) != 0xbab10c {
					continue
				}
			}
			valid := false
			for size := 1024; size <= 8192 && at+size <= len(ring); size *= 2 {
				if at%size == 0 && validUber(ring[at:at+size], uint64(base+(128<<10)+int64(at)), bo) {
					valid = true
					break
				}
			}
			if !valid {
				continue
			}
			txg := bo.Uint64(ring[at+16:])
			if txg != 0 {
				choices = append(choices, uber{txg, pointer{append([]byte(nil), ring[at+40:at+168]...), bo}})
			}
		}
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].txg > choices[j].txg })
	var last error
	for _, u := range choices {
		mos, err := p.objset(u.bp)
		if err != nil {
			last = err
			continue
		}
		directory, err := mos.zap(1)
		if err != nil {
			last = err
			continue
		}
		root, err := scalar(directory, "root_dataset")
		if err != nil {
			last = err
			continue
		}
		return &datasetTree{mos: mos, id: root, depth: p.depth}, nil
	}
	if last == nil {
		last = fmt.Errorf("zfs: no readable uberblock")
	}
	return nil, last
}

type datasetTree struct {
	mos   *objset
	id    uint64
	depth int
}

func (d *datasetTree) Entries() ([]auto.Entry, error) {
	if d.depth <= 0 {
		return nil, auto.ErrLimit
	}
	obj, err := d.mos.get(d.id)
	if err != nil {
		return nil, err
	}
	bonus := obj.bonus()
	if len(bonus) < 40 {
		return nil, fmt.Errorf("zfs: short DSL directory")
	}
	head, children := obj.o.Uint64(bonus[8:]), obj.o.Uint64(bonus[32:])
	var entries []auto.Entry
	if head != 0 {
		ds, err := d.mos.get(head)
		if err != nil {
			return nil, err
		}
		b := ds.bonus()
		if len(b) < 256 {
			return nil, fmt.Errorf("zfs: short DSL dataset")
		}
		set, err := d.mos.p.objset(pointer{b[128:256], ds.o})
		if err != nil {
			return nil, err
		}
		fs, root, err := newFS(set)
		if err != nil {
			return nil, err
		}
		entries = append(entries, auto.Entry{Name: "files", Kind: "directory", View: &directory{fs, root, d.depth}})
	}
	if children != 0 {
		names, err := d.mos.zap(children)
		if err != nil {
			return nil, err
		}
		for name, ids := range names {
			if strings.HasPrefix(name, "$") {
				continue
			}
			if len(ids) != 1 {
				return nil, fmt.Errorf("zfs: invalid DSL child")
			}
			entries = append(entries, auto.Entry{Name: name, Kind: "directory", View: &datasetTree{d.mos, ids[0], d.depth - 1}})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

type attribute struct {
	name string
	size int
}
type fs struct {
	s       *objset
	attrs   map[uint64]attribute
	layouts map[string][]uint64
}

func newFS(s *objset) (*fs, uint64, error) {
	m, err := s.zap(1)
	if err != nil {
		return nil, 0, err
	}
	root, err := scalar(m, "ROOT")
	if err != nil {
		return nil, 0, err
	}
	f := &fs{s: s, attrs: map[uint64]attribute{}}
	if sa, ok := m["SA_ATTRS"]; ok {
		if len(sa) != 1 {
			return nil, 0, fmt.Errorf("zfs: invalid SA master")
		}
		master, err := s.zap(sa[0])
		if err != nil {
			return nil, 0, err
		}
		registry, err := scalar(master, "REGISTRY")
		if err != nil {
			return nil, 0, err
		}
		layout, err := scalar(master, "LAYOUTS")
		if err != nil {
			return nil, 0, err
		}
		reg, err := s.zap(registry)
		if err != nil {
			return nil, 0, err
		}
		for name, v := range reg {
			if len(v) != 1 {
				return nil, 0, fmt.Errorf("zfs: invalid SA registry")
			}
			f.attrs[v[0]&65535] = attribute{name, int(v[0] >> 24 & 65535)}
		}
		f.layouts, err = s.zap(layout)
		if err != nil {
			return nil, 0, err
		}
	}
	return f, root, nil
}
func (f *fs) attributes(obj *object) (map[string][]byte, error) {
	out := map[string][]byte{}
	b := obj.bonus()
	if obj.raw[4] == 17 {
		if len(b) < 144 {
			return nil, fmt.Errorf("zfs: truncated znode")
		}
		out["ZPL_MODE"] = b[72:80]
		out["ZPL_SIZE"] = b[80:88]
		return out, nil
	}
	parse := func(b []byte, o binary.ByteOrder) error {
		if len(b) == 0 {
			return nil
		}
		if len(b) < 8 || o.Uint32(b) != 0x2f505a {
			return fmt.Errorf("zfs: invalid SA header")
		}
		info := o.Uint16(b[4:])
		pos := int(info>>10) * 8
		if pos < 8 || pos > len(b) {
			return fmt.Errorf("zfs: SA header size")
		}
		layout, ok := f.layouts[strconv.Itoa(int(info&1023))]
		if !ok {
			return fmt.Errorf("zfs: missing SA layout %d", info&1023)
		}
		variable := 6
		for _, id := range layout {
			a, ok := f.attrs[id]
			if !ok {
				return fmt.Errorf("zfs: missing SA registry attribute %d", id)
			}
			n := a.size
			if n == 0 {
				if variable+2 > int(info>>10)*8 {
					return fmt.Errorf("zfs: SA variable length table")
				}
				n = int(o.Uint16(b[variable:]))
				variable += 2
			}
			if n > len(b)-pos {
				return fmt.Errorf("zfs: SA attribute bounds")
			}
			out[a.name] = b[pos : pos+n]
			pos += n
		}
		return nil
	}
	if err := parse(b, obj.o); err != nil {
		return nil, err
	}
	if obj.raw[7]&4 != 0 {
		spill, bo, err := obj.p.block(pointer{obj.raw[len(obj.raw)-128:], obj.o})
		if err != nil {
			return nil, err
		}
		if err = parse(spill, bo); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type directory struct {
	fs    *fs
	id    uint64
	depth int
}

func (d *directory) Entries() ([]auto.Entry, error) {
	if d.depth <= 0 {
		return nil, auto.ErrLimit
	}
	names, err := d.fs.s.zap(d.id)
	if err != nil {
		return nil, err
	}
	var entries []auto.Entry
	for name, value := range names {
		if name == "." || name == ".." {
			continue
		}
		if strings.ContainsAny(name, "/\x00") || len(value) != 1 {
			return nil, fmt.Errorf("zfs: invalid directory entry")
		}
		id := value[0] & ((1 << 48) - 1)
		kind := value[0] >> 60
		e := auto.Entry{Name: name, Kind: "file", Attributes: map[string]any{"object": id}}
		if kind == 4 {
			e.Kind = "directory"
			e.View = &directory{d.fs, id, d.depth - 1}
		} else {
			obj, err := d.fs.s.get(id)
			if err != nil {
				return nil, err
			}
			attrs, err := d.fs.attributes(obj)
			if err != nil {
				return nil, fmt.Errorf("zfs: %s: %w", name, err)
			}
			sizeData := attrs["ZPL_SIZE"]
			if len(sizeData) != 8 {
				return nil, fmt.Errorf("zfs: missing size for %s", name)
			}
			size := obj.o.Uint64(sizeData)
			if size > 1<<63-1 || (kind == 8 && size > uint64(obj.Size())) {
				return nil, fmt.Errorf("zfs: oversized file")
			}
			if kind == 10 {
				e.Kind = "symlink"
				if target := attrs["ZPL_SYMLINK"]; target != nil {
					e.Attributes["link"] = string(target)
				}
			} else if kind == 8 {
				e.Reader = io.NewSectionReader(obj, 0, int64(size))
			} else {
				e.Kind = "special"
			}
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}
