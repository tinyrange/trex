package ckd

import (
	"fmt"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// VolumeValue is a CKD volume composed from one or more part files, for
// auto(), which browses it as a ckd image.
type VolumeValue struct{ Disk *Disk }

func (v *VolumeValue) String() string {
	return fmt.Sprintf("<ckd_volume %d tracks>", (v.Disk.Source.Size()-512)/int64(v.Disk.TrackSize))
}
func (*VolumeValue) Type() string          { return "ckd_volume" }
func (*VolumeValue) Freeze()               {}
func (*VolumeValue) Truth() starlark.Bool  { return true }
func (*VolumeValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: ckd_volume") }

// AutoView lets auto() browse the composed volume.
func (v *VolumeValue) AutoView(o auto.Options) (auto.View, error) {
	return v.Disk.View(o.MaxEntries), nil
}

func (v *VolumeValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "tracks":
		return starlark.MakeUint64(uint64((v.Disk.Source.Size() - 512) / int64(v.Disk.TrackSize))), nil
	case "heads":
		return starlark.MakeUint64(uint64(v.Disk.Heads)), nil
	case "track":
		return starlark.NewBuiltin("track", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var n int
			if err := starlark.UnpackArgs("track", args, kwargs, "number", &n); err != nil {
				return nil, err
			}
			if n < 0 {
				return nil, fmt.Errorf("track: negative track number")
			}
			recs, err := v.Disk.Track(uint32(n))
			if err != nil {
				return nil, err
			}
			out := make([]starlark.Value, len(recs))
			for i, r := range recs {
				out[i] = starfile.NewRecord(starlark.StringDict{
					"cylinder": starlark.MakeInt(int(r.Cylinder)), "head": starlark.MakeInt(int(r.Head)),
					"record": starlark.MakeInt(int(r.Number)), "key": starlark.Bytes(r.Key), "data": starlark.Bytes(r.Data),
				})
			}
			return starlark.NewList(out), nil
		}), nil
	case "hfs_live":
		// hfs_live(dataset) -> {pages, live}: the HFS pages a full walk reads.
		return starlark.NewBuiltin("hfs_live", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("hfs_live", args, kwargs, "dataset", &name); err != nil {
				return nil, err
			}
			v2, err := v.Disk.ReadVTOC(1000000)
			if err != nil {
				return nil, err
			}
			for _, ds := range v2.Datasets {
				if ds.Name == name {
					live, total, err := ds.HFSLivePages(10000000)
					if err != nil {
						return nil, err
					}
					return starfile.NewRecord(starlark.StringDict{"pages": starlark.MakeUint64(total), "live": starlark.MakeInt(len(live))}), nil
				}
			}
			return nil, fmt.Errorf("hfs_live: %s is not on the volume", name)
		}), nil
	case "trim":
		return starlark.NewBuiltin("trim", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var remove, blank, compact *starlark.List
			var members, keepMembers, uncatalog *starlark.Dict
			format := "cckd"
			if err := starlark.UnpackArgs("trim", args, kwargs, "remove", &remove, "blank?", &blank, "compact?", &compact, "members?", &members, "keep_members?", &keepMembers, "uncatalog?", &uncatalog, "format?", &format); err != nil {
				return nil, err
			}
			strings := func(l *starlark.List) ([]string, error) {
				if l == nil {
					return nil, nil
				}
				out := make([]string, l.Len())
				for i := range out {
					s, ok := starlark.AsString(l.Index(i))
					if !ok {
						return nil, fmt.Errorf("trim: data set names must be strings")
					}
					out[i] = s
				}
				return out, nil
			}
			names, err := strings(remove)
			if err != nil {
				return nil, err
			}
			blanks, err := strings(blank)
			if err != nil {
				return nil, err
			}
			t, err := NewEdit(v.Disk)
			if err != nil {
				return nil, err
			}
			if err := t.Remove(names); err != nil {
				return nil, err
			}
			if err := t.Blank(blanks); err != nil {
				return nil, err
			}
			if keepMembers != nil {
				for _, item := range keepMembers.Items() {
					ds, ok := starlark.AsString(item[0])
					l, ok2 := item[1].(*starlark.List)
					if !ok || !ok2 {
						return nil, fmt.Errorf("trim: keep_members maps a data set name to a list of member names")
					}
					names, err := strings(l)
					if err != nil {
						return nil, err
					}
					if err := t.KeepMembers(ds, names); err != nil {
						return nil, err
					}
				}
			}
			uncataloged := starlark.NewDict(2)
			if uncatalog != nil {
				for _, item := range uncatalog.Items() {
					cat, ok := starlark.AsString(item[0])
					l, ok2 := item[1].(*starlark.List)
					if !ok || !ok2 {
						return nil, fmt.Errorf("trim: uncatalog maps a catalog to a list of data set names")
					}
					names, err := strings(l)
					if err != nil {
						return nil, err
					}
					gone, err := t.Uncatalog(cat, names)
					if err != nil {
						return nil, err
					}
					out := make([]starlark.Value, len(gone))
					for i, n := range gone {
						out[i] = starlark.String(n)
					}
					uncataloged.SetKey(starlark.String(cat), starlark.NewList(out))
				}
			}
			compacts, err := strings(compact)
			if err != nil {
				return nil, err
			}
			dead, err := t.Compact(compacts)
			if err != nil {
				return nil, err
			}
			if members != nil {
				for _, item := range members.Items() {
					ds, ok := starlark.AsString(item[0])
					byName, ok2 := item[1].(*starlark.Dict)
					if !ok || !ok2 {
						return nil, fmt.Errorf("trim: members maps a data set name to {member: [records]}")
					}
					var add []NewMember
					for _, m := range byName.Items() {
						name, ok := starlark.AsString(m[0])
						recs, ok2 := m[1].(*starlark.List)
						if !ok || !ok2 {
							return nil, fmt.Errorf("trim: %s: a member maps its name to a list of records", ds)
						}
						nm := NewMember{Name: name}
						for i := 0; i < recs.Len(); i++ {
							b, ok := recs.Index(i).(starlark.Bytes)
							if !ok {
								return nil, fmt.Errorf("trim: %s(%s): records must be bytes", ds, name)
							}
							nm.Records = append(nm.Records, []byte(b))
						}
						add = append(add, nm)
					}
					if err := t.AddMembers(ds, add); err != nil {
						return nil, err
					}
				}
			}
			header := make([]byte, 512)
			if _, err := v.Disk.Source.ReadAt(header, 0); err != nil {
				return nil, err
			}
			var image storage.Reader
			stored := make([]starlark.Value, t.Tracks())
			switch format {
			case "cckd":
				img, err := Compress(t, header, v.Disk.Heads, v.Disk.TrackSize)
				if err != nil {
					return nil, err
				}
				for i := range stored {
					stored[i] = starlark.MakeInt(img.StoredBytes(uint32(i)))
				}
				image = img
			case "ckdz":
				img, err := WriteCKDZ(t, header, v.Disk.Heads)
				if err != nil {
					return nil, err
				}
				for i := range stored {
					stored[i] = starlark.MakeInt(0)
				}
				image = img
			default:
				return nil, fmt.Errorf("trim: format must be cckd or ckdz")
			}
			removed := make([]starlark.Value, len(t.Removed))
			for i, n := range t.Removed {
				removed[i] = starlark.String(n)
			}
			return starfile.NewRecord(starlark.StringDict{
				"image":       starfile.NewReader("volume."+format, image),
				"removed":     starlark.NewList(removed),
				"kept_tracks": starlark.MakeUint64(uint64(t.Kept())),
				"tracks":      starlark.MakeUint64(uint64(t.Tracks())),
				"stored":      starlark.NewList(stored),
				"dead_bytes":  starlark.MakeInt(dead),
				"uncataloged": uncataloged,
			}), nil
		}), nil
	}
	return nil, nil
}
func (*VolumeValue) AttrNames() []string {
	return []string{"heads", "hfs_live", "track", "tracks", "trim"}
}

// VolumeBuiltin is ckd_volume(parts): a volume stored as a list of CKD part
// files (or a single file), composed without copying.
func VolumeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var v starlark.Value
	if err := starlark.UnpackArgs("ckd_volume", args, kwargs, "parts", &v); err != nil {
		return nil, err
	}
	var parts []storage.Reader
	if l, ok := v.(*starlark.List); ok {
		for i := 0; i < l.Len(); i++ {
			r, ok := l.Index(i).(storage.Reader)
			if !ok {
				return nil, fmt.Errorf("ckd_volume: parts must be portable files")
			}
			parts = append(parts, r)
		}
	} else if r, ok := v.(storage.Reader); ok {
		parts = []storage.Reader{r}
	} else {
		return nil, fmt.Errorf("ckd_volume: a portable file or list of parts is required")
	}
	d, err := OpenParts(parts)
	if err != nil {
		return nil, err
	}
	return &VolumeValue{Disk: d}, nil
}
