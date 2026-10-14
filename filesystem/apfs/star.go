package apfs

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("apfs", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("apfs: expected file")
	}
	c, err := Open(source)
	if err != nil {
		return nil, err
	}
	volumes := []starlark.Value{}
	for _, v := range c.Volumes {
		value, err := volumeValue(v)
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, value)
	}
	return starfile.NewRecord(starlark.StringDict{"superblock": starfile.NewReader("APFS container superblock", c.Superblock), "block_size": starlark.MakeUint64(uint64(c.BlockSize)), "blocks": starlark.MakeUint64(c.Blocks), "transaction": starlark.MakeUint64(c.Transaction), "volumes": starlark.NewList(volumes), "allocation": allocationBuiltin(c)}), nil
}

func volumeValue(v *Volume) (starlark.Value, error) {
	c := v.container
	browse := starlark.NewBuiltin("apfs.browse", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		raw := false
		if err := starlark.UnpackArgs("browse", args, kwargs, "raw?", &raw); err != nil {
			return nil, err
		}
		entries, err := v.Entries(raw)
		if err != nil {
			return nil, err
		}
		values := make([]starlark.Value, 0, len(entries))
		paths := make([]starlark.Value, 0, len(entries))
		index := map[string]starlark.Value{}
		for _, e := range entries {
			var rawData starlark.Value = starlark.None
			if e.RawData != nil {
				rawData = starfile.NewReader(e.Path, e.RawData)
			}
			var data starlark.Value = starlark.None
			if e.Data != nil {
				data = starfile.NewReader(e.Path, e.Data)
			}
			xattrs := starlark.NewDict(len(e.Xattrs))
			for name, value := range e.Xattrs {
				if err := xattrs.SetKey(starlark.String(name), starfile.NewReader(name, value)); err != nil {
					return nil, err
				}
			}
			streams := starlark.NewDict(len(e.XattrStreams))
			for name, id := range e.XattrStreams {
				if err := streams.SetKey(starlark.String(name), starlark.MakeUint64(id)); err != nil {
					return nil, err
				}
			}
			row := starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "entry_type": starlark.String(e.Kind), "id": starlark.MakeUint64(e.ID), "private_id": starlark.MakeUint64(e.PrivateID), "size": starlark.MakeUint64(e.Size), "mode": starlark.MakeUint64(uint64(e.Mode)), "uid": starlark.MakeUint64(uint64(e.UID)), "gid": starlark.MakeUint64(uint64(e.GID)), "target": starlark.String(e.Target), "data": data, "raw_data": rawData, "compression_type": starlark.MakeUint64(uint64(e.CompressionType)), "xattrs": xattrs, "xattr_streams": streams})
			values = append(values, row)
			paths = append(paths, starlark.String(e.Path))
			index[e.Path] = row
		}
		find := starlark.NewBuiltin("apfs.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var path string
			if err := starlark.UnpackArgs("find", args, kwargs, "path", &path); err != nil {
				return nil, err
			}
			if value := index[path]; value != nil {
				return value, nil
			}
			return starlark.None, nil
		})
		return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(values), "files": starlark.NewList(paths), "find": find}), nil
	})
	address, err := v.rootAddress(v.RootTree, v.RootTreeType)
	if err != nil {
		return nil, err
	}
	b, err := c.raw(address)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{
		"superblock":        starfile.NewReader("APFS volume superblock", v.Superblock),
		"browse":            browse,
		"seal_info":         sealInfoBuiltin(v),
		"verify_seal":       verifySealBuiltin(v),
		"records":           recordsBuiltin(v),
		"canonical_records": canonicalRecordsBuiltin(v),
		"seal_image":        sealImageBuiltin(v),
		"snapshots":         snapshotsBuiltin(v),
		"snapshot":          snapshotBuiltin(v),
		"object":            objectBuiltin(v),
		"name":              starlark.String(v.Name), "id": starlark.MakeUint64(v.ID), "transaction": starlark.MakeUint64(v.Transaction),
		"uuid":                  starlark.String(fmt.Sprintf("%X-%X-%X-%X-%X", v.UUID[:4], v.UUID[4:6], v.UUID[6:8], v.UUID[8:10], v.UUID[10:])),
		"incompatible_features": starlark.MakeUint64(v.Incompatible), "flags": starlark.MakeUint64(v.Flags), "role": starlark.MakeUint64(uint64(v.Role)),
		"root_tree": starlark.MakeUint64(v.RootTree), "root_tree_type": starlark.MakeUint64(uint64(v.RootTreeType)),
		"extent_tree": starlark.MakeUint64(v.ExtentTree), "integrity": starlark.MakeUint64(v.Integrity),
		"snapshot_count": starlark.MakeUint64(v.SnapshotCount), "snapshot_tree": starlark.MakeUint64(v.SnapshotTree), "snapshot_tree_type": starlark.MakeUint64(uint64(v.SnapshotTreeType)),
		"root_level": starlark.MakeUint64(uint64(le.Uint16(b[34:]))), "root_flags": starlark.MakeUint64(uint64(le.Uint16(b[32:]))),
		"tree_flags": starlark.MakeUint64(uint64(le.Uint32(b[len(b)-40:]))),
	}), nil
}

func sealImageBuiltin(v *Volume) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.seal_image", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var values *starlark.List
		var expected starlark.Bytes
		var options SealImageOptions
		var companions *starlark.List
		if err := starlark.UnpackArgs("seal_image", args, kwargs, "records", &values, "expected", &expected, "snapshot_name?", &options.SnapshotName, "snapshot_time_ns?", &options.SnapshotTime, "companions?", &companions); err != nil {
			return nil, err
		}
		if companions != nil {
			if companions.Len() > 16 {
				return nil, fmt.Errorf("apfs: excessive companion volumes")
			}
			for i := 0; i < companions.Len(); i++ {
				row, ok := companions.Index(i).(*starlark.Dict)
				if !ok {
					return nil, fmt.Errorf("apfs: companion must be a dictionary")
				}
				var spec VolumeSpec
				var directories *starlark.List
				var entries *starlark.List
				if err := starlark.UnpackArgs("companion", nil, row.Items(), "name", &spec.Name, "role", &spec.Role, "created_ns", &spec.Created, "directories?", &directories, "entries?", &entries); err != nil {
					return nil, err
				}
				if entries != nil {
					if entries.Len() > 1024 {
						return nil, fmt.Errorf("apfs: excessive companion entries")
					}
					for j := 0; j < entries.Len(); j++ {
						d, ok := entries.Index(j).(*starlark.Dict)
						if !ok {
							return nil, fmt.Errorf("apfs: companion entry must be dictionary")
						}
						var e Entry
						var data starlark.Value = starlark.None
						if err := starlark.UnpackArgs("companion entry", nil, d.Items(), "path", &e.Path, "entry_type", &e.Kind, "mode", &e.Mode, "uid?", &e.UID, "gid?", &e.GID, "data?", &data, "target?", &e.Target); err != nil {
							return nil, err
						}
						if data != starlark.None {
							var ok bool
							e.Data, ok = data.(storage.Reader)
							if !ok {
								return nil, fmt.Errorf("apfs: companion data must be file")
							}
						}
						spec.Entries = append(spec.Entries, e)
					}
				}
				if directories != nil {
					if directories.Len() > 128 {
						return nil, fmt.Errorf("apfs: excessive companion directories")
					}
					for j := 0; j < directories.Len(); j++ {
						name, ok := starlark.AsString(directories.Index(j))
						if !ok {
							return nil, fmt.Errorf("apfs: companion directory must be a string")
						}
						spec.Directories = append(spec.Directories, name)
					}
				}
				options.Companions = append(options.Companions, spec)
			}
		}
		records, err := recordsFromList(values)
		if err != nil {
			return nil, err
		}
		built, err := v.SealImageWithOptions(records, []byte(expected), options)
		if err != nil {
			return nil, err
		}
		return starfile.NewRecord(starlark.StringDict{
			"file":      starfile.NewReader("APFS sealed container image", built.File),
			"root_hash": starlark.Bytes(built.RootHash), "transaction": starlark.MakeUint64(built.Transaction),
			"tree_nodes": starlark.MakeUint64(built.TreeNodes), "allocated_blocks": starlark.MakeUint64(built.AllocatedBlocks), "freed_blocks": starlark.MakeUint64(built.FreedBlocks),
			"snapshot_name": starlark.String(built.SnapshotName), "snapshot_transaction": starlark.MakeUint64(built.SnapshotTransaction), "snapshot_uuid": starlark.String(fmt.Sprintf("%X-%X-%X-%X-%X", built.SnapshotUUID[:4], built.SnapshotUUID[4:6], built.SnapshotUUID[6:8], built.SnapshotUUID[8:10], built.SnapshotUUID[10:])),
		}), nil
	})
}

func snapshotsBuiltin(v *Volume) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.snapshots", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("snapshots", args, kwargs); err != nil {
			return nil, err
		}
		rows, err := v.Snapshots()
		if err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(rows))
		for i, s := range rows {
			out[i] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(s.Name), "transaction": starlark.MakeUint64(s.Transaction), "superblock_address": starlark.MakeUint64(s.Superblock), "extent_reference_tree": starlark.MakeUint64(s.ExtentReferenceTree), "created_ns": starlark.MakeUint64(s.Created), "changed_ns": starlark.MakeUint64(s.Changed), "flags": starlark.MakeUint64(uint64(s.Flags))})
		}
		return starlark.NewList(out), nil
	})
}

func snapshotBuiltin(v *Volume) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.snapshot", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("snapshot", args, kwargs, "name", &name); err != nil {
			return nil, err
		}
		snapshot, err := v.SnapshotVolume(name)
		if err != nil {
			return nil, err
		}
		return volumeValue(snapshot)
	})
}

func objectBuiltin(v *Volume) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.object", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var id uint64
		if err := starlark.UnpackArgs("object", args, kwargs, "id", &id); err != nil {
			return nil, err
		}
		address, err := resolve(v.omap, id)
		if err != nil {
			return nil, err
		}
		m := v.omap[id]
		return starfile.NewRecord(starlark.StringDict{"address": starlark.MakeUint64(address), "transaction": starlark.MakeUint64(m.xid), "flags": starlark.MakeUint64(uint64(m.flags)), "file": starfile.NewReader("APFS object", io.NewSectionReader(v.container.Source, int64(address*uint64(v.container.BlockSize)), int64(m.size)))}), nil
	})
}
