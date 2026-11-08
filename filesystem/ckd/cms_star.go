package ckd

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// CMSBuiltin opens the CMS EDF minidisk whose label is on the given cylinder
// of a CKD image. Minidisk discovery (CP directory or label scan) stays in
// Starlark; content is decoded only by the returned read() method.
func CMSBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var cylinder, extent, origin uint32
	maxFiles := 100000
	if err := starlark.UnpackArgs("cms", args, kwargs, "file", &value, "cylinder", &cylinder, "cylinders?", &extent, "directory_origin?", &origin, "max_files?", &maxFiles); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maxFiles <= 0 {
		return nil, fmt.Errorf("cms: portable CKD file and positive max_files required")
	}
	d, err := Open(source)
	if err != nil {
		return nil, err
	}
	m, err := OpenCMS(d, cylinder, extent)
	if err != nil {
		return nil, err
	}
	if origin == 0 {
		origin = m.Label.DirectoryOrigin
	}
	files, err := m.FilesAt(origin, maxFiles)
	if err != nil {
		return nil, err
	}
	list := make([]starlark.Value, len(files))
	for i, f := range files {
		recfm := "F"
		if f.RecordFormat == 0xe5 {
			recfm = "V"
		}
		list[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(f.Name), "type": starlark.String(f.Type), "mode": starlark.String(f.Mode),
			"record_format": starlark.String(recfm), "record_length": starlark.MakeUint64(uint64(f.RecordLength)),
			"records": starlark.MakeUint64(uint64(f.Records)), "data_blocks": starlark.MakeUint64(uint64(f.DataBlocks)),
			"origin": starlark.MakeUint64(uint64(f.Origin)), "levels": starlark.MakeInt(int(f.Levels)),
			"flags": starlark.MakeInt(int(f.Flags)), "date": starlark.String(f.Date), "century": starlark.MakeInt(int(f.Century)),
			"fst": starlark.Bytes(f.FST),
		})
	}
	read := starlark.NewBuiltin("read", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var index int
		maximum := 64 << 20
		if err := starlark.UnpackArgs("read", args, kwargs, "index", &index, "max_bytes?", &maximum); err != nil {
			return nil, err
		}
		if index < 0 || index >= len(files) || maximum <= 0 {
			return nil, fmt.Errorf("cms read: index outside directory or invalid max_bytes")
		}
		b, err := m.Content(files[index], int64(maximum))
		if err != nil {
			return nil, err
		}
		f := files[index]
		return starfile.NewReader(f.Name+" "+f.Type, byteFile{bytes.NewReader(b)}), nil
	})
	// verify decodes every file and reports failures per file rather than
	// stopping, so isolated damage is distinguishable from format gaps.
	verify := starlark.NewBuiltin("verify", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		maximum := 64 << 20
		if err := starlark.UnpackArgs("verify", args, kwargs, "max_bytes?", &maximum); err != nil {
			return nil, err
		}
		if maximum <= 0 {
			return nil, fmt.Errorf("cms verify: max_bytes must be positive")
		}
		var total int64
		var failures []starlark.Value
		for i, f := range files {
			b, err := m.Content(f, int64(maximum))
			if err != nil {
				failures = append(failures, starfile.NewRecord(starlark.StringDict{"index": starlark.MakeInt(i), "error": starlark.String(err.Error())}))
				continue
			}
			total += int64(len(b))
		}
		return starfile.NewRecord(starlark.StringDict{"files": starlark.MakeInt(len(files) - len(failures)), "bytes": starlark.MakeInt64(total), "errors": starlark.NewList(failures)}), nil
	})
	l := m.Label
	return starfile.NewRecord(starlark.StringDict{
		"id": starlark.String(l.ID), "block_size": starlark.MakeUint64(uint64(l.BlockSize)),
		"blocks": starlark.MakeUint64(uint64(l.Blocks)), "used_blocks": starlark.MakeUint64(uint64(l.UsedBlocks)),
		"cylinders": starlark.MakeUint64(uint64(l.Cylinders)), "maximum_cylinders": starlark.MakeUint64(uint64(l.MaximumCylinders)),
		"blocks_per_track": starlark.MakeUint64(uint64(m.BlocksPerTrack)), "directory_origin": starlark.MakeUint64(uint64(l.DirectoryOrigin)),
		"created": starlark.String(l.Created), "label": starlark.Bytes(l.Raw), "files": starlark.NewList(list), "read": read, "verify": verify,
	}), nil
}

// CMSLibraryBuiltin decodes a LIBPDS MACLIB/TXTLIB from fixed 80-byte content
// such as the result of cms(...).read(index).
func CMSLibraryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maxEntries, maxBytes := 1000000, 512<<20
	if err := starlark.UnpackArgs("cms_library", args, kwargs, "file", &value, "max_entries?", &maxEntries, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maxEntries <= 0 || maxBytes <= 0 {
		return nil, fmt.Errorf("cms_library: portable file and positive limits required")
	}
	if source.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("cms_library: %d bytes exceed max_bytes", source.Size())
	}
	data, err := readWhole(source, maxBytes)
	if err != nil {
		return nil, err
	}
	l, err := ParseCMSLibrary(data, maxEntries)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(l.Entries))
	for i, e := range l.Entries {
		entries[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(e.Name), "raw_name": starlark.Bytes(e.RawName), "flags": starlark.MakeUint64(uint64(e.Flags)),
			"record": starlark.MakeUint64(uint64(e.Record)), "records": starlark.MakeUint64(uint64(e.Records)),
			"data": starfile.NewReader(e.Name, byteFile{bytes.NewReader(l.Member(i))}),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"format": starlark.String(l.Format), "directory_bytes": starlark.MakeUint64(uint64(l.DirectoryBytes)),
		"directory_record": starlark.MakeUint64(uint64(l.DirectoryRecord)),
		"reserved":         starlark.NewList([]starlark.Value{starlark.MakeUint64(uint64(l.Reserved[0])), starlark.MakeUint64(uint64(l.Reserved[1]))}),
		"entries":          starlark.NewList(entries),
	}), nil
}

// CMSUnpackBuiltin decodes COPYFILE PACK content such as cms(...).read(index).
func CMSUnpackBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maxBytes := 256 << 20
	container := "F"
	if err := starlark.UnpackArgs("cms_unpack", args, kwargs, "file", &value, "record_format?", &container, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maxBytes <= 0 || source.Size() > int64(maxBytes) || (container != "F" && container != "V") {
		return nil, fmt.Errorf("cms_unpack: portable file within positive max_bytes and record_format F or V required")
	}
	data, err := readWhole(source, maxBytes)
	if err != nil {
		return nil, err
	}
	var u *CMSUnpacked
	if container == "F" {
		u, err = UnpackCMS(data, maxBytes)
	} else {
		var records [][]byte
		for p := 0; p < len(data); {
			if p+2 > len(data) || p+2+int(be.Uint16(data[p:])) > len(data) {
				return nil, fmt.Errorf("cms_unpack: truncated variable record")
			}
			n := int(be.Uint16(data[p:]))
			records = append(records, data[p+2:p+2+n])
			p += 2 + n
		}
		u, err = UnpackCMSRecords(records, maxBytes)
	}
	if err != nil {
		return nil, err
	}
	recfm := "F"
	if u.RecordFormat == 0xe5 {
		recfm = "V"
	}
	return starfile.NewRecord(starlark.StringDict{
		"record_format": starlark.String(recfm), "record_length": starlark.MakeUint64(uint64(u.RecordLength)),
		"records": starlark.MakeInt(u.Records), "maximum_record": starlark.MakeInt(u.MaximumRecord),
		"data": starfile.NewReader("unpacked", byteFile{bytes.NewReader(u.Data)}),
	}), nil
}

// CMSModuleBuiltin decodes MODULE content such as cms(...).read(index).
func CMSModuleBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	recfm := "V"
	maxEntries, maxBytes := 16000000, 512<<20
	if err := starlark.UnpackArgs("cms_module", args, kwargs, "file", &value, "record_format?", &recfm, "max_entries?", &maxEntries, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || (recfm != "F" && recfm != "V") || maxEntries <= 0 || maxBytes <= 0 || source.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("cms_module: portable file, record_format F or V and positive limits required")
	}
	data, err := readWhole(source, maxBytes)
	if err != nil {
		return nil, err
	}
	m, err := ParseCMSModule(data, recfm == "V", maxEntries)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{"segments": segmentsValue(m.Segments)}), nil
}

func segmentsValue(segs []CMSModuleSegment) *starlark.List {
	file := func(name string, b []byte) starlark.Value {
		if b == nil {
			return starlark.None
		}
		return starfile.NewReader(name, byteFile{bytes.NewReader(b)})
	}
	segments := make([]starlark.Value, len(segs))
	for si, seg := range segs {
		loader := make([]starlark.Value, len(seg.LoaderTable))
		for i, e := range seg.LoaderTable {
			words := make([]starlark.Value, len(e.Words))
			for k, w := range e.Words {
				words[k] = starlark.MakeUint64(uint64(w))
			}
			loader[i] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(e.Name), "raw_name": starlark.Bytes(e.RawName), "words": starlark.NewList(words)})
		}
		header := starlark.Value(starlark.None)
		if seg.Header != nil {
			header = starlark.Bytes(seg.Header)
		}
		segments[si] = starfile.NewRecord(starlark.StringDict{
			"header": header, "entry": starlark.MakeUint64(uint64(seg.Entry)), "origin": starlark.MakeUint64(uint64(seg.Origin)),
			"end": starlark.MakeUint64(uint64(seg.End)), "end2": starlark.MakeUint64(uint64(seg.End2)),
			"image": file("image", seg.Image), "trailer": file("trailer", seg.Trailer), "program_object": file("program object", seg.ProgramObject),
			"loader_table": starlark.NewList(loader), "relocation_count": starlark.MakeInt(len(seg.Relocations)),
			"relocation_width": starlark.MakeInt(seg.RelocationWidth), "relocation_data": file("relocations", seg.RelocationData),
			"extra": file("extra", seg.Extra),
		})
	}
	return starlark.NewList(segments)
}

// CMSCallableLibraryBuiltin decodes a CSLLIB such as cms(...).read(index).
func CMSCallableLibraryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maxEntries, maxBytes := 16000000, 512<<20
	if err := starlark.UnpackArgs("cms_csllib", args, kwargs, "file", &value, "max_entries?", &maxEntries, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maxEntries <= 0 || maxBytes <= 0 || source.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("cms_csllib: portable file within positive limits required")
	}
	data, err := readWhole(source, maxBytes)
	if err != nil {
		return nil, err
	}
	l, err := ParseCMSCallableLibrary(data, maxEntries)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{
		"name": starlark.String(l.Name), "date": starlark.String(l.Date), "time": starlark.String(l.Time),
		"identifiers": starlark.NewList([]starlark.Value{starlark.String(l.Identifiers[0]), starlark.String(l.Identifiers[1])}),
		"header":      starlark.Bytes(l.Header), "segments": segmentsValue(l.Segments),
	}), nil
}

// CMSLoadLibraryBuiltin decodes a variable-format LOADLIB such as
// cms(...).read(index); each member's data is its load module records as a
// 2-byte length-prefixed stream.
func CMSLoadLibraryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maxEntries, maxBytes := 1000000, 512<<20
	if err := starlark.UnpackArgs("cms_loadlib", args, kwargs, "file", &value, "max_entries?", &maxEntries, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maxEntries <= 0 || maxBytes <= 0 || source.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("cms_loadlib: portable file within positive limits required")
	}
	data, err := readWhole(source, maxBytes)
	if err != nil {
		return nil, err
	}
	l, err := ParseCMSLoadLibrary(data, maxEntries)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(l.Entries))
	// Aliases share their member's stream, so build each member once.
	streams := map[uint32][]byte{}
	for i, e := range l.Entries {
		stream, ok := streams[e.Record]
		if !ok {
			for _, r := range e.Records {
				stream = append(stream, byte(len(r)>>8), byte(len(r)))
				stream = append(stream, r...)
			}
			streams[e.Record] = stream
		}
		entries[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(e.Name), "raw_name": starlark.Bytes(e.RawName), "alias": starlark.Bool(e.Alias),
			"record": starlark.MakeUint64(uint64(e.Record)), "records": starlark.MakeInt(len(e.Records)),
			"user_data": starlark.Bytes(e.UserData), "data": starfile.NewReader(e.Name, byteFile{bytes.NewReader(stream)}),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"directory_bytes": starlark.MakeUint64(uint64(l.DirectoryBytes)), "directory_record": starlark.MakeUint64(uint64(l.DirectoryRecord)),
		"header": starlark.Bytes(l.Header), "entries": starlark.NewList(entries),
	}), nil
}

// ObjectDeckBuiltin decodes F 80 object card content (TEXT files, TXTLIB
// members) into symbols, END cards, counts and assembled sections.
func ObjectDeckBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maxCards, maxBytes := 10000000, 256<<20
	if err := starlark.UnpackArgs("object_deck", args, kwargs, "file", &value, "max_cards?", &maxCards, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maxCards <= 0 || maxBytes <= 0 || source.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("object_deck: portable file within positive limits required")
	}
	data, err := readWhole(source, maxBytes)
	if err != nil {
		return nil, err
	}
	d, err := ParseObjectDeck(data, maxCards)
	if err != nil {
		return nil, err
	}
	sections, err := d.Sections(maxBytes)
	if err != nil {
		return nil, err
	}
	symbol := func(s ObjectSymbol) starlark.Value {
		return starfile.NewRecord(starlark.StringDict{
			"module": starlark.MakeInt(s.Module), "name": starlark.String(s.Name), "raw_name": starlark.Bytes(s.RawName),
			"type": starlark.MakeInt(int(s.Type)), "id": starlark.MakeInt(int(s.ID)), "owner": starlark.MakeInt(int(s.Owner)),
			"address": starlark.MakeUint64(uint64(s.Address)), "value": starlark.MakeUint64(uint64(s.Value)), "flags": starlark.MakeInt(int(s.Flags)),
			"extended": starlark.Bool(s.Extended), "kind": starlark.MakeInt(int(s.Kind)),
		})
	}
	symbols := make([]starlark.Value, len(d.Symbols))
	for i, s := range d.Symbols {
		symbols[i] = symbol(s)
	}
	ends := make([]starlark.Value, len(d.Ends))
	for i, e := range d.Ends {
		ends[i] = starfile.NewRecord(starlark.StringDict{"address": starlark.MakeUint64(uint64(e.Address)), "id": starlark.MakeInt(int(e.ID)), "name": starlark.String(e.Name)})
	}
	secs := make([]starlark.Value, len(sections))
	for i, s := range sections {
		secs[i] = starfile.NewRecord(starlark.StringDict{"symbol": symbol(s.Symbol), "data": starfile.NewReader(s.Symbol.Name, byteFile{bytes.NewReader(s.Data)})})
	}
	return starfile.NewRecord(starlark.StringDict{
		"symbols": starlark.NewList(symbols), "ends": starlark.NewList(ends), "sections": starlark.NewList(secs),
		"text_cards": starlark.MakeInt(len(d.Texts)), "relocations": starlark.MakeInt(len(d.Relocations)), "other_cards": starlark.MakeInt(len(d.Others)),
	}), nil
}

// ProgramObjectBuiltin validates a stored binder program object (IEWPLMH
// versions 2-5), such as a CMS module's program_object trailer, and returns it.
func ProgramObjectBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("program_object", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("program_object: portable file required")
	}
	c, err := OpenStoredProgramObject(source)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("program object", c), nil
}

// CPDirectoryBuiltin reads the CP object directory of a CKD volume, by
// default the one selected by its VOL1 label.
func CPDirectoryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var root uint32
	maxUsers := 100000
	if err := starlark.UnpackArgs("cp_directory", args, kwargs, "file", &value, "root?", &root, "max_users?", &maxUsers); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maxUsers <= 0 {
		return nil, fmt.Errorf("cp_directory: portable CKD file and positive max_users required")
	}
	d, err := Open(source)
	if err != nil {
		return nil, err
	}
	c, err := OpenCPDirectory(d, root, maxUsers)
	if err != nil {
		return nil, err
	}
	groups := make([]starlark.Value, len(c.Groups))
	for i, g := range c.Groups {
		groups[i] = starfile.NewRecord(starlark.StringDict{"gid": starlark.MakeUint64(uint64(g.GID)), "name": starlark.String(g.Name)})
	}
	return starfile.NewRecord(starlark.StringDict{
		"root": starlark.MakeUint64(uint64(c.Root)), "header": starlark.MakeUint64(uint64(c.Header)),
		"users": cpUsersValue(c.Users), "profiles": cpUsersValue(c.Profiles), "groups": starlark.NewList(groups),
	}), nil
}

func cpDevicesValue(ds []CPDevice) *starlark.List {
	out := make([]starlark.Value, len(ds))
	for k, x := range ds {
		out[k] = starfile.NewRecord(starlark.StringDict{
			"address": starlark.MakeInt(int(x.Address)), "type": starlark.MakeInt(int(x.Type)), "owner": starlark.String(x.Owner),
			"start": starlark.MakeInt(int(x.Start)), "end": starlark.MakeInt(int(x.End)), "volume": starlark.String(x.Volume),
			"mode": starlark.String(x.ModeName()), "mode_code": starlark.MakeInt(int(x.Mode)), "password_flags": starlark.MakeInt(int(x.PasswordFlags)),
			"target_user": starlark.String(x.TargetUser), "target_address": starlark.MakeInt(int(x.TargetAddress)), "link_mode": starlark.MakeInt(int(x.LinkMode)),
			"device_type": starlark.MakeInt(int(x.DeviceType)), "spool_class": starlark.String(x.SpoolClass), "real_address": starlark.MakeInt(int(x.RealAddress)),
			"raw": starlark.Bytes(x.Raw),
		})
	}
	return starlark.NewList(out)
}

func cpUsersValue(us []CPUser) *starlark.List {
	out := make([]starlark.Value, len(us))
	strs := func(ss []string) *starlark.List {
		v := make([]starlark.Value, len(ss))
		for i, s := range ss {
			v[i] = starlark.String(s)
		}
		return starlark.NewList(v)
	}
	for i, u := range us {
		f := u.Fields
		iucv := make([]starlark.Value, len(u.IUCV))
		for k, x := range u.IUCV {
			iucv[k] = starfile.NewRecord(starlark.StringDict{"target": starlark.String(x.Target), "resource": starlark.String(x.Resource),
				"message_limit": starlark.MakeInt(int(x.MessageLimit)), "priority": starlark.Bool(x.Priority), "ident_flags": starlark.MakeInt(int(x.IdentFlags))})
		}
		out[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(u.Name), "raw_name": starlark.Bytes(u.RawName), "flags": starlark.MakeUint64(uint64(u.Flags)),
			"word": starlark.MakeUint64(uint64(u.Word)), "device_count": starlark.MakeInt(u.DeviceCount), "block": starlark.Bytes(u.Block),
			"devices": cpDevicesValue(u.Devices), "configuration": cpDevicesValue(u.Configuration),
			"iucv": starlark.NewList(iucv), "namesave": strs(u.NameSave),
			"distribution": starlark.String(f.Distribution), "account": starlark.String(f.Account), "acigroup": starlark.String(f.ACIGroup),
			"include": starlark.String(f.Include), "ipl": starlark.String(f.IPL), "password_date": starlark.String(f.PasswordDate),
			"autolog": strs(f.Autolog), "machine": starlark.String(f.Machine), "nolog": starlark.Bool(f.NoLog),
			"classes": starlark.MakeUint64(uint64(f.Classes)), "storage_kb": starlark.MakeUint64(uint64(f.StorageKB)),
			"maximum_storage_kb": starlark.MakeUint64(uint64(f.MaximumStorageKB)), "maxconn": starlark.MakeInt(int(f.MaxConn)),
			"share_absolute": starlark.MakeInt(int(f.ShareAbsolute)), "share_relative": starlark.MakeInt(int(f.ShareRelative)),
			"posix_uid": starlark.MakeUint64(uint64(f.POSIXUID)), "posix_gid": starlark.MakeUint64(uint64(f.POSIXGID)),
			"posix_group": starlark.String(f.POSIXGroup), "options": strs(f.Options),
		})
	}
	return starlark.NewList(out)
}

// readWhole reads all of source, failing on any read error or short read and
// on sources larger than maximum bytes.
func readWhole(source storage.Reader, maximum int) ([]byte, error) {
	size := source.Size()
	if size < 0 || size > int64(maximum) {
		return nil, fmt.Errorf("source of %d bytes exceeds max_bytes %d", size, maximum)
	}
	// One ReadAt: a full read may report io.EOF; any other error, or a short
	// read even without an error, fails (looping on a reader that breaks the
	// io.ReaderAt contract could otherwise never finish).
	data := make([]byte, size)
	n, err := source.ReadAt(data, 0)
	if err != nil && !(err == io.EOF && int64(n) == size) {
		return nil, err
	}
	if int64(n) != size {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}
