package star

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/tinyrange/trex/archive/ibmiimd"
	binaryapi "github.com/tinyrange/trex/binary"
	"github.com/tinyrange/trex/binary/ibmidasd"
	"github.com/tinyrange/trex/binary/issi"
	starfile "github.com/tinyrange/trex/storage/star"
	starjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
)

func ibmiDASDIndexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source, rangesValue starlark.Value
	maximum := int64(1 << 20)
	if err := starlark.UnpackArgs("ibmi_dasd_index", args, kwargs, "source", &source, "ranges", &rangesValue, "maximum_pages?", &maximum); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	iterable, ok := rangesValue.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("ibmi_dasd_index: ranges must be (offset,size) pairs")
	}
	iter := iterable.Iterate()
	defer iter.Done()
	var ranges []ibmidasd.Range
	var item starlark.Value
	for iter.Next(&item) {
		pair, ok := item.(starlark.Indexable)
		if !ok || pair.Len() != 2 {
			return nil, fmt.Errorf("ibmi_dasd_index: invalid range pair")
		}
		var r ibmidasd.Range
		if err := starlark.AsInt(pair.Index(0), &r.Offset); err != nil {
			return nil, err
		}
		if err := starlark.AsInt(pair.Index(1), &r.Size); err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
		if len(ranges) > 65536 {
			return nil, fmt.Errorf("ibmi_dasd_index: range budget")
		}
	}
	idx, err := ibmidasd.Open(view, ranges, maximum)
	if err != nil {
		return nil, err
	}
	matches := starlark.NewBuiltin("matches", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var value starlark.Value
		if err := starlark.UnpackArgs("matches", args, kwargs, "address", &value); err != nil {
			return nil, err
		}
		var address uint64
		if err := starlark.AsInt(value, &address); err != nil {
			return nil, err
		}
		var records []starlark.Value
		if len(idx.Pages[address]) > 1024 {
			return nil, fmt.Errorf("ibmi dasd: match budget")
		}
		for _, offset := range idx.Pages[address] {
			data, err := ibmidasd.Page(view, offset)
			if err != nil {
				return nil, err
			}
			header := io.NewSectionReader(view, offset+ibmidasd.PageBytes+8, issi.HeaderBytes)
			var raw [issi.HeaderBytes]byte
			if _, err := header.ReadAt(raw[:], 0); err != nil {
				return nil, err
			}
			tags := issi.PointerTags(&raw)
			records = append(records, starfile.NewRecord(starlark.StringDict{
				"offset": starlark.MakeInt64(offset), "address": starlark.MakeUint64(address),
				"data":         starfile.NewReader("page", data),
				"headers":      starfile.NewReader("headers", header),
				"pointer_tags": starlark.Bytes(tags[:]),
				"sidecar":      starfile.NewReader("sidecar", io.NewSectionReader(view, offset+4096, 512)),
			}))
		}
		return starlark.NewList(records), nil
	})
	file := starlark.NewBuiltin("file", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var value starlark.Value
		var size int64
		if err := starlark.UnpackArgs("file", args, kwargs, "address", &value, "size", &size); err != nil {
			return nil, err
		}
		var address uint64
		if err := starlark.AsInt(value, &address); err != nil {
			return nil, err
		}
		reader, err := idx.VirtualFile(address, size)
		if err != nil {
			return nil, err
		}
		return starfile.NewReader("sls", reader), nil
	})
	pageAddress := starlark.NewBuiltin("page_address", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var offset int64
		if err := starlark.UnpackArgs("page_address", args, kwargs, "offset", &offset); err != nil {
			return nil, err
		}
		address, ok, err := idx.PageAddress(offset)
		if err != nil {
			return nil, err
		}
		if !ok {
			return starlark.None, nil
		}
		return starlark.MakeUint64(address), nil
	})
	return starfile.NewRecord(starlark.StringDict{"file": file, "matches": matches, "page_address": pageAddress, "address_count": starlark.MakeInt(len(idx.Pages)), "scanned_pages": starlark.MakeInt64(idx.Scanned), "unmapped_pages": starlark.MakeInt64(idx.Unmapped)}), nil
}

func ibmiLIDDirectoryBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var offset int64
	maximum := 4096
	if err := starlark.UnpackArgs("ibmi_lid_directory", args, kwargs, "source", &source, "offset?", &offset, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 1 || maximum > 65536 {
		return nil, fmt.Errorf("ibmi_lid_directory: entry budget")
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	entries, _, err := ibmiimd.ReadDirectory(view, offset, maximum)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(encoded)}, nil)
}

func ibmiProceduresBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var name string
	maximum := 64
	maximumBytes := int64(64 << 20)
	if err := starlark.UnpackArgs("ibmi_procedures", args, kwargs, "source", &source, "name", &name, "maximum_matches?", &maximum, "maximum_bytes?", &maximumBytes); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	encoded, err := binaryapi.EncodeText(name, "ibm037", false)
	if err != nil {
		return nil, err
	}
	procedures, err := ibmiimd.FindProcedure(view, encoded, maximum, maximumBytes)
	if err != nil {
		return nil, err
	}
	var records []starlark.Value
	for _, p := range procedures {
		records = append(records, starfile.NewRecord(starlark.StringDict{"record_offset": starlark.MakeInt64(p.RecordOffset), "entry": starlark.MakeUint64(p.Entry), "name": starlark.String(name)}))
	}
	return starlark.NewList(records), nil
}
