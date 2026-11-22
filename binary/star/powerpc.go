package star

import (
	"encoding/json"
	"fmt"
	binaryapi "github.com/tinyrange/trex/binary"
	starjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
)

func powerPCInstructionsBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var offset int64
	size := int64(256)
	address := starlark.Value(starlark.MakeInt(0))
	order := "big"
	maximum := 4096
	if err := starlark.UnpackArgs("ppc_instructions", args, kwargs, "source", &source, "offset?", &offset, "size?", &size, "address?", &address, "byte_order?", &order, "maximum?", &maximum); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	var pc uint64
	if err := starlark.AsInt(address, &pc); err != nil {
		return nil, fmt.Errorf("ppc_instructions: address: %w", err)
	}
	records, err := binaryapi.PowerPCInstructions(view, offset, size, pc, order, maximum)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(encoded)}, nil)
}

func powerPCCensusBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var rangesValue starlark.Value = starlark.None
	order := "big"
	samples := 4
	maximum := int64(1 << 30)
	flow := false
	if err := starlark.UnpackArgs("ppc_census", args, kwargs, "source", &source, "ranges?", &rangesValue, "byte_order?", &order, "samples?", &samples, "maximum?", &maximum, "flow?", &flow); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	var ranges []binaryapi.PowerPCRange
	if rangesValue == starlark.None {
		ranges = []binaryapi.PowerPCRange{{Offset: 0, Size: view.Size() &^ 3}}
	} else {
		iterable, ok := rangesValue.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("ppc_census: ranges must be a sequence of (offset, size)")
		}
		iter := iterable.Iterate()
		defer iter.Done()
		var item starlark.Value
		for iter.Next(&item) {
			pair, ok := item.(starlark.Indexable)
			if !ok || pair.Len() != 2 {
				return nil, fmt.Errorf("ppc_census: ranges must be a sequence of (offset, size)")
			}
			var r binaryapi.PowerPCRange
			if err := starlark.AsInt(pair.Index(0), &r.Offset); err != nil {
				return nil, fmt.Errorf("ppc_census: offset: %w", err)
			}
			if err := starlark.AsInt(pair.Index(1), &r.Size); err != nil {
				return nil, fmt.Errorf("ppc_census: size: %w", err)
			}
			ranges = append(ranges, r)
		}
	}
	census, err := binaryapi.PowerPCCensusRanges(view, ranges, order, samples, maximum, flow)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(census)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(encoded)}, nil)
}

func locateTableBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var list *starlark.List
	high := 0xffffffff
	top := 10
	var wordMask, wordValue starlark.Value = starlark.None, starlark.None
	if err := starlark.UnpackArgs("locate_table", args, kwargs, "source", &source, "addresses", &list, "high?", &high, "top?", &top, "word_mask?", &wordMask, "word_value?", &wordValue); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	addrs := make([]uint64, list.Len())
	for i := range addrs {
		if err := starlark.AsInt(list.Index(i), &addrs[i]); err != nil {
			return nil, fmt.Errorf("locate_table: address %d: %w", i, err)
		}
	}
	var got []binaryapi.TableBase
	if wordMask != starlark.None {
		var mask, value uint32
		if err := starlark.AsInt(wordMask, &mask); err != nil {
			return nil, fmt.Errorf("locate_table: word_mask: %w", err)
		}
		if err := starlark.AsInt(wordValue, &value); err != nil {
			return nil, fmt.Errorf("locate_table: word_value: %w", err)
		}
		got, err = binaryapi.LocateWords(view, addrs, mask, value, top)
	} else {
		got, err = binaryapi.LocateTable(view, addrs, uint32(high), top)
	}
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		return nil, err
	}
	return starlark.Call(thread, starjson.Module.Members["decode"], starlark.Tuple{starlark.String(encoded)}, nil)
}
