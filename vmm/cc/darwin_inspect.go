package cc

import (
	"fmt"
	"github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
	"sort"
	"strings"
)

func (i inspection) symbol(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("cc.symbol", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	var address uint64
	err := i.driver.call(i.ctx, func() error {
		var ok bool
		address, ok = i.driver.pc.darwinSymbols[name]
		if !ok {
			return fmt.Errorf("cc: kernel symbol %q not found", name)
		}
		return nil
	})
	return starlark.MakeUint64(address), err
}

// symbols lists a bounded selection of original kernel symbols for observations.
func (i inspection) symbols(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var prefix string
	if err := starlark.UnpackArgs("cc.symbols", args, kwargs, "prefix", &prefix); err != nil {
		return nil, err
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() error {
		names := []string{}
		for n := range i.driver.pc.darwinSymbols {
			if strings.HasPrefix(n, prefix) {
				names = append(names, n)
			}
		}
		if len(names) > 128 {
			return fmt.Errorf("cc: more than 128 symbols; narrow prefix")
		}
		sort.Strings(names)
		out := starlark.NewDict(len(names))
		for _, n := range names {
			if err := out.SetKey(starlark.String(n), starlark.MakeUint64(i.driver.pc.darwinSymbols[n])); err != nil {
				return err
			}
		}
		result = out
		return nil
	})
	return result, err
}
func (i inspection) symbolize(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	if err := starlark.UnpackArgs("cc.symbolize", args, kwargs, "address", &address); err != nil {
		return nil, err
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() error {
		var best uint64
		var name string
		for n, a := range i.driver.pc.darwinSymbols {
			if a <= address && (a > best || a == best && n < name) {
				best, name = a, n
			}
		}
		if name == "" {
			result = starlark.None
			return nil
		}
		var err error
		result = value.NewRecord(starlark.StringDict{"symbol": starlark.String(name), "offset": starlark.MakeUint64(address - best)})
		return err
	})
	return result, err
}
func (i inspection) readVirtual(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var size int
	var pageTable uint64
	if err := starlark.UnpackArgs("cc.read_virtual", args, kwargs, "address", &address, "size", &size, "page_table?", &pageTable); err != nil {
		return nil, err
	}
	if size < 0 || size > 65536 || uint64(size) > ^uint64(0)-address {
		return nil, fmt.Errorf("cc: read_virtual size must be 0..65536")
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() error {
		b, err := i.driver.pc.readVirtualBytes(address, size, pageTable)
		if err != nil {
			return err
		}
		result = starlark.Bytes(string(b))
		return nil
	})
	return result, err
}
