package windows

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("hive", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("regf")) {
			return nil, auto.ErrNoMatch
		}
		hive, err := newRegistryHive(adapter.File(source))
		if err != nil {
			return nil, err
		}
		root, err := hive.lookup("/")
		if err != nil {
			return nil, err
		}
		return hiveAutoView(hive, root, options, nil, 0), nil
	})
}

// Registry browsing expands one key at a time. In particular, identifying a
// hive does not materialize every value or recursively traverse corrupt keys.
func hiveAutoView(hive *registryHive, key hiveKey, options auto.Options, ancestors map[uint32]bool, depth int) auto.View {
	return &auto.FoldedView{View: auto.ViewFunc(func() ([]auto.Entry, error) {
		if depth >= options.MaxDepth {
			return nil, fmt.Errorf("%w: registry key depth", auto.ErrLimit)
		}
		if ancestors[key.cell] {
			return nil, fmt.Errorf("registry key cycle at %#x", key.cell)
		}
		visited := make(map[uint32]bool, len(ancestors)+1)
		for cell := range ancestors {
			visited[cell] = true
		}
		visited[key.cell] = true
		values, err := hive.readValues(key)
		if err != nil {
			return nil, err
		}
		children, err := hive.readSubkeys(key)
		if err != nil {
			return nil, err
		}
		if len(children) > options.MaxEntries {
			return nil, fmt.Errorf("%w: registry children", auto.ErrLimit)
		}
		entries := make([]auto.Entry, 0, len(children)+1)
		if len(values.Items()) != 0 {
			native, err := starlarkNative(values)
			if err != nil {
				return nil, err
			}
			data, err := json.MarshalIndent(native, "", "  ")
			if err != nil {
				return nil, err
			}
			entries = append(entries, auto.Entry{Name: "_values.json", Kind: "file", Reader: bytes.NewReader(append(data, '\n'))})
		}
		for _, child := range children {
			entries = append(entries, auto.Entry{Name: child.name, Kind: "directory", View: hiveAutoView(hive, child, options, visited, depth+1)})
		}
		return entries, nil
	})}
}
