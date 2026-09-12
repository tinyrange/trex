package installshield

import (
	"bytes"
	"errors"
	"fmt"
	"go.starlark.net/starlark"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

func init() {
	auto.Register("installer", 20, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("MZ")) || source.Size() < cabinetHeaderSize+2 {
			return nil, auto.ErrNoMatch
		}
		// Use the same recognizers as archive.installer: embedded Cabinets, nested
		// InstallShield packages, InstallShield SFX envelopes and Wise overlays.
		installer, err := OpenInstaller(adapter.File(source), min(installerDefaultMaximumScan, options.MaxExpandedBytes), true, bytecache.New(bytecache.DefaultBytes), 1)
		if errors.Is(err, ErrNoPayload) {
			return nil, auto.ErrNoMatch
		}
		if err != nil {
			return nil, err
		}
		names, err := installer.payload.Attr("files")
		if err != nil {
			return nil, err
		}
		var entries []auto.Entry
		iter := names.(starlark.Iterable).Iterate()
		defer iter.Done()
		var item starlark.Value
		for iter.Next(&item) {
			name, ok := starlark.AsString(item)
			if !ok {
				return nil, fmt.Errorf("installer: invalid member name")
			}
			value, found, err := installer.payload.Get(item)
			if err != nil {
				return nil, err
			}
			reader, ok := value.(storage.Reader)
			if !found || !ok {
				return nil, fmt.Errorf("installer: missing readable member %q", name)
			}
			entries = append(entries, auto.Entry{Name: name, Kind: "file", Reader: reader})
			if len(entries) > options.MaxEntries {
				return nil, auto.ErrLimit
			}
		}
		view, err := auto.Tree(entries, options)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: view, Format: installer.format, Attributes: map[string]any{"payload_offset": installer.offset, "payload_size": installer.size}}, nil
	})
}
