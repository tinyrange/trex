package installshield

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("installer", 20, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("MZ")) || source.Size() < cabinetHeaderSize+2 {
			return nil, auto.ErrNoMatch
		}
		// Use the same recognizers as archive.installer: embedded Cabinets, nested
		// InstallShield packages, SFX envelopes, Wise overlays and NSIS containers.
		installer, err := openInstaller(adapter.File(source), min(installerDefaultMaximumScan, options.MaxExpandedBytes), true, bytecache.New(bytecache.DefaultBytes), 1, options.MaxExpandedBytes)
		if errors.Is(err, ErrNoPayload) {
			return nil, auto.ErrNoMatch
		}
		if err != nil {
			return nil, err
		}
		return installerAutoView(installer, options)
	})
}

func installerAutoView(installer *Installer, options auto.Options) (auto.View, error) {
	type payloadRoot struct {
		root    string
		payload installerPayload
	}
	payloads := []payloadRoot{{payload: installer.payload}}
	if len(installer.packages) > 1 {
		payloads = nil
		for _, pkg := range installer.packages {
			payloads = append(payloads, payloadRoot{root: strings.Trim(pkg.root, "/"), payload: pkg.payload})
		}
	}
	var entries []auto.Entry
	for _, pkg := range payloads {
		names, err := pkg.payload.Attr("files")
		if err != nil {
			return nil, err
		}
		iter := names.(starlark.Iterable).Iterate()
		defer iter.Done()
		var item starlark.Value
		for iter.Next(&item) {
			name, ok := starlark.AsString(item)
			if !ok {
				return nil, fmt.Errorf("installer: invalid member name")
			}
			value, found, err := pkg.payload.Get(item)
			if err != nil {
				return nil, err
			}
			reader, ok := value.(storage.Reader)
			if !found || !ok {
				return nil, fmt.Errorf("installer: missing readable member %q", name)
			}
			if pkg.root != "" {
				name = pkg.root + "/" + strings.TrimPrefix(name, "/")
			}
			entries = append(entries, auto.Entry{Name: name, Kind: "file", Reader: reader})
			if len(entries) > options.MaxEntries {
				return nil, auto.ErrLimit
			}
		}
	}
	view, err := auto.Tree(entries, options)
	if err != nil {
		return nil, err
	}
	return &auto.DescribedView{View: view, Format: installer.format, Attributes: map[string]any{"payload_offset": installer.offset, "payload_size": installer.size}}, nil
}
