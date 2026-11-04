package native

import (
	"context"
	"fmt"
	"sync"

	"github.com/tinyrange/trex/lifecycle"
	windowsupdate "github.com/tinyrange/trex/windows/update"
	"go.starlark.net/starlark"
)

// A request starts exactly one synchronization. Only native, owned profile data
// crosses the goroutine boundary; no Starlark callbacks or caller dictionaries
// are evaluated there. Completion is published by closing done.
type catalogRequest struct {
	cancel       context.CancelFunc
	done         chan struct{}
	catalog      *windowsupdate.Catalog
	err          error
	options      windowsupdate.ScanOptions
	protocol     windowsupdate.ClientProtocol
	once         sync.Once
	value        *catalogValue
	allowNetwork bool
}

func startCatalogRequest(resources *lifecycle.Resources, options windowsupdate.ScanOptions, protocol windowsupdate.ClientProtocol) (*catalogRequest, error) {
	return newCatalogRequest(resources, options, protocol, func(ctx context.Context) (*windowsupdate.Catalog, error) {
		return protocol.SyncCatalog(ctx, options)
	})
}

func newCatalogRequest(resources *lifecycle.Resources, options windowsupdate.ScanOptions, protocol windowsupdate.ClientProtocol, scan func(context.Context) (*windowsupdate.Catalog, error)) (*catalogRequest, error) {
	ctx, cancel := context.WithCancel(resources.Context())
	request := &catalogRequest{cancel: cancel, done: make(chan struct{}), options: options, protocol: protocol}
	// Register before launching so a closed execution cannot leak a scan.
	if _, err := resources.Add(request); err != nil {
		cancel()
		return nil, err
	}
	go func() {
		defer close(request.done)
		request.catalog, request.err = scan(ctx)
	}()
	return request, nil
}

func (*catalogRequest) String() string       { return "<windows_update_catalog_request>" }
func (*catalogRequest) Type() string         { return "windows_update_catalog_request" }
func (*catalogRequest) Freeze()              {}
func (*catalogRequest) Truth() starlark.Bool { return starlark.True }
func (*catalogRequest) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: windows_update_catalog_request")
}
func (*catalogRequest) AttrNames() []string { return []string{"close", "result"} }
func (r *catalogRequest) Attr(name string) (starlark.Value, error) {
	switch name {
	case "result":
		return starlark.NewBuiltin("update_catalog_request.result", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("update_catalog_request.result", args, kwargs); err != nil {
				return nil, err
			}
			return r.result()
		}), nil
	case "close":
		return starlark.NewBuiltin("update_catalog_request.close", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("update_catalog_request.close", args, kwargs); err != nil {
				return nil, err
			}
			return starlark.None, r.Close()
		}), nil
	}
	return nil, nil
}
func (r *catalogRequest) result() (*catalogValue, error) {
	<-r.done
	if r.err != nil {
		return nil, fmt.Errorf("update_catalog: %w", r.err)
	}
	r.once.Do(func() {
		r.value = newCatalogValue(r.catalog, r.options, r.protocol)
		r.value.allowNetwork = r.allowNetwork
	})
	return r.value, nil
}

// Close cancels an unfinished request and joins its worker. Completed results
// stay readable, and neither result nor close ever repeats a synchronization.
func (r *catalogRequest) Close() error {
	r.cancel()
	<-r.done
	return nil
}
