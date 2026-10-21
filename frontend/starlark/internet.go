package starlarkfrontend

import (
	"github.com/tinyrange/trex/vmm/ethernet"
	ethernetnative "github.com/tinyrange/trex/vmm/ethernet/native"
	vmmstar "github.com/tinyrange/trex/vmm/star"
	"go.starlark.net/starlark"
)

func installInternet(thread *starlark.Thread, allowed bool) {
	if !allowed {
		return
	}
	vmmstar.SetInternetFactory(thread, func(guest [6]byte) (*ethernet.Switch, error) {
		resources, err := resourcesForThread(thread)
		if err != nil {
			return nil, err
		}
		host := guest
		host[5] ^= 0xff
		g, err := ethernetnative.NewGateway(resources.Context(), guest, host, true)
		if err != nil {
			return nil, err
		}
		if _, err := resources.Add(g); err != nil {
			g.Close()
			return nil, err
		}
		return g.Switch, nil
	})
}
