package star

import (
	"github.com/tinyrange/trex/vmm/ethernet"
	"go.starlark.net/starlark"
)

const internetFactoryKey = "trex.vmm.internetFactory"

// InternetFactory is an embedding-provided capability, not a script-settable flag.
type InternetFactory func(guest [6]byte) (*ethernet.Switch, error)

func SetInternetFactory(thread *starlark.Thread, factory InternetFactory) {
	thread.SetLocal(internetFactoryKey, factory)
}
