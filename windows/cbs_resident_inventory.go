package windows

import (
	"context"
	"fmt"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

type cbsResidentInventoryValue struct {
	inventory *uup.CBSResidentInventory
}

func (v *cbsResidentInventoryValue) String() string       { return "<CBS resident inventory>" }
func (v *cbsResidentInventoryValue) Type() string         { return "cbs_resident_inventory" }
func (v *cbsResidentInventoryValue) Freeze()              {}
func (v *cbsResidentInventoryValue) Truth() starlark.Bool { return starlark.True }
func (v *cbsResidentInventoryValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: cbs_resident_inventory")
}

func cbsResidentInventoryBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("cbs_resident_inventory", args, kwargs, "components", &value); err != nil {
		return nil, err
	}
	hive, ok := value.(*registryHive)
	if !ok {
		return nil, fmt.Errorf("cbs_resident_inventory requires a COMPONENTS hive snapshot")
	}
	reader, err := hive.portableReader()
	if err != nil {
		return nil, err
	}
	if !reader.IsSnapshot() {
		return nil, fmt.Errorf("cbs_resident_inventory requires an immutable COMPONENTS hive")
	}
	ctx := context.Background()
	var cache storage.DerivedCache
	if resources, err := lifecycle.ForThread(thread); err == nil {
		ctx, cache = resources.Context(), resources.Derived
	}
	inventory, err := uup.ReadCBSResidentInventory(ctx, reader, cache)
	if err != nil {
		return nil, err
	}
	return &cbsResidentInventoryValue{inventory: inventory}, nil
}
