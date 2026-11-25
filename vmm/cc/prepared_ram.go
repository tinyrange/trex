package cc

import (
	"context"
	"fmt"
	"runtime"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
)

type preparedRAM interface {
	storage.Reader
	lifecycle.Resource
	mapPrivate([]byte) error
	rewindTemplate() []byte
	newDirectCPU(context.Context) (hypervisor.X86, error)
}

type preparedRAMValue struct {
	preparedRAM
	runSlots      chan struct{}
	sharedWorkers bool
}

func (*preparedRAMValue) String() string        { return "<cc.prepared_ram>" }
func (*preparedRAMValue) Type() string          { return "cc.prepared_ram" }
func (*preparedRAMValue) Freeze()               {}
func (*preparedRAMValue) Truth() starlark.Bool  { return starlark.True }
func (*preparedRAMValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: cc.prepared_ram") }

func prepareRAMBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var sharedWorkers bool
	if err := starlark.UnpackArgs("cc.prepare_ram", args, kwargs, "ram", &value, "shared_workers?", &sharedWorkers); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || source.Size() <= 0 || source.Size() > 3<<30 || source.Size()%4096 != 0 {
		return nil, fmt.Errorf("cc.prepare_ram: expected a page-aligned RAM image up to 3 GiB")
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	ram, err := prepareRAM(source, sharedWorkers)
	if err != nil {
		return nil, err
	}
	if _, err := resources.Add(ram); err != nil {
		_ = ram.Close()
		return nil, err
	}
	return &preparedRAMValue{preparedRAM: ram, runSlots: make(chan struct{}, runtime.GOMAXPROCS(0)), sharedWorkers: sharedWorkers}, nil
}
