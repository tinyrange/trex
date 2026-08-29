package starlarkfrontend

import (
	blockpkg "github.com/tinyrange/trex/block"
	nbdapi "github.com/tinyrange/trex/block/nbd"
	blockstar "github.com/tinyrange/trex/block/star"
	x86api "github.com/tinyrange/trex/emulator/x86"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type File = starfile.File
type fileBlockDevice = blockpkg.FileDevice
type emulatorX86 = x86api.Machine
type runtimeMetrics = lifecycle.Metrics
type runtimeResources = lifecycle.Resources

func installRuntimeResources(thread *starlark.Thread) *runtimeResources {
	return lifecycle.Install(thread)
}

func resourcesForThread(thread *starlark.Thread) (*runtimeResources, error) {
	return lifecycle.ForThread(thread)
}

func blockNamespace() namespace {
	builtins := blockstar.Builtins()
	builtins["nbd"] = starlark.NewBuiltin("nbd", nbdapi.Builtin)
	return namespace{name: "block", attrs: builtins}
}

func newFileBlockDevice(file starfile.File, logicalBlockSize, physicalBlockSize uint32, writable bool) (*fileBlockDevice, error) {
	return blockpkg.NewFileDevice(file, blockpkg.FileDeviceOptions{LogicalBlockSize: logicalBlockSize, PhysicalBlockSize: physicalBlockSize, Writable: writable})
}

func emulatorX86Builtin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return x86api.Builtin(thread, builtin, args, kwargs)
}
