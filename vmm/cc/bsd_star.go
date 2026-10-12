package cc

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"j5.nz/cc/kernelvm"
)

type bsdDisk struct{ *blockstar.OverlayDevice }

func (d bsdDisk) Size() int64 { return d.Geometry().Size }

func bsdBootBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kernelValue starlark.Value
	var opts kernelvm.BSDOptions
	var rootOverlay *blockstar.OverlayDevice
	rootValue, console := starlark.Value(starlark.None), starlark.Value(starlark.None)
	timeout, dirty := 60.0, int64(64<<20)
	opts.MemoryMB = 1024
	if err := starlark.UnpackArgs("cc.boot_bsd", args, kwargs, "os", &opts.OS, "kernel", &kernelValue, "marker", &opts.Marker, "root?", &rootValue, "memory_mb?", &opts.MemoryMB, "timeout?", &timeout, "console?", &console, "overlay_limit?", &dirty); err != nil {
		return nil, err
	}
	kernel, ok := kernelValue.(storage.Reader)
	if !ok || kernel.Size() <= 0 || kernel.Size() > 256<<20 {
		return nil, fmt.Errorf("cc.boot_bsd: expected kernel file up to 256 MiB")
	}
	if !(timeout > 0 && timeout <= 600) || dirty <= 0 {
		return nil, fmt.Errorf("cc.boot_bsd: timeout must be 0..600 seconds and overlay_limit positive")
	}
	if rootValue != starlark.None {
		root, ok := rootValue.(storage.Reader)
		if !ok {
			return nil, fmt.Errorf("cc.boot_bsd: root must be a file")
		}
		device, err := block.NewFileDevice(root, block.FileDeviceOptions{})
		if err != nil {
			return nil, err
		}
		overlay, err := blockstar.NewOverlayDevice(device, dirty, blockstar.DefaultOverlayChunk)
		if err != nil {
			return nil, err
		}
		rootOverlay = overlay
		opts.Root = bsdDisk{overlay}
	}
	if console != starlark.None {
		iterable := starlark.Iterate(console)
		if iterable == nil {
			return nil, fmt.Errorf("cc.boot_bsd: console must be iterable of (wait, send) pairs")
		}
		defer iterable.Done()
		var value starlark.Value
		for iterable.Next(&value) {
			pair, ok := value.(starlark.Tuple)
			if !ok || len(pair) != 2 || len(opts.Console) >= 64 {
				return nil, fmt.Errorf("cc.boot_bsd: expected at most 64 console pairs")
			}
			wait, a := starlark.AsString(pair[0])
			send, b := starlark.AsString(pair[1])
			if !a || !b {
				return nil, fmt.Errorf("cc.boot_bsd: console pair must contain strings")
			}
			opts.Console = append(opts.Console, kernelvm.ConsoleStep{Wait: wait, Send: send})
		}
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(resources.Context(), time.Duration(timeout*float64(time.Second)))
	defer cancel()
	data := make([]byte, kernel.Size())
	if _, err := io.ReadFull(io.NewSectionReader(kernel, 0, kernel.Size()), data); err != nil {
		return nil, err
	}
	serial, bootErr := kernelvm.RunBSD(ctx, data, opts)
	detail := ""
	if bootErr != nil {
		detail = bootErr.Error()
	}
	var rootAfter starlark.Value = starlark.None
	if rootOverlay != nil {
		snapshot, err := rootOverlay.Snapshot()
		if err != nil {
			return nil, err
		}
		rootAfter = snapshot
	}
	return starfile.NewRecord(starlark.StringDict{"root": rootAfter, "success": starlark.Bool(bootErr == nil), "serial": starlark.String(serial), "error": starlark.String(detail)}), nil
}
