package qemu

import (
	"context"
	"fmt"
	blockpkg "github.com/tinyrange/trex/block"
	vmmapi "github.com/tinyrange/trex/vmm"
)

func removableBus(disk vmmapi.Disk) string {
	bus := disk.Bus
	if bus == "auto" {
		if disk.Media == "floppy" {
			bus = "floppy"
		} else {
			bus = "ide"
		}
	}
	if bus == "floppy" && disk.Media == "floppy" || bus == "ide" && disk.Media == "cdrom" {
		return bus
	}
	return ""
}

func mediaTarget(machine vmmapi.Machine, name string, source blockpkg.Device) (int, error) {
	for i, disk := range machine.Disks {
		if disk.Name != name {
			continue
		}
		if removableBus(disk) == "" || !disk.ReadOnly || disk.Snapshot {
			return 0, fmt.Errorf("replace_media: %q must be a read-only, non-snapshot floppy or IDE CD-ROM", name)
		}
		if source == nil {
			return 0, fmt.Errorf("replace_media: nil source")
		}
		geometry := source.Geometry()
		if geometry.Size <= 0 || geometry.LogicalBlockSize != disk.Device.Geometry().LogicalBlockSize {
			return 0, fmt.Errorf("replace_media: incompatible replacement geometry")
		}
		if disk.Media == "floppy" && geometry.Size != disk.Device.Geometry().Size {
			return 0, fmt.Errorf("replace_media: floppy replacement must preserve media size")
		}
		return i, nil
	}
	return 0, fmt.Errorf("replace_media: unknown disk %q", name)
}

// ReplaceMedia serves the actual supplied source through an owned native NBD
// export. It neither reads the entire source nor reopens its host pathname.
func (d *qemuDriver) ReplaceMedia(ctx context.Context, name string, source blockpkg.Device) error {
	index, err := mediaTarget(d.machine, name, source)
	if err != nil {
		return err
	}
	d.mediaMu.Lock()
	defer d.mediaMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.ctx.Err(); err != nil {
		return err
	}
	exportName, err := qemuExportName(index)
	if err != nil {
		return err
	}
	export, port, err := newQEMUNBDExport(d.ctx, source, exportName)
	if err != nil {
		return err
	}
	d.exportMu.Lock()
	if d.exportsClosed || d.ctx.Err() != nil {
		d.exportMu.Unlock()
		export.Close()
		<-export.done
		return fmt.Errorf("replace_media: VM transports are closed")
	}
	d.exports = append(d.exports, export)
	d.exportMu.Unlock()
	// Keep the export even on error: a lost reply does not establish that QEMU
	// rejected the change. Closing it could break an already-inserted medium.
	_, err = d.qmp.Call(ctx, "blockdev-change-medium", map[string]any{
		"id":       fmt.Sprintf("trx-media-%d", index),
		"filename": fmt.Sprintf("nbd://127.0.0.1:%s/%s", port, exportName),
		"format":   "raw", "read-only-mode": "read-only",
	})
	return err
}

func (d *qemuDriver) exportSnapshot(closing bool) []*qemuNBDExport {
	d.exportMu.Lock()
	defer d.exportMu.Unlock()
	if closing {
		d.exportsClosed = true
	}
	return append([]*qemuNBDExport(nil), d.exports...)
}
