package r3000

import (
	"fmt"
	"maps"
	"slices"

	blockstar "github.com/tinyrange/trex/block/star"
	starfile "github.com/tinyrange/trex/storage/star"
)

// IP24Checkpoint is an immutable in-memory Indy template. The emulator must
// be paused while taking a checkpoint. Its read-only backing media must remain
// available for the lifetime of the template and every machine it creates.
type IP24Checkpoint struct {
	state    *IP24
	writable [8]bool
}

// Checkpoint captures guest-visible state and freezes every writable disk.
func (m *IP24) Checkpoint() (*IP24Checkpoint, error) {
	if m.closed {
		return nil, fmt.Errorf("ip24: machine closed")
	}
	checkpoint := &IP24Checkpoint{state: m.copyState()}
	for index, disk := range m.targets {
		if disk == nil || !disk.Media().Capabilities().Writable {
			continue
		}
		media := disk.Media()
		source, ok := media.(interface{ Snapshot() (starfile.File, error) })
		if !ok {
			return nil, fmt.Errorf("ip24: SCSI target %d cannot snapshot writable media", index)
		}
		file, err := source.Snapshot()
		if err != nil {
			return nil, fmt.Errorf("ip24: snapshot SCSI target %d: %w", index, err)
		}
		geometry := media.Geometry()
		base, err := blockstar.NewFileBlockDevice(file, blockstar.FileBlockDeviceOptions{
			LogicalBlockSize: geometry.LogicalBlockSize, PhysicalBlockSize: geometry.PhysicalBlockSize,
		})
		if err != nil {
			return nil, err
		}
		checkpoint.state.targets[index], err = disk.CopyWithMedia(base)
		if err != nil {
			return nil, err
		}
		checkpoint.writable[index] = true
	}
	return checkpoint, nil
}

// Restore starts an independent branch of the checkpoint with private RAM,
// device queues, serial channel, and writable disk overlays.
func (c *IP24Checkpoint) Restore() (*IP24, error) {
	m := c.state.copyState()
	restored := false
	defer func() {
		if !restored {
			_ = m.Close()
		}
	}()
	for index, writable := range c.writable {
		if !writable {
			continue
		}
		disk := m.targets[index]
		base := disk.Media()
		size := base.Geometry().Size
		overlay, err := blockstar.NewOverlayDevice(base, size, min(size, blockstar.DefaultOverlayChunk))
		if err != nil {
			return nil, err
		}
		m.targets[index], err = disk.CopyWithMedia(overlay)
		if err != nil {
			return nil, err
		}
	}
	restored = true
	return m, nil
}

func (m *IP24) copyState() *IP24 {
	copy := *m
	copy.ram = slices.Clone(m.ram)
	// PROM is immutable after construction.
	copy.arcs.env = maps.Clone(m.arcs.env)
	copy.breaks = maps.Clone(m.breaks)
	copy.scsi.data = slices.Clone(m.scsi.data)
	copy.scsi.pio = slices.Clone(m.scsi.pio)
	copy.scsi.writeCDB = slices.Clone(m.scsi.writeCDB)
	copy.scsi.writeData = slices.Clone(m.scsi.writeData)
	copy.console, copy.scc.ports[ip24SerialPort].stream = m.console.Fork()
	if m.newport != nil {
		screen := *m.newport
		screen.rgb, screen.aux = slices.Clone(screen.rgb), slices.Clone(screen.aux)
		copy.newport = &screen
	}
	for i, disk := range m.targets {
		if disk != nil {
			clone := *disk
			copy.targets[i] = &clone
		}
	}
	return &copy
}
