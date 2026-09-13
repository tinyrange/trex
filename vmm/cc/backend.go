// Package cc implements an in-process PC backend using CrumbleCracker.
package cc

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/vmm/ramfb"
	"runtime"
	"time"

	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

type Backend struct{}

func Available() bool { return runtime.GOOS == "linux" && runtime.GOARCH == "amd64" }
func Capabilities() []string {
	return []string{"disk", "disk.bus.ide", "disk.snapshot", "disk.geometry.chs", "display.capturable", "screenshot", "input.key", "input.pointer", "lifecycle.pause", "lifecycle.stop", "extension.cc.v1"}
}
func (*Backend) ID() string             { return "cc.v1" }
func (*Backend) Capabilities() []string { return Capabilities() }
func (b *Backend) Validate(m vmm.Machine) []vmm.ValidationIssue {
	var issues []vmm.ValidationIssue
	add := func(field, message string) {
		issues = append(issues, vmm.ValidationIssue{Code: "cc.unsupported", Field: field, Message: message, Backend: b.ID()})
	}
	if !Available() {
		add("backend", "cc PC execution requires Linux/amd64 KVM")
	}
	if m.Architecture != "i386" {
		add("architecture", "cc PC supports i386")
	}
	if m.CPUs != 1 {
		add("cpus", "cc PC requires one CPU")
	}
	if m.Memory < 16<<20 || m.Memory > 1<<30 || m.Memory%4096 != 0 {
		add("memory", "memory must be page-aligned and between 16 MiB and 1 GiB")
	}
	if len(m.Disks) != 1 {
		add("disks", "cc PC requires one primary IDE disk")
	}
	for i, d := range m.Disks {
		field := fmt.Sprintf("disks[%d]", i)
		if d.Device == nil {
			add(field, "disk device is required")
			continue
		}
		if d.Bus != "" && d.Bus != "auto" && d.Bus != "ide" || d.Unit != 0 || d.Media != "" && d.Media != "disk" {
			add(field, "disk must be primary IDE master with disk media")
		}
		g := d.Device.Geometry()
		if g.LogicalBlockSize != 512 || g.Size < 512 || g.Size%512 != 0 {
			add(field, "disk requires complete 512-byte sectors")
		}
		if d.CHS != nil {
			c := d.CHS
			if c.Cylinders < 1 || c.Cylinders > 1024 || c.Heads < 1 || c.Heads > 16 || c.Sectors < 1 || c.Sectors > 63 || int64(c.Cylinders*c.Heads*c.Sectors)*512 > g.Size {
				add(field+".chs", "invalid legacy ATA geometry")
			}
		}
		if !d.ReadOnly && !d.Snapshot && !d.Device.Capabilities().Writable {
			add(field, "writable disk or snapshot overlay is required")
		}
	}
	if len(m.Networks) != 0 {
		add("networks", "cc PC has no network device")
	}
	if len(m.Channels) != 0 {
		add("channels", "cc PC has no channel devices")
	}
	if m.Display.Mode != "" && m.Display.Mode != "none" && m.Display.Mode != "capturable" {
		add("display", "cc PC supports headless VGA capture")
	}
	for _, required := range m.RequiredCapabilities {
		found := false
		for _, c := range Capabilities() {
			if c == required {
				found = true
			}
		}
		if !found {
			add("required_capabilities", "unsupported capability "+required)
		}
	}
	return issues
}
func (b *Backend) Start(ctx context.Context, m vmm.Machine) (vmm.Driver, error) {
	if issues := b.Validate(m); len(issues) != 0 {
		return nil, &vmm.Error{Code: vmm.ErrorInvalid, Message: "invalid cc machine", Detail: issues[0].Field + ": " + issues[0].Message}
	}
	disk := m.Disks[0]
	if disk.Snapshot {
		overlay, err := blockstar.NewOverlayDevice(disk.Device, 256<<20, 64<<10)
		if err != nil {
			return nil, err
		}
		disk.Device = overlay
	}
	cpu, err := hypervisor.NewX86(ctx)
	if err != nil {
		return nil, err
	}
	ram, err := cpu.MapRAMRegions(uint64(m.Memory)+ramfb.Size, []hypervisor.RAMRegion{{Address: 0, Offset: 0, Size: 0xa0000}, {Address: 0xc0000, Offset: 0xc0000, Size: uint64(m.Memory) - 0xc0000}, {Address: ramfb.Address, Offset: uint64(m.Memory), Size: ramfb.Size}})
	if err != nil {
		cpu.Close()
		return nil, err
	}
	platform, err := newPC(cpu, ram[:m.Memory], disk, time.Now)
	if err != nil {
		cpu.Close()
		return nil, err
	}
	platform.framebuffer = ram[m.Memory:]
	binary.LittleEndian.PutUint32(platform.framebuffer, ramfb.Magic)
	return newDriver(ctx, platform, m.StartPaused), nil
}
