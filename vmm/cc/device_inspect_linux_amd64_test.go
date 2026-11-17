//go:build linux && amd64

package cc

import (
	"github.com/tinyrange/trex/emulator/s390"
	"github.com/tinyrange/trex/vmm/device"
	"go.starlark.net/starlark"
	"testing"
	"time"
)

func TestAttachedDeviceInspectionUsesNamedOwnerPath(t *testing.T) {
	d, i := debugFixture(t, []byte{0xeb, 0xfe}, false)
	err := d.call(i.ctx, func() error {
		p := d.pc
		p.devices.Reserved = p.deviceReservations
		p.devices.SetIRQ = p.setDeviceIRQ
		if err := p.devices.Attach([]device.Spec{s390.P390Device("renamed", 7<<3, false, time.Time{})}, device.Profile{Architecture: "i386", CPUs: 1}, reservedPCISlots()); err != nil {
			return err
		}
		_, err := p.devices.Transfer(device.Memory, 0xd0200000, 2, 1, true, []byte{0x12, 0x34}, nil)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	extension, err := d.Extension(i.ctx, "cc.v1")
	if err != nil {
		t.Fatal(err)
	}
	read, err := extension.(starlark.HasAttrs).Attr("device_read")
	if err != nil || read == nil {
		t.Fatal("generic inspection not exported", err)
	}
	call := func(name, space string, address, size int) (starlark.Value, error) {
		return starlark.Call(&starlark.Thread{Name: "device-inspect"}, read, starlark.Tuple{starlark.String(name), starlark.String(space), starlark.MakeInt(address), starlark.MakeInt(size)}, nil)
	}
	got, err := call("renamed", "aperture", 0x200000, 2)
	if err != nil || got != starlark.Bytes("\x12\x34") {
		t.Fatal("named observation", got, err)
	}
	physical, err := i.readPhysical(nil, nil, starlark.Tuple{starlark.MakeInt64(0xd0200000), starlark.MakeInt(2)}, nil)
	if err != nil || physical != got {
		t.Fatal("physical BAR observation", physical, err)
	}
	for _, tc := range []struct {
		name, space   string
		address, size int
	}{
		{"missing", "aperture", 0, 1}, {"renamed", "unknown", 0, 1}, {"renamed", "main", 0, -1}, {"renamed", "main", 0, 65537}, {"renamed", "aperture", 0x3fffff, 2},
	} {
		if _, err := call(tc.name, tc.space, tc.address, tc.size); err == nil {
			t.Fatal("invalid observation accepted", tc)
		}
	}
	if _, err := i.readMainframe(nil, nil, starlark.Tuple{starlark.MakeInt(0), starlark.MakeInt(1)}, nil); err == nil {
		t.Fatal("legacy alias ignored explicit name")
	}
	if err := d.Close(i.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := call("renamed", "main", 0, 1); err == nil {
		t.Fatal("inspection after teardown accepted")
	}
}
