package cc

import (
	"encoding/binary"

	"github.com/tinyrange/trex/block"
)

// newAppleStoragePCI implements Apple's storage-role byte and vendor capability
// over the shared PCI block transport. The caller supplies the role and backing;
// request sectors already include any region offset from the guest device tree.
// An eight-byte zero Apple capability selects unencrypted VirtIO block requests.
func newAppleStoragePCI(configBase uint64, bar uint32, role uint8, store block.Device, memory func(uint64, uint64, bool) ([]byte, error), msi func(uint64, uint32) error) *virtioPCI {
	block := &virtioPCIBlock{disk: store}
	v := newVirtioPCI(virtioPCIOptions{
		ConfigBase: configBase, BAR: bar,
		VendorID: 0x106b, DeviceID: 0x1a00, SubsystemVendorID: 0x106b, SubsystemID: 2,
		Revision: 1, Class: 1, Subclass: 0x80,
		Offered: block.offered,
		DeviceConfig: func() [64]byte {
			c := block.deviceConfig()
			c[0x3c] = role
			return c
		},
		Request: block.request,
	}, memory, msi)
	// VirtIO vendor-data capability: id, next, length, type, vendor, payload.
	v.config[0x85] = 0x90
	copy(v.config[0x90:], []byte{9, 0, 14, 9})
	binary.LittleEndian.PutUint16(v.config[0x94:], 0x106b)
	return v
}
