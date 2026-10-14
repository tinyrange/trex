package cc

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/boot/darwin"
	"github.com/tinyrange/trex/storage"
)

type testUtilityStore struct{ *storage.MemoryStore }

func (*testUtilityStore) Geometry() block.Geometry {
	return block.Geometry{Size: 32 << 20, LogicalBlockSize: 512, PhysicalBlockSize: 512}
}
func (*testUtilityStore) Capabilities() block.Capabilities { return block.Capabilities{Writable: true} }

type testUtility struct {
	store    *testUtilityStore
	complete bool
	device   *appleSimpleStorage
}

func (u *testUtility) init() error {
	u.store = &testUtilityStore{storage.NewMemoryStore(32 << 20)}
	if e := u.store.Truncate(32 << 20); e != nil {
		return e
	}
	b, e := darwin.EmptyARM64NVRAM(8192)
	if e != nil {
		return e
	}
	_, e = u.store.WriteAt(b, 0xa00000)
	return e
}

type protocolTestBus struct {
	*appleSimpleUSB
	ram        []byte
	ramBase    uint64
	disk       block.Device
	util       testUtility
	ctrr       virtualCTRR
	pciUtil    *virtioPCI
	completion bool
	storage    *appleSimpleStorage
}

func newProtocolTestBus(emit func(string, any)) *protocolTestBus {
	d := &protocolTestBus{}
	d.appleSimpleUSB = &appleSimpleUSB{address: 0x30100000, emit: emit, appleQueue: appleQueue{dmaMemory: d.dmaMemory}}
	binary.LittleEndian.PutUint32(d.usbTransport[:], 1)
	binary.LittleEndian.PutUint32(d.usbTransport[4:], 0x1a01)
	binary.LittleEndian.PutUint64(d.usbTransport[8:], 4096)
	d.storage = &appleSimpleStorage{address: 0x30000000, appleQueue: appleQueue{dmaMemory: d.dmaMemory}}
	binary.LittleEndian.PutUint32(d.storage.transport[:], 1)
	return d
}
func (d *protocolTestBus) memory(a, n uint64) ([]byte, error) {
	if a < d.ramBase || a-d.ramBase > uint64(len(d.ram)) || n > uint64(len(d.ram))-(a-d.ramBase) {
		return nil, fmt.Errorf("outside test RAM")
	}
	return d.ram[a-d.ramBase : a-d.ramBase+n], nil
}
func (d *protocolTestBus) dmaMemory(a, n uint64, w bool) ([]byte, error) {
	if w && !d.ctrr.writable(a, n) {
		return nil, fmt.Errorf("test DMA protected")
	}
	return d.memory(a, n)
}
func (d *protocolTestBus) utility() *appleSimpleStorage {
	if d.util.device == nil {
		d.util.device = &appleSimpleStorage{address: 0x30010000, disk: d.util.store, appleQueue: appleQueue{dmaMemory: d.dmaMemory}}
		binary.LittleEndian.PutUint32(d.util.device.transport[:], 1)
	}
	return d.util.device
}
func (d *protocolTestBus) Read(a uint64, n int) (uint64, error) {
	if d.pciUtil != nil && d.pciUtil.contains(a, n) {
		return d.pciUtil.read(a, n)
	}
	if d.util.store != nil && a >= 0x30010000 && a < 0x30012000 {
		return d.utility().Read(a, n)
	}
	if d.storage.Contains(a, n) {
		d.storage.disk = d.disk
		return d.storage.Read(a, n)
	}
	return d.appleSimpleUSB.Read(a, n)
}
func (d *protocolTestBus) Write(a uint64, n int, v uint64) error {
	if d.pciUtil != nil && d.pciUtil.contains(a, n) {
		return d.pciUtil.write(a, n, v)
	}
	if d.util.store != nil && a >= 0x30010000 && a < 0x30012000 {
		e := d.utility().Write(a, n, v)
		d.util.complete = d.utility().complete
		return e
	}
	if d.storage.Contains(a, n) {
		d.storage.disk = d.disk
		e := d.storage.Write(a, n, v)
		d.completion = d.storage.complete
		return e
	}
	return d.appleSimpleUSB.Write(a, n, v)
}
