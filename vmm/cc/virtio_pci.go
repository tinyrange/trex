package cc

import (
	"encoding/binary"
	"fmt"
)

type virtioPCIOptions struct {
	ConfigBase                                         uint64
	BAR                                                uint32
	VendorID, DeviceID, SubsystemVendorID, SubsystemID uint16
	Revision, Class, Subclass                          byte
	Offered                                            func(uint32) uint32
	DeviceConfig                                       func() [64]byte
	DeviceWrite                                        func(offset uint64, size int, value uint64) error
	Request                                            func([]virtioBuffer) (uint32, error)
	QueueCount                                         uint16
	QueueRequest                                       func(uint16, []virtioBuffer) (uint32, bool, error)
	Reset                                              func()
}

// virtioPCI implements modern PCI transport and bounded split queues.
// The transport is described by OASIS VirtIO 1.2 section 4.1.
// Each queue and configuration changes have independent MSI-X vectors. DMA stays in guest RAM and
// passes the board's memory protection checks. It shares no firmware queues.
type virtioPCI struct {
	options     virtioPCIOptions
	memory      func(uint64, uint64, bool) ([]byte, error)
	msi         func(uint64, uint32) error
	config      [4096]byte
	bar         uint32
	probe       bool
	common      [56]byte
	features    [2]uint32
	queues      []inputQueue
	queueConfig [][32]byte
	table       [48]byte
	pending     uint64
	isr         byte
}

func newVirtioPCI(options virtioPCIOptions, memory func(uint64, uint64, bool) ([]byte, error), msi func(uint64, uint32) error) *virtioPCI {
	if options.QueueCount == 0 {
		options.QueueCount = 1
	}
	if options.QueueCount > 2 {
		panic("virtio PCI: unsupported queue count")
	}
	v := &virtioPCI{options: options, memory: memory, msi: msi, bar: options.BAR}
	c := v.config[:]
	binary.LittleEndian.PutUint16(c, options.VendorID)
	binary.LittleEndian.PutUint16(c[2:], options.DeviceID)
	c[6], c[8], c[10], c[11], c[0x34] = 0x10, options.Revision, options.Subclass, options.Class, 0x40
	binary.LittleEndian.PutUint16(c[0x2c:], options.SubsystemVendorID)
	binary.LittleEndian.PutUint16(c[0x2e:], options.SubsystemID)
	capability := func(at, next, kind byte, offset, length uint32) {
		c[at], c[at+1], c[at+2], c[at+3] = 9, next, 16, kind
		binary.LittleEndian.PutUint32(c[int(at)+8:], offset)
		binary.LittleEndian.PutUint32(c[int(at)+12:], length)
	}
	capability(0x40, 0x50, 1, 0, 56)
	capability(0x50, 0x64, 2, 0x1000, 4)
	c[0x52] = 20
	binary.LittleEndian.PutUint32(c[0x60:], 4)
	capability(0x64, 0x74, 3, 0x2000, 1)
	capability(0x74, 0x84, 4, 0x2100, 64)
	c[0x84] = 0x11
	binary.LittleEndian.PutUint16(c[0x86:], options.QueueCount) // queues plus configuration, encoded minus one
	binary.LittleEndian.PutUint32(c[0x88:], 0x3000)
	binary.LittleEndian.PutUint32(c[0x8c:], 0x3800)
	v.reset()
	return v
}
func (v *virtioPCI) reset() {
	v.common = [56]byte{}
	v.features = [2]uint32{}
	v.queues = make([]inputQueue, v.options.QueueCount)
	v.queueConfig = make([][32]byte, v.options.QueueCount)
	v.isr, v.pending = 0, 0
	binary.LittleEndian.PutUint16(v.common[16:], 0xffff)
	binary.LittleEndian.PutUint16(v.common[18:], v.options.QueueCount)
	for i := range v.queueConfig {
		binary.LittleEndian.PutUint16(v.queueConfig[i][:], 128)
		binary.LittleEndian.PutUint16(v.queueConfig[i][2:], 0xffff)
	}
	if v.options.Reset != nil {
		v.options.Reset()
	}
}
func (v *virtioPCI) offered(selectID uint32) uint32 {
	if v.options.Offered != nil {
		return v.options.Offered(selectID)
	}
	if selectID == 1 {
		return 1
	} // VIRTIO_F_VERSION_1
	return 0
}
func (v *virtioPCI) configContains(a uint64, n int) bool {
	return (n == 1 || n == 2 || n == 4) && a%uint64(n) == 0 && a >= v.options.ConfigBase && a-v.options.ConfigBase <= 4096-uint64(n)
}
func (v *virtioPCI) contains(a uint64, n int) bool {
	return v.configContains(a, n) || (n == 1 || n == 2 || n == 4 || n == 8) && a%uint64(n) == 0 && v.config[4]&2 != 0 && a >= uint64(v.bar) && a-uint64(v.bar) <= 0x10000-uint64(n)
}
func loadLE(p []byte, n int) uint64 {
	var x uint64
	for i := 0; i < n; i++ {
		x |= uint64(p[i]) << uint(i*8)
	}
	return x
}
func storeLE(p []byte, n int, x uint64) {
	for i := 0; i < n; i++ {
		p[i] = byte(x >> uint(i*8))
	}
}
func (v *virtioPCI) read(a uint64, n int) (uint64, error) {
	if !v.contains(a, n) {
		return 0, fmt.Errorf("virtio PCI: invalid read%d at %#x", n, a)
	}
	if v.configContains(a, n) {
		o := a - v.options.ConfigBase
		if o >= 0x10 && o+uint64(n) <= 0x14 {
			b := v.bar
			if v.probe {
				b = 0xffff0000
			}
			return uint64(b) >> ((o - 0x10) * 8) & (uint64(1)<<(n*8) - 1), nil
		}
		return loadLE(v.config[o:], n), nil
	}
	o := a - uint64(v.bar)
	switch {
	case o+uint64(n) <= 56:
		c := v.common
		binary.LittleEndian.PutUint32(c[4:], v.offered(binary.LittleEndian.Uint32(c[:])))
		selector := binary.LittleEndian.Uint32(c[8:])
		if selector < 2 {
			binary.LittleEndian.PutUint32(c[12:], v.features[selector])
		} else {
			clear(c[12:16])
		}
		queue := binary.LittleEndian.Uint16(c[22:])
		if queue < v.options.QueueCount {
			copy(c[24:], v.queueConfig[queue][:])
		} else {
			clear(c[24:])
			binary.LittleEndian.PutUint16(c[26:], 0xffff)
		}
		return loadLE(c[o:], n), nil
	case o == 0x2000 && n == 1:
		x := v.isr
		v.isr = 0
		return uint64(x), nil
	case o >= 0x2100 && o+uint64(n) <= 0x2140:
		var c [64]byte
		if v.options.DeviceConfig != nil {
			c = v.options.DeviceConfig()
		}
		return loadLE(c[o-0x2100:], n), nil
	case o >= 0x3000 && o+uint64(n) <= 0x3000+uint64(v.options.QueueCount+1)*16:
		return loadLE(v.table[o-0x3000:], n), nil
	case o >= 0x3800 && o+uint64(n) <= 0x3808:
		return v.pending >> ((o - 0x3800) * 8) & (uint64(1)<<(n*8) - 1), nil
	}
	return 0, fmt.Errorf("virtio PCI: unsupported read%d offset %#x", n, o)
}
func (v *virtioPCI) write(a uint64, n int, x uint64) error {
	if !v.contains(a, n) {
		return fmt.Errorf("virtio PCI: invalid write%d at %#x", n, a)
	}
	if v.configContains(a, n) {
		o := int(a - v.options.ConfigBase)
		if o == 0x10 && n == 4 {
			v.probe = x == 0xffffffff
			if !v.probe {
				v.bar = uint32(x) & 0xffff0000
			}
			return nil
		}
		for i := 0; i < n; i++ {
			at := o + i
			b := byte(x >> uint(8*i))
			switch at {
			case 4:
				v.config[at] = b & 6
			case 5:
				v.config[at] = b & 4
			case 0xc, 0xd:
				v.config[at] = b
			case 0x87:
				v.config[at] = b & 0xc0
			}
		}
		return v.deliverPending()
	}
	o := a - uint64(v.bar)
	// A device without a write hook has read-only device configuration.
	if o >= 0x2100 && o+uint64(n) <= 0x2140 {
		if v.options.DeviceWrite != nil {
			return v.options.DeviceWrite(o-0x2100, n, x)
		}
		return nil
	}
	if o >= 0x3000 && o+uint64(n) <= 0x3000+uint64(v.options.QueueCount+1)*16 {
		storeLE(v.table[o-0x3000:], n, x)
		return v.deliverPending()
	}
	if o == 0x1000 && (n == 2 || n == 4) {
		if x >= uint64(v.options.QueueCount) {
			return fmt.Errorf("virtio PCI: invalid queue notification %d", x)
		}
		return v.process(uint16(x))
	}
	if o+uint64(n) > 56 {
		return fmt.Errorf("virtio PCI: unsupported write%d offset %#x value %#x", n, o, x)
	}
	if o == 20 && n == 1 {
		if x == 0 {
			v.reset()
			return nil
		}
		v.common[20] = byte(x)
		if x&8 != 0 && (v.features[0]&^v.offered(0) != 0 || v.features[1]&^v.offered(1) != 0 || v.features[1]&1 == 0) {
			v.common[20] &^= 8
		}
		return nil
	}
	if o == 12 && n == 4 {
		sel := binary.LittleEndian.Uint32(v.common[8:])
		if sel < 2 && v.common[20]&8 == 0 {
			v.features[sel] = uint32(x)
		}
		return nil
	}
	switch o {
	case 0, 8:
		if n != 4 {
			break
		}
		storeLE(v.common[o:], n, x)
		return nil
	case 16:
		if n != 2 {
			break
		}
		if x >= uint64(v.options.QueueCount+1) {
			x = 0xffff
		}
		storeLE(v.common[o:], n, x)
		return nil
	case 22:
		if n != 2 {
			break
		}
		storeLE(v.common[o:], n, x)
		return nil
	case 24, 26, 28:
		if n != 2 {
			break
		}
		queue := binary.LittleEndian.Uint16(v.common[22:])
		if queue >= v.options.QueueCount {
			return nil
		}
		if o == 26 && x >= uint64(v.options.QueueCount+1) {
			x = 0xffff
		}
		if o == 24 && v.queues[queue].ready {
			return fmt.Errorf("virtio PCI: queue size changed while enabled")
		}
		if o == 28 {
			if x != 1 {
				return fmt.Errorf("virtio PCI: invalid queue enable value %#x", x)
			}
			if err := v.enable(queue); err != nil {
				return err
			}
		}
		storeLE(v.queueConfig[queue][o-24:], n, x)
		return nil
	case 32, 36, 40, 44, 48, 52:
		if (n != 4 && n != 8) || o+uint64(n) > 56 {
			break
		}
		queue := binary.LittleEndian.Uint16(v.common[22:])
		if queue >= v.options.QueueCount {
			return nil
		}
		if v.queues[queue].ready {
			break
		}
		storeLE(v.queueConfig[queue][o-24:], n, x)
		return nil
	}
	return fmt.Errorf("virtio PCI: unsupported common write%d offset %#x value %#x", n, o, x)
}
func (v *virtioPCI) enable(queue uint16) error {
	if v.queues[queue].ready {
		return nil
	}
	c := v.queueConfig[queue][:]
	q := inputQueue{size: uint32(binary.LittleEndian.Uint16(c)), desc: binary.LittleEndian.Uint64(c[8:]), avail: binary.LittleEndian.Uint64(c[16:]), used: binary.LittleEndian.Uint64(c[24:]), ready: true}
	if q.size == 0 || q.size > 128 || q.size&(q.size-1) != 0 || q.desc%16 != 0 || q.avail%2 != 0 || q.used%4 != 0 {
		return fmt.Errorf("virtio PCI: invalid queue geometry")
	}
	for _, r := range []struct {
		a, n uint64
		w    bool
	}{{q.desc, uint64(q.size) * 16, false}, {q.avail, 4 + uint64(q.size)*2, false}, {q.used, 4 + uint64(q.size)*8, true}} {
		if _, err := v.memory(r.a, r.n, r.w); err != nil {
			return err
		}
	}
	v.queues[queue] = q
	return nil
}
func (v *virtioPCI) deliverPending() error {
	control := binary.LittleEndian.Uint16(v.config[0x86:])
	if control&0xc000 != 0x8000 {
		return nil
	}
	for i := uint64(0); i < uint64(v.options.QueueCount+1); i++ {
		entry := v.table[i*16:]
		if v.pending&(1<<i) == 0 || binary.LittleEndian.Uint32(entry[12:])&1 != 0 {
			continue
		}
		if v.msi == nil {
			return fmt.Errorf("virtio PCI: no MSI sink")
		}
		if err := v.msi(binary.LittleEndian.Uint64(entry), binary.LittleEndian.Uint32(entry[8:])); err != nil {
			return err
		}
		v.pending &^= 1 << i
	}
	return nil
}
func (v *virtioPCI) process(queue uint16) error {
	q := &v.queues[queue]
	if v.common[20]&0xcf != 15 || !q.ready {
		return fmt.Errorf("virtio PCI: notification before driver ready")
	}
	avail, err := v.memory(q.avail, 4+uint64(q.size)*2, false)
	if err != nil {
		return err
	}
	used, err := v.memory(q.used, 4+uint64(q.size)*8, true)
	if err != nil {
		return err
	}
	index := binary.LittleEndian.Uint16(avail[2:])
	if uint32(uint16(index-q.last)) > q.size {
		return fmt.Errorf("virtio PCI: available ring overrun")
	}
	if q.last == index {
		return nil
	}
	before := q.last
	for q.last != index {
		head := binary.LittleEndian.Uint16(avail[4+uint32(q.last)%q.size*2:])
		parts, err := v.buffers(queue, head)
		if err != nil {
			return err
		}
		var n uint32
		ready := true
		if v.options.QueueRequest != nil {
			n, ready, err = v.options.QueueRequest(queue, parts)
		} else if v.options.Request != nil {
			n, err = v.options.Request(parts)
		} else {
			return fmt.Errorf("virtio PCI: no request handler")
		}
		if err != nil {
			return err
		}
		if !ready {
			break
		}
		r := used[4+uint32(q.written)%q.size*8:]
		binary.LittleEndian.PutUint32(r, uint32(head))
		binary.LittleEndian.PutUint32(r[4:], n)
		q.last++
		q.written++
		binary.LittleEndian.PutUint16(used[2:], q.written)
	}
	if q.last != before && binary.LittleEndian.Uint16(avail)&1 == 0 {
		v.isr |= 1
		vector := binary.LittleEndian.Uint16(v.queueConfig[queue][2:])
		if vector < v.options.QueueCount+1 {
			v.pending |= 1 << vector
			return v.deliverPending()
		}
	}
	return nil
}

// poll retries pending asynchronous requests. A not-ready callback must leave
// guest buffers unchanged; every retry revalidates both chain and used-ring DMA.
func (v *virtioPCI) poll() error {
	if v.common[20]&0xcf != 15 {
		return nil
	}
	for queue := uint16(0); queue < v.options.QueueCount; queue++ {
		if v.queues[queue].ready {
			if err := v.process(queue); err != nil {
				return err
			}
		}
	}
	return nil
}

type virtioBuffer struct {
	data  []byte
	write bool
}

func (v *virtioPCI) buffers(queue, head uint16) ([]virtioBuffer, error) {
	q := &v.queues[queue]
	var parts []virtioBuffer
	var total uint64
	seen := map[uint16]bool{}
	for {
		if uint32(head) >= q.size || seen[head] {
			return nil, fmt.Errorf("virtio PCI: invalid descriptor chain")
		}
		seen[head] = true
		d, err := v.memory(q.desc+uint64(head)*16, 16, false)
		if err != nil {
			return nil, err
		}
		flags := binary.LittleEndian.Uint16(d[12:])
		length := uint64(binary.LittleEndian.Uint32(d[8:]))
		if flags&^uint16(3) != 0 || length > 8<<20 || total+length > 8<<20 {
			return nil, fmt.Errorf("virtio PCI: unsupported flags/length")
		}
		p, err := v.memory(binary.LittleEndian.Uint64(d), length, flags&2 != 0)
		if err != nil {
			return nil, err
		}
		parts = append(parts, virtioBuffer{p, flags&2 != 0})
		total += length
		if flags&1 == 0 {
			break
		}
		head = binary.LittleEndian.Uint16(d[14:])
	}
	return parts, nil
}
