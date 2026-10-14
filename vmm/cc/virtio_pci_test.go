package cc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

// Two independent PCI functions share guest RAM, but must retain their own
// enumeration, negotiation, queue and interrupt state.
func TestVirtioPCIDeviceIsolationAndReset(t *testing.T) {
	ram := make([]byte, 8192)
	memory := func(a, n uint64, write bool) ([]byte, error) {
		if a > uint64(len(ram)) || n > uint64(len(ram))-a {
			return nil, fmt.Errorf("outside RAM")
		}
		return ram[a : a+n], nil
	}
	calls := [2]int{}
	devices := [2]*virtioPCI{}
	for i := range devices {
		i := i
		devices[i] = newVirtioPCI(virtioPCIOptions{
			ConfigBase: 0x40008000 + uint64(i)*0x8000, BAR: 0x50000000 + uint32(i)*0x10000,
			VendorID: uint16(0x106b + i), DeviceID: uint16(0x1a00 + i),
			Offered: func(selector uint32) uint32 {
				if selector == 1 {
					return 1
				}
				if selector == 0 {
					return uint32(1) << uint(i)
				}
				return 0
			},
			DeviceConfig: func() (c [64]byte) { c[0] = byte(0x40 + i); return },
			Request: func(parts []virtioBuffer) (uint32, error) {
				if len(parts) != 2 || parts[0].write || !parts[1].write || len(parts[0].data) != 3 || len(parts[1].data) != 2 {
					return 0, fmt.Errorf("bad vendor request")
				}
				calls[i]++
				copy(parts[1].data, parts[0].data[:2])
				return 2, nil
			},
		}, memory, nil)
	}
	write := func(v *virtioPCI, a uint64, n int, x uint64) {
		t.Helper()
		if err := v.write(a, n, x); err != nil {
			t.Fatal(err)
		}
	}
	for i, v := range devices {
		other := devices[1-i]
		if other.contains(v.options.ConfigBase, 4) {
			t.Fatal("overlapping ECAM functions")
		}
		got, err := v.read(v.options.ConfigBase, 4)
		if err != nil || got != uint64(0x1a00+i)<<16|uint64(0x106b+i) {
			t.Fatal("identity", got, err)
		}
		write(v, v.options.ConfigBase+4, 2, 6)
		base := uint64(v.bar)
		if other.contains(base, 4) {
			t.Fatal("overlapping BARs")
		}
		got, err = v.read(base+0x2100, 1)
		if err != nil || got != uint64(0x40+i) {
			t.Fatal("device config", got, err)
		}
		got, err = v.read(base+4, 4)
		if err != nil || got != uint64(1)<<uint(i) {
			t.Fatal("feature hook", got, err)
		}
		write(v, base+20, 1, 3)
		write(v, base+8, 4, 1)
		write(v, base+12, 4, 1)
		write(v, base+20, 1, 11)
		write(v, base+24, 2, 8)
		offset := uint64(i) * 4096
		write(v, base+32, 8, offset)
		write(v, base+40, 8, offset+256)
		write(v, base+48, 8, offset+512)
		write(v, base+28, 2, 1)
		write(v, base+20, 1, 15)
		binary.LittleEndian.PutUint64(ram[offset:], offset+768)
		binary.LittleEndian.PutUint32(ram[offset+8:], 3)
		binary.LittleEndian.PutUint16(ram[offset+12:], 1)
		binary.LittleEndian.PutUint16(ram[offset+14:], 1)
		binary.LittleEndian.PutUint64(ram[offset+16:], offset+800)
		binary.LittleEndian.PutUint32(ram[offset+24:], 2)
		binary.LittleEndian.PutUint16(ram[offset+28:], 2)
		copy(ram[offset+768:], []byte{byte(7 + i), 9, 11})
		binary.LittleEndian.PutUint16(ram[offset+258:], 1)
		write(v, base+0x1000, 2, 0)
		if calls[i] != 1 || ram[offset+800] != byte(7+i) || binary.LittleEndian.Uint32(ram[offset+520:]) != 2 {
			t.Fatal("vendor request/completion")
		}
		if other.queues[0].last != uint16(i) {
			t.Fatal("queue state leaked to other function")
		}
		// An enable write cannot rewind the already consumed queue.
		write(v, base+28, 2, 1)
		_, _ = v.read(base+0x2000, 1)
		write(v, base+0x1000, 2, 0)
		if calls[i] != 1 || v.isr != 0 {
			t.Fatal("empty notification completed or interrupted")
		}
		if err := v.write(base+24, 2, 16); err == nil {
			t.Fatal("live queue resized")
		}
		if err := v.write(base+28, 2, 0); err == nil {
			t.Fatal("invalid queue disable accepted")
		}
	}
	v := devices[0]
	base := uint64(v.bar)
	write(v, base+20, 1, 0)
	if v.queues[0].ready || v.queues[0].last != 0 || v.features != [2]uint32{} || v.pending != 0 || v.common[20] != 0 {
		t.Fatal("reset left transport state")
	}
	if !devices[1].queues[0].ready || devices[1].queues[0].last != 1 {
		t.Fatal("reset affected another function")
	}
	// Invalid and wrapped accesses must not reach backing arrays or callbacks.
	for _, a := range []uint64{0, ^uint64(0) - 3, v.options.ConfigBase + 4096, base + 0x10000} {
		if v.contains(a, 4) {
			t.Fatalf("contains invalid address %#x", a)
		}
		if _, err := v.read(a, 4); err == nil {
			t.Fatal("invalid read accepted")
		}
		if err := v.write(a, 4, 0); err == nil {
			t.Fatal("invalid write accepted")
		}
	}
}

func TestVirtioPCIValidatesChainBeforeDeviceHook(t *testing.T) {
	ram := make([]byte, 1024)
	calls := 0
	memory := func(a, n uint64, write bool) ([]byte, error) {
		if a > uint64(len(ram)) || n > uint64(len(ram))-a || write && a >= 768 {
			return nil, fmt.Errorf("unsafe DMA")
		}
		return ram[a : a+n], nil
	}
	v := newVirtioPCI(virtioPCIOptions{ConfigBase: 0x40010000, BAR: 0x50010000, Request: func([]virtioBuffer) (uint32, error) { calls++; return 0, nil }}, memory, nil)
	v.config[4] = 6
	v.common[20] = 15
	v.queues[0] = inputQueue{size: 8, desc: 0, avail: 256, used: 512, ready: true}
	binary.LittleEndian.PutUint64(ram, 640)
	binary.LittleEndian.PutUint32(ram[8:], 4)
	binary.LittleEndian.PutUint16(ram[12:], 1)
	binary.LittleEndian.PutUint16(ram[14:], 1)
	binary.LittleEndian.PutUint64(ram[16:], 768)
	binary.LittleEndian.PutUint32(ram[24:], 4)
	binary.LittleEndian.PutUint16(ram[28:], 2)
	binary.LittleEndian.PutUint16(ram[258:], 1)
	if err := v.write(0x50011000, 2, 0); err == nil || calls != 0 || binary.LittleEndian.Uint16(ram[514:]) != 0 {
		t.Fatal("unsafe DMA reached hook/completion", err)
	}
}

func TestVirtioPCIAsyncQueuesRevalidateAndReset(t *testing.T) {
	ram := make([]byte, 4096)
	blocked, ready := false, false
	calls := [2]int{}
	resets := 0
	var interrupts []uint32
	v := newVirtioPCI(virtioPCIOptions{
		ConfigBase: 0x40008000, BAR: 0x50000000, QueueCount: 2,
		QueueRequest: func(queue uint16, parts []virtioBuffer) (uint32, bool, error) {
			calls[queue]++
			if queue == 0 {
				if !ready {
					return 0, false, nil
				}
				copy(parts[0].data, []byte{7, 9})
				return 2, true, nil
			}
			if parts[0].write || !bytes.Equal(parts[0].data, []byte{3, 5}) {
				return 0, false, fmt.Errorf("invalid TX")
			}
			return 0, true, nil
		}, Reset: func() { resets++ },
	}, func(a, n uint64, write bool) ([]byte, error) {
		if a > uint64(len(ram)) || n > uint64(len(ram))-a || blocked && write && a == 0x300 {
			return nil, fmt.Errorf("protected DMA")
		}
		return ram[a : a+n], nil
	}, func(a uint64, data uint32) error { interrupts = append(interrupts, data); return nil })
	write := func(a uint64, n int, x uint64) {
		t.Helper()
		if err := v.write(a, n, x); err != nil {
			t.Fatal(err)
		}
	}
	write(0x40008004, 2, 6)
	write(0x50000014, 1, 3)
	write(0x50000008, 4, 1)
	write(0x5000000c, 4, 1)
	write(0x50000014, 1, 11)
	for queue := uint64(0); queue < 2; queue++ {
		off := queue * 0x800
		write(0x50000016, 2, queue)
		write(0x50000018, 2, 8)
		write(0x5000001a, 2, queue+1)
		write(0x50000020, 8, off)
		write(0x50000028, 8, off+0x100)
		write(0x50000030, 8, off+0x200)
		write(0x5000001c, 2, 1)
		binary.LittleEndian.PutUint64(ram[off:], off+0x300)
		binary.LittleEndian.PutUint32(ram[off+8:], 2)
		if queue == 0 {
			binary.LittleEndian.PutUint16(ram[off+12:], 2)
		}
		binary.LittleEndian.PutUint16(ram[off+0x102:], 1)
		write(0x50003000+(queue+1)*16, 8, 0x1fff0040)
		write(0x50003008+(queue+1)*16, 4, 81+queue)
	}
	copy(ram[0xb00:], []byte{3, 5})
	write(0x50000014, 1, 15)
	write(0x40008086, 2, 0x8002)
	write(0x50001000, 2, 0)
	if calls[0] != 1 || v.queues[0].last != 0 || len(interrupts) != 0 {
		t.Fatal("pending request completed")
	}
	write(0x50001000, 2, 1)
	if calls[1] != 1 || v.queues[1].last != 1 || !reflect.DeepEqual(interrupts, []uint32{82}) {
		t.Fatal("pending RX blocked TX", interrupts)
	}
	// Guest DMA protection may change while a request waits for host data.
	// The retry must fail before invoking the callback or publishing completion.
	blocked, ready = true, true
	if err := v.poll(); err == nil || calls[0] != 1 || ram[0x300] != 0 || v.queues[0].last != 0 {
		t.Fatal("pending DMA not revalidated", err)
	}
	blocked = false
	if err := v.poll(); err != nil {
		t.Fatal(err)
	}
	if calls[0] != 2 || calls[1] != 1 || !bytes.Equal(ram[0x300:0x302], []byte{7, 9}) || !reflect.DeepEqual(interrupts, []uint32{82, 81}) {
		t.Fatal("asynchronous completion", calls, interrupts)
	}
	before := resets
	write(0x50000014, 1, 0)
	if err := v.poll(); err != nil {
		t.Fatal(err)
	}
	if resets != before+1 || v.queues[0].ready || v.queues[1].ready || calls != [2]int{2, 1} {
		t.Fatal("reset retained pending work")
	}
}
