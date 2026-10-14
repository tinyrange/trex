package cc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/pl011"
	vmmstar "github.com/tinyrange/trex/vmm/star"
	"go.starlark.net/starlark"
)

// These are configurable protocol primitives. Board placement, identity,
// attachment selection, and interrupt routing belong to the caller's platform.
func init() {
	for _, kind := range []string{"pl011", "pl031", "pl061", "apple-aes", "apple-rtc", "apple-ctrr", "virtio-block", "apple-storage-pci", "apple-usb-pci", "apple-simple-storage", "apple-simple-usb"} {
		kind := kind
		vmmstar.RegisterARM64Device(kind, func(runtime vmm.ARM64Runtime, thread *starlark.Thread, options *starlark.Dict) (vmm.ARM64Device, error) {
			return makeARM64Device(runtime, thread, kind, options)
		})
	}
}

type nativeARM64Device struct {
	contains func(uint64, int) bool
	read     func(uint64, int) (uint64, error)
	write    func(uint64, int, uint64) error
	poll     func() error
	flush    func()
}

type arm64PollingChannel struct {
	channel.ByteChannel
	reader channel.AvailableReader
	writer channel.AvailableWriter
}

func (c arm64PollingChannel) Read(b []byte) (int, error)  { return c.reader.ReadAvailable(b) }
func (c arm64PollingChannel) Write(b []byte) (int, error) { return c.writer.WriteAvailable(b) }

func (d *nativeARM64Device) Contains(a uint64, n int) bool         { return d.contains(a, n) }
func (d *nativeARM64Device) Read(a uint64, n int) (uint64, error)  { return d.read(a, n) }
func (d *nativeARM64Device) Write(a uint64, n int, v uint64) error { return d.write(a, n, v) }
func (d *nativeARM64Device) Poll() error {
	if d.poll != nil {
		return d.poll()
	}
	return nil
}
func (d *nativeARM64Device) Flush() {
	if d.flush != nil {
		d.flush()
	}
}

func nativeARM64PCI(v *virtioPCI) *nativeARM64Device {
	d := &nativeARM64Device{contains: v.contains, read: v.read, write: v.write}
	// Only asynchronous transports need retries between guest entries.
	// Synchronous storage completes when its queue is notified.
	if v.options.QueueRequest != nil {
		d.poll = v.poll
	}
	return d
}

func makeARM64Device(runtime vmm.ARM64Runtime, thread *starlark.Thread, kind string, options *starlark.Dict) (vmm.ARM64Device, error) {
	var address, configBase uint64
	var bar uint32
	var channelName string
	var diskValue, msiValue starlark.Value = starlark.None, starlark.None
	var role uint8
	var irq int = -1
	var seedBank int = -1
	var seedAddress, seedSize uint64
	version, deviceID := uint32(1), uint32(0)
	var pageSize uint64 = 4096
	args := []any{}
	switch kind {
	case "virtio-block", "apple-storage-pci", "apple-usb-pci":
		args = append(args, "config_base", &configBase, "bar", &bar, "msi?", &msiValue)
	default:
		args = append(args, "address", &address)
	}
	switch kind {
	case "pl011", "apple-usb-pci", "apple-simple-usb":
		args = append(args, "channel", &channelName)
	case "virtio-block", "apple-storage-pci", "apple-simple-storage":
		args = append(args, "disk", &diskValue)
	case "apple-aes":
		args = append(args, "irq?", &irq)
	case "apple-ctrr":
		args = append(args, "seed_bank?", &seedBank, "seed_address?", &seedAddress, "seed_size?", &seedSize)
	}
	if kind == "apple-storage-pci" {
		args = append(args, "role", &role)
	}
	if kind == "apple-simple-storage" || kind == "apple-simple-usb" {
		args = append(args, "version?", &version, "device_id?", &deviceID, "page_size?", &pageSize)
	}
	if err := starlark.UnpackArgs(kind, nil, options.Items(), args...); err != nil {
		return nil, err
	}
	if address > ^uint64(0)-0x10000 {
		return nil, fmt.Errorf("device address overflow")
	}
	if kind == "virtio-block" || kind == "apple-storage-pci" || kind == "apple-usb-pci" {
		if configBase&0xfff != 0 || configBase > ^uint64(0)-4096 || bar&0xffff != 0 || uint64(bar)+0x10000 > 1<<32 {
			return nil, fmt.Errorf("PCI placement requires 4 KiB config and 64 KiB BAR alignment")
		}
	}
	if (kind == "virtio-block" || kind == "apple-storage-pci" || kind == "apple-simple-storage") && diskValue == starlark.None {
		return nil, fmt.Errorf("storage requires block device")
	}
	if kind == "pl011" && channelName == "" {
		return nil, fmt.Errorf("PL011 requires a named byte channel")
	}
	var disk block.Device
	if diskValue != starlark.None {
		var err error
		disk, err = blockstar.AsDevice(diskValue)
		if err != nil {
			return nil, err
		}
		if disk.Geometry().LogicalBlockSize != 512 {
			return nil, fmt.Errorf("storage protocol requires 512-byte sectors")
		}
	}
	var host channel.ByteChannel
	if channelName != "" {
		var err error
		host, err = runtime.GuestChannel(channelName)
		if err != nil {
			return nil, err
		}
		reader, rok := host.(channel.AvailableReader)
		writer, wok := host.(channel.AvailableWriter)
		if !rok || !wok {
			return nil, fmt.Errorf("device channel requires nonblocking read/write operations")
		}
		host = arm64PollingChannel{ByteChannel: host, reader: reader, writer: writer}
	}
	var msi func(uint64, uint32) error
	if msiValue != starlark.None {
		callback, ok := msiValue.(starlark.Callable)
		if !ok {
			return nil, fmt.Errorf("msi must be callable")
		}
		msi = func(a uint64, data uint32) error {
			v, err := starlark.Call(thread, callback, starlark.Tuple{starlark.MakeUint64(a), starlark.MakeUint(uint(data))}, nil)
			if err == nil && v != starlark.None {
				return fmt.Errorf("msi must return None")
			}
			return err
		}
	}
	memory := runtime.Memory

	switch kind {
	case "virtio-block":
		return nativeARM64PCI(newVirtioPCIBlock(configBase, bar, disk, memory, msi).virtioPCI), nil
	case "apple-storage-pci":
		return nativeARM64PCI(newAppleStoragePCI(configBase, bar, role, disk, memory, msi)), nil
	case "apple-usb-pci":
		return nativeARM64PCI(newAppleUSBPCI(configBase, bar, host, memory, msi, runtime.Emit).virtioPCI), nil
	case "apple-simple-storage":
		d := &appleSimpleStorage{address: address, disk: disk, appleQueue: appleQueue{dmaMemory: memory}}
		binary.LittleEndian.PutUint32(d.transport[:], version)
		binary.LittleEndian.PutUint32(d.transport[4:], deviceID)
		binary.LittleEndian.PutUint64(d.transport[8:], pageSize)
		return d, nil
	case "apple-simple-usb":
		d := &appleSimpleUSB{address: address, usb: host, emit: runtime.Emit, appleQueue: appleQueue{dmaMemory: memory}}
		binary.LittleEndian.PutUint32(d.usbTransport[:], version)
		binary.LittleEndian.PutUint32(d.usbTransport[4:], deviceID)
		binary.LittleEndian.PutUint64(d.usbTransport[8:], pageSize)
		return d, nil
	case "pl061":
		return &pl061{address: address}, nil
	case "apple-aes":
		d := &appleAES{address: address, memory: memory}
		if irq >= 0 {
			if irq > 1019 {
				return nil, fmt.Errorf("invalid AES IRQ")
			}
			d.irq = func(level bool) error { return runtime.SetSPI(uint32(irq), level) }
		}
		return d, nil
	case "apple-ctrr":
		m := runtime.Machine()
		d := &virtualCTRR{address: address, base: m.ARM64Boot.MemoryBase, size: uint64(m.Memory), protect: func(a, n uint64) error {
			if err := runtime.Protect(a, n, true, false, true); err != nil {
				return err
			}
			runtime.Emit("memory.protected", map[string]any{"address": a, "size": n})
			return nil
		}}
		if seedBank >= 0 {
			if seedBank >= 8 || seedSize == 0 || seedAddress > ^uint64(0)-seedSize || seedAddress < d.base || seedAddress-d.base > d.size || seedSize > d.size-(seedAddress-d.base) {
				return nil, fmt.Errorf("invalid CTRR seed")
			}
			d.banks[seedBank] = ctrrBank{lower: seedAddress, upper: seedAddress + seedSize - 1}
		}
		return d, nil
	case "pl031", "apple-rtc":
		ticks, _, err := runtime.Counter()
		if err != nil {
			return nil, err
		}
		if kind == "pl031" {
			epoch := uint32(runtime.EpochMicroseconds() / 1000000)
			return &pl031{address: address, clock: runtime.Counter, start: ticks, value: epoch, last: epoch, control: 1}, nil
		}
		return &avpRTC{address: address, clock: runtime.Counter, start: ticks, epoch: runtime.EpochMicroseconds()}, nil
	case "pl011":
		var serial []byte
		uart := pl011.New(address, func(b byte) error {
			if len(serial) >= 1<<20 {
				return fmt.Errorf("serial evidence exceeds 1 MiB")
			}
			serial = append(serial, b)
			_, err := host.Write([]byte{b})
			return err
		})
		read := func(a uint64, n int) (uint64, error) {
			if a == address || a == address+0x18 {
				flags, err := uart.Read(address+0x18, 4)
				if err != nil {
					return 0, err
				}
				if flags&0x10 != 0 {
					var b [1]byte
					count, err := host.Read(b[:])
					if err != nil && !errors.Is(err, channel.ErrWouldBlock) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
						return 0, err
					}
					if count == 1 {
						if err := uart.Receive(b[:]); err != nil {
							return 0, err
						}
					}
				}
			}
			return uart.Read(a, n)
		}
		return &nativeARM64Device{contains: uart.Contains, read: read, write: uart.Write, flush: func() {
			if len(serial) != 0 {
				runtime.Emit("serial", string(serial))
				serial = nil
			}
		}}, nil
	}
	return nil, fmt.Errorf("unknown device protocol %q", kind)
}
