package cc

import (
	"context"
	"fmt"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/vmm"
)

type arm64Permission struct {
	address, size        uint64
	read, write, execute bool
}

func (d *arm64Driver) Context() context.Context                  { return d.ctx }
func (d *arm64Driver) Machine() vmm.Machine                      { return d.machine }
func (d *arm64Driver) EpochMicroseconds() uint64                 { return d.epoch }
func (d *arm64Driver) Counter() (uint64, uint64, error)          { return d.cpu.Counter() }
func (d *arm64Driver) SetSPI(id uint32, level bool) error        { return d.cpu.SetSPI(id, level) }
func (d *arm64Driver) Register(id uint32) (uint64, error)        { return d.cpu.Register(id) }
func (d *arm64Driver) SetRegister(id uint32, value uint64) error { return d.cpu.SetRegister(id, value) }
func (d *arm64Driver) Emit(kind string, payload any)             { d.emit(kind, payload) }
func (d *arm64Driver) GuestChannel(name string) (channel.ByteChannel, error) {
	c, ok := d.guestChannels[name]
	if !ok {
		return nil, fmt.Errorf("unknown platform channel %q", name)
	}
	return c, nil
}
func (d *arm64Driver) Memory(address, size uint64, write bool) ([]byte, error) {
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}
	if address < d.base || address-d.base > uint64(len(d.ram)) || size > uint64(len(d.ram))-(address-d.base) {
		return nil, fmt.Errorf("guest range %#x+%#x outside RAM", address, size)
	}
	for _, p := range d.permissions {
		if address < p.address+p.size && address+size > p.address && (!p.read && !write || !p.write && write) {
			return nil, fmt.Errorf("guest DMA violates memory protection at %#x", address)
		}
	}
	return d.ram[address-d.base : address-d.base+size], nil
}
func (d *arm64Driver) Protect(address, size uint64, read, write, execute bool) error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	if size == 0 || address < d.base || address-d.base >= uint64(len(d.ram)) || size > uint64(len(d.ram))-(address-d.base) {
		return fmt.Errorf("protection range outside guest RAM")
	}
	if err := d.cpu.ProtectRAM(address, size, read, write, execute); err != nil {
		return err
	}
	var next []arm64Permission
	for _, p := range d.permissions {
		end := p.address + p.size
		if end <= address || p.address >= address+size {
			next = append(next, p)
			continue
		}
		if p.address < address {
			q := p
			q.size = address - p.address
			next = append(next, q)
		}
		if end > address+size {
			q := p
			q.address = address + size
			q.size = end - q.address
			next = append(next, q)
		}
	}
	d.permissions = append(next, arm64Permission{address: address, size: size, read: read, write: write, execute: execute})
	return nil
}
