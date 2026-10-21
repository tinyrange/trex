package rfe

import (
	"fmt"
	"j5.nz/cc/hypervisor"
)

func (c *cpu) ReadPort(port uint16, n int) (uint32, error) { return c.portAccess(port, n, false, 0) }
func (c *cpu) WritePort(port uint16, n int, v uint32) error {
	_, err := c.portAccess(port, n, true, v)
	return err
}
func (c *cpu) portAccess(port uint16, n int, write bool, v uint32) (uint32, error) {
	index := c.operationIndex
	c.operationIndex++
	if index < len(c.operations) {
		op := c.operations[index]
		if !op.ready || op.ex.Reason != hypervisor.X86ExitIO || op.ex.Port != port || int(op.ex.Size) != n || op.ex.Write != write {
			return 0, fmt.Errorf("inconsistent port instruction replay")
		}
		var value uint32
		for j, b := range op.ex.Data {
			value |= uint32(b) << uint(j*8)
		}
		if write && value != v {
			return 0, fmt.Errorf("port write changed during replay")
		}
		return value, nil
	}
	internal := false
	if write {
		internal = c.deviceOut(port, byte(v))
	} else {
		var value byte
		value, internal = c.deviceIn(port)
		if internal {
			v = uint32(value)
		}
	}
	data := make([]byte, n)
	for j := range data {
		data[j] = byte(v >> uint(j*8))
	}
	ex := hypervisor.X86Exit{Reason: hypervisor.X86ExitIO, Port: port, Size: uint8(n), Count: 1, Write: write, Data: data}
	c.operations = append(c.operations, mmioOperation{ex: ex, ready: internal})
	if internal {
		return v, nil
	}
	return 0, &memoryExit{ex}
}
