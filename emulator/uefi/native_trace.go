package uefi

import "github.com/tinyrange/trex/windows/guid"

// NativeFirmwareCall is a completed firmware call. Protocol is captured while
// its input pointer is valid, so later inspection does not depend on guest RAM.
type NativeFirmwareCall struct {
	Service  string
	Args     [8]uint64
	Status   uint64
	Protocol string
}

func (n *NativeExecution) observeFirmware(name string, args [8]uint64, status uint64) {
	if n.FirmwareLimit == 0 {
		return
	}
	call := NativeFirmwareCall{Service: name, Args: args, Status: status}
	var pointer uint64
	switch name {
	case "OpenProtocol", "HandleProtocol", "CloseProtocol":
		pointer = args[1]
	case "LocateProtocol":
		pointer = args[0]
	case "LocateHandle", "LocateHandleBuffer":
		if args[0] == 2 {
			pointer = args[1]
		}
	}
	if pointer != 0 {
		var raw [16]byte
		if err := n.ReadVirtualMemory(pointer, raw[:]); err == nil {
			call.Protocol = guid.Format(raw)
		}
	}
	if len(n.FirmwareCalls) >= n.FirmwareLimit {
		copy(n.FirmwareCalls, n.FirmwareCalls[len(n.FirmwareCalls)-n.FirmwareLimit+1:])
		n.FirmwareCalls = n.FirmwareCalls[:n.FirmwareLimit-1]
	}
	n.FirmwareCalls = append(n.FirmwareCalls, call)
}
