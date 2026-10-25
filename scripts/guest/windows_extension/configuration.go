//go:build renvo && win16 && configuration_agent

package main

import "unsafe"

const manifest = "API\t1\t1024\nABOUT\tsNative Windows 9x Configuration Manager inspection\nFN\tping\tstr\tsReadiness\nEND\nFN\tconfiguration_device\tmap\tsRead live device status and adjacent instance IDs; empty instance selects root; strings are hex bytes\nARG\tinstance\tstr\ts\nEND\nDONE\n"

// renvo:linkstatic TREX,ConfigCall
func nativeConfigurationCall(record uint16) {}

var configCall [10]uint16
var configNode [4]byte
var configOther [4]byte
var configStatus [4]byte
var configProblem [4]byte
var configChild [200]byte
var configSibling [200]byte

func configPointer(p *byte) uint32 { return uint32(dataSegment())<<16 | uint32(pointer(p)) }
func configValue(p *[4]byte) uint32 {
	return uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16 | uint32(p[3])<<24
}
func configInvoke(service uint16, a, b, c, d uint32) uint16 {
	configCall[0] = service
	configCall[1] = 0xffff
	configCall[2] = uint16(a)
	configCall[3] = uint16(a >> 16)
	configCall[4] = uint16(b)
	configCall[5] = uint16(b >> 16)
	configCall[6] = uint16(c)
	configCall[7] = uint16(c >> 16)
	configCall[8] = uint16(d)
	configCall[9] = uint16(d >> 16)
	nativeConfigurationCall(uint16(uintptr(unsafe.Pointer(&configCall[0]))))
	return configCall[1]
}
func configError(code uint16) {
	send("ERR\tsconfiguration\tsConfiguration Manager result ")
	sendInt(code)
	send("\n")
}
func configNeighbor(service uint16, node uint32, id *[200]byte) uint16 {
	id[0] = 0
	result := configInvoke(service, configPointer(&configOther[0]), node, 0, 0)
	if result == 0x0d {
		return 0
	} // CR_NO_SUCH_DEVNODE: end of this branch.
	if result != 0 {
		return result
	}
	return configInvoke(7, configValue(&configOther), configPointer(&id[0]), 200, 0)
}
func configID(id *[200]byte) {
	for i := 0; i < len(id) && id[i] != 0; i++ {
		sendHex(id[i])
	}
}
func configurationDevice() {
	if fields != 3 || !stringArg(2, 199, true) {
		bad()
		return
	}
	var instance uint32
	if ends[2]-starts[2] > 1 {
		instance = uint32(segment)<<16 | uint32(argPointer(2))
	}
	result := configInvoke(2, configPointer(&configNode[0]), instance, 0, 0)
	if result != 0 {
		configError(result)
		return
	}
	node := configValue(&configNode)
	result = configInvoke(54, configPointer(&configStatus[0]), configPointer(&configProblem[0]), node, 0)
	if result != 0 {
		configError(result)
		return
	}
	result = configNeighbor(4, node, &configChild)
	if result != 0 {
		configError(result)
		return
	}
	result = configNeighbor(5, node, &configSibling)
	if result != 0 {
		configError(result)
		return
	}
	send("OK\tm5\tsnode_hex\ts")
	for i := 0; i < 4; i++ {
		sendHex(configNode[i])
	}
	send("\tsstatus_hex\ts")
	for i := 0; i < 4; i++ {
		sendHex(configStatus[i])
	}
	send("\tsproblem_hex\ts")
	for i := 0; i < 4; i++ {
		sendHex(configProblem[i])
	}
	send("\tschild_hex\ts")
	configID(&configChild)
	send("\tssibling_hex\ts")
	configID(&configSibling)
	send("\n")
}
func dispatchCall() {
	if fields == 1 && equalField(0, "?") {
		send(manifest)
		return
	}
	if fields < 2 || !equalField(0, "CALL") {
		bad()
		return
	}
	if fields == 2 && equalField(1, "ping") {
		send(pingReply)
	} else if equalField(1, "configuration_device") {
		configurationDevice()
	} else {
		bad()
	}
}
