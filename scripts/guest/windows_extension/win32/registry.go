//go:build renvo && windows

package main

import "unsafe"

const registryManifest = "FN\tread_registry\tmap\tsRead one native registry value; type and at most 256 bytes as hex\nARG\troot\tstr\tsHKLM HKCC HKCU or HKU\nARG\tkey\tstr\tsBackslash-separated subkey\nARG\tname\tstr\tsEmpty selects the default value\nEND\n"

// renvo:linkstatic advapi32.dll,RegOpenKeyExA
func openRegistry(root, path uintptr, options, access uint32, result uintptr) uint32 { return 0 }

// renvo:linkstatic advapi32.dll,RegQueryValueExA
func queryRegistry(key, name, reserved, kind, data, length uintptr) uint32 { return 0 }

// renvo:linkstatic advapi32.dll,RegCloseKey
func closeRegistry(key uintptr) uint32 { return 0 }

func readRegistry() {
	if fields != 5 || !stringArg(2, 4, false) || !stringArg(3, 255, true) || !stringArg(4, 128, true) {
		bad()
		return
	}
	// Predefined handles are sign-extended LONG values on 64-bit Windows.
	var root uintptr
	if equalField(2, "sHKLM") {
		root = ^uintptr(0) - 0x7ffffffd
	} else if equalField(2, "sHKCC") {
		root = ^uintptr(0) - 0x7ffffffa
	} else if equalField(2, "sHKCU") {
		root = ^uintptr(0) - 0x7ffffffe
	} else if equalField(2, "sHKU") {
		root = ^uintptr(0) - 0x7ffffffc
	} else {
		bad()
		return
	}
	var key uintptr
	status := openRegistry(root, arg(3), 0, 0x20019, uintptr(unsafe.Pointer(&key)))
	if status != 0 {
		osError(status)
		return
	}
	var kind uint32
	var value [256]byte
	length := uint32(len(value))
	status = queryRegistry(key, arg(4), 0, uintptr(unsafe.Pointer(&kind)), ptr(&value[0]), uintptr(unsafe.Pointer(&length)))
	closeRegistry(key)
	if status != 0 {
		osError(status)
		return
	}
	if length > uint32(len(value)) {
		send("ERR\tslimit\tsRegistry value exceeds 256 bytes\n")
		return
	}
	send("OK\tm2\tstype\ti")
	number(kind)
	send("\tsdata_hex\ts")
	sendHex(value[:length])
	send("\n")
}
