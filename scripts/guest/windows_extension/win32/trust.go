//go:build renvo && windows

package main

import "unsafe"

const extraManifest = "FN\tverify_trust\tmap\tsNative Authenticode verification; local cache only; status is unsigned WinVerifyTrust result\nARG\tpath\tstr\ts\nEND\n"

// renvo:linkstatic wintrust.dll,WinVerifyTrust
func winVerifyTrust(window, action, data uintptr) int32 { return 0 }

type trustFile struct {
	Size                  uint32
	Path, Handle, Subject uintptr
}

type trustData struct {
	Size                   uint32
	Policy, SIP            uintptr
	UI, Revocation, Choice uint32
	File                   uintptr
	Action                 uint32
	State, URL             uintptr
	Flags, Context         uint32
	SignatureSettings      uintptr
}

func dispatchExtra() bool {
	if !equalField(1, "verify_trust") {
		return false
	}
	if fields != 3 || !stringArg(2, 259, false) {
		bad()
		return true
	}
	var path [260]uint16
	for i := 0; i < ends[2]-starts[2]-1; i++ {
		path[i] = uint16(input[starts[2]+1+i])
	}
	// WINTRUST_ACTION_GENERIC_VERIFY_V2, not the WHQL-only driver policy.
	action := [4]uint32{0x00aac56b, 0x11d0cd44, 0xc000c28c, 0xee95c24f}
	var file trustFile
	file.Size = uint32(unsafe.Sizeof(file))
	file.Path = uintptr(unsafe.Pointer(&path))
	var data trustData
	data.Size = uint32(unsafe.Sizeof(data))
	data.UI, data.Choice, data.Action = 2, 1, 1
	data.Flags = 0x1000 // WTD_CACHE_ONLY_URL_RETRIEVAL: never access the network.
	data.File = uintptr(unsafe.Pointer(&file))
	result := winVerifyTrust(^uintptr(0), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	data.Action = 2 // Every VERIFY must be paired with CLOSE, including failures.
	winVerifyTrust(^uintptr(0), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	send("OK\tm2\tstrusted\tb")
	if result == 0 {
		send("1")
	} else {
		send("0")
	}
	send("\tsstatus\ti")
	number(uint32(result))
	send("\n")
	return true
}
