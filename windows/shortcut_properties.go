package windows

import (
	"bytes"
	"unicode/utf16"
)

// MS-SHLLINK 2.5.7, MS-PROPSTORE 2.2/2.3.2 and MS-OLEPS 2.15.
// PKEY_AppUserModel_ID uses FMTID 9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3, PID 5.
func writeAppUserModelID(out *bytes.Buffer, id string) {
	var value bytes.Buffer
	writeLE(&value, uint32(5))
	value.WriteByte(0)          // Reserved; TypedPropertyValue is deliberately unaligned.
	writeLE(&value, uint16(31)) // VT_LPWSTR
	writeLE(&value, uint16(0))
	chars := append(utf16.Encode([]rune(id)), 0)
	writeLE(&value, uint32(len(chars)))
	for _, ch := range chars {
		writeLE(&value, ch)
	}
	// UnicodeString padding is relative to the string, not the enclosing record.
	if len(chars)%2 != 0 {
		writeLE(&value, uint16(0))
	}
	var storage bytes.Buffer
	writeLE(&storage, uint32(24+4+value.Len()+4))
	writeLE(&storage, uint32(0x53505331))
	storage.Write([]byte{0x55, 0x28, 0x4c, 0x9f, 0x79, 0x9f, 0x39, 0x4b, 0xa8, 0xd0, 0xe1, 0xd4, 0x2d, 0xe1, 0xd5, 0xf3})
	writeLE(&storage, uint32(4+value.Len()))
	storage.Write(value.Bytes())
	writeLE(&storage, uint32(0)) // Last property
	writeLE(out, uint32(8+storage.Len()+4))
	writeLE(out, uint32(0xa0000009))
	out.Write(storage.Bytes())
	writeLE(out, uint32(0)) // Last storage
}
