package starlarkfrontend

import (
	"encoding/binary"
	"testing"

	"go.starlark.net/starlark"
)

func TestAMD64ClassFactoryDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name            string
		prefix, between []byte
		want            bool
	}{
		{"class", []byte{0x4c, 0x8b, 0x11}, nil, true},      // mov r10,[rcx]
		{"interface", []byte{0x4c, 0x8b, 0x12}, nil, false}, // IID is RDX, not RCX
		{"clobbered_base", []byte{0x4c, 0x8b, 0x11}, []byte{0x45, 0x31, 0xc0}, false},
		{"clobbered_value", []byte{0x4c, 0x8b, 0x11}, []byte{0x45, 0x31, 0xd2}, false},
		{"call_boundary", []byte{0x4c, 0x8b, 0x11}, []byte{0xe8, 0, 0, 0, 0}, false},
		{"argument_clobber", []byte{0x4c, 0x8b, 0x11}, []byte{0x31, 0xc9}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A complete PE32+ with an exported factory, a RIP-relative image
			// base above 4 GiB, and corroborating ASCII registration data.
			data := make([]byte, 0x800)
			u16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(data[off:], v) }
			u32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(data[off:], v) }
			copy(data, "MZ")
			u32(0x3c, 0x80)
			copy(data[0x80:], "PE\x00\x00")
			u16(0x84, 0x8664)
			u16(0x86, 1)
			u16(0x94, 240)
			u16(0x96, 0x2022)
			u16(0x98, 0x20b)
			u32(0xa8, 0x1000)
			binary.LittleEndian.PutUint64(data[0xb0:], 0x7ff78000000)
			u32(0xb8, 0x1000)
			u32(0xbc, 0x200)
			u32(0xd0, 0x2000)
			u32(0xd4, 0x200)
			u32(0x104, 16)
			u32(0x108, 0x1100)
			u32(0x10c, 0x80)
			copy(data[0x188:], ".text")
			u32(0x190, 0x600)
			u32(0x194, 0x1000)
			u32(0x198, 0x600)
			u32(0x19c, 0x200)
			u32(0x1ac, 0x60000020)
			u32(0x310, 1)
			u32(0x314, 1)
			u32(0x318, 1)
			u32(0x31c, 0x1140)
			u32(0x320, 0x1144)
			u32(0x324, 0x1148)
			u32(0x340, 0x1000)
			u32(0x344, 0x1150)
			copy(data[0x350:], "DllGetClassObject\x00")
			code := append([]byte{}, tc.prefix...)
			code = append(code, 0x4c, 0x8d, 0x05, 0xf6, 0xef, 0xff, 0xff) // lea r8,[rip-100a]
			code = append(code, tc.between...)
			code = append(code, 0x4d, 0x3b, 0x90, 0x00, 0x12, 0, 0, 0xc3) // cmp r10,[r8+1200]; ret
			copy(data[0x200:], code)
			copy(data[0x400:], []byte{0x94, 0x2d, 0x8a, 0x7b, 0xc9, 0x0a, 0xd1, 0x11, 0x89, 0x6c, 0, 0xc0, 0x4f, 0xb6, 0xbf, 0xc4})
			copy(data[0x420:], "CLSID\\{7B8A2D94-0AC9-11D1-896C-00C04FB6BFC4}\\InprocServer32\x00")
			thread, globals, err := newStarlarkRuntime("-")
			if err != nil {
				t.Fatal(err)
			}
			globals["fixture"] = starlark.Bytes(data)
			globals["want"] = starlark.Bool(tc.want)
			_, err = starlark.ExecFile(thread, "amd64-class.star", `
load("@stdlib//windows/selfreg:facts.star", "class_ids")
def check():
    classes = class_ids(binary.concat([fixture]))
    expected = ["{7B8A2D94-0AC9-11D1-896C-00C04FB6BFC4}"] if want else []
    if classes != expected:
        fail("unexpected factory classes: " + str(classes))
check()
`, globals)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
