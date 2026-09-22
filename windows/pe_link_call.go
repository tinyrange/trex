package windows

import "fmt"

// callBridge adapts cdecl callers to imported x86 fastcall functions, or to a
// stdcall function pointer supplied as the first argument. The latter permits
// callbacks returned by a foreign API without changing the compiler's ABI.
func (image *pe32SectionImage) callBridge(target string, words int, fastcall bool) (int, error) {
	if words < 0 || words > 64 {
		return 0, fmt.Errorf("invalid call argument count")
	}
	image.align(16)
	start := len(image.section)
	image.section = append(image.section, 0x55, 0x89, 0xe5) // push ebp; mov ebp,esp
	first, offset := 0, 12
	if fastcall {
		first, offset = 2, 8
	}
	for i := words - 1; i >= first; i-- {
		image.section = append(image.section, 0xff, 0xb5)
		image.dword(uint32(offset + 4*i))
	}
	if fastcall {
		if words > 0 {
			image.section = append(image.section, 0x8b, 0x4d, 0x08)
		} // ecx
		if words > 1 {
			image.section = append(image.section, 0x8b, 0x55, 0x0c)
		} // edx
		image.section = append(image.section, 0xff, 0x15)
		image.fixups = append(image.fixups, pe32Fixup{offset: len(image.section), label: target, kind: "address"})
		image.dword(0)
	} else {
		image.section = append(image.section, 0xff, 0x55, 0x08) // call [ebp+8]
	}
	image.section = append(image.section, 0xc9, 0xc3)
	return start, nil
}
