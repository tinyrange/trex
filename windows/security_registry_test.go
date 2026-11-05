package windows

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestInheritRegistrySecurityNative(t *testing.T) {
	// Independent WCP 26100.9441 registry setter (83800) captures at the
	// NtSetSecurityObject boundary, with actual SIL and NTDLL inheritance.
	// The caller supplies SYSTEM defaults and ORs AR bits after inheritance;
	// these two caller policies are deliberately outside this format API.
	for _, tc := range []struct{ name, source, parent, native string }{
		{"protected", "O:SYG:SYD:P(A;;KA;;;SY)", "O:SYG:SYD:P(A;CI;KA;;;SY)", "0100049f300000003c000000000000001400000002001c0001000000000014003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"},
		{"inherit", "O:SYG:SYD:(A;;KR;;;BU)", "O:SYG:SYD:P(A;CI;KA;;;SY)", "0100048f480000005400000000000000140000000200340002000000000018001900020001020000000000052000000021020000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"},
		{"generic", "O:SYG:SYD:P(A;CI;GA;;;BU)", "O:SYG:SYD:P(A;CI;KA;;;SY)", "0100049f4c0000005800000000000000140000000200380002000000000018003f000f0001020000000000052000000021020000000a18000000001001020000000000052000000021020000010100000000000512000000010100000000000512000000"},
		{"creator", "O:SYG:SYD:(A;CI;GA;;;CO)", "O:SYG:SYD:P(A;CI;KR;;;BA)", "0100048f5c0000006800000000000000140000000200480003000000000014003f000f00010100000000000512000000000a140000000010010100000000000300000000001218001900020001020000000000052000000020020000010100000000000512000000010100000000000512000000"},
		{"owner-rights-propagation", "O:SYG:SYD:P(A;CIIO;RC;;;OW)", "O:SYG:SYD:P(A;CI;KA;;;SY)", "0100049f300000003c000000000000001400000002001c0001000000000a140000000200010100000000000304000000010100000000000512000000010100000000000512000000"},
		{"owner-rights-effective", "O:SYG:SYD:P(A;CI;GA;;;OW)", "O:SYG:SYD:P(A;CI;KA;;;SY)", "0100049f440000005000000000000000140000000200300002000000000014003f000f00010100000000000304000000000a140000000010010100000000000304000000010100000000000512000000010100000000000512000000"},
		{"owner-rights-parent", "O:SYG:SYD:", "O:SYG:SYD:P(A;CI;GA;;;OW)", "0100048f440000005000000000000000140000000200300002000000001014003f000f00010100000000000304000000001a140000000010010100000000000304000000010100000000000512000000010100000000000512000000"},
		{"parent-oi", "O:SYG:SYD:", "O:SYG:SYD:P(A;OI;GA;;;BU)", "0100048f340000004000000000000000140000000200200001000000001918000000001001020000000000052000000021020000010100000000000512000000010100000000000512000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := CompileSDDL(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			parent, err := CompileSDDL(tc.parent)
			if err != nil {
				t.Fatal(err)
			}
			native, err := hex.DecodeString(tc.native)
			if err != nil {
				t.Fatal(err)
			}
			got, err := InheritRegistrySecurity(source, parent)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := readFileSecurityParts(got, false)
			if err != nil {
				t.Fatal(err)
			}
			want, err := readFileSecurityParts(native, false)
			if err != nil {
				t.Fatal(err)
			}
			if actual.control|0x300 != want.control || !bytes.Equal(actual.owner, want.owner) || !bytes.Equal(actual.group, want.group) || !bytes.Equal(actual.dacl, want.dacl) || !bytes.Equal(actual.sacl, want.sacl) {
				t.Fatalf("got %x; native %x", got, native)
			}
		})
	}
	for _, text := range []string{"D:(A;;KA;;;SY)", "O:SYG:SYD:NO_ACCESS_CONTROL"} {
		source, err := CompileSDDL(text)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := InheritRegistrySecurity(source, nil); err == nil {
			t.Fatalf("accepted policy-dependent input %s", text)
		}
	}
}
