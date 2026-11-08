package msdelta

import (
	"bytes"
	"testing"
)

func TestCLILocalCustomModifierUsesBareTypeBoundary(t *testing.T) {
	// GroupPolicy.Management.Interop26100.33296: ten bad bytes all originated
	// in LocalVarSig custom-modifier prefixes. The native PA31 oracle leaves
	// those signatures unchanged, including the following CLASS/VALUETYPE.
	// Method parameters and PTR-nested modifiers are contrasting controls.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{
		2: {{Source: 0, Target: 0}, {Source: 2, Target: 3}},
	}})
	for _, tc := range []struct {
		name      string
		src, want []byte
	}{
		{"local optional", []byte{7, 1, 0x20, 9, 0x12, 9}, nil},
		{"local required", []byte{7, 2, 0x1f, 9, 0x12, 9, 0x12, 9}, nil},
		{"pinned byref local", []byte{7, 1, 0x45, 0x10, 0x20, 9, 0x12, 9}, nil},
		{"method modifier", []byte{0, 0, 0x20, 9, 0x12, 9}, []byte{0, 0, 0x20, 13, 0x12, 13}},
		{"pointer modifier", []byte{7, 1, 0xf, 0x20, 9, 0x12, 9}, []byte{7, 1, 0xf, 0x20, 13, 0x12, 13}},
		{"pinned byref class", []byte{7, 2, 0x45, 0x10, 0x12, 9, 0x12, 9}, []byte{7, 2, 0x45, 0x10, 0x12, 13, 0x12, 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := append([]byte{byte(len(tc.src))}, tc.src...)
			dst := bytes.Clone(source)
			transformCLISignature(dst, source, CLIStreamInfo{Size: uint32(len(source))}, 0, 17, &r)
			want := tc.want
			if want == nil {
				want = tc.src
			}
			if !bytes.Equal(dst[1:], want) {
				t.Fatalf("got %x want %x", dst[1:], want)
			}
		})
	}
}
