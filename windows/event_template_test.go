package windows

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
)

func nativeEventTemplateDirectory(t *testing.T) []byte {
	t.Helper()
	// Exact directory/block headers from 26300.9457 win32kbase.sys's English
	// WEVT_TEMPLATE. Opaque event records are omitted: this API deliberately
	// validates the provider directory, not those records. Includes the native
	// two trailing zero resource bytes beyond CRIM's declared extent.
	data := make([]byte, 152994)
	header, _ := hex.DecodeString("4352494da05502000500010002000000796c418c9bd4014fa467e56d3aa8234c38000000a1420aaf2537614bb4763694bf352f1b704d020057455654384d0200ffffffff0900000005000000")
	copy(data, header)
	second, _ := hex.DecodeString("5745565430080000ffffffff0800000005000000")
	copy(data[150896:], second)
	return data
}

func TestEventTemplateNativeDirectory(t *testing.T) {
	data := nativeEventTemplateDirectory(t)
	original := bytes.Clone(data)
	got, err := EventTemplateProviders(data)
	want := []string{"{8c416c79-d49b-4f01-a467-e56d3aa8234c}", "{af0a42a1-3725-4b61-b476-3694bf352f1b}"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("providers=%v err=%v", got, err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("mutated source")
	}
}

func TestEventTemplateRejectsMalformedDirectory(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"truncated":              func(b []byte) []byte { return b[:15] },
		"unsupported version":    func(b []byte) []byte { b[8] = 4; return b },
		"overflowing count":      func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], 0xffffffff); return b },
		"directory alias":        func(b []byte) []byte { binary.LittleEndian.PutUint32(b[32:], 16); return b },
		"offset overflow":        func(b []byte) []byte { binary.LittleEndian.PutUint32(b[32:], 0xfffffffc); return b },
		"extent overflow":        func(b []byte) []byte { binary.LittleEndian.PutUint32(b[60:], 0xffffffff); return b },
		"overlapping blocks":     func(b []byte) []byte { binary.LittleEndian.PutUint32(b[60:], 150860); return b },
		"duplicate guid":         func(b []byte) []byte { copy(b[36:52], b[16:32]); return b },
		"bad block signature":    func(b []byte) []byte { b[56] = 0; return b },
		"nonzero trailing bytes": func(b []byte) []byte { b[len(b)-1] = 1; return b },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := EventTemplateProviders(modify(nativeEventTemplateDirectory(t))); err == nil {
				t.Fatal("accepted malformed directory")
			}
		})
	}
}
