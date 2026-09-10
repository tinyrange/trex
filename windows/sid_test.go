package windows

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestSIDString(t *testing.T) {
	for _, tc := range []struct {
		authority uint64
		subs      []uint32
		want      string
	}{
		{5, []uint32{18}, "S-1-5-18"},
		{15, []uint32{2, 1, 2, 3, 4, 5, 6, 0xffffffff}, "S-1-15-2-1-2-3-4-5-6-4294967295"},
		{0xffffffff, []uint32{0}, "S-1-4294967295-0"},
		{1 << 32, []uint32{0x12345678}, "S-1-0x000100000000-305419896"},
		{0xffffffffffff, []uint32{0}, "S-1-0xffffffffffff-0"},
		{0, nil, "S-1-0"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			raw := make([]byte, 8+4*len(tc.subs))
			raw[0], raw[1] = 1, byte(len(tc.subs))
			for i := 0; i < 6; i++ {
				raw[2+i] = byte(tc.authority >> ((5 - i) * 8))
			}
			for i, sub := range tc.subs {
				binary.LittleEndian.PutUint32(raw[8+i*4:], sub)
			}
			got, err := SIDString(raw)
			if err != nil || got != tc.want {
				t.Fatalf("SIDString = %q, %v; want %q", got, err, tc.want)
			}
			for _, value := range []starlark.Value{starlark.Bytes(raw), &starfile.Bytes{Name: "SID", Data: raw}} {
				got, err := starlark.Call(&starlark.Thread{}, Builtins()["sid_string"], starlark.Tuple{value}, nil)
				if err != nil || got != starlark.String(tc.want) {
					t.Fatalf("sid_string(%s) = %v, %v", value.Type(), got, err)
				}
			}
		})
	}
}

func TestSIDStringRejectsMalformed(t *testing.T) {
	for _, raw := range [][]byte{
		nil, {1}, {1, 0, 0, 0, 0, 0, 5},
		{2, 0, 0, 0, 0, 0, 0, 5},
		{1, 1, 0, 0, 0, 0, 0, 5},
		{1, 0, 0, 0, 0, 0, 0, 5, 0},
		append([]byte{1, 16, 0, 0, 0, 0, 0, 5}, make([]byte, 64)...),
	} {
		if _, err := SIDString(raw); err == nil {
			t.Fatalf("accepted malformed SID %x", raw)
		}
		if _, err := sidStringBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(raw)}, nil); err == nil {
			t.Fatalf("builtin accepted malformed SID %x", raw)
		}
	}
	raw := append([]byte{1, 15, 0, 0, 0, 0, 0, 5}, make([]byte, 60)...)
	if _, err := SIDString(raw); err != nil {
		t.Fatalf("rejected maximum-length SID: %v", err)
	}
}
