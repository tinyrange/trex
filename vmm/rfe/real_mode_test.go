package rfe

import (
	"bytes"
	"strings"
	"testing"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestRunRealModeOwnsRAM(t *testing.T) {
	// mov byte [0000h],42h; hlt
	input := []byte{0xc6, 0x06, 0, 0, 0x42, 0xf4}
	source := &starfile.Bytes{Data: input}
	value, err := runRealModeBuiltin(nil, nil, starlark.Tuple{source, starlark.NewDict(0), starlark.MakeInt(2)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(*starvalue.Record)
	if result.Get("reason") != starlark.String("halt") || result.Get("retired").String() != "2" {
		t.Fatalf("unexpected stop: %v after %v", result.Get("reason"), result.Get("retired"))
	}
	output := result.Get("memory").(*starfile.Bytes)
	if input[0] != 0xc6 || output.Data[0] != 0x42 || !bytes.Equal(input[1:], output.Data[1:]) {
		t.Fatalf("source %x, result %x", input, output.Data)
	}
}

func TestRunRealModeStopsAtPortAccess(t *testing.T) {
	// out 40h,al would reach the PIT on a PC with devices.
	value, err := runRealModeBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("\xe6\x40\xf4"), starlark.NewDict(0), starlark.MakeInt(2)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(*starvalue.Record)
	detail, _ := starlark.AsString(result.Get("detail"))
	if result.Get("reason") != starlark.String("fault") || !strings.Contains(detail, "no port bus") || result.Get("registers").(*starvalue.Record).Get("ip").String() != "0" {
		t.Fatalf("unexpected port stop: %v (%s), %v", result.Get("reason"), detail, result.Get("registers").(*starvalue.Record).Get("ip"))
	}
}
