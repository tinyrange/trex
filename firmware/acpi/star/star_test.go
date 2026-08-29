package star

import (
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestFirmwareACPITableBuiltin(t *testing.T) {
	value, err := firmwareACPITableBuiltin(nil, nil, starlark.Tuple{starlark.String("TEST"), starlark.Bytes("body")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	file := value.(starfile.File)
	data := make([]byte, file.Size())
	if _, err := file.ReadAt(data, 0); err != nil {
		t.Fatal(err)
	}
	if string(data[:4]) != "TEST" || string(data[36:]) != "body" {
		t.Fatalf("unexpected table: %x", data)
	}
}
