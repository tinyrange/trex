package star

import (
	"bytes"
	"io"
	"math"
	"testing"

	blockstar "github.com/tinyrange/trex/block/star"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestZerosHugeBoundedReaderAndBlockBase(t *testing.T) {
	// A huge logical size makes eager allocation impractical. Exercise actual
	// file/block consumers, EOF tails and rejected writes without a full read.
	value, err := starlark.Call(&starlark.Thread{Name: "zeros"}, Builtins()["zeros"], starlark.Tuple{starlark.MakeInt64(math.MaxInt64)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	file := value.(starfile.File)
	if file.Size() != math.MaxInt64 {
		t.Fatal(file.Size())
	}
	p := bytes.Repeat([]byte{0x7f}, 8)
	n, err := file.ReadAt(p, math.MaxInt64-3)
	if n != 3 || err != io.EOF || !bytes.Equal(p[:3], make([]byte, 3)) || p[3] != 0x7f {
		t.Fatalf("tail %d %v %x", n, err, p)
	}
	if _, err := file.WriteAt([]byte{1}, 0); err == nil {
		t.Fatal("mutable zeros")
	}
	if _, err := file.ReadAt(p, -1); err == nil {
		t.Fatal("negative offset accepted")
	}
	small, err := binaryZerosBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(4096)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockValue, err := starlark.Call(&starlark.Thread{Name: "device"}, blockstar.Builtins()["device"], starlark.Tuple{small}, nil)
	if err != nil {
		t.Fatal(err)
	}
	device, err := blockstar.AsDevice(blockValue)
	if err != nil {
		t.Fatal(err)
	}
	p = bytes.Repeat([]byte{0x7f}, 512)
	if n, err := device.ReadAt(p, 3584); n != 512 || err != nil || !bytes.Equal(p, make([]byte, 512)) {
		t.Fatalf("block %d %v", n, err)
	}
	for _, size := range []starlark.Int{starlark.MakeInt(-1), starlark.MakeUint64(math.MaxUint64)} {
		if _, err := binaryZerosBuiltin(nil, nil, starlark.Tuple{size}, nil); err == nil {
			t.Fatal("invalid size accepted", size)
		}
	}
	empty, err := binaryZerosBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("size"), starlark.MakeInt(0)}})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := empty.(starfile.File).ReadAt(p, 0); n != 0 || err != io.EOF {
		t.Fatalf("empty %d %v", n, err)
	}
}
