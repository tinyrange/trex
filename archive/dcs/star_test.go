package dcs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestBoundedDCSFile(t *testing.T) {
	// Independent Microsoft Compression API pattern fixture, also used by lzms tests.
	raw, _ := base64.StdEncoding.DecodeString("OBPQvwAA0HSBfr66/srvvq3e")
	data := []byte{'D', 'C', 'S', 1, 1, 0, 0, 0, 0, 32, 0, 0}
	data = binary.LittleEndian.AppendUint32(data, uint32(len(raw)+4))
	data = binary.LittleEndian.AppendUint32(data, 8192)
	data = append(data, raw...)
	file := &starfile.Bytes{Name: "fixture", Data: data}
	decoded, err := Open(file, 8192)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(decoded, 0, decoded.Size()))
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(got)) != "d0691fda8844318e6b51e6099ffef9ffe0f88a96a5971d28e2c5c4e39224c046" {
		t.Fatalf("decoded hash: %v", err)
	}
	for _, limit := range []int64{-1, 0, 12, 8191, 512<<20 + 1} {
		if _, err := Open(file, limit); err == nil {
			t.Fatalf("accepted bound %d", limit)
		}
	}
	if _, err := Open(&starfile.Bytes{Data: append(data, 0)}, 8192); err == nil {
		t.Fatal("accepted trailing byte")
	}
	if _, err := Builtin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, nil); err == nil {
		t.Fatal("accepted bytes instead of file")
	}
	if _, err := Builtin(nil, nil, starlark.Tuple{file}, []starlark.Tuple{{starlark.String("maximum_bytes"), starlark.MakeInt(8191)}}); err == nil {
		t.Fatal("binding ignored bound")
	}
	if _, err := Builtin(nil, nil, starlark.Tuple{file}, nil); err != nil {
		t.Fatal(err)
	}
}
