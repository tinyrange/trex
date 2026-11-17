package ckd

import (
	"bytes"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestVolumeCanonicalImageFromCompressedInput(t *testing.T) {
	want := fixture()
	compressed := compressImage(t, want, cckdOptions{raw: map[int]bool{2: true}})
	value, err := VolumeBuiltin(nil, nil, starlark.Tuple{starfile.NewReader("compressed.ckd", raw(compressed))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v := value.(*VolumeValue)
	image, err := v.Attr("image")
	if err != nil {
		t.Fatal(err)
	}
	reader := image.(storage.Reader)
	got := make([]byte, reader.Size())
	if _, err = reader.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("image did not expose the complete canonical uncompressed volume")
	}
	reopened, err := Open(reader)
	if err != nil {
		t.Fatal(err)
	}
	vtoc, err := reopened.ReadVTOC(20)
	if err != nil || vtoc.Serial != "TEST01" || len(vtoc.Datasets) != 1 {
		t.Fatalf("canonical image lost filesystem contents: %+v %v", vtoc, err)
	}
	for name, want := range map[string]int{"device": int(reopened.Device), "track_size": int(reopened.TrackSize), "heads": int(reopened.Heads), "tracks": 6} {
		attr, err := v.Attr(name)
		if err != nil {
			t.Fatal(err)
		}
		n, err := starlark.AsInt32(attr)
		if err != nil || n != want {
			t.Fatalf("%s: %v %v, want %d", name, attr, err, want)
		}
	}
}
