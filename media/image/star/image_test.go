package star

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func encodedTestImage(t *testing.T, changed bool) starlark.Bytes {
	t.Helper()
	frame := image.NewRGBA(image.Rect(0, 0, 20, 10))
	for y := 0; y < 10; y++ {
		for x := 0; x < 20; x++ {
			shade := uint8(20)
			if changed && x < 5 {
				shade = 220
			}
			frame.SetRGBA(x, y, color.RGBA{R: shade, G: shade, B: shade, A: 255})
		}
	}
	var output bytes.Buffer
	if err := png.Encode(&output, frame); err != nil {
		t.Fatal(err)
	}
	return starlark.Bytes(output.String())
}

func TestImageCompareReportsMaterialPixelChanges(t *testing.T) {
	left := encodedTestImage(t, false)
	right := encodedTestImage(t, true)
	value, err := imageCompareBuiltin(nil, nil, starlark.Tuple{left, right}, nil)
	if err != nil {
		t.Fatal(err)
	}
	record := value.(*starvalue.Record)
	changed, _ := record.Values["changed_pixels"].(starlark.Int).Uint64()
	ppm, _ := record.Values["changed_ppm"].(starlark.Int).Uint64()
	if changed != 50 || ppm != 250000 {
		t.Fatalf("changed pixels = %d (%d ppm), want 50 (250000 ppm)", changed, ppm)
	}
}

func TestImageCompareRejectsDimensionMismatch(t *testing.T) {
	left := encodedTestImage(t, false)
	frame := image.NewRGBA(image.Rect(0, 0, 1, 1))
	var output bytes.Buffer
	if err := png.Encode(&output, frame); err != nil {
		t.Fatal(err)
	}
	if _, err := imageCompareBuiltin(nil, nil, starlark.Tuple{left, starlark.Bytes(output.String())}, nil); err == nil {
		t.Fatal("dimension mismatch unexpectedly succeeded")
	}
}

func TestImagePixelSamplesDecodedColor(t *testing.T) {
	frame := image.NewRGBA(image.Rect(0, 0, 2, 2))
	frame.SetRGBA(1, 0, color.RGBA{R: 17, G: 34, B: 51, A: 255})
	var output bytes.Buffer
	if err := png.Encode(&output, frame); err != nil {
		t.Fatal(err)
	}
	value, err := imagePixelBuiltin(nil, nil, starlark.Tuple{
		starlark.Bytes(output.String()), starlark.MakeInt(1), starlark.MakeInt(0),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	record := value.(*starvalue.Record)
	for name, want := range map[string]uint64{"r": 17, "g": 34, "b": 51, "a": 255} {
		got, _ := record.Values[name].(starlark.Int).Uint64()
		if got != want {
			t.Fatalf("%s = %d, want %d", name, got, want)
		}
	}
}

func TestImagePixelRejectsOutOfBoundsCoordinate(t *testing.T) {
	image := encodedTestImage(t, false)
	if _, err := imagePixelBuiltin(nil, nil, starlark.Tuple{
		image, starlark.MakeInt(20), starlark.MakeInt(0),
	}, nil); err == nil {
		t.Fatal("out-of-bounds coordinate unexpectedly succeeded")
	}
}

func TestDecodedImageSnapshotDoesNotReadSourceAgain(t *testing.T) {
	data := []byte(encodedTestImage(t, false))
	source := &starfile.Bytes{Data: data}
	v, err := imageDecodeBuiltin(nil, nil, starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := v.(*starvalue.Record)
	if width, _ := snapshot.Values["width"].(starlark.Int).Int64(); width != 20 {
		t.Fatal(width)
	}
	// Destroy the mutable encoded input after snapshot construction. Sampling
	// must remain valid: neither a hidden decode nor an alias into source RAM.
	clear(data)
	pixel := snapshot.Values["pixel"].(*starlark.Builtin)
	for n := 0; n < 20; n++ {
		v, err = starlark.Call(&starlark.Thread{Name: "snapshot"}, pixel, starlark.Tuple{starlark.MakeInt(n), starlark.MakeInt(0)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r, _ := v.(*starvalue.Record).Values["r"].(starlark.Int).Int64(); r != 20 {
			t.Fatal(r)
		}
	}
	if _, err = starlark.Call(&starlark.Thread{}, pixel, starlark.Tuple{starlark.MakeInt(20), starlark.MakeInt(0)}, nil); err == nil {
		t.Fatal("snapshot accepted out-of-bounds coordinates")
	}
}
func TestDecodedImageSnapshotHonorsInputAndPixelLimits(t *testing.T) {
	source := encodedTestImage(t, false)
	for _, arg := range []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt(1)}, {starlark.String("max_pixels"), starlark.MakeInt(199)}} {
		if _, err := imageDecodeBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{arg}); err == nil {
			t.Fatal("snapshot bypassed image resource limit", arg)
		}
	}
}
