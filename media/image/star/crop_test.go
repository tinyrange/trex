package star

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestCropExcludesOutsidePixelsAndPreservesCoordinatesAlpha(t *testing.T) {
	frame := image.NewNRGBA(image.Rect(0, 0, 4, 3))
	for y := 0; y < 3; y++ {
		for x := 0; x < 4; x++ {
			frame.SetNRGBA(x, y, color.NRGBA{R: 255, A: 255})
		}
	}
	frame.SetNRGBA(1, 1, color.NRGBA{R: 17, G: 34, B: 51, A: 128})
	frame.SetNRGBA(2, 1, color.NRGBA{G: 222, A: 255})
	var source bytes.Buffer
	if err := png.Encode(&source, frame); err != nil {
		t.Fatal(err)
	}
	value, err := imageCropBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(source.String()), starlark.MakeInt(1), starlark.MakeInt(1), starlark.MakeInt(2), starlark.MakeInt(1)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := starfile.ReadAll(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	result, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if result.Bounds() != image.Rect(0, 0, 2, 1) {
		t.Fatal(result.Bounds())
	}
	for x, want := range []color.NRGBA{{R: 17, G: 34, B: 51, A: 128}, {G: 222, A: 255}} {
		got := color.NRGBAModel.Convert(result.At(x, 0)).(color.NRGBA)
		if got != want {
			t.Fatalf("pixel%d got%v want%v", x, got, want)
		}
	}
}

func TestCropRejectsBadBoundsOverflowAndDecodeLimits(t *testing.T) {
	src := encodedTestImage(t, false)
	for _, r := range [][4]int{{-1, 0, 1, 1}, {0, -1, 1, 1}, {0, 0, 0, 1}, {0, 0, 1, -1}, {19, 0, 2, 1}, {0, 9, 1, 2}, {int(^uint(0) >> 1), 0, 2, 1}} {
		_, err := imageCropBuiltin(nil, nil, starlark.Tuple{src, starlark.MakeInt(r[0]), starlark.MakeInt(r[1]), starlark.MakeInt(r[2]), starlark.MakeInt(r[3])}, nil)
		if err == nil {
			t.Fatalf("accepted%v", r)
		}
	}
	args := starlark.Tuple{src, starlark.MakeInt(0), starlark.MakeInt(0), starlark.MakeInt(1), starlark.MakeInt(1)}
	for _, kw := range []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt(1)}, {starlark.String("max_pixels"), starlark.MakeInt(1)}} {
		if _, err := imageCropBuiltin(nil, nil, args, []starlark.Tuple{kw}); err == nil {
			t.Fatal("decode limit ignored")
		}
	}
}
