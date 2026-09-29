package star

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
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

func TestImageSamplePreservesOrderDuplicatesAndPixelColors(t *testing.T) {
	frame := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	frame.SetNRGBA(0, 0, color.NRGBA{R: 17, G: 34, B: 51, A: 255})
	frame.SetNRGBA(1, 0, color.NRGBA{R: 200, G: 100, B: 50, A: 128})
	var output bytes.Buffer
	if err := png.Encode(&output, frame); err != nil {
		t.Fatal(err)
	}
	source := starlark.Bytes(output.String())
	points := starlark.Tuple{
		starlark.NewList([]starlark.Value{starlark.MakeInt(1), starlark.MakeInt(0)}),
		starlark.Tuple{starlark.MakeInt(0), starlark.MakeInt(0)},
		starlark.Tuple{starlark.MakeInt(1), starlark.MakeInt(1)},
		starlark.Tuple{starlark.MakeInt(1), starlark.MakeInt(0)},
	}
	value, err := starlark.Call(&starlark.Thread{}, Builtins()["sample"], starlark.Tuple{source, points}, nil)
	if err != nil {
		t.Fatal(err)
	}
	colors := value.(*starlark.List)
	if colors.Len() != len(points) {
		t.Fatalf("sample returned %d colors, want %d", colors.Len(), len(points))
	}
	wantColors := [][4]int{{100, 50, 25, 128}, {17, 34, 51, 255}, {0, 0, 0, 0}, {100, 50, 25, 128}}
	for i, point := range points {
		pair := point.(starlark.Indexable)
		pixel, err := imagePixelBuiltin(nil, nil, starlark.Tuple{source, pair.Index(0), pair.Index(1)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := colors.Index(i).(*starvalue.Record)
		for channel, name := range []string{"r", "g", "b", "a"} {
			want := starlark.MakeInt(wantColors[i][channel])
			if got.Values[name] != want || got.Values[name] != pixel.(*starvalue.Record).Values[name] {
				t.Errorf("point %d %s = %s, want %s and image.pixel agreement", i, name, got.Values[name], want)
			}
		}
	}
}

type countedImageFile struct {
	starfile.Bytes
	reads int
}

func (f *countedImageFile) ReadAt(data []byte, offset int64) (int, error) {
	f.reads++
	return f.Bytes.ReadAt(data, offset)
}

func TestImageSampleReadsOnceWithoutCaching(t *testing.T) {
	source := &countedImageFile{Bytes: starfile.Bytes{Data: []byte(encodedTestImage(t, false))}}
	points := make([]starlark.Value, 2800)
	for i := range points {
		points[i] = starlark.Tuple{starlark.MakeInt(0), starlark.MakeInt(0)}
	}
	for call, want := range []int{20, 220} {
		value, err := imageSampleBuiltin(nil, nil, starlark.Tuple{source, starlark.NewList(points)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		colors := value.(*starlark.List)
		if colors.Len() != len(points) || source.reads != call+1 {
			t.Fatalf("call %d: %d colors and %d source reads", call, colors.Len(), source.reads)
		}
		for i := range points {
			got := colors.Index(i).(*starvalue.Record).Values["r"]
			if got != starlark.MakeInt(want) {
				t.Fatalf("call %d point %d red = %s, want %d", call, i, got, want)
			}
		}
		source.Data = []byte(encodedTestImage(t, true))
	}
}

func TestImageSampleRejectsMalformedAndOutOfBoundsPoints(t *testing.T) {
	source := encodedTestImage(t, false)
	point := func(x, y int) starlark.Value {
		return starlark.NewList([]starlark.Value{starlark.Tuple{starlark.MakeInt(x), starlark.MakeInt(y)}})
	}
	for _, tc := range []struct {
		name, want string
		points     starlark.Value
	}{
		{"outer string", "points must be a list or tuple", starlark.String("00")},
		{"outer dict", "points must be a list or tuple", starlark.NewDict(0)},
		{"point string", "point 0 must be an (x, y) list or tuple", starlark.Tuple{starlark.String("00")}},
		{"short point", "exactly two coordinates", starlark.Tuple{starlark.Tuple{starlark.MakeInt(0)}}},
		{"long point", "exactly two coordinates", starlark.Tuple{starlark.Tuple{starlark.MakeInt(0), starlark.MakeInt(0), starlark.MakeInt(0)}}},
		{"float x", "point 0 x", starlark.Tuple{starlark.Tuple{starlark.Float(0), starlark.MakeInt(0)}}},
		{"bool y", "point 0 y", starlark.Tuple{starlark.Tuple{starlark.MakeInt(0), starlark.False}}},
		{"overflow x", "point 0 x", starlark.Tuple{starlark.Tuple{starlark.MakeUint64(^uint64(0)), starlark.MakeInt(0)}}},
		{"negative x", "outside 20x10 image", point(-1, 0)},
		{"negative y", "outside 20x10 image", point(0, -1)},
		{"past width", "outside 20x10 image", point(20, 0)},
		{"past height", "outside 20x10 image", point(0, 10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := imageSampleBuiltin(nil, nil, starlark.Tuple{source, tc.points}, nil)
			if value != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("sample = %v, %v; want no result and error containing %q", value, err, tc.want)
			}
		})
	}
}

func TestImageSampleBoundsAndEmptySelection(t *testing.T) {
	source := &countedImageFile{Bytes: starfile.Bytes{Data: []byte(encodedTestImage(t, false))}}
	empty := starlark.NewList(nil)
	for _, tc := range []struct {
		name, key string
		limit     int64
	}{
		{"zero pixels", "max_pixels", 0},
		{"excessive pixels", "max_pixels", 1<<30 + 1},
		{"image pixels", "max_pixels", 199},
		{"zero bytes", "maximum", 0},
		{"excessive bytes", "maximum", 1<<30 + 1},
		{"encoded bytes", "maximum", int64(len(source.Data)) - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := imageSampleBuiltin(nil, nil, starlark.Tuple{source, empty}, []starlark.Tuple{{starlark.String(tc.key), starlark.MakeInt64(tc.limit)}}); err == nil {
				t.Fatal("invalid limit unexpectedly succeeded")
			}
		})
	}
	points := starlark.Tuple{starlark.Tuple{starlark.MakeInt(0), starlark.MakeInt(0)}, starlark.Tuple{starlark.MakeInt(0), starlark.MakeInt(0)}}
	source.reads = 0
	if _, err := imageSampleBuiltin(nil, nil, starlark.Tuple{source, points}, []starlark.Tuple{{starlark.String("max_pixels"), starlark.MakeInt(1)}}); err == nil || !strings.Contains(err.Error(), "point count") {
		t.Fatalf("point count bound: %v", err)
	}
	if source.reads != 0 {
		t.Fatal("point count bound read the image before rejecting the request")
	}
	value, err := imageSampleBuiltin(nil, nil, starlark.Tuple{source, empty}, nil)
	if err != nil || value.(*starlark.List).Len() != 0 {
		t.Fatalf("empty sample = %v, %v", value, err)
	}
	if _, err := imageSampleBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("bad PNG"), empty}, nil); err == nil || !strings.Contains(err.Error(), "decode image header") {
		t.Fatalf("invalid source: %v", err)
	}
}
