package star

import (
	"bytes"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"image"
	"image/draw"
	"image/png"
)

// imageCropBuiltin returns newly encoded pixels only: excluded pixels and source
// metadata are never retained in the result. Coordinates are source-relative.
func imageCropBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var x, y, width, height int
	maximum := int64(defaultImageInputLimit)
	maxPixels := int64(defaultImagePixelLimit)
	if err := starlark.UnpackArgs("image.crop", args, kwargs, "source", &source, "x", &x, "y", &y, "width", &width, "height", &height, "maximum?", &maximum, "max_pixels?", &maxPixels); err != nil {
		return nil, err
	}
	if x < 0 || y < 0 || width <= 0 || height <= 0 {
		return nil, fmt.Errorf("image.crop: origin must be nonnegative and dimensions positive")
	}
	decoded, _, err := decodeBoundedImage(source, maximum, maxPixels)
	if err != nil {
		return nil, fmt.Errorf("image.crop: %w", err)
	}
	bounds := decoded.Bounds()
	// Subtraction avoids overflowing x+width on hostile arguments.
	if x > bounds.Dx() || y > bounds.Dy() || width > bounds.Dx()-x || height > bounds.Dy()-y {
		return nil, fmt.Errorf("image.crop: rectangle outside %dx%d image", bounds.Dx(), bounds.Dy())
	}
	cropped := image.NewNRGBA(image.Rect(0, 0, width, height))
	draw.Draw(cropped, cropped.Bounds(), decoded, bounds.Min.Add(image.Pt(x, y)), draw.Src)
	var output bytes.Buffer
	if err := png.Encode(&output, cropped); err != nil {
		return nil, fmt.Errorf("image.crop: encode PNG: %w", err)
	}
	return &starfile.Bytes{Name: "cropped.png", Data: output.Bytes()}, nil
}
