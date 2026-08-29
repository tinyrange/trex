package star

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	defaultImageInputLimit = 128 << 20
	defaultImagePixelLimit = 16 << 20
)

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"compare": starlark.NewBuiltin("image.compare", imageCompareBuiltin),
		"info":    starlark.NewBuiltin("image.info", imageInfoBuiltin),
		"pixel":   starlark.NewBuiltin("image.pixel", imagePixelBuiltin),
	}
}

func boundedImageBytes(value starlark.Value, maximum int64) ([]byte, error) {
	if maximum < 1 || maximum > 1<<30 {
		return nil, fmt.Errorf("maximum must be between 1 byte and 1 GiB")
	}
	if file, ok := value.(starfile.File); ok {
		if file.Size() < 0 || file.Size() > maximum {
			return nil, fmt.Errorf("encoded image size %d exceeds limit %d", file.Size(), maximum)
		}
		data := make([]byte, file.Size())
		_, err := starfile.ReadFullAt(file, data, 0)
		return data, err
	}
	data, err := starfile.BytesForValue(value, maximum)
	if err != nil {
		return nil, fmt.Errorf("got %s, want file, string, or bytes", value.Type())
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("encoded image size %d exceeds limit %d", len(data), maximum)
	}
	return data, nil
}

func decodeBoundedImage(value starlark.Value, maximum, maxPixels int64) (image.Image, string, error) {
	if maxPixels < 1 || maxPixels > 1<<30 {
		return nil, "", fmt.Errorf("max_pixels must be between 1 and 1 GiPixel")
	}
	data, err := boundedImageBytes(value, maximum)
	if err != nil {
		return nil, "", err
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("decode image header: %w", err)
	}
	if config.Width < 1 || config.Height < 1 || int64(config.Width) > maxPixels/int64(config.Height) {
		return nil, "", fmt.Errorf("decoded image dimensions %dx%d exceed pixel limit %d", config.Width, config.Height, maxPixels)
	}
	decoded, decodedFormat, err := image.Decode(io.LimitReader(bytes.NewReader(data), maximum))
	if err != nil {
		return nil, "", fmt.Errorf("decode image: %w", err)
	}
	if decodedFormat != format {
		return nil, "", fmt.Errorf("image format changed from %s to %s while decoding", format, decodedFormat)
	}
	return decoded, format, nil
}

func imageInfoBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum := int64(defaultImageInputLimit)
	maxPixels := int64(defaultImagePixelLimit)
	if err := starlark.UnpackArgs("image.info", args, kwargs, "source", &source, "maximum?", &maximum, "max_pixels?", &maxPixels); err != nil {
		return nil, err
	}
	decoded, format, err := decodeBoundedImage(source, maximum, maxPixels)
	if err != nil {
		return nil, fmt.Errorf("image.info: %w", err)
	}
	bounds := decoded.Bounds()
	return starvalue.NewRecord(starlark.StringDict{
		"format": starlark.String(format),
		"height": starlark.MakeInt(bounds.Dy()),
		"pixels": starlark.MakeInt64(int64(bounds.Dx()) * int64(bounds.Dy())),
		"width":  starlark.MakeInt(bounds.Dx()),
	}), nil
}

func imagePixelBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	x, y := 0, 0
	maximum := int64(defaultImageInputLimit)
	maxPixels := int64(defaultImagePixelLimit)
	if err := starlark.UnpackArgs("image.pixel", args, kwargs,
		"source", &source, "x", &x, "y", &y,
		"maximum?", &maximum, "max_pixels?", &maxPixels); err != nil {
		return nil, err
	}
	decoded, _, err := decodeBoundedImage(source, maximum, maxPixels)
	if err != nil {
		return nil, fmt.Errorf("image.pixel: %w", err)
	}
	bounds := decoded.Bounds()
	if x < 0 || y < 0 || x >= bounds.Dx() || y >= bounds.Dy() {
		return nil, fmt.Errorf("image.pixel: coordinate (%d,%d) is outside %dx%d image", x, y, bounds.Dx(), bounds.Dy())
	}
	r, g, b, a := decoded.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
	return starvalue.NewRecord(starlark.StringDict{
		"r": starlark.MakeInt(int(r >> 8)),
		"g": starlark.MakeInt(int(g >> 8)),
		"b": starlark.MakeInt(int(b >> 8)),
		"a": starlark.MakeInt(int(a >> 8)),
	}), nil
}

func imageCompareBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var leftValue, rightValue starlark.Value
	threshold := 8
	maximum := int64(defaultImageInputLimit)
	maxPixels := int64(defaultImagePixelLimit)
	if err := starlark.UnpackArgs("image.compare", args, kwargs,
		"left", &leftValue, "right", &rightValue, "threshold?", &threshold,
		"maximum?", &maximum, "max_pixels?", &maxPixels); err != nil {
		return nil, err
	}
	if threshold < 0 || threshold > 255 {
		return nil, fmt.Errorf("image.compare: threshold must be between 0 and 255")
	}
	left, _, err := decodeBoundedImage(leftValue, maximum, maxPixels)
	if err != nil {
		return nil, fmt.Errorf("image.compare: left: %w", err)
	}
	right, _, err := decodeBoundedImage(rightValue, maximum, maxPixels)
	if err != nil {
		return nil, fmt.Errorf("image.compare: right: %w", err)
	}
	leftBounds, rightBounds := left.Bounds(), right.Bounds()
	if leftBounds.Dx() != rightBounds.Dx() || leftBounds.Dy() != rightBounds.Dy() {
		return nil, fmt.Errorf("image.compare: dimensions differ: %dx%d and %dx%d", leftBounds.Dx(), leftBounds.Dy(), rightBounds.Dx(), rightBounds.Dy())
	}
	pixels := int64(leftBounds.Dx()) * int64(leftBounds.Dy())
	limit := uint32(threshold) * 257
	var changed, absolute uint64
	for y := 0; y < leftBounds.Dy(); y++ {
		for x := 0; x < leftBounds.Dx(); x++ {
			lr, lg, lb, la := left.At(leftBounds.Min.X+x, leftBounds.Min.Y+y).RGBA()
			rr, rg, rb, ra := right.At(rightBounds.Min.X+x, rightBounds.Min.Y+y).RGBA()
			dr, dg := imageChannelDifference(lr, rr), imageChannelDifference(lg, rg)
			db, da := imageChannelDifference(lb, rb), imageChannelDifference(la, ra)
			absolute += uint64(dr) + uint64(dg) + uint64(db) + uint64(da)
			if dr > limit || dg > limit || db > limit || da > limit {
				changed++
			}
		}
	}
	meanDenominator := uint64(pixels) * 4 * 65535
	return starvalue.NewRecord(starlark.StringDict{
		"changed_pixels":          starlark.MakeUint64(changed),
		"changed_ppm":             starlark.MakeUint64(changed * 1_000_000 / uint64(pixels)),
		"height":                  starlark.MakeInt(leftBounds.Dy()),
		"mean_absolute_error_ppm": starlark.MakeUint64(absolute * 1_000_000 / meanDenominator),
		"pixels":                  starlark.MakeInt64(pixels),
		"threshold":               starlark.MakeInt(threshold),
		"width":                   starlark.MakeInt(leftBounds.Dx()),
	}), nil
}

func imageChannelDifference(left, right uint32) uint32 {
	if left > right {
		return left - right
	}
	return right - left
}
