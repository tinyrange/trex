package windows

import (
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

// bitmapInfo describes the layout of a Windows uncompressed RGB DIB. Parsing
// the header does not allocate the pixel array or depend on a host display.
type bitmapInfo struct {
	Width, Height, Depth, Stride, Size int64
	TopDown                            bool
}

func parseBitmapInfo(data []byte) (bitmapInfo, error) {
	var info bitmapInfo
	if len(data) < 40 || binary.LittleEndian.Uint32(data) < 40 {
		return info, fmt.Errorf("bitmap_info: truncated BITMAPINFOHEADER")
	}
	info.Width = int64(int32(binary.LittleEndian.Uint32(data[4:])))
	info.Height = int64(int32(binary.LittleEndian.Uint32(data[8:])))
	info.Depth = int64(binary.LittleEndian.Uint16(data[14:]))
	info.TopDown = info.Height < 0
	if info.TopDown {
		info.Height = -info.Height
	}
	if info.Width <= 0 || info.Height == 0 || binary.LittleEndian.Uint16(data[12:]) != 1 {
		return bitmapInfo{}, fmt.Errorf("bitmap_info: invalid dimensions or plane count")
	}
	if binary.LittleEndian.Uint32(data[16:]) != 0 || (info.Depth != 24 && info.Depth != 32) {
		return bitmapInfo{}, fmt.Errorf("bitmap_info: requires uncompressed 24/32-bit RGB")
	}
	info.Stride = ((info.Width*info.Depth + 31) / 32) * 4
	if info.Height > (1<<63-1)/info.Stride {
		return bitmapInfo{}, fmt.Errorf("bitmap_info: pixel size overflow")
	}
	info.Size = info.Stride * info.Height
	return info, nil
}

func bitmapInfoBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Bytes
	if err := starlark.UnpackArgs("bitmap_info", args, kwargs, "header", &data); err != nil {
		return nil, err
	}
	info, err := parseBitmapInfo([]byte(data))
	if err != nil {
		return nil, err
	}
	result := starlark.NewDict(6)
	for name, value := range map[string]int64{"width": info.Width, "height": info.Height, "depth": info.Depth, "stride": info.Stride, "size": info.Size} {
		if err := result.SetKey(starlark.String(name), starlark.MakeInt64(value)); err != nil {
			return nil, err
		}
	}
	if err := result.SetKey(starlark.String("top_down"), starlark.Bool(info.TopDown)); err != nil {
		return nil, err
	}
	return result, nil
}
