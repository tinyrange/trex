package ckd

import (
	"context"
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// ScanBuiltin exposes the physical reader's full validation without host paths.
// Dataset selection, directory enumeration and corpus checks stay in Starlark.
func ScanBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 16777216
	if err := starlark.UnpackArgs("ckd_scan", args, kwargs, "file", &value, "max_tracks?", &maximum); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maximum <= 0 {
		return nil, fmt.Errorf("ckd_scan: portable file and positive max_tracks required")
	}
	d, err := Open(source)
	if err != nil {
		return nil, err
	}
	stats, err := d.Walk(context.Background(), func(track uint32, _ []Record) error {
		if uint64(track) >= uint64(maximum) {
			return fmt.Errorf("ckd_scan: track limit exceeded")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{
		"tracks": starlark.MakeInt64(stats.Tracks), "records": starlark.MakeInt64(stats.Records),
		"data_bytes": starlark.MakeInt64(stats.DataBytes), "key_bytes": starlark.MakeInt64(stats.KeyBytes),
		"image_bytes": starlark.MakeInt64(stats.ImageBytes),
	}), nil
}
