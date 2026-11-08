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
	maximum, maxErrors := 16777216, 0
	if err := starlark.UnpackArgs("ckd_scan", args, kwargs, "file", &value, "max_tracks?", &maximum, "max_errors?", &maxErrors); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maximum <= 0 || maxErrors < 0 || maxErrors > 1<<20 {
		return nil, fmt.Errorf("ckd_scan: portable file, positive max_tracks and max_errors in 0..1M required")
	}
	d, err := Open(source)
	if err != nil {
		return nil, err
	}
	if maxErrors > 0 {
		return d.scanTolerant(maximum, maxErrors)
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

// scanTolerant parses every track implied by the image size and records
// per-track failures instead of stopping, so isolated media damage can be
// distinguished from systematic decoding faults. It still fails on an image
// size that is not cylinder-aligned or when maxErrors is exceeded.
func (d *Disk) scanTolerant(maximum, maxErrors int) (starlark.Value, error) {
	cylinder := int64(d.TrackSize) * int64(d.Heads)
	size := d.Source.Size() - 512
	if size <= 0 || size%cylinder != 0 {
		return nil, fmt.Errorf("ckd_scan: image size %d is not cylinder-aligned", d.Source.Size())
	}
	tracks := size / int64(d.TrackSize)
	if tracks > int64(maximum) {
		return nil, fmt.Errorf("ckd_scan: track limit exceeded")
	}
	var s Stats
	var failures []starlark.Value
	for t := uint32(0); int64(t) < tracks; t++ {
		records, err := d.Track(t)
		if err != nil {
			if len(failures) == maxErrors {
				return nil, fmt.Errorf("ckd_scan: more than %d track errors; last: %w", maxErrors, err)
			}
			failures = append(failures, starfile.NewRecord(starlark.StringDict{"track": starlark.MakeUint64(uint64(t)), "error": starlark.String(err.Error())}))
			continue
		}
		s.Tracks++
		s.Records += int64(len(records))
		for _, r := range records {
			s.DataBytes += int64(len(r.Data))
			s.KeyBytes += int64(len(r.Key))
		}
	}
	return starfile.NewRecord(starlark.StringDict{
		"tracks": starlark.MakeInt64(s.Tracks), "records": starlark.MakeInt64(s.Records),
		"data_bytes": starlark.MakeInt64(s.DataBytes), "key_bytes": starlark.MakeInt64(s.KeyBytes),
		"image_bytes": starlark.MakeInt64(d.Source.Size()), "errors": starlark.NewList(failures),
	}), nil
}
