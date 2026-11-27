package sevenzip

import (
	"fmt"

	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"golang.org/x/sync/errgroup"
)

// MaterializeBuiltin decodes complete members into independent read-only files
// for callers that need random access throughout a compressed member.
func MaterializeBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	const name = "sevenzip_unpack"
	var members *starlark.List
	var maximum int64
	workers := 4
	if err := starlark.UnpackArgs(name, args, kwargs, "members", &members, "maximum_bytes", &maximum, "workers?", &workers); err != nil {
		return nil, err
	}
	if maximum <= 0 || workers < 1 || workers > 8 {
		return nil, fmt.Errorf("%s: require a positive byte limit and 1..8 workers", name)
	}
	entries := make([]*Entry, members.Len())
	var total int64
	for i := range entries {
		entry, ok := members.Index(i).(*Entry)
		if !ok || entry.directory || entry.anti {
			return nil, fmt.Errorf("%s: members[%d] must be a 7z file member", name, i)
		}
		if entry.size < 0 || entry.size > int64(int(^uint(0)>>1)) || entry.size > maximum-total {
			return nil, fmt.Errorf("%s: members exceed the %d-byte limit at %q", name, maximum, entry.path)
		}
		entries[i] = entry
		total += entry.size
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	group, ctx := errgroup.WithContext(resources.Context())
	group.SetLimit(workers)
	results := make([]starlark.Value, len(entries))
	for i, entry := range entries {
		group.Go(func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			data := make([]byte, int(entry.size))
			for off := 0; off < len(data); {
				if err := ctx.Err(); err != nil {
					return err
				}
				end := off + min(4<<20, len(data)-off)
				if _, err := starfile.ReadFullAt(entry, data[off:end], int64(off)); err != nil {
					return fmt.Errorf("%s: %q: %w", name, entry.path, err)
				}
				off = end
			}
			results[i] = &starfile.Bytes{Data: data}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return starlark.NewList(results), nil
}
