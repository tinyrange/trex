package cpio

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/binary/appledouble"
	"path"
	"strings"
)

// WithAppleDouble explicitly folds macOS ._ sidecars into the matching entry.
// No original payloads or input attribute maps are changed. Missing targets,
// malformed metadata and unsupported IDs fail rather than silently losing data.
func WithAppleDouble(entries []auto.Entry) ([]auto.Entry, error) {
	byName := make(map[string]int, len(entries))
	out := make([]auto.Entry, 0, len(entries))
	var sidecars []auto.Entry
	for _, e := range entries {
		if strings.HasPrefix(path.Base(e.Name), "._") {
			sidecars = append(sidecars, e)
		} else {
			byName[e.Name] = len(out)
			out = append(out, e)
		}
	}
	for _, e := range sidecars {
		if e.Kind != "file" || e.Reader == nil {
			return nil, fmt.Errorf("cpio: AppleDouble sidecar %q is not a file", e.Name)
		}
		name := path.Join(path.Dir(e.Name), strings.TrimPrefix(path.Base(e.Name), "._"))
		index, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("cpio: AppleDouble sidecar %q has no target", e.Name)
		}
		m, err := appledouble.OpenMetadata(e.Reader)
		if err != nil {
			return nil, fmt.Errorf("cpio: AppleDouble sidecar %q: %w", e.Name, err)
		}
		if len(m.Other) != 0 {
			return nil, fmt.Errorf("cpio: AppleDouble sidecar %q has unsupported entry ID %d", e.Name, m.Other[0].ID)
		}
		attrs := make(map[string]any, len(out[index].Attributes)+3)
		for k, v := range out[index].Attributes {
			attrs[k] = v
		}
		if m.FinderInfo != nil {
			attrs["finder_info"] = m.FinderInfo
		}
		if m.Resource != nil {
			attrs["resource"] = m.Resource
		}
		if len(m.Attributes) != 0 {
			attrs["xattrs"] = m.Attributes
		}
		out[index].Attributes = attrs
	}
	return out, nil
}
