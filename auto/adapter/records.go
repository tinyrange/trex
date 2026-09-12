package adapter

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"path"
	"strings"
)

// Repeated record paths are distinct objects. Numbered occurrences under the
// original path preserve them without inventing potentially colliding siblings.
func recordTree(items []auto.Entry, options auto.Options) (auto.View, error) {
	if options.MaxEntries > 0 && len(items) > options.MaxEntries {
		return nil, fmt.Errorf("%w: record count", auto.ErrLimit)
	}
	indices := map[string]int{}
	groups := map[int][]auto.Entry{}
	var out []auto.Entry
	for _, e := range items {
		for _, part := range strings.Split(strings.ReplaceAll(e.Name, "\\", "/"), "/") {
			if part == ".." || strings.ContainsRune(part, 0) {
				return nil, fmt.Errorf("unsafe archive path %q", e.Name)
			}
		}
		key := path.Clean("/" + strings.ReplaceAll(e.Name, "\\", "/"))
		if i, found := indices[key]; found && e.Kind != "directory" {
			if out[i].Kind == "directory" {
				return ordinalRecords(items, options)
			}
			group := groups[i]
			if group == nil {
				first := out[i]
				first.Name = "1"
				group = []auto.Entry{first}
			}
			e.Name = fmt.Sprint(len(group) + 1)
			groups[i] = append(group, e)
		} else {
			if i, found := indices[key]; found && out[i].Kind != "directory" {
				return ordinalRecords(items, options)
			}
			indices[key] = len(out)
			out = append(out, e)
		}
	}
	for i, group := range groups {
		out[i].Reader = nil
		out[i].View = auto.ViewFunc(func() ([]auto.Entry, error) { return group, nil })
		out[i].Attributes = map[string]any{"occurrences": len(group)}
	}
	for _, e := range out {
		key := path.Clean("/" + strings.ReplaceAll(e.Name, "\\", "/"))
		for parent := path.Dir(key); parent != "/"; parent = path.Dir(parent) {
			if i, found := indices[parent]; found && out[i].Kind != "directory" {
				return ordinalRecords(items, options)
			}
		}
	}
	return auto.Tree(out, options)
}

// Installer metadata may legitimately use a directory's name. In that case
// present the original record sequence, keeping paths as metadata instead of
// pretending that the records form a conventional filesystem.
func ordinalRecords(items []auto.Entry, options auto.Options) (auto.View, error) {
	entries := make([]auto.Entry, len(items))
	for i, e := range items {
		for _, part := range strings.Split(strings.ReplaceAll(e.Name, "\\", "/"), "/") {
			if part == ".." || strings.ContainsRune(part, 0) {
				return nil, fmt.Errorf("unsafe archive path %q", e.Name)
			}
		}
		attrs := map[string]any{"original_path": e.Name}
		for k, v := range e.Attributes {
			attrs[k] = v
		}
		e.Attributes = attrs
		e.Name = fmt.Sprint(i + 1)
		if e.Kind == "directory" && e.View == nil {
			e.View = auto.ViewFunc(func() ([]auto.Entry, error) { return nil, nil })
		}
		entries[i] = e
	}
	return &auto.DescribedView{View: auto.ViewFunc(func() ([]auto.Entry, error) { return entries, nil }), Attributes: map[string]any{"record_namespace": "ordinal"}}, nil
}
