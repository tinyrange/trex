package cab

import (
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/tinyrange/trex/auto"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

// wrappedCompanion considers just one layer of independent CAB wrappers in
// the containing directory. It does not enter arbitrary files or search the
// host filesystem. This supports IE_Sn.CAB -> IE_n.CAB distributions.
func wrappedCompanion(context *auto.SourceContext, name string, o auto.Options, store *bytecache.Cache) (auto.Entry, error) {
	if context.Parent == nil || context.Parent.Tree == nil || path.Dir(name) != path.Dir(context.Path) {
		return auto.Entry{}, fs.ErrNotExist
	}
	parent := context.Parent
	view := parent.Tree
	if dir := path.Dir(parent.Path); dir != "." {
		e, err := parent.Lookup(dir, o)
		if err != nil {
			return auto.Entry{}, err
		}
		if e.Kind != "directory" || e.View == nil {
			return auto.Entry{}, fs.ErrNotExist
		}
		view = e.View
	}
	siblings, err := view.Entries()
	if err != nil {
		return auto.Entry{}, err
	}
	if len(siblings) > o.MaxEntries {
		return auto.Entry{}, auto.ErrLimit
	}
	var found auto.Entry
	candidates, entries := 0, 0
	for i, sibling := range siblings {
		if sibling.Kind != "file" || sibling.Reader == nil {
			continue
		}
		var signature [4]byte
		if _, err := sibling.Reader.ReadAt(signature[:], 0); err != nil || string(signature[:]) != "MSCF" {
			continue
		}
		candidates++
		if candidates > 256 {
			return auto.Entry{}, auto.ErrLimit
		}
		archive, err := OpenWithCache(sibling.Reader, true, store, 1<<32+uint64(i))
		if err != nil || archive.flags&3 != 0 {
			continue
		}
		entries += len(archive.files)
		if entries > o.MaxEntries {
			return auto.Entry{}, auto.ErrLimit
		}
		for _, f := range archive.files {
			candidate := strings.TrimPrefix(strings.ReplaceAll(f.name, string([]byte{92}), "/"), "/")
			if !strings.EqualFold(candidate, name) {
				continue
			}
			if found.Reader != nil {
				return auto.Entry{}, fmt.Errorf("cab: ambiguous wrapped companion %q", name)
			}
			reader, err := archive.LookupExact(f.name)
			if err != nil {
				return auto.Entry{}, err
			}
			found = auto.Entry{Name: name, Kind: "file", Reader: reader}
		}
	}
	if found.Reader == nil {
		return auto.Entry{}, fs.ErrNotExist
	}
	return found, nil
}
