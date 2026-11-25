package fat

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"time"
)

func (i *fatImage) AttrNames() []string { return []string{"metadata"} }
func (i *fatImage) Attr(name string) (starlark.Value, error) {
	if name == "metadata" {
		return starlark.NewBuiltin("fat.metadata", i.metadataBuiltin), nil
	}
	return nil, nil
}

// metadata exposes original DOS calendar words without inventing a timezone or
// normalizing invalid/unspecified dates. A FAT root has no owning short entry.
func (i *fatImage) metadataBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("fat.metadata", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	name = storage.CleanPath(name)
	if name == "/" {
		return starlark.None, nil
	}
	if name == "/$metadata" || i.virtualFile(name) != nil {
		return nil, fmt.Errorf("fat.metadata: virtual files have no DOS directory entry")
	}
	entry, err := i.lookup(name)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{
		"attributes":                starlark.MakeInt(int(entry.attr)),
		"creation_date":             starlark.MakeInt(int(entry.times.creationDate)),
		"creation_time":             starlark.MakeInt(int(entry.times.creationTime)),
		"creation_hundredths":       starlark.MakeInt(int(entry.times.creationHundredths)),
		"last_access_date":          starlark.MakeInt(int(entry.times.accessDate)),
		"last_write_date":           starlark.MakeInt(int(entry.times.writeDate)),
		"last_write_time":           starlark.MakeInt(int(entry.times.writeTime)),
		"last_write_local_filetime": fatLocalFiletime(entry.times.writeDate, entry.times.writeTime),
	}), nil
}

// fatLocalFiletime returns a FILETIME-shaped local calendar value. It is NOT
// UTC and must not silently acquire the host or guest timezone. Preserve bad
// DOS date/time words in metadata, but do not normalize them into a valid date.
func fatLocalFiletime(date, clock uint16) starlark.Value {
	year, month, day := 1980+int(date>>9), int(date>>5&15), int(date&31)
	hour, minute, second := int(clock>>11), int(clock>>5&63), int(clock&31)*2
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 {
		return starlark.None
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	if t.Year() != year || int(t.Month()) != month || t.Day() != day {
		return starlark.None
	}
	return starlark.MakeUint64(uint64(t.Unix()+11644473600) * 10000000)
}
