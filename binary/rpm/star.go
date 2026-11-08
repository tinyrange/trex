package rpm

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Names are convenience aliases for stored tags, not computed rpm query tags.
var names = map[uint32]string{
	1000: "name", 1001: "version", 1002: "release", 1003: "epoch",
	1004: "summary", 1005: "description", 1006: "build_time", 1007: "build_host",
	1008: "install_time", 1009: "size", 1010: "distribution", 1011: "vendor",
	1014: "license", 1015: "packager", 1016: "group", 1020: "url", 1021: "os", 1022: "arch",
	1044: "source_rpm", 1080: "changelog_time", 1081: "changelog_name", 1082: "changelog_text",
	1124: "payload_format", 1125: "payload_compressor", 1126: "payload_flags",
	1123: "dist_url", 1106: "source_package", 5011: "file_digest_algorithm", 5062: "encoding",
}

func entryValue(e Entry) starlark.Value {
	switch e.Type {
	case 0:
		return starlark.None
	case 6:
		return starlark.String(e.Text[0])
	case 7:
		return starlark.Bytes(string(e.Bytes))
	case 8, 9:
		vals := make([]starlark.Value, len(e.Text))
		for i, s := range e.Text {
			vals[i] = starlark.String(s)
		}
		return starlark.NewList(vals)
	default:
		vals := make([]starlark.Value, len(e.Numbers))
		for i, n := range e.Numbers {
			vals[i] = starlark.MakeUint64(n)
		}
		return starlark.NewList(vals)
	}
}
func headerValue(h Header) (*starlark.Dict, *starlark.Dict) {
	tags := starlark.NewDict(len(h.Entries))
	fields := starlark.NewDict(0)
	for _, e := range h.Entries {
		v := entryValue(e)
		tags.SetKey(starlark.MakeUint64(uint64(e.Tag)), starfile.NewRecord(starlark.StringDict{
			"type": starlark.MakeUint64(uint64(e.Type)), "count": starlark.MakeUint64(uint64(e.Count)), "value": v,
		}))
		if name, ok := names[e.Tag]; ok {
			fields.SetKey(starlark.String(name), v)
		}
	}
	return tags, fields
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	limits := DefaultLimits()
	if err := starlark.UnpackArgs("rpm_metadata", args, kwargs, "file", &value, "maximum_entries?", &limits.MaximumEntries, "maximum_bytes?", &limits.MaximumBytes); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("rpm_metadata: expected file")
	}
	pkg, err := Open(source, limits)
	if err != nil {
		return nil, fmt.Errorf("rpm_metadata %v: %w", value, err)
	}
	tags, fields := headerValue(pkg.Header)
	sig, _ := headerValue(pkg.Signature)
	return starfile.NewRecord(starlark.StringDict{
		"source_package": starlark.Bool(pkg.Source), "fields": fields, "tags": tags, "signature_tags": sig,
		"payload_offset": starlark.MakeInt64(pkg.PayloadOffset), "payload": starfile.NewReader("rpm payload", pkg.Payload),
	}), nil
}
