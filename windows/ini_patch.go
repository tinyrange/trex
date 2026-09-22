package windows

import (
	"fmt"
	"strings"

	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// patchINIBuiltin merges literal Windows profile strings without turning
// values containing commas or quotes into INF argument lists.
func patchINIBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var changes *starlark.Dict
	if err := starlark.UnpackArgs("patch_ini", args, kwargs, "source", &source, "changes", &changes); err != nil {
		return nil, err
	}
	text := ""
	if source != starlark.None {
		f, ok := source.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("patch_ini: source must be a file or None")
		}
		if f.Size() > 1<<20 {
			return nil, fmt.Errorf("patch_ini: source exceeds limit")
		}
		b, err := starfile.ReadAll(f)
		if err != nil {
			return nil, err
		}
		text, err = binaryapi.DecodeText(b, "windows1252", false)
		if err != nil {
			return nil, err
		}
	}
	type setting struct{ name, value string }
	names := []string{}
	sectionNames := map[string]string{}
	updates := map[string][]setting{}
	for _, pair := range changes.Items() {
		name, ok := starlark.AsString(pair[0])
		d, valid := pair[1].(*starlark.Dict)
		if !ok || !valid || name == "" || strings.ContainsAny(name, "[]\r\n\x00") {
			return nil, fmt.Errorf("patch_ini: invalid section")
		}
		lower := strings.ToLower(name)
		if _, exists := updates[lower]; !exists {
			names = append(names, lower)
		}
		sectionNames[lower] = name
		updates[lower] = []setting{}
		for _, item := range d.Items() {
			key, ok := starlark.AsString(item[0])
			value, valid := starlark.AsString(item[1])
			if !ok || !valid || key == "" || strings.ContainsAny(key, "=\r\n\x00") || strings.ContainsAny(value, "\r\n\x00") {
				return nil, fmt.Errorf("patch_ini: invalid setting")
			}
			updates[lower] = append(updates[lower], setting{key, value})
		}
	}
	out := []string{}
	written := map[string]bool{}
	section := ""
	flush := func() {
		if written[section] {
			return
		}
		for _, item := range updates[section] {
			out = append(out, item.name+"="+item.value)
		}
		written[section] = true
	}
	for _, line := range strings.Split(strings.TrimRight(text, "\r\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") && strings.Contains(trim, "]") {
			flush()
			section = strings.ToLower(strings.TrimSpace(strings.SplitN(trim[1:], "]", 2)[0]))
			out = append(out, line)
			continue
		}
		key, _, has := strings.Cut(trim, "=")
		replace := false
		if has && !strings.HasPrefix(trim, ";") {
			for _, item := range updates[section] {
				if strings.EqualFold(strings.TrimSpace(key), item.name) {
					replace = true
					break
				}
			}
		}
		if !replace {
			out = append(out, line)
		}
	}
	flush()
	for _, name := range names {
		if written[name] {
			continue
		}
		section = name
		out = append(out, "["+sectionNames[name]+"]")
		flush()
	}
	encoded, err := binaryapi.EncodeText(strings.Join(out, "\r\n")+"\r\n", "windows1252", false)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: encoded}, nil
}
