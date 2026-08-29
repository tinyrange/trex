package windows

import (
	"encoding/xml"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"regexp"
	"strings"

	"go.starlark.net/starlark"
)

var mscGUIDPattern = regexp.MustCompile(`(?i)\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}`)

func mscSnapinsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("msc_snapins", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("msc_snapins: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	values := mscSnapins(data)
	out := make([]starlark.Value, len(values))
	for index, value := range values {
		out[index] = starlark.String(value)
	}
	return starlark.NewList(out), nil
}

func mscSnapins(data []byte) []string {
	text := decodeINFText(data)
	decoder := xml.NewDecoder(strings.NewReader(text))
	var candidates []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			candidates = append(candidates, text)
			break
		}
		switch token := token.(type) {
		case xml.CharData:
			candidates = append(candidates, string(token))
		case xml.StartElement:
			for _, attribute := range token.Attr {
				candidates = append(candidates, attribute.Value)
			}
		}
	}
	seen := make(map[string]bool)
	var out []string
	for _, candidate := range candidates {
		for _, match := range mscGUIDPattern.FindAllString(candidate, -1) {
			raw, ok := parseWindowsGUID(match)
			if !ok {
				continue
			}
			guid := windowsGUIDString(raw)
			if !seen[guid] {
				seen[guid] = true
				out = append(out, guid)
			}
		}
	}
	return out
}
