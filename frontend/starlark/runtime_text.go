package starlarkfrontend

import (
	"fmt"
	stdhtml "html"
	"net/url"
	"regexp"

	"go.starlark.net/starlark"
)

func htmlEscapeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	if err := starlark.UnpackArgs("html.escape", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	return starlark.String(stdhtml.EscapeString(value)), nil
}

func htmlUnescapeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	if err := starlark.UnpackArgs("html.unescape", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	return starlark.String(stdhtml.UnescapeString(value)), nil
}

func urlPathEscapeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	if err := starlark.UnpackArgs("url.path_escape", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	return starlark.String(url.PathEscape(value)), nil
}

func urlPathUnescapeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	if err := starlark.UnpackArgs("url.path_unescape", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return nil, err
	}
	return starlark.String(decoded), nil
}

type starlarkRegexp struct {
	pattern string
	value   *regexp.Regexp
}

func regexpCompileBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern string
	if err := starlark.UnpackArgs("regexp.compile", args, kwargs, "pattern", &pattern); err != nil {
		return nil, err
	}
	value, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &starlarkRegexp{pattern: pattern, value: value}, nil
}

func (r *starlarkRegexp) String() string       { return fmt.Sprintf("regexp.compile(%q)", r.pattern) }
func (r *starlarkRegexp) Type() string         { return "regexp" }
func (r *starlarkRegexp) Freeze()              {}
func (r *starlarkRegexp) Truth() starlark.Bool { return starlark.True }
func (r *starlarkRegexp) Hash() (uint32, error) {
	return starlark.String(r.pattern).Hash()
}
func (r *starlarkRegexp) AttrNames() []string { return []string{"find_all", "replace_all"} }
func (r *starlarkRegexp) Attr(name string) (starlark.Value, error) {
	switch name {
	case "find_all":
		return starlark.NewBuiltin("regexp.find_all", r.findAllBuiltin), nil
	case "replace_all":
		return starlark.NewBuiltin("regexp.replace_all", r.replaceAllBuiltin), nil
	default:
		return nil, nil
	}
}

func (r *starlarkRegexp) findAllBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	limit := -1
	if err := starlark.UnpackArgs("regexp.find_all", args, kwargs, "value", &value, "limit?", &limit); err != nil {
		return nil, err
	}
	locations := r.value.FindAllStringSubmatchIndex(value, limit)
	results := make([]starlark.Value, 0, len(locations))
	for _, location := range locations {
		groups := make([]starlark.Value, (len(location)-2)/2)
		for index := range groups {
			start, end := location[index*2+2], location[index*2+3]
			if start < 0 {
				groups[index] = starlark.None
			} else {
				groups[index] = starlark.String(value[start:end])
			}
		}
		results = append(results, newStarlarkRecord(starlark.StringDict{
			"start":  starlark.MakeInt(location[0]),
			"end":    starlark.MakeInt(location[1]),
			"text":   starlark.String(value[location[0]:location[1]]),
			"groups": starlark.NewList(groups),
		}))
	}
	return starlark.NewList(results), nil
}

func (r *starlarkRegexp) replaceAllBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value, replacement string
	if err := starlark.UnpackArgs("regexp.replace_all", args, kwargs, "value", &value, "replacement", &replacement); err != nil {
		return nil, err
	}
	return starlark.String(r.value.ReplaceAllString(value, replacement)), nil
}
