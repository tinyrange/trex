package script

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/tinyrange/trex/scs/repo"
	"go.starlark.net/starlark"
)

func (v *Value) search(a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
	var pattern, glob starlark.Value
	regex := false
	max := 1000
	limit := 1 << 20
	if err := starlark.UnpackArgs("workspace.search", a, k, "pattern", &pattern, "regex?", &regex, "glob?", &glob, "max_matches?", &max, "output_limit?", &limit); err != nil {
		return nil, err
	}
	patterns, err := stringsArg(pattern)
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("at least one pattern is required")
	}
	globs, err := stringsArg(glob)
	if err != nil {
		return nil, err
	}
	for _, g := range globs {
		if _, err := repo.Match(g, ""); err != nil {
			return nil, err
		}
	}
	if max < 0 || limit < 0 {
		return nil, fmt.Errorf("search limits must be nonnegative")
	}
	matchers := []*regexp.Regexp{}
	for _, p := range patterns {
		if !regex {
			p = regexp.QuoteMeta(p)
		}
		r, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, r)
	}
	matches := []starlark.Value{}
	searched, output, skipped := 0, 0, 0
	truncated := false
	paths, err := v.w.PathsWithError()
	if err != nil {
		return nil, err
	}
outer:
	for _, p := range paths {
		if err := v.ctx.Err(); err != nil {
			return nil, err
		}
		e, err := v.w.Stat(p)
		if err != nil {
			return nil, err
		}
		if e.Kind != "file" {
			continue
		}
		selected := len(globs) == 0
		for _, g := range globs {
			ok, _ := repo.Match(g, p)
			selected = selected || ok
		}
		if !selected {
			continue
		}
		data, err := v.w.ReadFile(p)
		if err != nil {
			return nil, err
		}
		searched++
		if bytes.IndexByte(data, 0) >= 0 {
			continue
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		for _, line := range lines {
			if len(line) > 8<<20 {
				skipped++
				continue outer
			}
		}
		for n, line := range lines {
			column := -1
			for _, r := range matchers {
				loc := r.FindStringIndex(line)
				if loc != nil && (column < 0 || loc[0] < column) {
					column = loc[0]
				}
			}
			if column < 0 {
				continue
			}
			size := len(p) + len(line)
			if len(matches) >= max || size > limit-output {
				truncated = true
				break outer
			}
			output += size
			matches = append(matches, record(starlark.StringDict{"path": starlark.String(p), "line": starlark.MakeInt(n + 1), "column": starlark.MakeInt(column + 1), "text": starlark.String(line)}))
		}
	}
	return record(starlark.StringDict{"matches": starlark.NewList(matches), "match_count": starlark.MakeInt(len(matches)), "files_searched": starlark.MakeInt(searched), "output_bytes": starlark.MakeInt(output), "skipped_large_files": starlark.MakeInt(skipped), "truncated": starlark.Bool(truncated)}), nil
}
