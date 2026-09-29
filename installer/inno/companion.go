package inno

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tinyrange/trex/auto"
	binaryapi "github.com/tinyrange/trex/binary"
	"github.com/tinyrange/trex/storage"
)

// Unflagged legacy ZIP members may retain raw ANSI bytes. Interpret those
// only in this ANSI installer context; do not rewrite names in the source tree.
func companionName(name string) string {
	if !utf8.ValidString(name) {
		if decoded, err := binaryapi.DecodeText([]byte(name), "windows1252", false); err == nil {
			return decoded
		}
	}
	return name
}
func (a *archive) companionEntry(name string) (auto.Entry, error) {
	ctx := a.options.Source
	if ctx == nil || ctx.Tree == nil {
		return auto.Entry{}, fs.ErrNotExist
	}
	view := ctx.Tree
	if name == "." {
		return auto.Entry{Kind: "directory", View: view}, nil
	}
	parts := strings.Split(name, "/")
	budget := a.options.MaxEntries
	if budget <= 0 {
		budget = 100000
	}
	if len(parts) > 256 {
		return auto.Entry{}, auto.ErrLimit
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, ":\x00") {
			return auto.Entry{}, fs.ErrInvalid
		}
		entries, err := view.Entries()
		if err != nil {
			return auto.Entry{}, err
		}
		budget -= len(entries)
		if budget < 0 {
			return auto.Entry{}, auto.ErrLimit
		}
		var found *auto.Entry
		for _, entry := range entries {
			if strings.EqualFold(companionName(entry.Name), part) {
				if found != nil {
					return auto.Entry{}, fmt.Errorf("inno: ambiguous companion %q", name)
				}
				copy := entry
				found = &copy
			}
		}
		if found == nil {
			return auto.Entry{}, fs.ErrNotExist
		}
		if i == len(parts)-1 {
			return *found, nil
		}
		if found.Kind != "directory" || found.View == nil {
			return auto.Entry{}, fs.ErrNotExist
		}
		view = found.View
	}
	return auto.Entry{}, fs.ErrNotExist
}
func (a *archive) companion(name string) (storage.Reader, error) {
	e, err := a.companionEntry(name)
	if err != nil {
		return nil, err
	}
	if e.Kind != "file" || e.Reader == nil {
		return nil, fs.ErrInvalid
	}
	return e.Reader, nil
}
func (a *archive) expand(name string) ([]auto.Entry, error) {
	dir := path.Dir(name)
	if strings.ContainsAny(dir, "*?") {
		return nil, fmt.Errorf("inno: wildcard source directory")
	}
	e, err := a.companionEntry(dir)
	if err != nil {
		return nil, err
	}
	if e.Kind != "directory" || e.View == nil {
		return nil, fs.ErrInvalid
	}
	pattern := path.Base(name)
	if pattern == "*.*" {
		pattern = "*"
	}
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, string([]byte{92})+"*", ".*")
	quoted = strings.ReplaceAll(quoted, string([]byte{92})+"?", ".")
	matcher, err := regexp.Compile("(?i)^" + quoted + "$")
	if err != nil {
		return nil, err
	}
	entries, err := e.View.Entries()
	if err != nil {
		return nil, err
	}
	limit := a.options.MaxEntries
	if limit <= 0 {
		limit = 100000
	}
	if len(entries) > limit {
		return nil, auto.ErrLimit
	}
	var result []auto.Entry
	for _, e := range entries {
		if e.Kind == "file" && e.Reader != nil && matcher.MatchString(companionName(e.Name)) {
			e.Name = companionName(e.Name)
			result = append(result, e)
		}
	}
	return result, nil
}
