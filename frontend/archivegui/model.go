// Package archivegui implements a desktop browser over trex's lazy file views.
package archivegui

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tinyrange/trex/auto"
)

const previewLimit = 64 << 10

type location struct {
	path      string
	node      *auto.Node
	children  []*auto.Node
	preview   []string
	format    string
	ancestors map[string][]*auto.Node
}

// readLocation only uses portable trex nodes. In particular, nested archives
// retain their readers; no temporary extracted files are needed.
func readLocation(root *auto.Node, name string) (location, error) {
	name = path.Clean("/" + name)
	n, err := root.Resolve(name)
	if err != nil {
		return location{}, err
	}
	loc := location{path: name, node: n, ancestors: make(map[string][]*auto.Node)}
	// Resolve has already loaded these parents. Include them even when the
	// address bar jumped across several archive boundaries in one operation.
	for parent := path.Dir(name); name != "/"; parent = path.Dir(parent) {
		p, err := root.Resolve(parent)
		if err != nil {
			return location{}, err
		}
		children, err := p.Children()
		if err != nil {
			return location{}, err
		}
		loc.ancestors[parent] = children
		if parent == "/" {
			break
		}
	}
	loc.children, err = n.Children()
	if err == nil {
		return loc, nil
	}
	if !errors.Is(err, auto.ErrNotContainer) {
		return location{}, err
	}
	r := n.Reader()
	if r == nil {
		return location{}, fmt.Errorf("%s has no readable data", n.Name())
	}
	b := make([]byte, min(int64(previewLimit), max(int64(0), r.Size())))
	count, err := r.ReadAt(b, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return location{}, err
	}
	b = b[:count]
	loc.format = "Text preview"
	if utf8.Valid(b) && !strings.ContainsFunc(string(b), func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) {
		loc.preview = strings.Split(strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", "\n"), "\t", "    "), "\n")
	} else {
		loc.format = "Hex preview"
		loc.preview = strings.Split(hex.Dump(b), "\n")
	}
	if r.Size() > int64(count) {
		loc.format += fmt.Sprintf(" (first %d bytes of %d)", count, r.Size())
	}
	return loc, nil
}

func rows(nodes []*auto.Node, filter string, column int, descending bool) []*auto.Node {
	out := make([]*auto.Node, 0, len(nodes))
	for _, n := range nodes {
		if strings.Contains(strings.ToLower(n.Name()), strings.ToLower(filter)) {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Summary(), out[j].Summary()
		if (a.Kind == "directory") != (b.Kind == "directory") {
			return a.Kind == "directory"
		}
		cmp := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		if cmp == 0 {
			cmp = strings.Compare(a.Name, b.Name)
		}
		if column == 1 && a.Size != b.Size {
			if a.Size < b.Size {
				cmp = -1
			} else {
				cmp = 1
			}
		}
		if column == 2 && fileType(out[i]) != fileType(out[j]) {
			cmp = strings.Compare(fileType(out[i]), fileType(out[j]))
		}
		if column == 3 && packedSize(out[i]) != packedSize(out[j]) {
			if packedSize(out[i]) < packedSize(out[j]) {
				cmp = -1
			} else {
				cmp = 1
			}
		}
		if column == 4 && modifiedValue(out[i]) != modifiedValue(out[j]) {
			cmp = strings.Compare(modifiedValue(out[i]), modifiedValue(out[j]))
		}
		if descending {
			return cmp > 0
		}
		return cmp < 0
	})
	return out
}

func fileType(n *auto.Node) string {
	if n.Summary().Kind == "directory" {
		return "Folder"
	}
	ext := strings.TrimPrefix(strings.ToUpper(path.Ext(n.Name())), ".")
	if ext == "" {
		return "File"
	}
	return ext + " file"
}
