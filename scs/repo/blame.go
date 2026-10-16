package repo

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
)

// Blame is deterministic, first-parent, exact-line LCS attribution. It does not
// infer copies/renames, ignore whitespace, or choose between merge parents.
type BlameLine struct {
	Line, SourceLine int
	Revision, Text   string
}
type BlameLimits struct{ MaxVisited, MaxFileBytes, MaxReadBytes, MaxCells int }
type blameLoad func(string) (*Workspace, string, error)

func (r *Repository) Blame(ctx context.Context, start ID, p string, limits BlameLimits) ([]BlameLine, error) {
	return blame(ctx, string(start), p, limits, func(id string) (*Workspace, string, error) {
		rev, err := r.indexedRevision(ID(id))
		if err != nil {
			return nil, "", err
		}
		w, err := r.Fork(ID(id))
		if err != nil {
			return nil, "", err
		}
		parent := ""
		if len(rev.Parents) > 0 {
			parent = string(rev.Parents[0])
		}
		return w, parent, nil
	})
}
func (r *Repository) GitBlame(ctx context.Context, catalog string, start GitOID, p string, limits BlameLimits) ([]BlameLine, error) {
	return blame(ctx, start.String(), p, limits, func(id string) (*Workspace, string, error) {
		oid, err := ParseGitOID(id)
		if err != nil {
			return nil, "", err
		}
		parents, err := r.GitCommitParents(oid)
		if err != nil {
			return nil, "", err
		}
		w, err := r.CheckoutGit(ctx, catalog, id)
		if err != nil {
			return nil, "", err
		}
		parent := ""
		if len(parents) > 0 {
			parent = parents[0].String()
		}
		return w, parent, nil
	})
}
func blame(ctx context.Context, start, p string, l BlameLimits, load blameLoad) ([]BlameLine, error) {
	if l.MaxVisited < 0 || l.MaxFileBytes < 0 || l.MaxReadBytes < 0 || l.MaxCells < 0 {
		return nil, errors.New("invalid blame limits")
	}
	if l.MaxVisited == 0 {
		l.MaxVisited = 10000
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = 1 << 20
	}
	if l.MaxReadBytes == 0 {
		l.MaxReadBytes = 8 << 20
	}
	if l.MaxCells == 0 {
		l.MaxCells = 8_000_000
	}
	if l.MaxCells > 64_000_000 {
		return nil, errors.New("blame matrix exceeds supported work limit")
	}
	p, err := clean(p)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w, parent, err := load(start)
	if err != nil {
		return nil, err
	}
	entry, err := w.Stat(p)
	if err != nil {
		return nil, err
	}
	if entry.Kind != "file" {
		return nil, errors.New("blame requires a regular file")
	}
	read := func(w *Workspace, e Entry) ([]string, error) {
		if e.Kind != "file" {
			return nil, nil
		}
		if e.Size > int64(l.MaxFileBytes) || e.Size > int64(l.MaxReadBytes) {
			return nil, ErrQueryLimit
		}
		l.MaxReadBytes -= int(e.Size)
		data, err := w.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if strings.IndexByte(string(data), 0) >= 0 {
			return nil, errors.New("blame requires text without NUL bytes")
		}
		lines := strings.SplitAfter(string(data), "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		return lines, nil
	}
	lines, err := read(w, entry)
	if err != nil {
		return nil, err
	}
	out := make([]BlameLine, len(lines))
	positions := make([]int, len(lines))
	for i, line := range lines {
		out[i] = BlameLine{Line: i + 1, Text: strings.TrimSuffix(line, "\n")}
		positions[i] = i
	}
	unresolved := len(lines)
	visited := 1
	current := start
	for unresolved > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if parent == "" {
			for i, pos := range positions {
				if pos >= 0 {
					out[i].Revision = current
					out[i].SourceLine = pos + 1
					positions[i] = -1
				}
			}
			break
		}
		if visited == l.MaxVisited {
			return nil, ErrQueryLimit
		}
		visited++
		previous, next, err := load(parent)
		if err != nil {
			return nil, err
		}
		old, err := previous.Stat(p)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if errors.Is(err, fs.ErrNotExist) {
			old = Entry{}
		}
		if sameReviewContent(entry, old) {
			current, parent, entry = parent, next, old
			continue
		}
		oldLines, err := read(previous, old)
		if err != nil {
			return nil, err
		}
		mapping, used, err := lineMapping(ctx, lines, oldLines, l.MaxCells)
		if err != nil {
			return nil, err
		}
		l.MaxCells -= used
		for i, pos := range positions {
			if pos < 0 {
				continue
			}
			mapped := mapping[pos]
			if mapped < 0 {
				out[i].Revision = current
				out[i].SourceLine = pos + 1
				positions[i] = -1
				unresolved--
			} else {
				positions[i] = mapped
			}
		}
		lines = oldLines
		current, parent, entry = parent, next, old
	}
	return out, nil
}

// O(n*m) is explicit and cumulatively budgeted, not hidden behind an API that
// claims cheap blame for arbitrary large files. Equal files use an O(n) path.
func lineMapping(ctx context.Context, a, b []string, budget int) ([]int, int, error) {
	mapping := make([]int, len(a))
	for i := range mapping {
		mapping[i] = -1
	}
	if slices.Equal(a, b) {
		for i := range mapping {
			mapping[i] = i
		}
		return mapping, 0, nil
	}
	if len(a) == 0 || len(b) == 0 {
		return mapping, 0, nil
	}
	width := len(b) + 1
	if len(a)+1 > budget/width {
		return nil, 0, ErrQueryLimit
	}
	cells := (len(a) + 1) * width
	table := make([]uint32, cells)
	for i := len(a) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i*width+j] = 1 + table[(i+1)*width+j+1]
			} else {
				table[i*width+j] = max(table[(i+1)*width+j], table[i*width+j+1])
			}
		}
	}
	for i, j := 0, 0; i < len(a) && j < len(b); {
		if a[i] == b[j] {
			mapping[i] = j
			i++
			j++
		} else if table[(i+1)*width+j] >= table[i*width+j+1] {
			i++
		} else {
			j++
		}
	}
	return mapping, cells, nil
}
