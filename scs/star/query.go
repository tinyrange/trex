package script

import (
	"context"
	"fmt"
	"github.com/tinyrange/trex/scs/repo"
	"go.starlark.net/starlark"
)

func revisionRecord(r repo.Revision) starlark.Value {
	parents := make([]string, len(r.Parents))
	for i, id := range r.Parents {
		parents[i] = string(id)
	}
	return record(starlark.StringDict{"id": starlark.String(r.ID), "tree": starlark.String(r.Tree), "source_commit": starlark.String(r.SourceCommit), "parents": list(parents), "author": starlark.String(r.Author), "message": starlark.String(r.Message), "task": starlark.String(r.Task)})
}
func (v *Value) query(name string, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
	unpack := func(pairs ...any) error { return starlark.UnpackArgs("workspace."+name, a, k, pairs...) }
	switch name {
	case "affected_targets":
		var other starlark.Value
		var targets *starlark.Dict
		prefix := "."
		max, work, matches := 1000, 100000, 100000
		if err := unpack("other", &other, "targets", &targets, "prefix?", &prefix, "max_changes?", &max, "max_visited?", &work, "max_matches?", &matches); err != nil {
			return nil, err
		}
		after, ok := other.(*Value)
		if !ok {
			return nil, fmt.Errorf("other must be an SCS workspace")
		}
		ctx, close, err := v.queryContext(after)
		if err != nil {
			return nil, err
		}
		defer close()
		specs := []repo.TargetSpec{}
		for _, item := range targets.Items() {
			name, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("target names must be strings")
			}
			patterns, err := stringsArg(item[1])
			if err != nil {
				return nil, err
			}
			specs = append(specs, repo.TargetSpec{Name: name, Patterns: patterns})
		}
		affected, err := repo.AffectedTargets(ctx, v.w, after.w, specs, repo.DiffOptions{Prefix: prefix, MaxChanges: max, MaxVisited: work, MaxMatches: matches})
		if err != nil {
			return nil, err
		}
		return list(affected), nil

	case "glob_page":
		var pattern string
		after := ""
		limit, work := 1000, 100000
		if err := unpack("pattern", &pattern, "after?", &after, "limit?", &limit, "max_visited?", &work); err != nil {
			return nil, err
		}
		page, err := v.w.GlobPage(v.ctx, pattern, after, repo.QueryLimits{Limit: limit, MaxVisited: work})
		if err != nil {
			return nil, err
		}
		return record(starlark.StringDict{"paths": list(page.Paths), "next": starlark.String(page.Next), "visited": starlark.MakeInt(page.Visited)}), nil
	case "revision":
		var parents starlark.Value
		author, message, task := "", "", ""
		if err := unpack("parents?", &parents, "author?", &author, "message?", &message, "task?", &task); err != nil {
			return nil, err
		}
		ps, err := stringsArg(parents)
		if err != nil {
			return nil, err
		}
		meta := repo.RevisionMetadata{Author: author, Message: message, Task: task}
		for _, p := range ps {
			meta.Parents = append(meta.Parents, repo.ID(p))
		}
		id, err := v.w.Revision(meta)
		if err != nil {
			return nil, err
		}
		return starlark.String(id), nil
	case "diff":
		var other starlark.Value
		prefix := "."
		max, work := 1000, 100000
		if err := unpack("other", &other, "prefix?", &prefix, "max_changes?", &max, "max_visited?", &work); err != nil {
			return nil, err
		}
		after, ok := other.(*Value)
		if !ok {
			return nil, fmt.Errorf("other must be an SCS workspace")
		}
		ctx, close, err := v.queryContext(after)
		if err != nil {
			return nil, err
		}
		defer close()
		changes, err := repo.DiffLimited(ctx, v.w, after.w, repo.DiffOptions{Prefix: prefix, MaxChanges: max, MaxVisited: work})
		if err != nil {
			return nil, err
		}
		values := make([]starlark.Value, 0, len(changes))
		info := func(i *repo.FileInfo) starlark.Value {
			if i == nil {
				return starlark.None
			}
			return record(starlark.StringDict{"kind": starlark.String(i.Kind), "mode": starlark.MakeUint(uint(i.Mode)), "size": starlark.MakeInt64(i.Size), "sha256": starlark.String(i.SHA256), "target": starlark.String(i.Target), "git_oid": starlark.String(i.GitOID)})
		}
		for _, c := range changes {
			values = append(values, record(starlark.StringDict{"path": starlark.String(c.Path), "status": starlark.String(c.Status), "before": info(c.Before), "after": info(c.After)}))
		}
		return starlark.NewList(values), nil
	}
	return nil, fmt.Errorf("unknown workspace query %q", name)
}
func (v *RepositoryValue) query(name string, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
	unpack := func(pairs ...any) error { return starlark.UnpackArgs("repository."+name, a, k, pairs...) }
	switch name {
	case "blame", "git_blame":
		var start, p string
		catalog := "git"
		visited, bytes, read, cells := 10000, 1<<20, 8<<20, 8_000_000
		pairs := []any{"start", &start, "path", &p, "max_visited?", &visited, "max_file_bytes?", &bytes, "max_read_bytes?", &read, "max_cells?", &cells}
		if name == "git_blame" {
			pairs = append(pairs, "catalog?", &catalog)
		}
		if err := unpack(pairs...); err != nil {
			return nil, err
		}
		limits := repo.BlameLimits{MaxVisited: visited, MaxFileBytes: bytes, MaxReadBytes: read, MaxCells: cells}
		var lines []repo.BlameLine
		var err error
		if name == "blame" {
			lines, err = v.r.Blame(v.ctx, repo.ID(start), p, limits)
		} else {
			id, e := repo.ParseGitOID(start)
			if e != nil {
				return nil, e
			}
			lines, err = v.r.GitBlame(v.ctx, catalog, id, p, limits)
		}
		if err != nil {
			return nil, err
		}
		values := make([]starlark.Value, len(lines))
		for i, line := range lines {
			values[i] = record(starlark.StringDict{"line": starlark.MakeInt(line.Line), "source_line": starlark.MakeInt(line.SourceLine), "revision": starlark.String(line.Revision), "text": starlark.String(line.Text)})
		}
		return starlark.NewList(values), nil

	case "git_is_ancestor", "git_merge_bases":
		var a, b string
		work := 100000
		if err := unpack("a", &a, "b", &b, "max_visited?", &work); err != nil {
			return nil, err
		}
		left, err := repo.ParseGitOID(a)
		if err != nil {
			return nil, err
		}
		right, err := repo.ParseGitOID(b)
		if err != nil {
			return nil, err
		}
		if name == "git_is_ancestor" {
			yes, err := v.r.GitIsAncestor(v.ctx, left, right, repo.GraphLimits{MaxVisited: work})
			return starlark.Bool(yes), err
		}
		bases, err := v.r.GitMergeBases(v.ctx, left, right, repo.GraphLimits{MaxVisited: work})
		if err != nil {
			return nil, err
		}
		out := make([]string, len(bases))
		for i, id := range bases {
			out[i] = id.String()
		}
		return list(out), nil

	case "checkout_revision", "revision":
		var id string
		if err := unpack("id", &id); err != nil {
			return nil, err
		}
		if name == "revision" {
			rev, err := v.r.Revision(repo.ID(id))
			if err != nil {
				return nil, err
			}
			return revisionRecord(rev), nil
		}
		w, err := v.r.Fork(repo.ID(id))
		if err != nil {
			return nil, err
		}
		return NewWorkspace(v.ctx, w), nil
	case "promote":
		var ref, expected, next string
		if err := unpack("name", &ref, "expected", &expected, "next", &next); err != nil {
			return nil, err
		}
		return starlark.None, v.r.Promote(ref, repo.ID(expected), repo.ID(next))
	case "drop":
		var ref, expected string
		if err := unpack("name", &ref, "expected", &expected); err != nil {
			return nil, err
		}
		return starlark.None, v.r.Drop(ref, repo.ID(expected))
	case "enable_indexed_refs":
		if err := unpack(); err != nil {
			return nil, err
		}
		return starlark.None, v.r.EnableIndexedRefs()
	case "clear_derived_indexes":
		if err := unpack(); err != nil {
			return nil, err
		}
		v.r.ClearDerivedIndexes()
		return starlark.None, nil
	case "is_ancestor", "merge_bases":
		var a, b string
		work := 100000
		if err := unpack("a", &a, "b", &b, "max_visited?", &work); err != nil {
			return nil, err
		}
		if name == "is_ancestor" {
			yes, err := v.r.IsAncestor(v.ctx, repo.ID(a), repo.ID(b), repo.GraphLimits{MaxVisited: work})
			return starlark.Bool(yes), err
		}
		bases, err := v.r.MergeBases(v.ctx, repo.ID(a), repo.ID(b), repo.GraphLimits{MaxVisited: work})
		if err != nil {
			return nil, err
		}
		out := make([]string, len(bases))
		for i, id := range bases {
			out[i] = string(id)
		}
		return list(out), nil
	case "path_history":
		var start, path string
		limit, work := 1000, 100000
		if err := unpack("start", &start, "path", &path, "limit?", &limit, "max_visited?", &work); err != nil {
			return nil, err
		}
		page, err := v.r.PathHistory(v.ctx, repo.ID(start), path, repo.QueryLimits{Limit: limit, MaxVisited: work})
		if err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(page.Revisions))
		for i, rev := range page.Revisions {
			out[i] = revisionRecord(rev)
		}
		return record(starlark.StringDict{"revisions": starlark.NewList(out), "next": starlark.String(page.Next), "visited": starlark.MakeInt(page.Visited)}), nil
	case "operation_stats":
		if err := unpack(); err != nil {
			return nil, err
		}
		s := v.r.OperationStats()
		return record(starlark.StringDict{"records_appended": starlark.MakeUint64(s.RecordsAppended), "bytes_appended": starlark.MakeUint64(s.BytesAppended), "object_reads": starlark.MakeUint64(s.ObjectReads), "object_bytes_read": starlark.MakeUint64(s.ObjectBytesRead), "body_decodes": starlark.MakeUint64(s.BodyDecodes), "body_decoded_bytes": starlark.MakeUint64(s.BodyDecodedBytes), "body_cache_hits": starlark.MakeUint64(s.BodyCacheHits), "derived_hits": starlark.MakeUint64(s.DerivedHits), "derived_misses": starlark.MakeUint64(s.DerivedMisses)}), nil
	}
	return nil, fmt.Errorf("unknown repository query %q", name)
}

// A query must not revive a context-cancelled operand by extracting its native
// workspace. Observe both lifetimes without leaking cancellation callbacks.
func (v *Value) queryContext(other *Value) (context.Context, func(), error) {
	if err := v.ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := other.ctx.Err(); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(v.ctx)
	stop := context.AfterFunc(other.ctx, cancel)
	return ctx, func() { stop(); cancel() }, nil
}
