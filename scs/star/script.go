// Package script exposes portable repository and workspace values to Starlark.
// Native opening and Git networking require explicitly injected backends;
// workspace values themselves grant no ambient host or subprocess authority.
package script

import (
	"context"
	"fmt"
	"github.com/tinyrange/trex/filesystem"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"

	"github.com/tinyrange/trex/scs/repo"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

type Options struct {
	MaxSteps uint64
	Print    io.Writer
	// NoPublish denies snapshot/fork/publication, including through derived views.
	NoPublish bool
}

// Run does not implicitly publish, including on success. Publications made by a
// script before a later failure remain durable; other live edits are ephemeral.
func Run(ctx context.Context, w *repo.Workspace, filename string, source []byte, opts Options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	thread := &starlark.Thread{Name: filename}
	if opts.Print != nil {
		thread.Print = func(_ *starlark.Thread, msg string) { fmt.Fprintln(opts.Print, msg) }
	} else {
		thread.Print = func(_ *starlark.Thread, _ string) {}
	}
	if opts.MaxSteps == 0 {
		opts.MaxSteps = 10_000_000
	}
	thread.SetMaxExecutionSteps(opts.MaxSteps)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			thread.Cancel(ctx.Err().Error())
		case <-done:
		}
	}()
	_, err := starlark.ExecFileOptions(&syntax.FileOptions{Set: true, While: true, TopLevelControl: true, GlobalReassign: true, Recursion: true}, thread, filename, source, starlark.StringDict{"workspace": &Value{w: w, ctx: ctx, noPublish: opts.NoPublish}})
	return err
}

type Value struct {
	w         *repo.Workspace
	ctx       context.Context
	noPublish bool
}

var _ starlark.HasAttrs = (*Value)(nil)

func (v *Value) String() string {
	if v.w.IsReadOnly() {
		return "workspace(readonly)"
	}
	return "workspace(writable)"
}
func (*Value) Type() string          { return "workspace" }
func (*Value) Freeze()               {}
func (*Value) Truth() starlark.Bool  { return starlark.True }
func (*Value) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: workspace") }
func (*Value) AttrNames() []string {
	return []string{"open_file", "view", "chmod", "delete", "fork", "glob", "list_dir", "mkdir", "publish", "read_file", "readlink", "readonly", "rename", "replace", "search", "snapshot", "stat", "symlink", "write_file"}
}
func (v *Value) Attr(name string) (starlark.Value, error) {
	for _, n := range v.AttrNames() {
		if name == n {
			return starlark.NewBuiltin("workspace."+name, func(t *starlark.Thread, b *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
				if err := v.ctx.Err(); err != nil {
					return nil, err
				}
				return v.call(name, a, k)
			}), nil
		}
	}
	return nil, nil
}
func record(fields starlark.StringDict) *starlarkstruct.Struct {
	return starlarkstruct.FromStringDict(starlark.String("result"), fields)
}
func list(ss []string) *starlark.List {
	vs := make([]starlark.Value, len(ss))
	for i, s := range ss {
		vs[i] = starlark.String(s)
	}
	return starlark.NewList(vs)
}
func (v *Value) call(name string, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
	if v.noPublish && (name == "publish" || name == "fork" || name == "snapshot") {
		return nil, fmt.Errorf("workspace.%s is controlled by the session host", name)
	}

	unpack := func(pairs ...any) error { return starlark.UnpackArgs("workspace."+name, a, k, pairs...) }
	var p, q, s string
	var err error
	switch name {
	case "open_file":
		if err = unpack("path", &p); err == nil {
			f, e := v.w.OpenReader(p)
			if e != nil {
				return nil, e
			}
			return starfile.NewReader(p, f), nil
		}
	case "view":
		if err = unpack(); err == nil {
			return &Value{w: v.w.View(), ctx: v.ctx, noPublish: v.noPublish}, nil
		}
	case "read_file":
		return v.readFile(a, k)
	case "search":
		return v.search(a, k)
	case "write_file":
		var content starlark.Value
		if err = unpack("path", &p, "content", &content); err == nil {
			switch data := content.(type) {
			case storage.Reader:
				err = v.w.WriteReader(p, data)
			case starlark.String:
				err = v.w.WriteFile(p, []byte(data))
			case starlark.Bytes:
				err = v.w.WriteFile(p, []byte(data))
			default:
				err = fmt.Errorf("content must be a string or bytes")
			}
		}
	case "replace":
		if err = unpack("path", &p, "old", &q, "new", &s); err == nil {
			err = v.w.Replace(p, q, s)
		}
	case "rename":
		if err = unpack("old", &p, "new", &q); err == nil {
			err = v.w.Rename(p, q)
		}
	case "symlink":
		if err = unpack("path", &p, "target", &q); err == nil {
			err = v.w.Symlink(p, q)
		}
	case "mkdir", "delete":
		if err = unpack("path", &p); err == nil {
			if name == "mkdir" {
				err = v.w.Mkdir(p)
			} else {
				err = v.w.Delete(p)
			}
		}
	case "chmod":
		var mode int
		if err = unpack("path", &p, "mode", &mode); err == nil {
			if mode < 0 || mode > 0777 {
				err = fmt.Errorf("mode must be in 0000..0777")
			} else {
				err = v.w.Chmod(p, uint32(mode))
			}
		}
	case "list_dir", "glob":
		arg := "path"
		if name == "glob" {
			arg = "pattern"
		}
		if err = unpack(arg, &p); err == nil {
			var out []string
			if name == "glob" {
				out, err = v.w.Glob(p)
			} else {
				out, err = v.w.ListDir(p)
			}
			if err == nil {
				return list(out), nil
			}
		}
	case "readlink":
		if err = unpack("path", &p); err == nil {
			s, err = v.w.Readlink(p)
			if err == nil {
				return starlark.String(s), nil
			}
		}
	case "stat":
		if err = unpack("path", &p); err == nil {
			var e repo.Entry
			e, err = v.w.Stat(p)
			if err == nil {
				return record(starlark.StringDict{"kind": starlark.String(e.Kind), "git_oid": starlark.String(e.GitOID), "mode": starlark.MakeUint(uint(e.Mode)), "size": starlark.MakeInt64(e.Size)}), nil
			}
		}
	case "readonly", "fork", "snapshot":
		if err = unpack(); err != nil {
			break
		}
		if name == "readonly" {
			return &Value{w: v.w.Readonly(), ctx: v.ctx, noPublish: v.noPublish}, nil
		}
		if name == "fork" {
			var w *repo.Workspace
			w, err = v.w.Fork()
			if err == nil {
				return &Value{w: w, ctx: v.ctx, noPublish: v.noPublish}, nil
			}
		} else {
			var id repo.ID
			id, err = v.w.Snapshot()
			if err == nil {
				return starlark.String(id), nil
			}
		}
	case "publish":
		if err = unpack("name", &p); err == nil {
			var id repo.ID
			id, err = v.w.Publish(p)
			if err == nil {
				return starlark.String(id), nil
			}
		}
	default:
		return nil, fmt.Errorf("unknown workspace operation %q", name)
	}
	if err != nil {
		return nil, err
	}
	return starlark.None, nil
}
func optionalInt(value starlark.Value, def int) (int, error) {
	if value == nil || value == starlark.None {
		return def, nil
	}
	var n int
	if err := starlark.AsInt(value, &n); err != nil {
		return 0, err
	}
	return n, nil
}
func (v *Value) readFile(a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
	var p string
	var start, end, limit starlark.Value
	if err := starlark.UnpackArgs("workspace.read_file", a, k, "path", &p, "line_start?", &start, "line_end?", &end, "output_limit?", &limit); err != nil {
		return nil, err
	}
	bounded := start != nil && start != starlark.None || end != nil && end != starlark.None || limit != nil && limit != starlark.None
	lo, err := optionalInt(start, 1)
	if err != nil {
		return nil, err
	}
	hi, err := optionalInt(end, 0)
	if err != nil {
		return nil, err
	}
	max, err := optionalInt(limit, -1)
	if err != nil {
		return nil, err
	}
	if lo < 1 || hi < 0 || (end != nil && end != starlark.None && hi < lo) || max < -1 {
		return nil, fmt.Errorf("invalid line bounds or output limit")
	}
	if limit != nil && limit != starlark.None && max < 0 {
		return nil, fmt.Errorf("output_limit must be nonnegative")
	}
	data, err := v.w.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if !bounded {
		return starlark.String(data), nil
	}
	text := string(data)
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	total := len(lines)
	if hi == 0 || hi > total {
		hi = total
	}
	if lo > total+1 {
		lo = total + 1
	}
	content := ""
	if lo <= hi {
		content = strings.Join(lines[lo-1:hi], "")
	}
	original := len(content)
	if max >= 0 && len(content) > max {
		content = content[:max]
	}
	return record(starlark.StringDict{"content": starlark.String(content), "line_start": starlark.MakeInt(lo), "line_end": starlark.MakeInt(hi), "total_lines": starlark.MakeInt(total), "output_bytes": starlark.MakeInt(len(content)), "truncated": starlark.Bool(len(content) < original), "truncated_bytes": starlark.MakeInt(original - len(content))}), nil
}
func stringsArg(value starlark.Value) ([]string, error) {
	if value == nil || value == starlark.None {
		return nil, nil
	}
	if s, ok := starlark.AsString(value); ok {
		return []string{s}, nil
	}
	var values []starlark.Value
	switch v := value.(type) {
	case *starlark.List:
		for i := 0; i < v.Len(); i++ {
			values = append(values, v.Index(i))
		}
	case starlark.Tuple:
		values = v
	default:
		return nil, fmt.Errorf("expected string or list/tuple of strings")
	}
	out := []string{}
	for _, v := range values {
		s, ok := starlark.AsString(v)
		if !ok {
			return nil, fmt.Errorf("expected string")
		}
		out = append(out, s)
	}
	return out, nil
}

// NewWorkspace borrows repository ownership and captures cancellation authority.
func NewWorkspace(ctx context.Context, w *repo.Workspace) *Value { return &Value{w: w, ctx: ctx} }
func (v *Value) SnapshotTree() (filesystem.Tree, error) {
	if err := v.ctx.Err(); err != nil {
		return nil, err
	}
	return v.w.SnapshotTree()
}
