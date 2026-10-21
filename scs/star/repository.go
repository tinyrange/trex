package script

import (
	"context"
	"fmt"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/tinyrange/trex/lifecycle"
	gitstore "github.com/tinyrange/trex/scs/git"
	"github.com/tinyrange/trex/scs/repo"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"io"
)

// Native authority is injected, not acquired by the portable scripting adapter.
type OpenRepository func(string) (*repo.Repository, error)
type ConnectGit func(string) (transport.Transport, error)

func Builtins(create, open OpenRepository, connect ConnectGit) starlark.StringDict {
	wrap := func(thread *starlark.Thread, r *repo.Repository) (starlark.Value, error) {
		ctx := context.Background()
		if resources, err := lifecycle.ForThread(thread); err == nil {
			ctx = resources.Context()
			if _, err = resources.Add(r); err != nil {
				r.Close()
				return nil, err
			}
		}
		return NewRepository(ctx, r, connect), nil
	}
	host := func(name string, fn OpenRepository) *starlark.Builtin {
		return starlark.NewBuiltin(name, func(t *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
			var path string
			if err := starlark.UnpackArgs(name, a, k, "path", &path); err != nil {
				return nil, err
			}
			if fn == nil {
				return nil, fmt.Errorf("%s: native repository backend unavailable", name)
			}
			r, err := fn(path)
			if err != nil {
				return nil, err
			}
			return wrap(t, r)
		})
	}
	return starlark.StringDict{
		"create": host("scs.create", create),
		"open":   host("scs.open", open),
		"memory": starlark.NewBuiltin("scs.memory", func(t *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
			var file starlark.Value = starlark.None
			limit := int64(512 << 20)
			if err := starlark.UnpackArgs("scs.memory", a, k, "file?", &file, "max_bytes?", &limit); err != nil {
				return nil, err
			}
			if limit < 8 {
				return nil, fmt.Errorf("max_bytes must be at least 8")
			}
			store := storage.NewMemoryStore(limit)
			var r *repo.Repository
			var err error
			if file == starlark.None {
				r, err = repo.CreateOptimized(store)
			} else {
				input, ok := file.(storage.Reader)
				if !ok || input.Size() < 0 {
					store.Close()
					return nil, fmt.Errorf("file must be a portable reader")
				}
				_, err = io.Copy(io.NewOffsetWriter(store, 0), io.NewSectionReader(input, 0, input.Size()))
				if err == nil {
					r, err = repo.Open(store)
				} else {
					store.Close()
				}
			}
			if err != nil {
				return nil, err
			}
			return wrap(t, r)
		}),
	}
}

type RepositoryValue struct {
	r       *repo.Repository
	ctx     context.Context
	connect ConnectGit
}

func NewRepository(ctx context.Context, r *repo.Repository, connect ConnectGit) *RepositoryValue {
	return &RepositoryValue{r: r, ctx: ctx, connect: connect}
}
func (*RepositoryValue) String() string        { return "<scs.repository>" }
func (*RepositoryValue) Type() string          { return "scs.repository" }
func (*RepositoryValue) Freeze()               {}
func (*RepositoryValue) Truth() starlark.Bool  { return starlark.True }
func (*RepositoryValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: repository") }
func (*RepositoryValue) AttrNames() []string {
	return []string{"checkout", "checkout_git", "checkpoint", "clone", "close", "empty", "file", "git_refs", "refs"}
}
func (v *RepositoryValue) Attr(name string) (starlark.Value, error) {
	for _, n := range v.AttrNames() {
		if n == name {
			return starlark.NewBuiltin("repository."+name, func(t *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
				if err := v.ctx.Err(); err != nil && name != "close" {
					return nil, err
				}
				return v.call(t, name, a, k)
			}), nil
		}
	}
	return nil, nil
}
func (v *RepositoryValue) call(_ *starlark.Thread, name string, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
	unpack := func(pairs ...any) error { return starlark.UnpackArgs("repository."+name, a, k, pairs...) }
	switch name {
	case "empty":
		if err := unpack(); err != nil {
			return nil, err
		}
		return NewWorkspace(v.ctx, v.r.Empty()), nil
	case "checkout":
		var name string
		if err := unpack("name", &name); err != nil {
			return nil, err
		}
		w, err := v.r.Checkout(name)
		if err != nil {
			return nil, err
		}
		return NewWorkspace(v.ctx, w), nil
	case "checkout_git":
		revision, catalog := "HEAD", "git"
		if err := unpack("revision?", &revision, "catalog?", &catalog); err != nil {
			return nil, err
		}
		w, err := v.r.CheckoutGit(v.ctx, catalog, revision)
		if err != nil {
			return nil, err
		}
		return NewWorkspace(v.ctx, w), nil
	case "clone":
		var url string
		catalog := "git"
		packLimit, nativeLimit := int64(256<<20), int64(512<<30)
		if err := unpack("url", &url, "catalog?", &catalog, "max_pack_bytes?", &packLimit, "max_native_bytes?", &nativeLimit); err != nil {
			return nil, err
		}
		if packLimit < 32 || nativeLimit < 1 {
			return nil, fmt.Errorf("invalid clone limits")
		}
		if v.connect == nil {
			return nil, fmt.Errorf("native Git transport unavailable")
		}
		backend, err := v.connect(url)
		if err != nil {
			return nil, err
		}
		report, err := gitstore.Clone(v.ctx, v.r, url, gitstore.Options{Name: catalog, MaxPackBytes: packLimit, MaxNativeBytes: nativeLimit, Transport: backend})
		if err != nil {
			return nil, err
		}
		return record(starlark.StringDict{"head": starlark.String(report.Download.Head), "objects": starlark.MakeUint64(report.Objects), "pack_bytes": starlark.MakeInt64(report.Download.PackBytes), "stored_bytes": starlark.MakeInt64(report.Storage.FileBytes)}), nil
	case "refs":
		if err := unpack(); err != nil {
			return nil, err
		}
		dict := starlark.NewDict(len(v.r.Refs()))
		for name, id := range v.r.Refs() {
			if err := dict.SetKey(starlark.String(name), starlark.String(id)); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case "git_refs":
		catalog := "git"
		if err := unpack("catalog?", &catalog); err != nil {
			return nil, err
		}
		c, err := v.r.GitCatalog(catalog)
		if err != nil {
			return nil, err
		}
		dict := starlark.NewDict(len(c.Refs))
		for name, id := range c.Refs {
			if err := dict.SetKey(starlark.String(name), starlark.String(id)); err != nil {
				return nil, err
			}
		}
		return dict, nil
	case "file":
		if err := unpack(); err != nil {
			return nil, err
		}
		if err := v.r.Checkpoint(); err != nil {
			return nil, err
		}
		file, err := v.r.SnapshotFile()
		if err != nil {
			return nil, err
		}
		return starfile.NewReader("repository.scs", file), nil
	case "checkpoint":
		if err := unpack(); err != nil {
			return nil, err
		}
		return starlark.None, v.r.Checkpoint()
	case "close":
		if err := unpack(); err != nil {
			return nil, err
		}
		return starlark.None, v.r.Close()
	}
	return nil, fmt.Errorf("unknown repository operation %q", name)
}
