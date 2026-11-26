package native

import (
	"context"
	"fmt"

	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

var backgroundMirrorSlots = make(chan struct{}, 3)

type mirrorRequest struct {
	cancel context.CancelFunc
	done   chan struct{}
	file   *CachedFile
	err    error
}

func startMirrorRequest(resources *lifecycle.Resources, cache *MirrorCache, request MirrorRequest) (*mirrorRequest, error) {
	ctx, cancel := context.WithCancel(resources.Context())
	result := &mirrorRequest{cancel: cancel, done: make(chan struct{})}
	if _, err := resources.Add(result); err != nil {
		cancel()
		return nil, err
	}
	go func() {
		defer close(result.done)
		select {
		case backgroundMirrorSlots <- struct{}{}:
			defer func() { <-backgroundMirrorSlots }()
			result.file, result.err = cache.Open(ctx, request)
		case <-ctx.Done():
			result.err = ctx.Err()
		}
	}()
	return result, nil
}

func (r *mirrorRequest) Close() error {
	r.cancel()
	<-r.done
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

func (*mirrorRequest) String() string        { return "<verified mirror request>" }
func (*mirrorRequest) Type() string          { return "mirror_request" }
func (*mirrorRequest) Freeze()               {}
func (*mirrorRequest) Truth() starlark.Bool  { return starlark.True }
func (*mirrorRequest) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: mirror_request") }
func (*mirrorRequest) AttrNames() []string   { return []string{"result"} }
func (r *mirrorRequest) Attr(name string) (starlark.Value, error) {
	if name != "result" {
		return nil, nil
	}
	return starlark.NewBuiltin("mirror_request.result", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("mirror_request.result", args, kwargs); err != nil {
			return nil, err
		}
		<-r.done
		if r.err != nil {
			return nil, r.err
		}
		return r.file, nil
	}), nil
}
