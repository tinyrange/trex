package lab

import (
	"context"
	"fmt"
	"sync"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// IndyTemplates retains one prepared Indy boot in the Lab service. The cached
// checkpoint represents an untouched login screen, independent of any guest.
type IndyTemplates struct {
	mu        sync.Mutex
	ready     *indyTemplate
	preparing map[string]starlark.Value
	prepared  chan struct{}
}

type indyTemplate struct {
	media      map[string]starlark.Value
	checkpoint starlark.Value
}

type versionedMedia interface {
	SameMediaVersion(starfile.File) bool
}

func sameIndyMedia(a, b map[string]starlark.Value) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for key, value := range a {
		saved, ok := value.(versionedMedia)
		current, fileOK := b[key].(starfile.File)
		if !ok || !fileOK || !saved.SameMediaVersion(current) {
			return false
		}
	}
	return true
}

func (t *IndyTemplates) checkpoint(ctx context.Context, media map[string]starlark.Value, prepare func() (starlark.Value, error)) (starlark.Value, error) {
	if t == nil {
		return starlark.None, nil
	}
	for {
		t.mu.Lock()
		if t.ready != nil && sameIndyMedia(t.ready.media, media) {
			result := t.ready.checkpoint
			t.mu.Unlock()
			return result, nil
		}
		if t.prepared != nil && (prepare != nil || sameIndyMedia(t.preparing, media)) {
			done := t.prepared
			t.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if prepare == nil {
			t.mu.Unlock()
			return starlark.None, nil
		}
		if !sameIndyMedia(media, media) {
			t.mu.Unlock()
			return nil, fmt.Errorf("Indy template requires identifiable original media")
		}
		done := make(chan struct{})
		t.preparing, t.prepared = media, done
		t.mu.Unlock()

		result, err := prepare()

		t.mu.Lock()
		if err == nil {
			t.ready = &indyTemplate{media, result}
		}
		t.preparing, t.prepared = nil, nil
		close(done)
		t.mu.Unlock()
		return result, err
	}
}

// PrepareIndy makes the default six-disc configuration available for fast
// launches without changing the saved lab or retaining a running guest.
func (f StarFactory) PrepareIndy(ctx context.Context, recipe Recipe, log func(string)) error {
	request := StartRequest{
		Node:   Node{ID: "irix-indy", Recipe: recipe.ID, Config: map[string]any{"source": "discs"}},
		Recipe: recipe, Log: log,
		Phase: func(_, message string) { log(message) },
	}
	guest, err := f.start(ctx, request, true)
	if err != nil {
		return err
	}
	return guest.Close()
}
