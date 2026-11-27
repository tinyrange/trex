package lab

import (
	"context"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type testIndyMedia struct {
	starfile.Bytes
	version string
}

func (m *testIndyMedia) SameMediaVersion(other starfile.File) bool {
	current, ok := other.(*testIndyMedia)
	return ok && m.version == current.version
}

func TestIndyTemplateUsesMatchingMedia(t *testing.T) {
	cache := &IndyTemplates{}
	source := func(version string) map[string]starlark.Value {
		return map[string]starlark.Value{"cd": &testIndyMedia{version: version}}
	}
	result, err := cache.checkpoint(t.Context(), source("original"), func() (starlark.Value, error) {
		return starlark.String("pristine checkpoint"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cache.checkpoint(t.Context(), source("original"), nil); got != result || err != nil {
		t.Fatalf("matching source: got %v, %v", got, err)
	}
	if got, err := cache.checkpoint(t.Context(), source("replaced"), nil); got != starlark.None || err != nil {
		t.Fatalf("changed source: got %v, %v", got, err)
	}
}

func TestIndyTemplateWaitsForMatchingPreparation(t *testing.T) {
	cache := &IndyTemplates{}
	media := map[string]starlark.Value{"cd": &testIndyMedia{version: "original"}}
	started := make(chan struct{})
	finish := make(chan struct{})
	prepared := make(chan error, 1)
	go func() {
		_, err := cache.checkpoint(t.Context(), media, func() (starlark.Value, error) {
			close(started)
			<-finish
			return starlark.String("ready"), nil
		})
		prepared <- err
	}()
	<-started
	wait, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := cache.checkpoint(wait, media, nil)
	close(finish)
	if prepareErr := <-prepared; prepareErr != nil {
		t.Fatal(prepareErr)
	}
	if err != context.Canceled {
		t.Fatalf("canceled waiter: got %v", err)
	}
	if got, err := cache.checkpoint(t.Context(), media, nil); got != starlark.String("ready") || err != nil {
		t.Fatalf("prepared source: got %v, %v", got, err)
	}
}
