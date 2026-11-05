package native

import (
	"context"
	"fmt"
	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

type catalogTransportFunc func(context.Context, windowsupdate.Request) (windowsupdate.Response, error)

func (f catalogTransportFunc) Do(ctx context.Context, r windowsupdate.Request) (windowsupdate.Response, error) {
	return f(ctx, r)
}
func cacheTestProfile() windowsupdate.ScanOptions {
	return windowsupdate.ScanOptions{DeviceAttributes: map[string]string{"OSArchitecture": "test"}, CallerAttributes: map[string]string{"App": "test"}, Products: "PN=Test", Locales: []string{"en-US"}, UserAgent: "Test/1", AssumeNonLeafInstalled: true}
}
func cacheTestProtocol(calls *int) windowsupdate.ClientProtocol {
	bodies := []string{
		`<Envelope><GetCookieResult><EncryptedData>opaque</EncryptedData></GetCookieResult></Envelope>`,
		`<Envelope><NewUpdates><UpdateInfo UpdateID="01234567-89ab-cdef-0123-456789abcdef" RevisionNumber="7"><ID>42</ID><IsLeaf>true</IsLeaf><Title>Pinned offer</Title></UpdateInfo></NewUpdates><Truncated>false</Truncated></Envelope>`,
		`<Envelope><NewUpdates/><Truncated>false</Truncated></Envelope>`,
	}
	return windowsupdate.ClientProtocol{Transport: catalogTransportFunc(func(context.Context, windowsupdate.Request) (windowsupdate.Response, error) {
		if *calls >= len(bodies) {
			return windowsupdate.Response{}, fmt.Errorf("unexpected extra request")
		}
		body := bodies[*calls]
		*calls++
		return windowsupdate.Response{StatusCode: 200, Body: []byte(body)}, nil
	})}
}
func TestOfflineCatalogReplayNeverCallsNetwork(t *testing.T) {
	root, options := t.TempDir(), cacheTestProfile()
	calls := 0
	live, err := cachedCatalog(context.Background(), root, options, true, cacheTestProtocol(&calls))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("fetch requests=%d", calls)
	}
	deny := windowsupdate.ClientProtocol{Transport: catalogTransportFunc(func(context.Context, windowsupdate.Request) (windowsupdate.Response, error) {
		t.Error("offline catalog invoked network")
		return windowsupdate.Response{}, fmt.Errorf("network forbidden")
	})}
	for range 2 {
		cached, err := cachedCatalog(context.Background(), root, options, false, deny)
		if err != nil || !reflect.DeepEqual(live, cached) {
			t.Fatalf("offline catalog differs: %v", err)
		}
	}
	// Profile drift must not pick a nearby cache, refresh, or rank another offer.
	options.Products = "PN=Other"
	if _, err := cachedCatalog(context.Background(), root, options, false, deny); err == nil || !strings.Contains(err.Error(), "offline update catalog unavailable") {
		t.Fatalf("profile miss: %v", err)
	}
	options = cacheTestProfile()
	name, _, _ := catalogSourcePath(root, options)
	original, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	// A failed explicit refresh must preserve the previously complete source.
	failed := windowsupdate.ClientProtocol{Transport: catalogTransportFunc(func(context.Context, windowsupdate.Request) (windowsupdate.Response, error) {
		return windowsupdate.Response{}, fmt.Errorf("fetch failed")
	})}
	if _, err := cachedCatalog(context.Background(), root, options, true, failed); err == nil {
		t.Fatal("failed refresh accepted")
	}
	after, _ := os.ReadFile(name)
	if !reflect.DeepEqual(original, after) {
		t.Fatal("failed refresh overwrote cache")
	}
	original[len(original)-1] ^= 1
	if err := os.WriteFile(name, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cachedCatalog(context.Background(), root, options, false, deny); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("corruption: %v", err)
	}
}
func TestOfflineCatalogRejectsIncompleteAndMismatchedSource(t *testing.T) {
	root, options := t.TempDir(), cacheTestProfile()
	calls := 0
	if _, err := cachedCatalog(context.Background(), root, options, true, cacheTestProtocol(&calls)); err != nil {
		t.Fatal(err)
	}
	name, key, _ := catalogSourcePath(root, options)
	source, err := readCatalogSource(name, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"profile", "version", "sequence", "missing", "trailing"} {
		altered := *source
		altered.Exchanges = append([]catalogExchange(nil), source.Exchanges...)
		switch variant {
		case "profile":
			altered.Profile = "other"
		case "version":
			altered.Version++
		case "sequence":
			altered.Exchanges[0].Action = "other"
		case "missing":
			altered.Exchanges = altered.Exchanges[:1]
		case "trailing":
			altered.Exchanges = append(altered.Exchanges, altered.Exchanges[0])
		}
		if err := writeCatalogSource(name, altered); err != nil {
			t.Fatal(err)
		}
		// Nil transport is deliberate: failures may never reach a live fallback.
		if _, err := cachedCatalog(context.Background(), root, options, false, windowsupdate.ClientProtocol{}); err == nil {
			t.Fatalf("accepted %s", variant)
		}
	}
}

func TestOfflineCatalogBuiltinDefaultsIncludingBackground(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", home)
	t.Setenv("LOCALAPPDATA", home)
	t.Setenv("HOME", home)
	root, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	options := cacheTestProfile()
	calls := 0
	if _, err := cachedCatalog(context.Background(), filepath.Join(root, "tinyrangex", "uup"), options, true, cacheTestProtocol(&calls)); err != nil {
		t.Fatal(err)
	}
	attrs := func(values map[string]string) *starlark.Dict {
		d := starlark.NewDict(len(values))
		for k, v := range values {
			if err := d.SetKey(starlark.String(k), starlark.String(v)); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	for _, background := range []bool{false, true} {
		resources := lifecycle.New()
		thread := &starlark.Thread{Name: "offline catalog"}
		thread.SetLocal(lifecycle.ResourcesKey, resources)
		kwargs := []starlark.Tuple{
			{starlark.String("device_attributes"), attrs(options.DeviceAttributes)},
			{starlark.String("caller_attributes"), attrs(options.CallerAttributes)},
			{starlark.String("products"), starlark.String(options.Products)},
			{starlark.String("locales"), starlark.NewList([]starlark.Value{starlark.String("en-US")})},
			{starlark.String("user_agent"), starlark.String(options.UserAgent)},
			{starlark.String("assume_non_leaf_installed"), starlark.True},
			{starlark.String("background"), starlark.Bool(background)},
		}
		value, err := CatalogBuiltin(thread, nil, nil, kwargs)
		if err != nil {
			resources.Close()
			t.Fatal(err)
		}
		var catalog *catalogValue
		if background {
			catalog, err = value.(*catalogRequest).result()
		} else {
			catalog = value.(*catalogValue)
		}
		if err != nil || catalog == nil {
			resources.Close()
			t.Fatalf("catalog: %v", err)
		}
		if catalog.allowNetwork || catalog.protocol.Transport != nil || len(catalog.catalog.Revisions) != 1 {
			t.Fatal("default API retained network or lost cached selection")
		}
		resources.Close()
	}
}
