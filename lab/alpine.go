package lab

import (
	"cmp"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tinyrange/trex/archive/apk"
	storagenative "github.com/tinyrange/trex/storage/native"
	"go.starlark.net/starlark"
)

const alpineMirror = "https://dl-cdn.alpinelinux.org/alpine/v3.22/"
const alpineArchitecture = "x86_64"
const maxAlpineChoices = 32

// The three x86_64 keys shipped by Alpine 3.22 in main/alpine-keys.
//
//go:embed alpinekeys/*.pub
var alpineKeyFiles embed.FS

// AlpineRepository shares the last authenticated index snapshot between search
// and guest construction in one lab. Package payloads are opened in memory.
type AlpineRepository struct {
	client *http.Client
	keys   map[string]*rsa.PublicKey
	mu     sync.Mutex
	load   chan struct{}
	index  []apk.Package
	expiry time.Time
}

func NewAlpineRepository() (*AlpineRepository, error) {
	entries, err := alpineKeyFiles.ReadDir("alpinekeys")
	if err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(entries))
	for _, entry := range entries {
		data, err := fs.ReadFile(alpineKeyFiles, "alpinekeys/"+entry.Name())
		if err != nil {
			return nil, err
		}
		key, err := apk.PublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("Alpine signing key %s: %w", entry.Name(), err)
		}
		keys[entry.Name()] = key
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &AlpineRepository{client: client, keys: keys}, nil
}

func alpineURL(repository, basename string) string {
	return alpineMirror + repository + "/" + alpineArchitecture + "/" + basename
}

func (a *AlpineRepository) fetchIndex(ctx context.Context) ([]apk.Package, error) {
	var index []apk.Package
	for _, repository := range []string{"main", "community"} {
		file, err := storagenative.HTTPGet(ctx, a.client, alpineURL(repository, "APKINDEX.tar.gz"), 16<<20)
		if err != nil {
			return nil, fmt.Errorf("Alpine %s index: %w", repository, err)
		}
		records, err := apk.ReadIndex(file, a.keys)
		if err != nil {
			return nil, fmt.Errorf("Alpine %s index: %w", repository, err)
		}
		for _, record := range records {
			if record.Architecture == alpineArchitecture || record.Architecture == "noarch" {
				index = append(index, apk.Package{Repository: repository, Record: record})
			}
		}
	}
	return index, nil
}

func (a *AlpineRepository) snapshot(ctx context.Context) ([]apk.Package, error) {
	for {
		a.mu.Lock()
		if time.Now().Before(a.expiry) {
			index := a.index
			a.mu.Unlock()
			return index, nil
		}
		loading := a.load
		if loading == nil {
			a.load = make(chan struct{})
			a.mu.Unlock()
			break
		}
		a.mu.Unlock()
		select {
		case <-loading:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	index, err := a.fetchIndex(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err == nil {
		a.index, a.expiry = index, time.Now().Add(time.Hour)
	}
	close(a.load)
	a.load = nil
	return index, err
}

type AlpinePackage struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Repository  string `json:"repository"`
}

// Search queries both authenticated repositories using names and descriptions.
func (a *AlpineRepository) Search(ctx context.Context, query string) ([]AlpinePackage, error) {
	terms := strings.Fields(strings.ToLower(query))
	results := []AlpinePackage{}
	if len(terms) == 0 {
		return results, nil
	}
	index, err := a.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	type match struct {
		pkg  apk.Package
		rank int
	}
	var matches []match
	for _, pkg := range index {
		switch pkg.Name {
		case "busybox", "musl", "linux-virt":
			// These are supplied by the boot recipe itself.
			continue
		}
		name := strings.ToLower(pkg.Name)
		text := name + " " + strings.ToLower(pkg.Description)
		if slices.ContainsFunc(terms, func(term string) bool { return !strings.Contains(text, term) }) {
			continue
		}
		rank := 3
		switch {
		case name == terms[0]:
			rank = 0
		case strings.HasPrefix(name, terms[0]):
			rank = 1
		case strings.Contains(name, terms[0]):
			rank = 2
		}
		matches = append(matches, match{pkg, rank})
	}
	slices.SortFunc(matches, func(a, b match) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), strings.Compare(a.pkg.Name, b.pkg.Name), strings.Compare(a.pkg.ID(), b.pkg.ID()))
	})
	for _, m := range matches[:min(len(matches), 100)] {
		p := m.pkg
		results = append(results, AlpinePackage{p.ID(), p.Name, p.Version, p.Description, p.Repository})
	}
	return results, nil
}

func alpineChoices(value any) ([]string, bool) {
	switch value.(type) {
	case []string, []any:
	default:
		return nil, false
	}
	ids, valid := softwareChoices(value)
	if !valid || len(ids) > maxAlpineChoices {
		return nil, false
	}
	for _, id := range ids {
		repo, spec, _ := strings.Cut(id, "/")
		name, version, _ := strings.Cut(spec, "=")
		if (repo != "main" && repo != "community") || !apk.ValidIdentity(name) || !apk.ValidIdentity(version) {
			return nil, false
		}
	}
	return ids, true
}

func baseAlpinePackages(base starlark.Tuple) ([]apk.Package, error) {
	packs := make([]apk.Package, 0, len(base))
	for _, item := range base {
		record, ok := item.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("alpine: expected a base package record")
		}
		name, nameOK := starlark.AsString(value(record, "name"))
		version, versionOK := starlark.AsString(value(record, "version"))
		if !nameOK || !versionOK {
			return nil, fmt.Errorf("alpine: invalid base package record")
		}
		list := func(key string) []string {
			var out []string
			if items, ok := value(record, key).(starlark.Iterable); ok {
				for item := range starlark.Elements(items) {
					if text, ok := starlark.AsString(item); ok {
						out = append(out, text)
					}
				}
			}
			return out
		}
		packs = append(packs, apk.Package{Record: apk.Record{
			Name: name, Version: version, Dependencies: list("depends"), Provides: list("provides"),
		}})
	}
	return packs, nil
}

func (a *AlpineRepository) materialize(ctx context.Context, base starlark.Tuple, ids []string, memoryMiB int) (starlark.Value, error) {
	index, err := a.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	preinstalled, err := baseAlpinePackages(base)
	if err != nil {
		return nil, err
	}
	selected, err := apk.Resolve(index, preinstalled, ids, []string{"initramfs-generator"})
	if err != nil {
		return nil, err
	}
	var size, installed int64
	for _, pkg := range selected {
		if pkg.Size > 128<<20 || pkg.InstalledSize < 0 || pkg.InstalledSize > 512<<20 {
			return nil, fmt.Errorf("Alpine package %s exceeds the image builder size limit", pkg.Name)
		}
		size += pkg.Size
		installed += pkg.InstalledSize
	}
	if size > 192<<20 || installed > min(384<<20, int64(memoryMiB)<<19) {
		return nil, fmt.Errorf("the selected Alpine packages exceed this guest's image budget")
	}
	records := make(starlark.Tuple, len(selected))
	for i, pkg := range selected {
		file, err := storagenative.HTTPGet(ctx, a.client, alpineURL(pkg.Repository, pkg.Name+"-"+pkg.Version+".apk"), pkg.Size)
		if err != nil {
			return nil, fmt.Errorf("Alpine package %s: %w", pkg.Name, err)
		}
		if err := apk.VerifyPackage(file, pkg.Record, a.keys, 512<<20); err != nil {
			return nil, fmt.Errorf("Alpine package %s: %w", pkg.Name, err)
		}
		sum := sha256.Sum256(file.Data)
		records[i] = dictionary(map[string]starlark.Value{
			"file": file, "sha256": starlark.String(hex.EncodeToString(sum[:])),
			"expected": dictionary(map[string]starlark.Value{
				"name": starlark.String(pkg.Name), "version": starlark.String(pkg.Version),
				"arch": starlark.String(pkg.Architecture), "size": starlark.MakeInt64(pkg.Size),
				"checksum": starlark.String(pkg.Checksum),
			}),
		})
	}
	return records, nil
}
