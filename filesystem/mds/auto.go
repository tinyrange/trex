package mds

import (
	"fmt"
	"path"
	"strings"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("mds", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if len(prefix) < 16 || string(prefix[:16]) != "MEDIA DESCRIPTOR" {
			return nil, auto.ErrNoMatch
		}
		image, err := Open(source)
		if err != nil {
			return nil, err
		}
		count := len(image.Sessions)
		for _, s := range image.Sessions {
			count += len(s.Tracks) * 4
		}
		if count > options.MaxEntries {
			return nil, auto.ErrLimit
		}
		var resolve Resolver
		if options.Source != nil {
			cache := map[string]storage.Reader{}
			resolve = func(name string) (storage.Reader, error) {
				if strings.EqualFold(name, "*.mdf") {
					base := path.Base(options.Source.Path)
					name = strings.TrimSuffix(base, path.Ext(base)) + name[1:]
				}
				if !safeCompanion(name) {
					return nil, fmt.Errorf("mds: unsafe companion name %q", name)
				}
				if f := cache[name]; f != nil {
					return f, nil
				}
				e, err := options.Source.Lookup(path.Join(path.Dir(options.Source.Path), name), options)
				if err != nil {
					return nil, err
				}
				if e.Kind != "file" || e.Reader == nil {
					return nil, fmt.Errorf("mds: companion %q is not a regular file", name)
				}
				cache[name] = e.Reader
				return e.Reader, nil
			}
		}
		return image.View(resolve)
	})
}
