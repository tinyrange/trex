package native

import (
	"context"
	"fmt"
	"strings"
	"sync"

	storagenative "github.com/tinyrange/trex/storage/native"
	windowsupdate "github.com/tinyrange/trex/windows/update"
)

// Renew only locations, never revision selection or payload identity. One
// response renews the whole media closure so concurrent readers can reuse it.
func payloadLocationResolver(original []windowsupdate.File, resolve func(context.Context) ([]windowsupdate.File, error)) storagenative.HTTPRangeLocationResolver {
	declared := append([]windowsupdate.File(nil), original...)
	var mu sync.Mutex
	var latest []windowsupdate.File
	return func(ctx context.Context, name string, size int64, previous []string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var expected *windowsupdate.File
		for i := range declared {
			f := &declared[i]
			if !strings.EqualFold(f.Name, name) || f.Size != size {
				continue
			}
			if f.DigestSHA256 == "" || (expected != nil && !strings.EqualFold(f.DigestSHA256, expected.DigestSHA256)) {
				return nil, fmt.Errorf("payload %q has ambiguous declared content identity", name)
			}
			expected = f
		}
		if expected == nil {
			return nil, fmt.Errorf("payload %q is absent from the original media closure", name)
		}
		selectURL := func(files []windowsupdate.File) (string, error) {
			var selected string
			for _, f := range files {
				if !strings.EqualFold(f.Name, expected.Name) {
					continue
				}
				if f.Size != expected.Size || !strings.EqualFold(f.DigestSHA256, expected.DigestSHA256) {
					return "", fmt.Errorf("refreshed payload %q changed its declared size or SHA-256", name)
				}
				if f.DownloadURL != "" {
					selected = f.DownloadURL
				}
			}
			return selected, nil
		}
		url, err := selectURL(latest)
		if err != nil {
			return nil, err
		}
		old := false
		for _, previousURL := range previous {
			old = old || previousURL == url
		}
		if url != "" && !old {
			return []string{url}, nil
		}
		files, err := resolve(ctx)
		if err != nil {
			return nil, err
		}
		url, err = selectURL(files)
		if err != nil {
			return nil, err
		}
		if url == "" {
			return nil, fmt.Errorf("payload %q is absent from renewed locations", name)
		}
		latest = files
		return []string{url}, nil
	}
}
