package native

import (
	"context"
	"testing"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

func TestPayloadLocationRefreshRetainsWholeClosure(t *testing.T) {
	original := []windowsupdate.File{
		{Name: "a.esd", Size: 8, DigestSHA256: "aaa", DownloadURL: "https://example.test/old-a"},
		{Name: "b.esd", Size: 16, DigestSHA256: "bbb", DownloadURL: "https://example.test/old-b"},
	}
	fresh := append([]windowsupdate.File(nil), original...)
	fresh[0].DownloadURL, fresh[1].DownloadURL = "https://example.test/new-a", "https://example.test/new-b"
	calls := 0
	resolve := payloadLocationResolver(original, func(context.Context) ([]windowsupdate.File, error) { calls++; return fresh, nil })
	for i, f := range original {
		got, err := resolve(context.Background(), f.Name, f.Size, []string{f.DownloadURL})
		if err != nil || len(got) != 1 || got[0] != fresh[i].DownloadURL {
			t.Fatalf("%s: %v, %v", f.Name, got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("closure refreshed %d times", calls)
	}
}

func TestPayloadLocationRefreshRejectsIdentityChanges(t *testing.T) {
	original := windowsupdate.File{Name: "a.esd", Size: 8, DigestSHA256: "aaa", DownloadURL: "https://example.test/old"}
	for _, changed := range []windowsupdate.File{
		{Name: "a.esd", Size: 9, DigestSHA256: "aaa", DownloadURL: "https://example.test/new"},
		{Name: "a.esd", Size: 8, DigestSHA256: "bbb", DownloadURL: "https://example.test/new"},
		{Name: "other.esd", Size: 8, DigestSHA256: "aaa", DownloadURL: "https://example.test/new"},
	} {
		resolve := payloadLocationResolver([]windowsupdate.File{original}, func(context.Context) ([]windowsupdate.File, error) { return []windowsupdate.File{changed}, nil })
		if _, err := resolve(context.Background(), original.Name, original.Size, []string{original.DownloadURL}); err == nil {
			t.Fatalf("accepted changed identity: %+v", changed)
		}
	}
}

func TestPayloadLocationRefreshRejectsUndeclaredAndCancelled(t *testing.T) {
	original := windowsupdate.File{Name: "a.esd", Size: 8, DigestSHA256: "aaa", DownloadURL: "https://example.test/old"}
	calls := 0
	resolve := payloadLocationResolver([]windowsupdate.File{original}, func(context.Context) ([]windowsupdate.File, error) { calls++; return nil, nil })
	if _, err := resolve(context.Background(), "other", 8, nil); err == nil {
		t.Fatal("accepted undeclared payload")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolve(ctx, original.Name, original.Size, nil); err == nil {
		t.Fatal("ignored cancellation")
	}
	if calls != 0 {
		t.Fatal("queried new locations for invalid request")
	}
}
