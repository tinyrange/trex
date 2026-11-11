package native

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	update "github.com/tinyrange/trex/windows/update"
	"testing"
)

func TestSnapshotReplayHasNoCatalogTransportOrLocationResolver(t *testing.T) {
	body := []byte("original bytes")
	file := update.File{Name: "metadata.cab", Size: int64(len(body)), DigestSHA256: fmt.Sprintf("%x", sha256.Sum256(body)), DownloadURL: "https://expired.invalid/source"}
	revision := update.Offer{ID: "historical", Revision: 1, IsLeaf: true, Files: []update.File{file}}
	snapshot := &SourceSnapshot{Version: 1, Selected: update.UpdateIdentity{ID: revision.ID, Revision: 1}, Revisions: []update.Offer{revision}, Files: []update.File{file}}
	opens := 0
	catalogArg, offerArg, err := ReplaySource(snapshot, func(_ context.Context, f update.File) (storage.Reader, error) {
		opens++
		if f.DigestSHA256 != file.DigestSHA256 {
			t.Fatal("identity changed")
		}
		return &starfile.Bytes{Data: body}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	catalog, offer, err := selectedOffer(catalogArg, offerArg)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.allowNetwork || catalog.protocol.Transport != nil {
		t.Fatal("replay installed a network transport")
	}
	if _, _, err = catalog.resolveFiles(context.Background(), offer); err == nil {
		t.Fatal("replay resolved URLs")
	}
	resources := lifecycle.New()
	defer resources.Close()
	reader, err := openPayload(resources, archivedPayloadPool{catalog.payloads}, file, file.Size)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(body))
	if _, err = reader.ReadAt(got, 0); err != nil || string(got) != string(body) || opens != 1 {
		t.Fatalf("%q %v opens=%d", got, err, opens)
	}
}
func TestSnapshotRejectsChangedDependencyAndUnknownFormat(t *testing.T) {
	file := update.File{Name: "a.cab", Size: 1, DigestSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("a")))}
	s := &SourceSnapshot{Version: 1, Selected: update.UpdateIdentity{ID: "one", Revision: 1}, Revisions: []update.Offer{{ID: "one", Revision: 1, Files: []update.File{file}}}, Files: []update.File{file}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Files[0].Size = 2
	if err := s.Validate(); err == nil {
		t.Fatal("accepted changed dependency")
	}
	s.Files[0] = file
	s.Version = 2
	if err := s.Validate(); err == nil {
		t.Fatal("accepted unsupported major")
	}
}

// Real Server bundles contain different versions of optional/language payloads
// under the same filename. Content identity, not filename, distinguishes them.
func TestSnapshotKeepsDifferentContentWithSameFilename(t *testing.T) {
	one := update.File{Name: "feature.cab", Size: 1, DigestSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("a")))}
	two := one
	two.DigestSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("b")))
	s := &SourceSnapshot{Version: 1, Selected: update.UpdateIdentity{ID: "root", Revision: 1}, Revisions: []update.Offer{{ID: "root", Revision: 1, Files: []update.File{one, two}}}, Files: []update.File{one, two}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Files = s.Files[:1]
	if err := s.Validate(); err == nil {
		t.Fatal("accepted missing same-name version")
	}
}
