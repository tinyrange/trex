package native

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	update "github.com/tinyrange/trex/windows/update"
)

type snapshotLocationTransport struct {
	t     *testing.T
	calls int
	body  string
}

func (s *snapshotLocationTransport) Do(_ context.Context, r update.Request) (update.Response, error) {
	s.calls++
	if r.Endpoint != update.ClientSecured || !strings.HasSuffix(r.Action, "/GetExtendedUpdateInfo2") || !strings.Contains(string(r.Body), "locked-revision") || !strings.Contains(string(r.Body), "<RevisionNumber>7</RevisionNumber>") {
		s.t.Fatalf("unexpected discovery or identity change: endpoint=%v action=%s", r.Endpoint, r.Action)
	}
	return update.Response{StatusCode: 200, Body: []byte(s.body)}, nil
}

func TestSnapshotLocationRenewalPreservesLockAndNeverScans(t *testing.T) {
	f := update.File{Name: "original.cab", Size: 1, DigestSHA1: "010203", DigestSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("a"))), DownloadURL: "https://expired.invalid/original"}
	profile := &update.ScanOptions{DeviceAttributes: map[string]string{}, CallerAttributes: map[string]string{}, Products: "locked-product", Locales: []string{"en-US"}, UserAgent: "test"}
	s := &SourceSnapshot{Version: 1, Selected: update.UpdateIdentity{ID: "locked-revision", Revision: 7}, Revisions: []update.Offer{{ID: "locked-revision", Revision: 7, Files: []update.File{f}}}, Files: []update.File{f}, LocationProfile: profile}
	before, _ := json.Marshal(s)
	transport := &snapshotLocationTransport{t: t, body: `<Envelope><FileLocations><FileLocation><FileDigest>AQID</FileDigest><Url>https://renewed.invalid/original</Url></FileLocation></FileLocations></Envelope>`}
	files, err := refreshSourceLocations(context.Background(), s, update.ClientProtocol{Transport: transport})
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	got := files[0]
	got.DownloadURL = f.DownloadURL
	if got != f || files[0].DownloadURL != "https://renewed.invalid/original" || transport.calls != 1 {
		t.Fatalf("renewal changed content: %+v calls=%d", files, transport.calls)
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("renewal mutated tested lock")
	}
	// A missing profile must fail without making any network call; older locks
	// remain replayable from their archived objects.
	s.LocationProfile = nil
	if _, err = refreshSourceLocations(context.Background(), s, update.ClientProtocol{Transport: transport}); err == nil || transport.calls != 1 {
		t.Fatal("missing profile used network")
	}
	s.LocationProfile = profile
	s.Files[0].Size++
	if _, err = refreshSourceLocations(context.Background(), s, update.ClientProtocol{Transport: transport}); err == nil || transport.calls != 1 {
		t.Fatal("invalid content identity used network")
	}
}
