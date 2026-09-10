package native

import (
	"context"
	"fmt"
	"strings"
	"testing"

	starvalue "github.com/tinyrange/trex/storage/star"
	windowsupdate "github.com/tinyrange/trex/windows/update"
	"go.starlark.net/starlark"
)

type locationOnlyTransport struct{ requests []windowsupdate.Request }

func (t *locationOnlyTransport) Do(_ context.Context, request windowsupdate.Request) (windowsupdate.Response, error) {
	t.requests = append(t.requests, request)
	if request.Endpoint != windowsupdate.ClientSecured || !strings.HasSuffix(request.Action, "/GetExtendedUpdateInfo2") {
		return windowsupdate.Response{}, fmt.Errorf("unexpected rediscovery: %s", request.Action)
	}
	return windowsupdate.Response{StatusCode: 200, Body: []byte(`<Envelope><FileLocations><FileLocation><FileDigest>AQID</FileDigest><Url>https://example.invalid/payload</Url></FileLocation></FileLocations></Envelope>`)}, nil
}
func testCatalog(t *testing.T, transport windowsupdate.Transport) *catalogValue {
	t.Helper()
	options := windowsupdate.ScanOptions{
		DeviceAttributes: map[string]string{"DeviceFamily": "Example.Server"},
		CallerAttributes: map[string]string{}, Products: "PN=Example", Locales: []string{"ja-JP"}, UserAgent: "Test/1",
	}
	revisions := []windowsupdate.Offer{{
		ID: "selected", ServerID: "1", Revision: 7, IsLeaf: true,
		Title: "Server Preview", ProductRelease: "Server.OS",
		Files: []windowsupdate.File{{Name: "custom.cab", DigestSHA1: "010203", DigestSHA256: "original", Size: 123}},
	}}
	// The catalog must not truncate selection to the old 100/1000 summary limits.
	for index := 0; index < 1100; index++ {
		revisions = append(revisions, windowsupdate.Offer{ID: fmt.Sprint(index), ServerID: fmt.Sprint(index + 2), Revision: 1})
	}
	return newCatalogValue(&windowsupdate.Catalog{Revisions: revisions}, options, windowsupdate.ClientProtocol{Transport: transport})
}
func TestCatalogSelectionPreservesIdentityWithoutDiscovery(t *testing.T) {
	transport := &locationOnlyTransport{}
	catalog := testCatalog(t, transport)
	offers := catalog.Get("offers").(*starlark.List)
	if offers.Len() != 1101 {
		t.Fatal("catalog truncated")
	}
	if err := offers.Append(starlark.None); err == nil {
		t.Fatal("offer list is mutable")
	}
	value := offers.Index(0).(*offerValue)
	files := value.Get("files").(*starlark.List)
	if err := files.Append(starlark.None); err == nil {
		t.Fatal("declared files are mutable")
	}
	if files.Index(0).(*starvalue.Record).Get("sha256") != starlark.String("original") {
		t.Fatal("file identity lost")
	}
	selected, offer, err := selectedOffer(catalog, value)
	if err != nil {
		t.Fatal(err)
	}
	// Server/preview titles are not filtered by Go. Refresh resolves only this
	// exact revision with the original profile and never calls SyncCatalog.
	for iteration := 0; iteration < 2; iteration++ {
		closure, resolved, err := selected.resolveFiles(context.Background(), offer)
		if err != nil {
			t.Fatal(err)
		}
		if len(closure) != 1 || closure[0].Revision != 7 || len(resolved) != 1 || resolved[0].DigestSHA256 != "original" || resolved[0].Size != 123 {
			t.Fatalf("identity changed: %+v %+v", closure, resolved)
		}
	}
	for _, request := range transport.requests {
		body := string(request.Body)
		if !strings.Contains(body, "<UpdateID>selected</UpdateID><RevisionNumber>7</RevisionNumber>") || !strings.Contains(body, "DeviceFamily=Example.Server") {
			t.Fatalf("selection/profile changed: %s", body)
		}
	}
	other := testCatalog(t, transport)
	if _, _, err := selectedOffer(other, value); err == nil {
		t.Fatal("accepted foreign catalog offer")
	}
	if _, _, err := selectedOffer(catalog, starvalue.NewRecord(starlark.StringDict{"id": starlark.String("selected")})); err == nil {
		t.Fatal("accepted forged offer")
	}
}
