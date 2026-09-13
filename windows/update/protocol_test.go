package update

import (
	"context"
	"strings"
	"testing"
	"time"
)

type scriptedTransport struct {
	requests  []Request
	responses []Response
}

func (t *scriptedTransport) Do(_ context.Context, request Request) (Response, error) {
	t.requests = append(t.requests, request)
	response := t.responses[0]
	t.responses = t.responses[1:]
	return response, nil
}

func TestSyncComposesCookieAndScanAndParsesLeafOffer(t *testing.T) {
	transport := &scriptedTransport{responses: []Response{
		{StatusCode: 200, Body: []byte(`<Envelope><GetCookieResult><Expiration>2026-09-03T00:00:00Z</Expiration><EncryptedData>opaque&amp;cookie</EncryptedData></GetCookieResult></Envelope>`)},
		{StatusCode: 200, Body: []byte(`<Envelope><NewUpdates><UpdateInfo UpdateID="01234567-89ab-cdef-0123-456789abcdef" RevisionNumber="7"><ID>42</ID><IsLeaf>true</IsLeaf><Title>Feature update to Windows 11</Title><Files><File Digest="AQID" FileName="metadata.esd" Size="123"><AdditionalDigest Algorithm="SHA256">BAUG</AdditionalDigest></File></Files></UpdateInfo><UpdateInfo UpdateID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" RevisionNumber="1"><ID>9</ID><IsLeaf>false</IsLeaf></UpdateInfo></NewUpdates><Truncated>false</Truncated></Envelope>`)},
		{StatusCode: 200, Body: []byte(`<Envelope><NewUpdates/><Truncated>false</Truncated></Envelope>`)},
	}}
	client := ClientProtocol{
		Transport: transport,
		Clock:     func() time.Time { return time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC) },
		Random:    strings.NewReader(strings.Repeat("r", 575)),
	}
	offers, err := client.Sync(context.Background(), testScanOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(transport.requests) != 3 || transport.requests[0].Endpoint != Client || transport.requests[1].Endpoint != Client || transport.requests[2].Endpoint != Client {
		t.Fatalf("requests = %#v", transport.requests)
	}
	if !strings.Contains(string(transport.requests[1].Body), "opaque&amp;cookie") || !strings.Contains(string(transport.requests[1].Body), "PN=Example.Server&amp;V=99.2.3.4") || strings.Contains(string(transport.requests[1].Body), "<int>9</int>") {
		t.Fatalf("SyncUpdates body = %s", transport.requests[1].Body)
	}
	if !strings.Contains(string(transport.requests[2].Body), `<InstalledNonLeafUpdateIDs><int>9</int></InstalledNonLeafUpdateIDs>`) ||
		!strings.Contains(string(transport.requests[2].Body), `<OtherCachedUpdateIDs><int>42</int></OtherCachedUpdateIDs>`) {
		t.Fatalf("second SyncUpdates body = %s", transport.requests[2].Body)
	}
	if len(offers) != 1 {
		t.Fatalf("offers = %#v", offers)
	}
	offer := offers[0]
	if offer.ID != "01234567-89ab-cdef-0123-456789abcdef" || offer.Revision != 7 || offer.Title != "Feature update to Windows 11" {
		t.Fatalf("offer = %#v", offer)
	}
	if len(offer.Files) != 1 || offer.Files[0].DigestSHA1 != "010203" || offer.Files[0].DigestSHA256 != "040506" || offer.Files[0].Size != 123 {
		t.Fatalf("files = %#v", offer.Files)
	}
}

func testScanOptions() ScanOptions {
	return ScanOptions{
		DeviceAttributes: map[string]string{"OSArchitecture": "future-arch", "DeviceFamily": "Example.Server", "IsFlightingEnabled": "1"},
		CallerAttributes: map[string]string{"App": "Example"}, Products: "PN=Example.Server&V=99.2.3.4",
		Locales: []string{"fr-FR", "ja-JP"}, UserAgent: "Example-Client/9", AssumeNonLeafInstalled: true,
	}
}

func TestScanOptionsAreExplicitAndPolicyFree(t *testing.T) {
	if err := ValidateScanOptions(ScanOptions{}); err == nil {
		t.Fatal("empty profile acquired implicit defaults")
	}
	options := testScanOptions()
	if err := ValidateScanOptions(options); err != nil {
		t.Fatal(err)
	}
	body := string(composeSyncUpdates(time.Unix(0, 0), "id", "device", Cookie{}, options, nil, nil))
	for _, wanted := range []string{"DeviceFamily=Example.Server", "OSArchitecture=future-arch", "IsFlightingEnabled=1", "<Locales><string>fr-FR</string><string>ja-JP</string></Locales>", "<CallerAttributes>E:App=Example</CallerAttributes>"} {
		if !strings.Contains(body, wanted) {
			t.Fatalf("missing %q in %s", wanted, body)
		}
	}
	for _, unwanted := range []string{"GE24H2", "GE25H2", "ge_release", "26100", "Windows.Desktop", "FlightRing=Retail", "Client.OS", "SecureBootCapable", "TPMVersion"} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("injected policy %q", unwanted)
		}
	}
	for _, mutate := range []func(*ScanOptions){
		func(o *ScanOptions) { o.DeviceAttributes = nil },
		func(o *ScanOptions) { o.CallerAttributes = nil },
		func(o *ScanOptions) { o.Products = "" },
		func(o *ScanOptions) { o.Locales = nil },
		func(o *ScanOptions) { o.UserAgent = "" },
		func(o *ScanOptions) { o.UserAgent = "bad\r\nheader" },
		func(o *ScanOptions) { o.DeviceAttributes["bad=key"] = "value" },
		func(o *ScanOptions) { o.CallerAttributes["App"] = "value&injected=1" },
	} {
		invalid := testScanOptions()
		mutate(&invalid)
		if err := ValidateScanOptions(invalid); err == nil {
			t.Fatalf("accepted invalid profile: %+v", invalid)
		}
	}
}

func TestNonLeafInstallationIsCallerPolicy(t *testing.T) {
	transport := &scriptedTransport{responses: []Response{
		{StatusCode: 200, Body: []byte(`<Envelope><GetCookieResult><EncryptedData>cookie</EncryptedData></GetCookieResult></Envelope>`)},
		{StatusCode: 200, Body: []byte(`<Envelope><NewUpdates><UpdateInfo UpdateID="id" RevisionNumber="1"><ID>9</ID><IsLeaf>false</IsLeaf></UpdateInfo></NewUpdates></Envelope>`)},
		{StatusCode: 200, Body: []byte(`<Envelope><NewUpdates/></Envelope>`)},
	}}
	options := testScanOptions()
	options.AssumeNonLeafInstalled = false
	_, err := (ClientProtocol{Transport: transport}).SyncCatalog(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	last := string(transport.requests[2].Body)
	if !strings.Contains(last, `<InstalledNonLeafUpdateIDs></InstalledNonLeafUpdateIDs>`) || !strings.Contains(last, `<OtherCachedUpdateIDs><int>9</int></OtherCachedUpdateIDs>`) {
		t.Fatalf("non-leaf installation policy ignored: %s", last)
	}
	for _, request := range transport.requests {
		if request.UserAgent != options.UserAgent {
			t.Fatal("user agent was changed")
		}
	}
}

func TestParseSyncOffersJoinsLeafToUpdateMetadata(t *testing.T) {
	data := []byte(`<Envelope><NewUpdates><UpdateInfo><ID>42</ID><IsLeaf>true</IsLeaf><Xml>&lt;UpdateIdentity UpdateID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" RevisionNumber="9" /&gt;&lt;ApplicabilityRules&gt;&lt;ProductReleaseInstalled Name="Client.OS.RS2.amd64" Version="10.0.26100.1" /&gt;&lt;/ApplicabilityRules&gt;&lt;Relationships&gt;&lt;Prerequisites&gt;&lt;AtLeastOne IsCategory="true"&gt;&lt;UpdateIdentity UpdateID="11111111-1111-1111-1111-111111111111" RevisionNumber="2"/&gt;&lt;UpdateIdentity UpdateID="22222222-2222-2222-2222-222222222222" RevisionNumber="3"/&gt;&lt;/AtLeastOne&gt;&lt;UpdateIdentity UpdateID="33333333-3333-3333-3333-333333333333" RevisionNumber="4"/&gt;&lt;/Prerequisites&gt;&lt;/Relationships&gt;</Xml></UpdateInfo><Update><ID>42</ID><Xml>&lt;LocalizedProperties&gt;&lt;Title&gt;Windows 11 feature update&lt;/Title&gt;&lt;/LocalizedProperties&gt;</Xml><Files><File Digest="AQID" FileName="metadata.esd" Size="123" /></Files></Update></NewUpdates></Envelope>`)
	offers, err := parseSyncOffers(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 1 {
		t.Fatalf("offers = %#v", offers)
	}
	offer := offers[0]
	if offer.ServerID != "42" || offer.ID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" || offer.Revision != 9 || offer.Title != "Windows 11 feature update" || offer.ProductRelease != "Client.OS.RS2.amd64" || len(offer.Files) != 1 || len(offer.Prerequisites) != 2 || len(offer.Prerequisites[0].Alternatives) != 2 || !offer.Prerequisites[0].IsCategory {
		t.Fatalf("offer = %#v", offer)
	}
}

func TestParseSyncRoundChangedOutOfScopeAndCookie(t *testing.T) {
	round, err := parseSyncRound([]byte(`<Envelope><ChangedUpdates><UpdateInfo><ID>7</ID><IsLeaf>false</IsLeaf><Deployment Action="Evaluate"/></UpdateInfo></ChangedUpdates><OutOfScopeRevisionIDs><int>8</int></OutOfScopeRevisionIDs><DeployedOutOfScopeRevisionIds><int>9</int></DeployedOutOfScopeRevisionIds><Truncated>true</Truncated><NewCookie><Expiration>later</Expiration><EncryptedData>next</EncryptedData></NewCookie></Envelope>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(round.New) != 0 || len(round.Changed) != 1 || round.Changed[0].ServerID != "7" || round.Changed[0].Deployment != "Evaluate" || !round.Truncated || round.Cookie == nil || round.Cookie.EncryptedData != "next" {
		t.Fatalf("round = %#v", round)
	}
	if _, found := round.OutOfScope["8"]; !found {
		t.Fatal("missing ordinary out-of-scope revision")
	}
	if _, found := round.OutOfScope["9"]; !found {
		t.Fatal("missing deployed out-of-scope revision")
	}
}

func TestParseFileLocationsJoinsDeclaredIdentity(t *testing.T) {
	files, err := parseFileLocations([]byte(`<Envelope><FileLocations><FileLocation><FileDigest>AQID</FileDigest><Url>https://download.example/files/payload</Url></FileLocation></FileLocations></Envelope>`), []File{{DigestSHA1: "010203", DigestSHA256: "040506", Name: "metadata.esd", Size: 123}})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != "metadata.esd" || files[0].DigestSHA256 != "040506" || files[0].Size != 123 || files[0].DownloadURL != "https://download.example/files/payload" {
		t.Fatalf("files = %#v", files)
	}
}
