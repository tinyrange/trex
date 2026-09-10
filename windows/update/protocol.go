// Package update implements the portable parts of the Microsoft Windows
// Update ClientWebService protocol. Network access is supplied by a backend
// Transport so request construction and response parsing remain usable in
// environments without native sockets.
package update

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Endpoint identifies a Windows Update service without exposing its native
// URL through the portable protocol API.
type Endpoint uint8

const (
	Client Endpoint = iota + 1
	ClientSecured
)

const (
	actionGetCookie       = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"
	actionSyncUpdates     = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates"
	actionGetExtendedInfo = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo2"
)

// Request is one bounded SOAP request to a Windows Update endpoint.
type Request struct {
	Endpoint  Endpoint
	Action    string
	Body      []byte
	UserAgent string
}

// Response contains the transport-independent result of a request.
type Response struct {
	StatusCode int
	Body       []byte
}

// Transport sends a Windows Update protocol request.
type Transport interface {
	Do(context.Context, Request) (Response, error)
}

// Cookie is the opaque server-issued state required by SyncUpdates.
type Cookie struct {
	Expiration    string
	EncryptedData string
}

// ScanOptions contains caller-authored discovery policy. No Windows release,
// device capabilities, channel, product or locale is inferred by the protocol.
type ScanOptions struct {
	DeviceAttributes       map[string]string
	CallerAttributes       map[string]string
	Products               string
	Locales                []string
	UserAgent              string
	AssumeNonLeafInstalled bool
}

// Offer is the stable identity and metadata exposed for one leaf update.
// RawXML is retained because Microsoft adds metadata fields over time.
type Offer struct {
	ID             string
	ServerID       string
	Revision       int
	IsLeaf         bool
	Deployment     string
	UpdateType     string
	Title          string
	ProductRelease string
	Files          []File
	Prerequisites  []RelationshipClause
	BundledUpdates []RelationshipClause
	RawXML         []byte
}

// UpdateIdentity is the stable identity used by prerequisite and bundle
// relationships. ServerID is deliberately absent: relationships are declared
// in terms of the global update ID and revision number.
type UpdateIdentity struct {
	ID       string
	Revision int
}

// RelationshipClause is one AND term containing one or more OR alternatives.
// A sequence of clauses is therefore satisfied only when every clause has at
// least one satisfied alternative.
type RelationshipClause struct {
	Alternatives []UpdateIdentity
	IsCategory   bool
}

const maximumSyncRounds = 64

type syncRound struct {
	New        []Offer
	Changed    []Offer
	OutOfScope map[string]struct{}
	Truncated  bool
	Cookie     *Cookie
}

// Catalog is the complete revision cache produced by an MS-WUSP software
// synchronization sequence. Revisions contains leaf offers, detectoids,
// categories, prerequisites, and bundle members; it is not a flat download
// list.
type Catalog struct {
	Revisions []Offer
	Rounds    int
}

// File describes one payload declared by an update offer. Download locations
// are acquired separately because Microsoft signs them for a short lifetime.
type File struct {
	DigestSHA1   string
	DigestSHA256 string
	Name         string
	Size         int64
	DownloadURL  string
}

// ClientProtocol coordinates portable request composition and parsing.
type ClientProtocol struct {
	Transport Transport
	Clock     func() time.Time
	Random    io.Reader
	Observe   func(SyncProgress)
}

// SyncProgress is a bounded per-round diagnostic. It contains counts only;
// callers that need metadata use the final Catalog.
type SyncProgress struct {
	Round, New, Changed, Cached, InstalledNonLeaf int
	Truncated                                     bool
}

// Sync performs the complete metadata synchronization sequence required by
// MS-WUSP and returns the leaf offers in the resulting client cache. This
// caller may explicitly request synthetic non-leaf installation; otherwise
// discovered revisions are retained as ordinary cached updates.
func (c ClientProtocol) Sync(ctx context.Context, options ScanOptions) ([]Offer, error) {
	catalog, err := c.SyncCatalog(ctx, options)
	if err != nil {
		return nil, err
	}
	cache := make(map[string]Offer, len(catalog.Revisions))
	for _, offer := range catalog.Revisions {
		cache[offer.ServerID] = offer
	}
	return leafOffers(cache), nil
}

// SyncCatalog performs the complete metadata synchronization sequence and
// returns every cached revision needed to resolve prerequisites and bundles.
func (c ClientProtocol) SyncCatalog(ctx context.Context, options ScanOptions) (*Catalog, error) {
	if c.Transport == nil {
		return nil, fmt.Errorf("windows update: transport is required")
	}
	if err := ValidateScanOptions(options); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if c.Clock != nil {
		now = c.Clock().UTC()
	}
	random := c.Random
	if random == nil {
		random = rand.Reader
	}
	device, err := anonymousDeviceToken(random)
	if err != nil {
		return nil, err
	}
	messageID, err := randomUUID(random)
	if err != nil {
		return nil, err
	}
	cookieResponse, err := c.Transport.Do(ctx, Request{
		Endpoint:  Client,
		Action:    actionGetCookie,
		Body:      composeGetCookie(now, messageID, device),
		UserAgent: options.UserAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("windows update GetCookie: %w", err)
	}
	if cookieResponse.StatusCode != 200 {
		return nil, responseError("GetCookie", cookieResponse)
	}
	cookie, err := parseCookie(cookieResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("windows update GetCookie: %w", err)
	}
	cache := make(map[string]Offer)
	installedNonLeaf := make(map[string]struct{})
	otherCached := make(map[string]struct{})
	for roundIndex := 0; roundIndex < maximumSyncRounds; roundIndex++ {
		messageID, err = randomUUID(random)
		if err != nil {
			return nil, err
		}
		syncResponse, err := c.Transport.Do(ctx, Request{
			Endpoint:  Client,
			Action:    actionSyncUpdates,
			UserAgent: options.UserAgent,
			Body: composeSyncUpdates(now, messageID, device, cookie, options,
				sortedSet(installedNonLeaf), sortedSet(otherCached)),
		})
		if err != nil {
			return nil, fmt.Errorf("windows update SyncUpdates round %d: %w", roundIndex+1, err)
		}
		if syncResponse.StatusCode != 200 {
			return nil, responseError(fmt.Sprintf("SyncUpdates round %d", roundIndex+1), syncResponse)
		}
		round, err := parseSyncRound(syncResponse.Body)
		if err != nil {
			return nil, fmt.Errorf("windows update SyncUpdates round %d: %w", roundIndex+1, err)
		}
		if round.Cookie != nil {
			cookie = *round.Cookie
		}
		for serverID := range round.OutOfScope {
			delete(cache, serverID)
			delete(installedNonLeaf, serverID)
			delete(otherCached, serverID)
		}
		for _, offer := range append(round.New, round.Changed...) {
			if offer.ServerID == "" {
				return nil, fmt.Errorf("windows update SyncUpdates round %d returned an update without a revision ID", roundIndex+1)
			}
			if previous, exists := cache[offer.ServerID]; exists {
				offer = mergeOffer(previous, offer)
			}
			cache[offer.ServerID] = offer
			if offer.IsLeaf || !options.AssumeNonLeafInstalled {
				otherCached[offer.ServerID] = struct{}{}
				delete(installedNonLeaf, offer.ServerID)
			} else {
				installedNonLeaf[offer.ServerID] = struct{}{}
				delete(otherCached, offer.ServerID)
			}
		}
		if c.Observe != nil {
			c.Observe(SyncProgress{
				Round: roundIndex + 1, New: len(round.New), Changed: len(round.Changed), Cached: len(cache),
				InstalledNonLeaf: len(installedNonLeaf), Truncated: round.Truncated,
			})
		}
		if len(round.New) == 0 && !round.Truncated {
			revisions := make([]Offer, 0, len(cache))
			for _, revision := range cache {
				revisions = append(revisions, revision)
			}
			sort.Slice(revisions, func(i, j int) bool {
				left, leftErr := strconv.ParseInt(revisions[i].ServerID, 10, 64)
				right, rightErr := strconv.ParseInt(revisions[j].ServerID, 10, 64)
				if leftErr == nil && rightErr == nil && left != right {
					return left < right
				}
				return revisions[i].ServerID < revisions[j].ServerID
			})
			return &Catalog{Revisions: revisions, Rounds: roundIndex + 1}, nil
		}
	}
	return nil, fmt.Errorf("windows update SyncUpdates exceeded %d rounds", maximumSyncRounds)
}

// ResolveFiles asks Microsoft for the short-lived download locations of the
// files declared by offer. Callers must retain the declared hashes and sizes;
// the signed URL is location data, not payload identity.
func (c ClientProtocol) ResolveFiles(ctx context.Context, options ScanOptions, offer Offer) ([]File, error) {
	return c.ResolveFilesForOffers(ctx, options, []Offer{offer})
}

// ResolveFilesForOffers obtains locations for a closed set of update
// revisions in one request and joins them to their declared names, sizes, and
// digests.
func (c ClientProtocol) ResolveFilesForOffers(ctx context.Context, options ScanOptions, offers []Offer) ([]File, error) {
	if c.Transport == nil {
		return nil, fmt.Errorf("windows update: transport is required")
	}
	if err := ValidateScanOptions(options); err != nil {
		return nil, err
	}
	if len(offers) == 0 {
		return nil, fmt.Errorf("windows update: at least one offer is required")
	}
	var declared []File
	for index, offer := range offers {
		if offer.ID == "" || offer.Revision <= 0 {
			return nil, fmt.Errorf("windows update: offer %d identity and revision are required", index)
		}
		declared = append(declared, offer.Files...)
	}
	now := time.Now().UTC()
	if c.Clock != nil {
		now = c.Clock().UTC()
	}
	random := c.Random
	if random == nil {
		random = rand.Reader
	}
	device, err := anonymousDeviceToken(random)
	if err != nil {
		return nil, err
	}
	messageID, err := randomUUID(random)
	if err != nil {
		return nil, err
	}
	response, err := c.Transport.Do(ctx, Request{
		Endpoint:  ClientSecured,
		Action:    actionGetExtendedInfo,
		Body:      composeGetExtendedInfo(now, messageID, device, options, offers),
		UserAgent: options.UserAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("windows update GetExtendedUpdateInfo2: %w", err)
	}
	if response.StatusCode != 200 {
		return nil, responseError("GetExtendedUpdateInfo2", response)
	}
	files, err := parseFileLocations(response.Body, declared)
	if err != nil {
		return nil, fmt.Errorf("windows update GetExtendedUpdateInfo2: %w", err)
	}
	return files, nil
}

// ValidateScanOptions checks protocol syntax and bounds, not OS policy.
func ValidateScanOptions(options ScanOptions) error {
	for name, attributes := range map[string]map[string]string{"device": options.DeviceAttributes, "caller": options.CallerAttributes} {
		if attributes == nil || len(attributes) > 256 {
			return fmt.Errorf("windows update: explicit %s attributes required (maximum 256)", name)
		}
		for key, value := range attributes {
			if key == "" || len(key) > 256 || len(value) > 4096 || strings.ContainsAny(key, "=&\x00\r\n") || strings.ContainsAny(value, "&\x00\r\n") {
				return fmt.Errorf("windows update: invalid %s attribute %q", name, key)
			}
		}
	}
	if options.Products == "" || len(options.Products) > 65536 || strings.ContainsAny(options.Products, "\x00\r\n") {
		return fmt.Errorf("windows update: explicit bounded products string required")
	}
	if len(options.Locales) == 0 || len(options.Locales) > 64 {
		return fmt.Errorf("windows update: 1 to 64 explicit locales required")
	}
	for _, locale := range options.Locales {
		if locale == "" || len(locale) > 128 || strings.ContainsAny(locale, "\x00\r\n") {
			return fmt.Errorf("windows update: invalid locale")
		}
	}
	if options.UserAgent == "" || len(options.UserAgent) > 4096 || strings.ContainsAny(options.UserAgent, "\x00\r\n") {
		return fmt.Errorf("windows update: explicit user agent required")
	}
	return nil
}

func composeGetCookie(now time.Time, messageID, device string) []byte {
	created := formatTime(now)
	expires := formatTime(now.Add(2 * time.Minute))
	return []byte(fmt.Sprintf(`<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><a:Action s:mustUnderstand="1">%s</a:Action><a:MessageID>urn:uuid:%s</a:MessageID><a:To s:mustUnderstand="1">https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx</a:To><o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><Created>%s</Created><Expires>%s</Expires></Timestamp><wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"><TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><Device>%s</Device></TicketType></wuws:WindowsUpdateTicketsToken></o:Security></s:Header><s:Body><GetCookie xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"><oldCookie><Expiration>%s</Expiration></oldCookie><lastChange>%s</lastChange><currentTime>%s</currentTime><protocolVersion>2.0</protocolVersion></GetCookie></s:Body></s:Envelope>`, actionGetCookie, messageID, created, expires, device, created, created, created))
}

func composeSyncUpdates(now time.Time, messageID, device string, cookie Cookie, options ScanOptions, installedNonLeaf, otherCached []string) []byte {
	created := formatTime(now)
	expires := formatTime(now.Add(2 * time.Minute))
	cookieExpires := cookie.Expiration
	if cookieExpires == "" {
		cookieExpires = formatTime(now.Add(7 * 24 * time.Hour))
	}
	product := options.Products
	deviceAttributes := composeAttributes(options.DeviceAttributes)
	callerAttributes := composeAttributes(options.CallerAttributes)
	return []byte(fmt.Sprintf(`<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><a:Action s:mustUnderstand="1">%s</a:Action><a:MessageID>urn:uuid:%s</a:MessageID><a:To s:mustUnderstand="1">https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx</a:To><o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><Created>%s</Created><Expires>%s</Expires></Timestamp><wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"><TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><Device>%s</Device></TicketType></wuws:WindowsUpdateTicketsToken></o:Security></s:Header><s:Body><SyncUpdates xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"><cookie><Expiration>%s</Expiration><EncryptedData>%s</EncryptedData></cookie><parameters><ExpressQuery>false</ExpressQuery><InstalledNonLeafUpdateIDs>%s</InstalledNonLeafUpdateIDs><OtherCachedUpdateIDs>%s</OtherCachedUpdateIDs><SkipSoftwareSync>false</SkipSoftwareSync><NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates><AlsoPerformRegularSync>true</AlsoPerformRegularSync><ComputerSpec/><ExtendedUpdateInfoParameters><XmlUpdateFragmentTypes><XmlUpdateFragmentType>Extended</XmlUpdateFragmentType><XmlUpdateFragmentType>LocalizedProperties</XmlUpdateFragmentType></XmlUpdateFragmentTypes><Locales>%s</Locales></ExtendedUpdateInfoParameters><ClientPreferredLanguages/><ProductsParameters><SyncCurrentVersionOnly>false</SyncCurrentVersionOnly><DeviceAttributes>%s</DeviceAttributes><CallerAttributes>%s</CallerAttributes><Products>%s</Products></ProductsParameters></parameters></SyncUpdates></s:Body></s:Envelope>`, actionSyncUpdates, messageID, created, expires, device, xmlEscape(cookieExpires), xmlEscape(cookie.EncryptedData), xmlIntElements(installedNonLeaf), xmlIntElements(otherCached), xmlStringElements(options.Locales), xmlEscape(deviceAttributes), xmlEscape(callerAttributes), xmlEscape(product)))
}

func composeGetExtendedInfo(now time.Time, messageID, device string, options ScanOptions, offers []Offer) []byte {
	created := formatTime(now)
	expires := formatTime(now.Add(2 * time.Minute))
	var identities strings.Builder
	for _, offer := range offers {
		fmt.Fprintf(&identities, "<UpdateIdentity><UpdateID>%s</UpdateID><RevisionNumber>%d</RevisionNumber></UpdateIdentity>", xmlEscape(offer.ID), offer.Revision)
	}
	return []byte(fmt.Sprintf(`<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><a:Action s:mustUnderstand="1">%s</a:Action><a:MessageID>urn:uuid:%s</a:MessageID><a:To s:mustUnderstand="1">https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured</a:To><o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><Created>%s</Created><Expires>%s</Expires></Timestamp><wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"><TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><Device>%s</Device></TicketType></wuws:WindowsUpdateTicketsToken></o:Security></s:Header><s:Body><GetExtendedUpdateInfo2 xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"><updateIDs>%s</updateIDs><infoTypes><XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType><XmlUpdateFragmentType>FileDecryption</XmlUpdateFragmentType><XmlUpdateFragmentType>EsrpDecryptionInformation</XmlUpdateFragmentType><XmlUpdateFragmentType>PiecesHashUrl</XmlUpdateFragmentType><XmlUpdateFragmentType>BlockMapUrl</XmlUpdateFragmentType></infoTypes><deviceAttributes>%s</deviceAttributes></GetExtendedUpdateInfo2></s:Body></s:Envelope>`, actionGetExtendedInfo, messageID, created, expires, device, identities.String(), xmlEscape(composeAttributes(options.DeviceAttributes))))
}

func composeAttributes(attributes map[string]string) string {
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+attributes[key])
	}
	return "E:" + strings.Join(parts, "&")
}

func xmlStringElements(values []string) string {
	var output strings.Builder
	for _, value := range values {
		output.WriteString("<string>" + xmlEscape(value) + "</string>")
	}
	return output.String()
}

func xmlIntElements(values []string) string {
	var output strings.Builder
	for _, value := range values {
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			continue
		}
		output.WriteString("<int>")
		output.WriteString(value)
		output.WriteString("</int>")
	}
	return output.String()
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		left, leftErr := strconv.ParseInt(result[i], 10, 64)
		right, rightErr := strconv.ParseInt(result[j], 10, 64)
		if leftErr == nil && rightErr == nil {
			return left < right
		}
		return result[i] < result[j]
	})
	return result
}

func mergeOffer(previous, update Offer) Offer {
	if update.ID == "" {
		update.ID = previous.ID
	}
	if update.Revision == 0 {
		update.Revision = previous.Revision
	}
	if update.Title == "" {
		update.Title = previous.Title
	}
	if update.ProductRelease == "" {
		update.ProductRelease = previous.ProductRelease
	}
	if update.UpdateType == "" {
		update.UpdateType = previous.UpdateType
	}
	if update.Deployment == "" {
		update.Deployment = previous.Deployment
	}
	if len(update.Files) == 0 {
		update.Files = previous.Files
	}
	if len(update.Prerequisites) == 0 {
		update.Prerequisites = previous.Prerequisites
	}
	if len(update.BundledUpdates) == 0 {
		update.BundledUpdates = previous.BundledUpdates
	}
	if len(update.RawXML) == 0 {
		update.RawXML = previous.RawXML
	}
	return update
}

func leafOffers(cache map[string]Offer) []Offer {
	result := make([]Offer, 0)
	for _, offer := range cache {
		if offer.IsLeaf {
			result = append(result, offer)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		return result[i].Revision < result[j].Revision
	})
	return result
}

func parseFileLocations(data []byte, declared []File) ([]File, error) {
	root, err := parseNode(data)
	if err != nil {
		return nil, err
	}
	if fault := root.findFirst("Fault"); fault != nil {
		return nil, fmt.Errorf("SOAP fault: %s", strings.TrimSpace(fault.allText()))
	}
	byDigest := make(map[string]File, len(declared))
	for _, file := range declared {
		byDigest[strings.ToLower(file.DigestSHA1)] = file
	}
	var locations []*xmlNode
	root.findAll("FileLocation", &locations)
	if len(locations) == 0 {
		counts := make(map[string]int)
		var visit func(*xmlNode)
		visit = func(node *xmlNode) {
			counts[node.XMLName.Local]++
			for _, child := range node.Nodes {
				visit(child)
			}
		}
		visit(root)
		names := make([]string, 0, len(counts))
		for name := range counts {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > 24 {
			names = names[:24]
		}
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, name+"="+strconv.Itoa(counts[name]))
		}
		return nil, fmt.Errorf("response has no file locations (bytes=%d declared=%d elements=%s)", len(data), len(declared), strings.Join(parts, ","))
	}
	files := make([]File, 0, len(locations))
	for _, location := range locations {
		digestBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(location.childText("FileDigest")))
		if err != nil || len(digestBytes) == 0 {
			return nil, fmt.Errorf("file location has invalid digest")
		}
		digest := hex.EncodeToString(digestBytes)
		file, found := byDigest[digest]
		if !found {
			file = File{DigestSHA1: digest, Size: -1}
		}
		file.DownloadURL = strings.TrimSpace(location.childText("Url"))
		if file.DownloadURL == "" {
			return nil, fmt.Errorf("file location %s has no URL", digest)
		}
		files = append(files, file)
	}
	return files, nil
}

func parseCookie(data []byte) (Cookie, error) {
	root, err := parseNode(data)
	if err != nil {
		return Cookie{}, err
	}
	container := root.findFirst("GetCookieResult")
	if container == nil {
		container = root.findFirst("NewCookie")
	}
	if container == nil {
		return Cookie{}, fmt.Errorf("response has no cookie")
	}
	cookie := Cookie{
		Expiration:    container.childText("Expiration"),
		EncryptedData: container.childText("EncryptedData"),
	}
	if cookie.EncryptedData == "" {
		return Cookie{}, fmt.Errorf("response cookie has no encrypted data")
	}
	return cookie, nil
}

func parseSyncOffers(data []byte) ([]Offer, error) {
	round, err := parseSyncRound(data)
	if err != nil {
		return nil, err
	}
	return leafOffersBySlice(append(round.New, round.Changed...)), nil
}

func parseSyncRound(data []byte) (syncRound, error) {
	root, err := parseNode(data)
	if err != nil {
		return syncRound{}, err
	}
	if fault := root.findFirst("Fault"); fault != nil {
		return syncRound{}, fmt.Errorf("SOAP fault: %s", strings.TrimSpace(fault.allText()))
	}
	updatesByID := make(map[string][]*xmlNode)
	var updates []*xmlNode
	root.findAll("Update", &updates)
	for _, update := range updates {
		if id := update.childText("ID"); id != "" {
			updatesByID[id] = append(updatesByID[id], update)
		}
	}
	result := syncRound{OutOfScope: make(map[string]struct{})}
	if value := root.findFirst("Truncated"); value != nil {
		result.Truncated = strings.EqualFold(strings.TrimSpace(value.allText()), "true")
	}
	if value := root.findFirst("NewCookie"); value != nil {
		cookie := Cookie{Expiration: value.childText("Expiration"), EncryptedData: value.childText("EncryptedData")}
		if cookie.EncryptedData == "" {
			return syncRound{}, fmt.Errorf("SyncUpdates NewCookie has no encrypted data")
		}
		result.Cookie = &cookie
	}
	for _, containerName := range []string{"OutOfScopeRevisionIDs", "DeployedOutOfScopeRevisionIds"} {
		container := root.findFirst(containerName)
		if container == nil {
			continue
		}
		var identifiers []*xmlNode
		container.findAll("int", &identifiers)
		for _, identifier := range identifiers {
			if value := strings.TrimSpace(identifier.allText()); value != "" {
				result.OutOfScope[value] = struct{}{}
			}
		}
	}
	parseContainer := func(name string) ([]Offer, error) {
		container := root.findFirst(name)
		if container == nil {
			return nil, nil
		}
		var infos []*xmlNode
		container.findAll("UpdateInfo", &infos)
		offers := make([]Offer, 0, len(infos))
		for _, info := range infos {
			offer, err := parseUpdateInfo(info, updatesByID)
			if err != nil {
				return nil, err
			}
			offers = append(offers, offer)
		}
		return offers, nil
	}
	result.New, err = parseContainer("NewUpdates")
	if err != nil {
		return syncRound{}, err
	}
	result.Changed, err = parseContainer("ChangedUpdates")
	if err != nil {
		return syncRound{}, err
	}
	return result, nil
}

func parseUpdateInfo(info *xmlNode, updatesByID map[string][]*xmlNode) (Offer, error) {
	offer := Offer{ServerID: info.childText("ID"), Revision: 1, IsLeaf: strings.EqualFold(info.childText("IsLeaf"), "true")}
	if deployment := info.firstChild("Deployment"); deployment != nil {
		offer.Deployment = deployment.attr("Action")
		if offer.Deployment == "" {
			offer.Deployment = deployment.childText("Action")
		}
	}
	for _, attr := range info.Attr {
		switch attr.Name.Local {
		case "UpdateID":
			offer.ID = attr.Value
		case "RevisionNumber":
			offer.Revision, _ = strconv.Atoi(attr.Value)
		}
	}
	if offer.ID == "" {
		offer.ID = info.childText("UpdateID")
	}
	if value := info.childText("RevisionNumber"); value != "" {
		offer.Revision, _ = strconv.Atoi(value)
	}
	offer.RawXML = []byte(info.innerXML())
	collectOfferMetadata(info, &offer)
	for _, metadata := range updatesByID[offer.ServerID] {
		collectOfferMetadata(metadata, &offer)
	}
	if offer.ServerID == "" {
		return Offer{}, fmt.Errorf("UpdateInfo has no ID")
	}
	return offer, nil
}

func leafOffersBySlice(values []Offer) []Offer {
	result := make([]Offer, 0, len(values))
	for _, offer := range values {
		if offer.IsLeaf {
			result = append(result, offer)
		}
	}
	return result
}

func collectOfferMetadata(node *xmlNode, offer *Offer) {
	if offer.Title == "" {
		offer.Title = node.childTextRecursive("Title")
	}
	collectOfferIdentity(node, offer)
	collectDeclaredFiles(node, offer)
	collectRelationships(node, offer)
	for _, text := range node.textFragments() {
		decoded := html.UnescapeString(strings.TrimSpace(text))
		if !strings.HasPrefix(decoded, "<") {
			continue
		}
		// Windows Update XML fragments commonly contain several top-level
		// elements, so give the standard XML decoder one synthetic root.
		fragment, err := parseNode([]byte("<Fragment>" + decoded + "</Fragment>"))
		if err != nil {
			continue
		}
		if offer.Title == "" {
			offer.Title = fragment.childTextRecursive("Title")
		}
		collectOfferIdentity(fragment, offer)
		collectDeclaredFiles(fragment, offer)
		collectRelationships(fragment, offer)
	}
}

func collectOfferIdentity(node *xmlNode, offer *Offer) {
	identity := node
	if node.XMLName.Local != "UpdateIdentity" {
		identity = node.firstChild("UpdateIdentity")
	}
	if identity != nil {
		if id := identity.attr("UpdateID"); id != "" && offer.ID == "" {
			offer.ID = id
		}
		if revision := identity.attr("RevisionNumber"); revision != "" {
			offer.Revision, _ = strconv.Atoi(revision)
		}
	}
	if product := node.findFirst("ProductReleaseInstalled"); product != nil {
		offer.ProductRelease = product.attr("Name")
	}
	if properties := node.findFirst("Properties"); properties != nil {
		if value := properties.attr("UpdateType"); value != "" {
			offer.UpdateType = value
		}
	}
}

func collectRelationships(node *xmlNode, offer *Offer) {
	relationships := node.findFirst("Relationships")
	if relationships == nil {
		return
	}
	if prerequisites := relationships.firstChild("Prerequisites"); prerequisites != nil {
		offer.Prerequisites = appendUniqueClauses(offer.Prerequisites, relationshipClauses(prerequisites))
	}
	if bundled := relationships.firstChild("BundledUpdates"); bundled != nil {
		offer.BundledUpdates = appendUniqueClauses(offer.BundledUpdates, relationshipClauses(bundled))
	}
}

func relationshipClauses(container *xmlNode) []RelationshipClause {
	var result []RelationshipClause
	for _, child := range container.Nodes {
		switch child.XMLName.Local {
		case "AtLeastOne":
			clause := RelationshipClause{IsCategory: strings.EqualFold(child.attr("IsCategory"), "true")}
			for _, identity := range child.Nodes {
				if identity.XMLName.Local == "UpdateIdentity" {
					clause.Alternatives = append(clause.Alternatives, parseRelationshipIdentity(identity))
				}
			}
			if len(clause.Alternatives) != 0 {
				result = append(result, clause)
			}
		case "UpdateIdentity":
			result = append(result, RelationshipClause{Alternatives: []UpdateIdentity{parseRelationshipIdentity(child)}})
		}
	}
	return result
}

func parseRelationshipIdentity(node *xmlNode) UpdateIdentity {
	result := UpdateIdentity{ID: node.attr("UpdateID")}
	result.Revision, _ = strconv.Atoi(node.attr("RevisionNumber"))
	return result
}

func appendUniqueClauses(current, more []RelationshipClause) []RelationshipClause {
	seen := make(map[string]struct{}, len(current))
	key := func(clause RelationshipClause) string {
		parts := make([]string, len(clause.Alternatives))
		for index, identity := range clause.Alternatives {
			parts[index] = strings.ToLower(identity.ID) + "@" + strconv.Itoa(identity.Revision)
		}
		return strconv.FormatBool(clause.IsCategory) + ":" + strings.Join(parts, "|")
	}
	for _, clause := range current {
		seen[key(clause)] = struct{}{}
	}
	for _, clause := range more {
		if _, exists := seen[key(clause)]; !exists {
			seen[key(clause)] = struct{}{}
			current = append(current, clause)
		}
	}
	return current
}

func collectDeclaredFiles(node *xmlNode, offer *Offer) {
	var files []*xmlNode
	node.findAll("File", &files)
	seen := make(map[string]bool, len(offer.Files))
	for _, existing := range offer.Files {
		seen[existing.DigestSHA1+"\x00"+existing.Name] = true
	}
	for _, fileNode := range files {
		file := File{Size: -1}
		for _, attr := range fileNode.Attr {
			switch attr.Name.Local {
			case "Digest":
				if decoded, err := base64.StdEncoding.DecodeString(attr.Value); err == nil {
					file.DigestSHA1 = hex.EncodeToString(decoded)
				}
			case "FileName":
				file.Name = attr.Value
			case "Size":
				file.Size, _ = strconv.ParseInt(attr.Value, 10, 64)
			}
		}
		var additional []*xmlNode
		fileNode.findAll("AdditionalDigest", &additional)
		for _, digest := range additional {
			if strings.EqualFold(digest.attr("Algorithm"), "SHA256") {
				if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(digest.allText())); err == nil {
					file.DigestSHA256 = hex.EncodeToString(decoded)
				}
			}
		}
		key := file.DigestSHA1 + "\x00" + file.Name
		if (file.DigestSHA1 != "" || file.Name != "") && !seen[key] {
			seen[key] = true
			offer.Files = append(offer.Files, file)
		}
	}
}

func responseError(operation string, response Response) error {
	body := strings.TrimSpace(string(response.Body))
	if len(body) > 1024 {
		body = body[:1024]
	}
	return fmt.Errorf("%s returned HTTP %d: %s", operation, response.StatusCode, body)
}

func anonymousDeviceToken(random io.Reader) (string, error) {
	header, err := hex.DecodeString("13003002c377040014d5bcac7a66de0d50beddf9bba16c87edb9e019898000")
	if err != nil {
		return "", err
	}
	randomBytes := make([]byte, 527)
	if _, err := io.ReadFull(random, randomBytes); err != nil {
		return "", fmt.Errorf("windows update device token: %w", err)
	}
	ticket := append(append(header, randomBytes...), 0xb4, 0x01)
	data := "t=" + base64.StdEncoding.EncodeToString(ticket) + "&p="
	utf16LE := make([]byte, len(data)*2)
	for index := range data {
		utf16LE[index*2] = data[index]
	}
	return base64.StdEncoding.EncodeToString(utf16LE), nil
}

func randomUUID(random io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("windows update message ID: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func formatTime(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05Z") }

func xmlEscape(value string) string {
	var output bytes.Buffer
	_ = xml.EscapeText(&output, []byte(value))
	return output.String()
}

type xmlNode struct {
	XMLName xml.Name
	Attr    []xml.Attr `xml:",any,attr"`
	Nodes   []*xmlNode `xml:",any"`
	Text    string     `xml:",chardata"`
}

func parseNode(data []byte) (*xmlNode, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var root xmlNode
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse XML: %w", err)
	}
	return &root, nil
}

func (n *xmlNode) findFirst(name string) *xmlNode {
	if n.XMLName.Local == name {
		return n
	}
	for _, child := range n.Nodes {
		if found := child.findFirst(name); found != nil {
			return found
		}
	}
	return nil
}

func (n *xmlNode) findAll(name string, output *[]*xmlNode) {
	if n.XMLName.Local == name {
		*output = append(*output, n)
	}
	for _, child := range n.Nodes {
		child.findAll(name, output)
	}
}

func (n *xmlNode) childText(name string) string {
	for _, child := range n.Nodes {
		if child.XMLName.Local == name {
			return strings.TrimSpace(child.allText())
		}
	}
	return ""
}

func (n *xmlNode) firstChild(name string) *xmlNode {
	for _, child := range n.Nodes {
		if child.XMLName.Local == name {
			return child
		}
	}
	return nil
}

func (n *xmlNode) childTextRecursive(name string) string {
	if found := n.findFirst(name); found != nil {
		return strings.TrimSpace(found.allText())
	}
	return ""
}

func (n *xmlNode) allText() string {
	var output strings.Builder
	output.WriteString(n.Text)
	for _, child := range n.Nodes {
		output.WriteString(child.allText())
	}
	return output.String()
}

func (n *xmlNode) textFragments() []string {
	result := []string{n.Text}
	for _, child := range n.Nodes {
		result = append(result, child.textFragments()...)
	}
	return result
}

func (n *xmlNode) attr(name string) string {
	for _, attr := range n.Attr {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func (n *xmlNode) innerXML() string {
	var output strings.Builder
	for _, child := range n.Nodes {
		output.WriteString("<" + child.XMLName.Local + ">")
		output.WriteString(child.allText())
		output.WriteString("</" + child.XMLName.Local + ">")
	}
	return output.String()
}
