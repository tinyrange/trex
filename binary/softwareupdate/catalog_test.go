package softwareupdate

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"

	"github.com/tinyrange/trex/binary/plist"
	"github.com/tinyrange/trex/storage"
)

// Synthetic fixtures describe published fields, not copied installer scripts.
const legacyProduct = `<dict><key>ExtendedMetaInfo</key><dict><key>InstallAssistantPackageIdentifiers</key><dict><key>OSInstall</key><string>com.apple.mpkg.OSInstall</string></dict></dict><key>Packages</key><array><dict><key>URL</key><string>https://example.test/InstallESDDmg.pkg</string><key>Size</key><integer>7739883774</integer><key>Digest</key><data>AQID</data><key>MetadataURL</key><string>https://example.test/metadata</string></dict></array><key>Distributions</key><dict><key>English</key><string>https://example.test/legacy.dist</string></dict><key>PostDate</key><date>2020-01-01T00:00:00Z</date></dict>`
const modernProduct = `<dict><key>ExtendedMetaInfo</key><dict><key>InstallAssistantPackageIdentifiers</key><dict><key>SharedSupport</key><string>com.apple.pkg.InstallAssistant.macOSTahoe</string></dict></dict><key>Packages</key><array><dict><key>URL</key><string>https://example.test/InstallAssistant.pkg</string><key>Size</key><integer>18380974544</integer></dict></array></dict>`

func catalogBody(body string) string {
	return `<plist version="1.0"><dict><key>CatalogVersion</key><integer>2</integer><key>Products</key><dict>` + body + `</dict></dict></plist>`
}
func fromString(s string) storage.Reader { return bytes.NewReader([]byte(s)) }

func TestCatalogDiscoveryAndPreservation(t *testing.T) {
	raw := catalogBody(`<key>z</key>` + legacyProduct + `<key>not-an-installer</key><dict><key>ExtendedMetaInfo</key><dict><key>InstallAssistantPackageIdentifiers</key><dict><key>SharedSupport</key><string>com.example.NotAnInstaller</string></dict></dict></dict><key>a</key>` + modernProduct)
	var zipped bytes.Buffer
	z := gzip.NewWriter(&zipped)
	if _, err := z.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{[]byte(raw), zipped.Bytes()} {
		products, err := Catalog(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if len(products) != 2 || products[0]["id"] != "a" || products[1]["id"] != "z" {
			t.Fatalf("installer selection/order: %v", products)
		}
		metadata := products[1]["metadata"].(map[string]any)
		packages := metadata["Packages"].([]any)
		pkg := packages[0].(map[string]any)
		if pkg["Size"] != int64(7739883774) || !bytes.Equal(pkg["Digest"].([]byte), []byte{1, 2, 3}) || pkg["MetadataURL"] != "https://example.test/metadata" {
			t.Fatalf("lost package metadata: %v", pkg)
		}
		if _, ok := metadata["PostDate"].(plist.Date); !ok {
			t.Fatal("lost date")
		}
	}
	corrupt := append([]byte(nil), zipped.Bytes()...)
	corrupt[len(corrupt)-8] ^= 1
	if _, err := Catalog(bytes.NewReader(corrupt)); err == nil {
		t.Fatal("accepted gzip checksum corruption")
	}
}
func TestCatalogExceedsWholePlistValueBudget(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 30000; i++ {
		fmt.Fprintf(&b, `<key>%d</key><dict><key>A</key><string>x</string><key>B</key><string>x</string><key>C</key><string>x</string></dict>`, i)
	}
	b.WriteString(`<key>installer</key>` + legacyProduct)
	raw := catalogBody(b.String())
	if _, err := plist.Decode([]byte(raw)); err == nil {
		t.Fatal("fixture no longer exceeds whole-plist budget")
	}
	products, err := Catalog(fromString(raw))
	if err != nil || len(products) != 1 || products[0]["id"] != "installer" {
		t.Fatalf("large catalog: %v %v", products, err)
	}
}
func TestCatalogRejectsMalformedInput(t *testing.T) {
	for _, raw := range []string{
		"", `<plist><dict/></plist>`, catalogBody(`<key>a</key>` + legacyProduct + `<key>a</key>` + modernProduct),
		catalogBody(`<key>a</key><string>not a dictionary</string>`),
		catalogBody(`<key>a</key><dict><key>A</key><integer>-bad</integer></dict>`),
		catalogBody(`<key>a</key><dict><key>A</key><string>&external;</string></dict>`),
		catalogBody(`<key>a</key>`+legacyProduct) + `<extra/>`,
		catalogBody(`<key>a</key>` + strings.Repeat(`<array>`, 129) + strings.Repeat(`</array>`, 129)),
		catalogBody(`<key>a</key>` + legacyProduct)[:100],
		`<plist><dict><key>Products</key><dict/><key>Products</key><dict/></dict></plist>`,
	} {
		if _, err := Catalog(fromString(raw)); err == nil {
			t.Fatalf("accepted malformed catalog %.120s", raw)
		}
	}
}

type oversizedReader struct{ size int64 }

func (r oversizedReader) Size() int64 { return r.size }
func (r oversizedReader) ReadAt([]byte, int64) (int, error) {
	panic("oversized source must not be read")
}
func TestSourceSizeLimitsBeforeRead(t *testing.T) {
	if _, err := Catalog(oversizedReader{MaxCatalogBytes + 1}); err == nil {
		t.Fatal("catalog size")
	}
	if _, err := Distribution(oversizedReader{MaxDistributionBytes + 1}); err == nil {
		t.Fatal("Distribution size")
	}
}
