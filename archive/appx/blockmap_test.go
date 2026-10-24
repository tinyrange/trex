package appx

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func mapFile(name string, data []byte) string {
	s := fmt.Sprintf(`<File Name="%s" Size="%d">`, name, len(data))
	for offset := 0; offset < len(data); offset += blockSize {
		h := sha256.Sum256(data[offset:min(offset+blockSize, len(data))])
		s += `<Block Hash="` + base64.StdEncoding.EncodeToString(h[:]) + `"/>`
	}
	return s + `</File>`
}
func TestBlockMapIntegrity(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), blockSize+7)
	body := mapFile("AppxManifest.xml", []byte(manifest)) + mapFile(`Assets\has space.txt`, payload) + mapFile("empty", nil)
	wrap := func(body string) string {
		return `<BlockMap xmlns="` + blockMapNamespace + `" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">` + body + `</BlockMap>`
	}
	cases := []struct {
		name, body string
		payload    []byte
		extra      bool
		budget     uint64
		good       bool
	}{
		{"valid", body, payload, false, 1 << 20, true},
		{"tamper with valid ZIP CRC", body, bytes.Repeat([]byte("y"), len(payload)), false, 1 << 20, false},
		{"omitted payload", mapFile("AppxManifest.xml", []byte(manifest)), payload, false, 1 << 20, false},
		{"duplicate", body + mapFile("empty", nil), payload, false, 1 << 20, false},
		{"extra file", body, payload, true, 1 << 20, false},
		{"budget", body, payload, false, 10, false},
		{"wrong size", strings.Replace(body, `Size="65543"`, `Size="65542"`, 1), payload, false, 1 << 20, false},
		{"missing block", strings.Replace(body, `<Block Hash=`, `<Other Hash=`, 1), payload, false, 1 << 20, false},
		{"unsafe name", strings.Replace(body, `Name="empty"`, `Name="..\empty"`, 1), payload, false, 1 << 20, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := []fixtureEntry{{"AppxManifest.xml", []byte(manifest)}, {"Assets/has%20space.txt", tc.payload}, {"empty", nil}, {"AppxBlockMap.xml", []byte(wrap(tc.body))}}
			if tc.extra {
				entries = append(entries, fixtureEntry{"unmapped", []byte("x")})
			}
			a, err := Open(bytes.NewReader(makeZIP(t, entries...)))
			if err != nil {
				t.Fatal(err)
			}
			err = a.VerifyBlockMap(tc.budget)
			if (err == nil) != tc.good {
				t.Fatalf("verification: %v", err)
			}
		})
	}
}
func TestBundleBlockMap(t *testing.T) {
	child := makeZIP(t, fixtureEntry{"AppxManifest.xml", []byte(manifest)})
	bundle := fmt.Sprintf(`<Bundle><Identity Name="Example.App" Publisher="CN=Example" Version="1.2.3.4"/><Packages><Package Type="application" Architecture="x64" Version="1.2.3.4" FileName="app.msix" Size="%d"/></Packages></Bundle>`, len(child))
	bm := `<BlockMap xmlns="` + blockMapNamespace + `" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">` + mapFile(`AppxMetadata\AppxBundleManifest.xml`, []byte(bundle)) + `</BlockMap>`
	a, err := Open(bytes.NewReader(makeZIP(t, fixtureEntry{"AppxMetadata/AppxBundleManifest.xml", []byte(bundle)}, fixtureEntry{"app.msix", child}, fixtureEntry{"AppxBlockMap.xml", []byte(bm)})))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyBlockMap(1 << 20); err != nil {
		t.Fatal(err)
	}
	// A successful outer map check is deliberately not recursive or signature trust.
	c, err := Open(a.Packages[0].File)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyBlockMap(1 << 20); err == nil {
		t.Fatal("missing inner map accepted")
	}
}
