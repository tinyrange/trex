// Package appx exposes unencrypted APPX/MSIX packages and bundles as portable
// file readers. It does not deploy packages or authenticate their publishers.
package appx

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"

	ziparchive "github.com/tinyrange/trex/archive/zip"
	"github.com/tinyrange/trex/storage"
)

const maxManifest = 8 << 20

type Identity struct {
	Name         string `xml:"Name,attr"`
	Publisher    string `xml:"Publisher,attr"`
	Version      string `xml:"Version,attr"`
	Architecture string `xml:"ProcessorArchitecture,attr"`
	ResourceID   string `xml:"ResourceId,attr"`
}

type Member struct {
	Name         string `xml:"FileName,attr"`
	Type         string `xml:"Type,attr"`
	Architecture string `xml:"Architecture,attr"`
	Version      string `xml:"Version,attr"`
	Size         uint64 `xml:"Size,attr"`
	IsStub       bool   `xml:"IsStub,attr"`
	File         *Entry `xml:"-"`
}

type Archive struct {
	Kind     string
	Identity Identity
	Entries  []*Entry
	Packages []Member
	zipFiles map[string]*zip.File
}

// Open borrows source. Entries decode lazily with bounded indexed MSIX blocks or ZIP windows; the
// caller must retain source. Bundle members are separate packages, never merged.
// ZIP CRC is checked by Verify (and whole-file ReadAt); indexed partial reads
// check block hashes. AppxSignature.p7x and the block
// map are exposed as files but are NOT signature or publisher trust validation.
func Open(source storage.Reader) (*Archive, error) {
	var magic [4]byte
	if _, err := source.ReadAt(magic[:], 0); err != nil {
		return nil, fmt.Errorf("appx: header: %w", err)
	}
	if string(magic[:]) == "EXPH" {
		return nil, fmt.Errorf("appx: encrypted packages are unsupported")
	}
	z, err := zip.NewReader(source, source.Size())
	if err != nil {
		return nil, fmt.Errorf("appx: ZIP: %w", err)
	}
	if len(z.File) > 100000 {
		return nil, fmt.Errorf("appx: too many entries")
	}
	a := &Archive{Kind: "package"}
	byName := map[string]*zip.File{}
	entries := map[string]*Entry{}
	for _, f := range z.File {
		decoded, err := url.PathUnescape(f.Name)
		if err != nil || !utf8.ValidString(decoded) || !safeName(strings.TrimSuffix(f.Name, "/")) || strings.HasSuffix(decoded, "/") != f.FileInfo().IsDir() {
			return nil, fmt.Errorf("appx: invalid encoded entry %q", f.Name)
		}
		name := strings.TrimSuffix(decoded, "/")
		if !safeName(name) || f.UncompressedSize64 > math.MaxInt64 || f.Flags&1 != 0 || (!f.Mode().IsRegular() && !f.FileInfo().IsDir()) {
			return nil, fmt.Errorf("appx: invalid or encrypted entry %q", f.Name)
		}
		key := strings.ToLower(name)
		if byName[key] != nil {
			return nil, fmt.Errorf("appx: duplicate entry %q", name)
		}
		byName[key] = f
		entry := &Entry{Entry: ziparchive.NewEntry(f), Name: decoded, ArchiveName: f.Name}
		entries[key] = entry
		a.Entries = append(a.Entries, entry)
	}
	// Reject file/directory aliases, including implicit parent directories.
	for name := range byName {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if f := byName[parent]; f != nil && !f.FileInfo().IsDir() {
				return nil, fmt.Errorf("appx: file/directory collision %q", parent)
			}
		}
	}
	manifest := byName["appxmanifest.xml"]
	bundle := byName["appxmetadata/appxbundlemanifest.xml"]
	if (manifest == nil) == (bundle == nil) {
		return nil, fmt.Errorf("appx: expected exactly one package or bundle manifest")
	}
	var doc struct {
		XMLName  xml.Name
		Identity Identity
		Packages []Member `xml:"Packages>Package"`
	}
	if bundle != nil {
		manifest = bundle
		a.Kind = "bundle"
	}
	if manifest.UncompressedSize64 > maxManifest {
		return nil, fmt.Errorf("appx: manifest exceeds 8MiB")
	}
	r, err := manifest.Open()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(r, maxManifest+1))
	_ = r.Close()
	if err != nil {
		return nil, fmt.Errorf("appx: manifest: %w", err)
	}
	if len(data) > maxManifest {
		return nil, fmt.Errorf("appx: manifest exceeds 8MiB")
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("appx: manifest XML: %w", err)
	}
	root := "Package"
	if bundle != nil {
		root = "Bundle"
	}
	if doc.XMLName.Local != root || doc.Identity.Name == "" || doc.Identity.Publisher == "" || doc.Identity.Version == "" {
		return nil, fmt.Errorf("appx: invalid %s identity", root)
	}
	a.Identity = doc.Identity
	if bundle != nil {
		seen := map[string]bool{}
		if len(doc.Packages) == 0 {
			return nil, fmt.Errorf("appx: empty bundle")
		}
		for _, m := range doc.Packages {
			// Bundle manifest references may use Windows separators (including
			// embedded stub packages). ZIP entry names remain strict OPC paths.
			m.Name = strings.ReplaceAll(m.Name, `\`, "/")
			key := strings.ToLower(m.Name)
			f := byName[key]
			if !safeName(m.Name) || seen[key] || f == nil || f.FileInfo().IsDir() || f.UncompressedSize64 != m.Size || (m.Type != "application" && m.Type != "resource") {
				return nil, fmt.Errorf("appx: invalid bundle member %q (external/flat bundles unsupported)", m.Name)
			}
			seen[key] = true
			m.File = entries[key]
			a.Packages = append(a.Packages, m)
		}
	}
	a.zipFiles = byName
	a.indexBlocks(entries)
	return a, nil
}

func safeName(name string) bool {
	if name == "" || name == "." || strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.ContainsAny(name, "\\:\x00") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
	}
	return true
}
