package update

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// SourceSnapshot is a portable, normalized Windows Update selection. It contains
// no cookies, SOAP responses or builder identity. Locations are acquisition hints;
// the declared digest and size remain authoritative after those URLs expire.
// Version changes only when interpreting existing fields would change semantics.
type SourceSnapshot struct {
	// Optional acquisition profile. Replay never uses it or opens a transport.
	LocationProfile *ScanOptions   `json:"location_profile,omitempty" yaml:"location_profile,omitempty"`
	Version         int            `json:"version" yaml:"version"`
	Selected        UpdateIdentity `json:"selected" yaml:"selected"`
	Revisions       []Offer        `json:"revisions" yaml:"revisions"`
	Files           []File         `json:"files" yaml:"files"`
}

func (s *SourceSnapshot) Selection() (*Catalog, Offer, error) {
	fail := func(message string) (*Catalog, Offer, error) {
		return nil, Offer{}, fmt.Errorf("source snapshot: %s", message)
	}
	if s == nil || s.Version != 1 {
		return fail("unsupported format version (supported: 1)")
	}
	if len(s.Revisions) == 0 || len(s.Revisions) > 100000 || len(s.Files) > 100000 {
		return fail("invalid catalog bounds")
	}
	catalog := &Catalog{Revisions: s.Revisions}
	var selected Offer
	seen := map[UpdateIdentity]bool{}
	for _, offer := range s.Revisions {
		key := UpdateIdentity{ID: strings.ToLower(offer.ID), Revision: offer.Revision}
		if key.ID == "" || key.Revision <= 0 || seen[key] {
			return fail("invalid or duplicate revision")
		}
		seen[key] = true
		if strings.EqualFold(offer.ID, s.Selected.ID) && offer.Revision == s.Selected.Revision {
			selected = offer
		}
	}
	if selected.ID == "" {
		return fail("selected revision is absent")
	}
	closure, err := catalog.ResolveBundleClosure(selected)
	if err != nil {
		return nil, Offer{}, err
	}
	declared := snapshotPayloadFiles(closure)
	identity := func(f File) File {
		f.Name = strings.ToLower(f.Name)
		f.DigestSHA1 = strings.ToLower(f.DigestSHA1)
		f.DigestSHA256 = strings.ToLower(f.DigestSHA256)
		f.DownloadURL = ""
		return f
	}
	files := map[File]bool{}
	for _, f := range s.Files {
		digest, err := hex.DecodeString(f.DigestSHA256)
		if err != nil || len(digest) != 32 || f.Size <= 0 || f.Name == "" {
			return fail("payload requires SHA-256, size and name")
		}
		key := identity(f)
		if files[key] {
			return fail("duplicate payload identity")
		}
		files[key] = true
	}
	if len(files) != len(declared) {
		return fail("payload inventory differs from selected bundle closure")
	}
	for _, f := range declared {
		if !files[identity(f)] {
			return fail("payload identity differs from selected bundle closure")
		}
	}
	return catalog, selected, nil
}

// Validate checks format, dependency closure and complete payload identities.
func (s *SourceSnapshot) Validate() error { _, _, err := s.Selection(); return err }

func snapshotPayloadFiles(offers []Offer) []File {
	type identity struct {
		name, sha1, sha256 string
		size               int64
	}
	seen := make(map[identity]bool)
	var files []File
	for _, offer := range offers {
		for _, file := range offer.Files {
			key := identity{strings.ToLower(file.Name), strings.ToLower(file.DigestSHA1), strings.ToLower(file.DigestSHA256), file.Size}
			if seen[key] {
				continue
			}
			seen[key] = true
			file.DownloadURL = ""
			files = append(files, file)
		}
	}
	return files
}
