package native

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	storagenative "github.com/tinyrange/trex/storage/native"
	update "github.com/tinyrange/trex/windows/update"
	"go.starlark.net/starlark"
)

// SourceSnapshot is the portable versioned selection.
type SourceSnapshot = update.SourceSnapshot

// CaptureSource resolves locations for this exact selection, never rescans.
func CaptureSource(ctx context.Context, catalogArg, offerArg starlark.Value) (*SourceSnapshot, error) {
	catalog, offer, err := selectedOffer(catalogArg, offerArg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	var files []update.File
	if catalog.allowNetwork {
		_, files, err = catalog.resolveFiles(ctx, offer)
	} else {
		if catalog.payloads != nil {
			return nil, fmt.Errorf("archived selection already has portable source metadata; no location renewal during replay")
		}
		// Capture is an explicitly online operation, including when the caller
		// deliberately selects a previously recorded catalog synchronization.
		closure, closureErr := catalog.catalog.ResolveBundleClosure(offer)
		if closureErr != nil {
			return nil, closureErr
		}
		client, clientErr := microsoftUpdateHTTPClient()
		if clientErr != nil {
			return nil, clientErr
		}
		defer client.CloseIdleConnections()
		protocol := update.ClientProtocol{Transport: Transport{Client: client}}
		files, err = protocol.ResolveFilesForOffers(ctx, catalog.options, closure)
	}
	if err != nil {
		return nil, err
	}
	profile := catalog.options
	s := &SourceSnapshot{Version: 1, Selected: update.UpdateIdentity{ID: offer.ID, Revision: offer.Revision}, LocationProfile: &profile}
	s.Files = normalizeSnapshotFiles(files)
	// Preserve prerequisite witnesses as well as bundle members. Raw XML is not
	// interpreted by reconstruction and may contain unrelated protocol state.
	for _, revision := range catalog.catalog.Revisions {
		revision.RawXML = nil
		revision.Files = append([]update.File(nil), revision.Files...)
		for i := range revision.Files {
			revision.Files[i].DownloadURL = ""
		}
		s.Revisions = append(s.Revisions, revision)
	}
	if _, _, err := s.Selection(); err != nil {
		return nil, err
	}
	return s, nil
}

// PayloadSource opens original payloads, not extracted or reconstructed files.
// Implementations must verify the declared content identity before returning it.
// The caller owns reader lifetimes until all constructed media is released.
type PayloadSource func(context.Context, update.File) (storage.Reader, error)

// ReplaySource cannot query the catalog or resolve URLs. Its only source of
// bytes is the explicitly supplied backend (typically a verified offline archive).
func ReplaySource(s *SourceSnapshot, source PayloadSource) (starlark.Value, starlark.Value, error) {
	// Freeze caller-owned slices/maps before constructing immutable native values.
	encoded, err := json.Marshal(s)
	if err != nil {
		return nil, nil, err
	}
	var copy SourceSnapshot
	if err = json.Unmarshal(encoded, &copy); err != nil {
		return nil, nil, err
	}
	s = &copy
	catalog, selected, err := s.Selection()
	if err != nil {
		return nil, nil, err
	}
	if source == nil {
		return nil, nil, fmt.Errorf("source snapshot: explicit payload backend required")
	}
	value := newCatalogValue(catalog, update.ScanOptions{}, update.ClientProtocol{})
	value.payloads = source
	offers, _ := value.Attr("offers")
	list := offers.(*starlark.List)
	for i := 0; i < list.Len(); i++ {
		offer := list.Index(i).(*offerValue)
		if offer.offer.ID == selected.ID && offer.offer.Revision == selected.Revision {
			return value, offer, nil
		}
	}
	return nil, nil, fmt.Errorf("source snapshot: selected offer missing")
}

type payloadPool interface {
	open(*lifecycle.Resources, update.File) (storage.Reader, error)
}
type archivedPayloadPool struct{ source PayloadSource }

func (p archivedPayloadPool) open(r *lifecycle.Resources, f update.File) (storage.Reader, error) {
	reader, err := p.source(r.Context(), f)
	if err == nil && (reader == nil || reader.Size() != f.Size) {
		return nil, fmt.Errorf("archived payload %q has incorrect size", f.Name)
	}
	return reader, err
}

type httpPayloadPool struct{ pool *storagenative.HTTPRangePool }

func (p httpPayloadPool) open(r *lifecycle.Resources, f update.File) (storage.Reader, error) {
	var urls []string
	if f.DownloadURL != "" {
		urls = []string{f.DownloadURL}
	}
	reader, err := p.pool.OpenSHA256(r.Context(), f.Name, urls, f.Size, f.DigestSHA256)
	if err != nil {
		return nil, err
	}
	if _, err = r.Add(reader); err != nil {
		reader.Close()
		return nil, err
	}
	return reader, nil
}

func normalizeSnapshotFiles(files []update.File) []update.File {
	var result []update.File
	seen := map[update.File]bool{}
	for _, file := range files {
		key := file
		key.Name = strings.ToLower(key.Name)
		key.DigestSHA1 = strings.ToLower(key.DigestSHA1)
		key.DigestSHA256 = strings.ToLower(key.DigestSHA256)
		key.DownloadURL = ""
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, file)
	}
	return result
}

// RefreshSourceLocations is explicitly online acquisition, never replay. It
// asks only for URLs of the saved identities and rejects any changed content.
// Callers need not rewrite the tested lockfile: URLs are acquisition hints.
func RefreshSourceLocations(ctx context.Context, s *SourceSnapshot, observe func(string)) ([]update.File, error) {
	client, err := microsoftUpdateHTTPClient()
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	return refreshSourceLocations(ctx, s, update.ClientProtocol{Transport: Transport{Client: client, Observe: observe}})
}
func refreshSourceLocations(ctx context.Context, s *SourceSnapshot, protocol update.ClientProtocol) ([]update.File, error) {
	catalog, selected, err := s.Selection()
	if err != nil {
		return nil, err
	}
	if s.LocationProfile == nil {
		return nil, fmt.Errorf("snapshot has no acquisition profile; restore archive or supply a same-content mirror")
	}
	if err = update.ValidateScanOptions(*s.LocationProfile); err != nil {
		return nil, err
	}
	closure, err := catalog.ResolveBundleClosure(selected)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	files, err := protocol.ResolveFilesForOffers(ctx, *s.LocationProfile, closure)
	if err != nil {
		return nil, err
	}
	check := *s
	check.Files = normalizeSnapshotFiles(files)
	if err = check.Validate(); err != nil {
		return nil, fmt.Errorf("refreshed locations changed locked content: %w", err)
	}
	return check.Files, nil
}
